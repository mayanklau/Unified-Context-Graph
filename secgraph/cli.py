"""Command line: run the service and operate it.

Every command reads configuration from ``SECGRAPH_*`` environment variables
(or ``.env``). ``secgraph --help`` lists the commands.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from secgraph import __version__
from secgraph.config import get_settings
from secgraph.errors import SecGraphError
from secgraph.governance.rbac import Principal

_CLI_ROLES = ["platform_admin"]


def _principal(tenant: str) -> Principal:
    return Principal.build(id="system:cli", name="cli", kind="service", tenant_id=tenant, roles=_CLI_ROLES)


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _context() -> Any:
    from secgraph.context import build_context
    from secgraph.observability import configure_logging

    settings = get_settings()
    configure_logging("WARNING" if settings.log_level.upper() == "INFO" else settings.log_level, settings.log_json)
    return build_context(settings)


def _tenant(args: argparse.Namespace) -> str:
    from secgraph.governance.auth import validate_tenant_id

    return validate_tenant_id(args.tenant or get_settings().default_tenant)


def _read_password(args: argparse.Namespace) -> str:
    if getattr(args, "password_env", None):
        value = os.environ.get(args.password_env)
        if not value:
            raise SystemExit(f"environment variable {args.password_env} is empty or not set")
        return value
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return first


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    settings.validate_for_environment()
    uvicorn.run(
        "secgraph.api.app:app_factory",
        factory=True,
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_config=None,
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips=args.forwarded_allow_ips,
        timeout_keep_alive=30,
    )
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from secgraph.store import migrate

    if args.action == "status":
        state = migrate.status()
        _print(state)
        return 0 if state["up_to_date"] else 1
    if args.action == "downgrade":
        if not args.yes:
            raise SystemExit("downgrade drops the schema and all data; re-run with --yes to confirm")
        migrate.downgrade()
        print("schema removed")
        return 0
    migrate.upgrade()
    _print(migrate.status())
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Check that this installation can run: configuration, database, schema, ontology, mappings."""
    from secgraph.ingest.mapping import MappingRegistry
    from secgraph.ontology import get_ontology
    from secgraph.store import migrate
    from secgraph.store.db import Database

    settings = get_settings()
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, work: Callable[[], str]) -> None:
        try:
            checks.append((name, True, work()))
        except Exception as exc:
            detail = exc.message if isinstance(exc, SecGraphError) else f"{type(exc).__name__}: {exc}"
            checks.append((name, False, detail))

    def _config() -> str:
        settings.validate_for_environment()
        return f"environment={settings.environment}"

    def _ontology() -> str:
        ontology = get_ontology(settings.ontology_file)
        return f"{ontology.name} {ontology.version}: {len(ontology.node_types)} node types, " \
               f"{len(ontology.edge_types)} edge types"

    def _mappings() -> str:
        registry = MappingRegistry(get_ontology(settings.ontology_file), settings.mappings_dir)
        return f"{len(registry.names())} mappings: {', '.join(registry.names())}"

    def _database() -> str:
        database = Database(settings)
        try:
            if not database.ping():
                raise RuntimeError("cannot connect")
            return database.dialect
        finally:
            database.dispose()

    def _schema() -> str:
        state = migrate.status(settings)
        if not state["up_to_date"]:
            raise RuntimeError(f"schema is at {state['current']}, expected {state['head']}; run 'secgraph migrate'")
        return f"revision {state['current']}"

    check("configuration", _config)
    check("ontology", _ontology)
    check("mappings", _mappings)
    check("database", _database)
    check("schema", _schema)
    width = max(len(name) for name, _ok, _detail in checks)
    for name, ok, detail in checks:
        print(f"{'ok  ' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    return 0 if all(ok for _name, ok, _detail in checks) else 1


def cmd_users(args: argparse.Namespace) -> int:
    ctx = _context()
    tenant = _tenant(args)
    if args.action == "list":
        _print(ctx.auth.list_users(tenant))
    elif args.action == "create":
        roles = [r.strip() for r in args.roles.split(",") if r.strip()]
        _print(
            ctx.auth.create_user(
                tenant, "system:cli", username=args.username, password=_read_password(args), roles=roles,
                allow_platform_admin=True,
            )
        )
    elif args.action == "set-password":
        _print(ctx.auth.update_user(tenant, "system:cli", args.username, password=_read_password(args)))
    elif args.action in ("disable", "enable"):
        _print(ctx.auth.update_user(tenant, "system:cli", args.username, disabled=args.action == "disable"))
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    ctx = _context()
    tenant = _tenant(args)
    if args.action == "list":
        _print(ctx.auth.list_api_keys(tenant))
    elif args.action == "create":
        created = ctx.auth.create_api_key(
            tenant,
            "system:cli",
            name=args.name,
            roles=[r.strip() for r in args.roles.split(",") if r.strip()],
            kind=args.kind,
            node_types=[t.strip() for t in args.node_types.split(",")] if args.node_types else None,
            expires_in_days=args.expires_in_days,
            known_node_types=set(ctx.ontology.node_types),
        )
        _print(created)
        print("\nStore this key now; it cannot be shown again.", file=sys.stderr)
    elif args.action == "revoke":
        ctx.auth.revoke_api_key(tenant, "system:cli", args.key_id)
        print("revoked")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from secgraph.ingest.canonical import IngestRequest
    from secgraph.ingest.pipeline import ingest_source

    ctx = _context()
    tenant = _tenant(args)
    payload = sys.stdin.buffer.read() if args.file == "-" else Path(args.file).read_bytes()
    if args.mapping:
        params = dict(item.split("=", 1) for item in args.param or [] if "=" in item)
        result = ingest_source(
            ctx.ingest, ctx.mappings, ctx.settings, tenant, "system:cli", args.mapping, payload, params=params,
            source=args.source,
        )
    else:
        request = IngestRequest.model_validate(json.loads(payload))
        result = ctx.ingest.ingest(tenant, "system:cli", request).to_dict()
        result.pop("refs", None)
    _print(result)
    return 0 if not result.get("quarantined_total") else 2


def cmd_mappings(_args: argparse.Namespace) -> int:
    ctx = _context()
    for mapping in ctx.mappings.describe():
        params = ", ".join(mapping["parameters"]) or "-"
        print(f"{mapping['name']:<28} {mapping['format']:<5} source={mapping['source']:<14} params: {params}")
        print(f"{'':<28} {mapping['description']}")
    return 0


def cmd_seed_demo(args: argparse.Namespace) -> int:
    from secgraph.demo.loader import seed_demo

    ctx = _context()
    tenant = _tenant(args)
    summary = seed_demo(ctx, tenant, _principal(tenant))
    if args.json:
        _print(summary)
        return 0
    print(f"Loaded the Meridian Bank demonstration estate into tenant '{tenant}'.\n")
    for source in summary["sources"]:
        nodes, edges = source["nodes"], source["edges"]
        print(
            f"  {source['file']:<36} nodes +{nodes['created']:<4} ~{nodes['updated']:<4} "
            f"edges +{edges['created']:<4} quarantined {source['quarantined']}"
        )
    graph = summary["graph"]
    print(f"\n  {graph['node_total']} nodes, {graph['edge_total']} edges, {summary['memory_notes']} memory notes added")
    from secgraph.governance.rbac import FULL_SCOPE

    overview = ctx.analytics.overview(tenant, FULL_SCOPE, limit=5)
    risk = overview["risk"]
    print(
        f"\nAttack model: {overview['entry_points']} entry points, {overview['targets_at_risk']} of "
        f"{overview['targets']} crown jewels at risk, expected impact {risk.get('estimate', risk['upper']):.2f} "
        f"of {overview['total_impact']:.0f}."
    )
    for target in overview["top_targets"]:
        p = target["probability"]
        print(f"  {target['name']:<28} {target['type']:<10} p={p.get('estimate', p['upper']):.3f} "
              f"[{p['lower']:.3f}, {p['upper']:.3f}]")
    return 0


def cmd_ontology(args: argparse.Namespace) -> int:
    from secgraph.ontology import load_ontology
    from secgraph.ontology.docs import render_markdown

    path = args.file or get_settings().ontology_file
    ontology = load_ontology(path)
    if args.action == "validate":
        print(
            f"ok: {ontology.name} {ontology.version} — {len(ontology.node_types)} node types, "
            f"{len(ontology.edge_types)} edge types, {len(ontology.attack_semantics.transitions)} transition rules"
        )
        from secgraph.ingest.mapping import MappingRegistry

        registry = MappingRegistry(ontology, get_settings().mappings_dir)
        print(f"ok: {len(registry.names())} mappings are consistent with it")
    elif args.action == "docs":
        sys.stdout.write(render_markdown(ontology))
    else:
        _print(ontology.model_dump(mode="json"))
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    from secgraph.governance import audit

    ctx = _context()
    with ctx.db.snapshot() as session:
        result = audit.verify(session, _tenant(args))
    _print(result)
    return 0 if result["ok"] else 1


def cmd_export_vault(args: argparse.Namespace) -> int:
    from secgraph.agents.vault import export_vault

    ctx = _context()
    tenant = _tenant(args)
    _print(export_vault(ctx, _principal(tenant), Path(args.directory), max_nodes=args.max_nodes))
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    from secgraph.observability import configure_logging
    from secgraph.worker import run_forever, run_once

    ctx = _context()
    if args.once:
        _print(run_once(ctx))
        return 0
    configure_logging(ctx.settings.log_level, ctx.settings.log_json)
    run_forever(ctx)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Print the attack-path analysis for a tenant as JSON."""
    from secgraph.governance.rbac import FULL_SCOPE

    ctx = _context()
    tenant = _tenant(args)
    actions: dict[str, Callable[[], Any]] = {
        "overview": lambda: ctx.analytics.overview(tenant, FULL_SCOPE, limit=args.limit),
        "paths": lambda: ctx.analytics.attack_paths(tenant, FULL_SCOPE, limit=args.limit),
        "priorities": lambda: ctx.analytics.remediation_priorities(tenant, FULL_SCOPE, by=args.by, limit=args.limit),
        "choke-points": lambda: ctx.analytics.choke_points(tenant, FULL_SCOPE, limit=args.limit),
        "detection-race": lambda: ctx.analytics.detection_race(tenant, FULL_SCOPE),
    }
    _print(actions[args.what]())
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """MCP over stdio. With --url, relay to a running server; otherwise serve from this process."""
    api_key = os.environ.get(args.api_key_env or "SECGRAPH_API_KEY", "")
    if args.url:
        import httpx

        if not api_key:
            raise SystemExit("set SECGRAPH_API_KEY (or --api-key-env) to the API key to use")
        endpoint = args.url.rstrip("/") + "/mcp"
        with httpx.Client(timeout=120, verify=args.ca_bundle or True) as client:
            for line in sys.stdin:
                if not line.strip():
                    continue
                try:
                    response = client.post(
                        endpoint, content=line.encode(),
                        headers={"Content-Type": "application/json", "X-API-Key": api_key,
                                 "Accept": "application/json"},
                    )
                    if response.status_code == 202 or not response.content:
                        continue
                    sys.stdout.write(response.text.strip() + "\n")
                except httpx.HTTPError as exc:
                    message = json.loads(line) if line.lstrip().startswith("{") else {}
                    if "id" in message:
                        sys.stdout.write(json.dumps({
                            "jsonrpc": "2.0", "id": message["id"],
                            "error": {"code": -32603, "message": f"cannot reach the graph: {exc}"}}) + "\n")
                sys.stdout.flush()
        return 0
    ctx = _context()
    if api_key:
        principal = ctx.auth.authenticate(None, api_key)
    else:
        tenant = _tenant(args)
        principal = Principal.build(
            id="system:mcp-stdio", name="mcp-stdio", kind="agent", tenant_id=tenant, roles=["agent"]
        )
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response: Any = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}}
        else:
            response = ctx.mcp.handle(message, principal)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":"), default=str) + "\n")
            sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secgraph", description="Security Graph — run and operate the service.")
    parser.add_argument("--version", action="version", version=f"secgraph {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def tenant_option(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tenant", help="tenant id (default: SECGRAPH_DEFAULT_TENANT)")

    p = sub.add_parser("serve", help="run the API and console")
    p.add_argument("--host", default="0.0.0.0")  # noqa: S104 - containers bind all interfaces
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--workers", type=int, default=1, help="processes; scale with replicas in Kubernetes instead")
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1", help="proxies whose X-Forwarded-* headers to trust")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("migrate", help="create or upgrade the database schema")
    p.add_argument("action", nargs="?", default="upgrade", choices=["upgrade", "status", "downgrade"])
    p.add_argument("--yes", action="store_true", help="confirm a destructive downgrade")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("doctor", help="check configuration, database, schema, ontology and mappings")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("users", help="manage users")
    p.add_argument("action", choices=["list", "create", "set-password", "disable", "enable"])
    p.add_argument("username", nargs="?")
    p.add_argument("--roles", default="analyst", help="comma-separated roles (create)")
    p.add_argument("--password-env", help="read the password from this environment variable")
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    tenant_option(p)
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("keys", help="manage API keys")
    p.add_argument("action", choices=["list", "create", "revoke"])
    p.add_argument("key_id", nargs="?")
    p.add_argument("--name")
    p.add_argument("--roles", default="agent")
    p.add_argument("--kind", default="service", choices=["service", "agent"])
    p.add_argument("--node-types", help="comma-separated node types this key may see (default: all)")
    p.add_argument("--expires-in-days", type=int)
    tenant_option(p)
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("ingest", help="ingest a file ('-' for standard input)")
    p.add_argument("file")
    p.add_argument("--mapping", help="source mapping name; omit for a canonical batch")
    p.add_argument("--param", action="append", help="mapping parameter name=value (repeatable)")
    p.add_argument("--source", help="override the source name")
    tenant_option(p)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("mappings", help="list the source formats that can be ingested")
    p.set_defaults(func=cmd_mappings)

    p = sub.add_parser("seed-demo", help="load the Meridian Bank demonstration estate")
    p.add_argument("--json", action="store_true")
    tenant_option(p)
    p.set_defaults(func=cmd_seed_demo)

    p = sub.add_parser("ontology", help="validate, print or document the ontology")
    p.add_argument("action", choices=["validate", "show", "docs"])
    p.add_argument("file", nargs="?", help="ontology file (default: the configured or packaged one)")
    p.set_defaults(func=cmd_ontology)

    p = sub.add_parser("verify-audit", help="recompute the audit hash chain")
    tenant_option(p)
    p.set_defaults(func=cmd_verify_audit)

    p = sub.add_parser("export-vault", help="export the graph as a Markdown vault")
    p.add_argument("directory")
    p.add_argument("--max-nodes", type=int, default=5000)
    tenant_option(p)
    p.set_defaults(func=cmd_export_vault)

    p = sub.add_parser("worker", help="deliver webhooks and run maintenance")
    p.add_argument("--once", action="store_true", help="run one pass and exit")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("report", help="print attack-path analytics as JSON")
    p.add_argument("what", choices=["overview", "paths", "priorities", "choke-points", "detection-race"])
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--by", default="vulnerability", choices=["finding", "vulnerability", "asset"])
    tenant_option(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("mcp", help="Model Context Protocol server over stdio")
    p.add_argument("--url", help="relay to a running Security Graph at this base URL")
    p.add_argument("--api-key-env", help="environment variable holding the API key (default SECGRAPH_API_KEY)")
    p.add_argument("--ca-bundle", help="CA bundle for --url")
    tenant_option(p)
    p.set_defaults(func=cmd_mcp)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in ("users", "keys"):
        needs = {"create": "username" if args.command == "users" else "name", "set-password": "username",
                 "disable": "username", "enable": "username", "revoke": "key_id"}.get(args.action)
        if needs and not getattr(args, needs, None):
            raise SystemExit(f"'{args.command} {args.action}' needs {needs.replace('_', '-')}")
    try:
        return int(args.func(args) or 0)
    except SecGraphError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        for problem in exc.detail.get("errors", exc.detail.get("problems", [])):
            print(f"  - {problem}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
