#!/usr/bin/env python3
"""A tour of the API against the demonstration estate, using the Python client.

    make demo                                   # in another terminal, or scripts/quickstart.sh --demo
    python examples/quickstart.py --password Meridian-Demo-2026

With an API key instead:  SECGRAPH_API_KEY=sg_… python examples/quickstart.py
"""

from __future__ import annotations

import argparse
import os

from secgraph.client import SecurityGraphClient


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("SECGRAPH_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=os.environ.get("SECGRAPH_PASSWORD"))
    args = parser.parse_args()

    api_key = os.environ.get("SECGRAPH_API_KEY")
    with SecurityGraphClient(args.url, api_key=api_key) as graph:
        if not api_key:
            if not args.password:
                parser.error("give --password, or set SECGRAPH_API_KEY")
            graph.login(args.username, args.password)

        stats = graph.stats()
        print(f"The graph holds {stats['node_total']} entities and {stats['edge_total']} relationships.\n")

        # 1. The same machine, whatever a source calls it.
        by_ip = graph.lookup("10.10.1.10")[0]
        by_name = graph.lookup("web-portal-01")[0]
        assert by_ip["id"] == by_name["id"]
        print(f"10.10.1.10 and web-portal-01 are one entity: {by_name['name']} ({by_name['id']})")
        print(f"  reported by: {', '.join(by_name.get('sources', []))}\n")

        # 2. How exposed is it, and why?
        exposure = graph.exposure(by_name["id"])
        p = exposure["compromise_probability"]
        print(f"Compromise probability {p['estimate']:.0%} (proven bounds {p['lower']:.0%} – {p['upper']:.0%})")
        for finding in exposure["open_findings"]:
            flag = " · known-exploited" if finding.get("kev") else ""
            name = finding.get("vulnerability") or finding["title"]
            print(f"  {name}: exploit probability {finding['probability']:.0%} by {finding['basis']}{flag}")

        # 3. Where does an attacker go from here?
        print("\nMost likely routes to crown jewels:")
        for path in graph.attack_paths(limit=3)["paths"]:
            hops = " → ".join(step["to"]["name"] for step in path["steps"])
            print(f"  {path['probability']:.0%}  attacker → {hops}")

        # 4. What should be fixed first?
        print("\nFix first (share of crown-jewel risk removed):")
        for fix in graph.remediation_priorities(by="vulnerability", limit=5)["items"]:
            where = ", ".join(asset["name"] for asset in fix["assets"])
            print(f"  {fix['risk_reduction_percent']:5.1f}%  {fix['vulnerability']}  on {where}")

        # 5. What would an agent be told about this host?
        pack = graph.context(by_name["id"], budget_tokens=400)
        print(f"\nContext pack ({pack['token_estimate']} tokens):\n")
        print(pack["text"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
