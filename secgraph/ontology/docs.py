"""Render the ontology as Markdown, so the reference document can never drift from the YAML."""

from __future__ import annotations

from secgraph.ontology.model import Ontology, ProbabilityModel, PropertyDef


def _type(definition: PropertyDef) -> str:
    text = definition.type
    if definition.type == "enum":
        text = "one of " + ", ".join(f"`{v}`" for v in definition.values or ())
    bounds = []
    if definition.minimum is not None:
        bounds.append(f"≥ {definition.minimum:g}")
    if definition.maximum is not None:
        bounds.append(f"≤ {definition.maximum:g}")
    if bounds:
        text += f" ({', '.join(bounds)})"
    return text


def _probability(model: ProbabilityModel) -> str:
    if model.model == "fixed":
        return f"{model.value:g}"
    if model.model == "by_property":
        values = ", ".join(f"{k} {v:g}" for k, v in (model.values or {}).items())
        return f"by `{model.property}`: {values}; otherwise {model.default:g}"
    return "exploitability of the destination" + (f" (never below {model.floor:g})" if model.floor else "")


def render_markdown(ontology: Ontology) -> str:
    out: list[str] = [
        f"# Ontology reference — {ontology.name} {ontology.version}",
        "",
        "> Generated from the ontology file by `secgraph ontology docs`. Do not edit by hand: change the YAML",
        "> and regenerate. A test fails if this file and the packaged ontology disagree.",
        "",
        ontology.ontology.description.strip(),
        "",
        f"Fingerprint: `{ontology.fingerprint()}`",
        "",
        "## Node types",
        "",
        "| Type | Plane | What it is |",
        "|---|---|---|",
    ]
    for name, node in ontology.node_types.items():
        out.append(f"| [{name}](#{name.lower()}) | {node.plane} | {node.description} |")
    for name, node in ontology.node_types.items():
        out += ["", f"### {name}", "", node.description, ""]
        if node.ttl_days:
            out += [f"Expires when not re-observed for {node.ttl_days} days.", ""]
        out += ["**Identifiers** (in matching priority)", "", "| Kind | Strength | Normalised as | Notes |", "|---|---|---|---|"]
        for ident in node.identifiers:
            if not ident.match:
                strength = "lookup only"
            elif ident.weak:
                strength = "weak"
            else:
                strength = "strong"
            if ident.exclusive:
                strength += ", exclusive"
            notes = ident.description
            if ident.derived_from:
                notes = (notes + " " if notes else "") + f"Derived from `{ident.derived_from}` when absent."
            if ident.sensitive:
                notes = (notes + " " if notes else "") + "Personal data (masked without `pii:read`)."
            out.append(f"| `{ident.kind}` | {strength} | {ident.normalize} | {notes} |")
        if node.properties:
            out += ["", "**Properties**", "", "| Property | Type | Notes |", "|---|---|---|"]
            for prop, definition in node.properties.items():
                notes = definition.description
                if definition.required:
                    notes = ("Required. " + notes).strip()
                if definition.sensitive:
                    notes = (notes + " Personal data (masked without `pii:read`).").strip()
                out.append(f"| `{prop}` | {_type(definition)} | {notes} |")
        if node.additional_properties:
            out += ["", "Other properties are accepted and stored as given."]

    out += ["", "## Edge types", "", "| Edge | From | To | Meaning | Expires |", "|---|---|---|---|---|"]
    for name, edge in ontology.edge_types.items():
        ttl = f"{edge.ttl_days} d" if edge.ttl_days else "—"
        out.append(f"| `{name}` | {', '.join(edge.source)} | {', '.join(edge.target)} | {edge.description} | {ttl} |")
    with_properties = {name: edge for name, edge in ontology.edge_types.items() if edge.properties}
    if with_properties:
        out += ["", "### Edge properties", "", "| Edge | Property | Type | Notes |", "|---|---|---|---|"]
        for name, edge in with_properties.items():
            for prop, definition in edge.properties.items():
                out.append(f"| `{name}` | `{prop}` | {_type(definition)} | {definition.description} |")

    sem = ontology.attack_semantics
    out += [
        "",
        "## Attack semantics",
        "",
        "How the graph becomes an attack graph. See [ANALYTICS_MATH.md](ANALYTICS_MATH.md) for the mathematics.",
        "",
        "**States an attacker can hold:** " + ", ".join(sem.compromisable),
        "",
        "### Entry rules",
        "",
        "| Rule | Applies to | Probability | Reduced by | Enabled |",
        "|---|---|---|---|---|",
    ]
    for entry in sem.entries:
        where = ", ".join(f"{k}={v}" for k, v in entry.where.items())
        out.append(
            f"| `{entry.name}` | {entry.node_type}" + (f" where {where}" if where else "")
            + f" | {_probability(entry.probability)} | {', '.join(entry.mitigated_by) or '—'} | "
            f"{'yes' if entry.enabled else 'no'} |"
        )
    out += [
        "",
        "### Transition rules",
        "",
        "| Rule | Edge | Attacker moves | Probability | Reduced by (control on) | What it models |",
        "|---|---|---|---|---|---|",
    ]
    for rule in sem.transitions:
        edge = ontology.edge_types[rule.edge]
        if rule.attacker_moves == "source_to_target":
            move = f"{'/'.join(edge.source)} → {'/'.join(edge.target)}"
        else:
            move = f"{'/'.join(edge.target)} → {'/'.join(edge.source)}"
        mitigations = f"{', '.join(rule.mitigated_by)} ({rule.control_on})" if rule.mitigated_by else "—"
        out.append(
            f"| `{rule.name}` | `{rule.edge}` | {move} | {_probability(rule.probability)} | {mitigations} | "
            f"{rule.description} |"
        )
    out += ["", "### Crown jewels", "", "| Rule | Applies to | Impact |", "|---|---|---|"]
    for target in sem.targets:
        where = ", ".join(f"{k}={v}" for k, v in target.where.items())
        if target.impact.property:
            values = ", ".join(f"{k}→{v:g}" for k, v in target.impact.values.items())
            impact = f"by `{target.impact.property}`: {values}; otherwise {target.impact.default:g}"
        else:
            impact = f"{target.impact.default:g}"
        out.append(f"| `{target.name}` | {target.node_type} where {where} | {impact} |")
    exploit = sem.exploitability
    out += [
        "",
        "### Exploitability parameters",
        "",
        "| Parameter | Value |",
        "|---|---|",
        f"| Finding statuses counted as open | {', '.join(exploit.open_statuses)} |",
        f"| Known-exploited floor | {exploit.kev_floor:g} |",
        f"| EPSS weight | {exploit.epss_weight:g} |",
        f"| CVSS vector weight | {exploit.cvss_vector_weight:g} |",
        f"| CVSS base-score weight | {exploit.cvss_score_weight:g} |",
        f"| Default when nothing is known | {exploit.unknown_default:g} |",
        "| Severity fallback (no linked vulnerability) | "
        + ", ".join(f"{k} {v:g}" for k, v in exploit.severity_fallback.items()) + " |",
        f"| Remotely exploitable attack vectors | {', '.join(exploit.remote_vectors)} |",
        f"| Unknown vector treated as remote | {'yes' if exploit.unknown_vector_is_remote else 'no'} |",
        f"| Probability cap | {exploit.max_probability:g} |",
        "",
        "### Control parameters",
        "",
        "| Parameter | Value |",
        "|---|---|",
        "| Default effectiveness by type | "
        + ", ".join(f"{k} {v:g}" for k, v in sem.controls.default_effectiveness.items()) + " |",
        f"| Fallback effectiveness | {sem.controls.fallback_effectiveness:g} |",
        f"| Degraded control factor | {sem.controls.degraded_factor:g} |",
        f"| Maximum combined reduction | {sem.controls.max_combined_reduction:g} |",
        f"| Detective control types | {', '.join(sem.controls.detection_types)} |",
        f"| Base detection per attempt | {sem.controls.detection_base:g} |",
        f"| Detection weight | {sem.controls.detection_weight:g} |",
        "",
    ]
    return "\n".join(out)
