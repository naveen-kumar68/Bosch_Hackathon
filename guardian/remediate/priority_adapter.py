"""Bridge: the priority module's output + scan facts -> remediate.PrioritisedFinding.

The priority algorithm (another team member) is deterministic and runs before this code.
Expected `row` (one prioritised finding):
    {"finding_id", "priority": "P0".."P3", "score", "score_breakdown", "decision", "rule",
     "evidence_ids", "paths": [[name, ...]], "dev_only": bool, "imported": bool}
Nothing here lets an AI change a row; fields are copied, never recomputed.
"""

from collections.abc import Iterable
from itertools import pairwise

from packageurl import PackageURL

from guardian.remediate.models import Edge, PrioritisedFinding

REMEDIATE_PRIORITIES = {"P0", "P1"}


def wants_remediation(row: dict) -> bool:
    """Orchestrator rule: only P0/P1 findings get fix options."""
    return row.get("priority") in REMEDIATE_PRIORITIES


def _parse(purl: str) -> tuple[str, str, str]:
    p = PackageURL.from_string(purl)
    return p.name, p.version or "", {"cargo": "cargo", "pypi": "pypi"}.get(p.type, p.type)


def _path_edges(paths, components, edges) -> list[Edge]:
    """Edges that lie on any root->component path, with the requirement each one states."""
    by_name = {c.name: c for c in components}
    names = [[_parse(n)[0] if str(n).startswith("pkg:") else n for n in path] for path in paths]
    on_path = {(a, b) for path in names for a, b in pairwise(path)}
    out = []
    for edge in edges:
        parent, child = by_name.get(_parse(edge.from_purl)[0]), by_name.get(_parse(edge.to_purl)[0])
        if not parent or not child or (parent.name, child.name) not in on_path:
            continue
        if edge.kind == "dev":
            continue
        out.append(
            Edge(
                parent=parent.name,
                parent_version=None if parent.is_root else parent.version,
                child=child.name,
                req=edge.version_req or "",
                is_root=parent.is_root,
            )
        )
    return out


def to_remediation_input(
    row: dict,
    finding,
    vulnerabilities: Iterable = (),
    components=(),
    edges=(),
    baseline_components=(),
) -> PrioritisedFinding:
    """Build the input for `candidates()` from the priority row, the Finding and scan data."""
    name, version, ecosystem = _parse(finding.component)
    related = [v for v in vulnerabilities if v.component == finding.component]
    fixed = sorted({f for v in related for f in v.fixed_versions})
    advisories = sorted({a for v in related for a in [v.id, *v.aliases]})
    baseline = next(
        (c.version for c in baseline_components if c.name == name and c.version != version), None
    )
    evidence = list(
        dict.fromkeys(
            [
                *row.get("evidence_ids", []),
                *finding.evidence_ids,
                *(e for v in related for e in v.evidence_ids),
            ]
        )
    )
    return PrioritisedFinding(
        finding_id=row["finding_id"],
        type="vulnerability" if related else finding.type,
        ecosystem=ecosystem,
        package=name,
        version=version,
        fixed_versions=fixed,
        advisory_ids=advisories,
        evidence_ids=evidence,
        edges=_path_edges(row.get("paths") or finding.paths, components, edges),
        baseline_version=baseline,
        baseline_evidence_ids=[],
        dev_only=bool(row.get("dev_only", False)),
        imported=bool(row.get("imported", True)),
        severity=finding.severity,
        priority=row.get("priority"),
    )
