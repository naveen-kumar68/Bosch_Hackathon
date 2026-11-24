"""Bridge: priority module output + scan facts -> RemediationRequest for CandidateGenerator.

The priority algorithm runs before this and is deterministic. Expected `row`:
    {"finding_id", "priority": "P0".."P3", "evidence_ids", ...}
Priority and decision are never recomputed or changed here; only P0/P1 get fix options.
"""

from collections.abc import Iterable

from packageurl import PackageURL

from guardian.remediate.models import (
    Boundary,
    Constraint,
    Location,
    Parent,
    RemediationRequest,
)

REMEDIATE_PRIORITIES = {"P0", "P1"}
LOCKFILE = {"cargo": "Cargo.lock", "pypi": "requirements.txt"}


def wants_remediation(row: dict) -> bool:
    return row.get("priority") in REMEDIATE_PRIORITIES


def to_remediation_input(
    row: dict,
    finding,
    vulnerabilities: Iterable = (),
    components=(),
    edges=(),
    baseline_components=(),
) -> RemediationRequest:
    purl = PackageURL.from_string(finding.component)
    lockfile = Location(file=LOCKFILE.get(purl.type, "requirements.txt"))
    by_purl = {c.purl: c for c in components}
    related = [v for v in vulnerabilities if v.component == finding.component]
    fixed = {}
    for v in related:
        for version in v.fixed_versions:
            fixed.setdefault(version, [])
            fixed[version] += [e for e in v.evidence_ids if e not in fixed[version]]

    def requirers(target_purl):
        return [e for e in edges if e.to_purl == target_purl and e.kind != "dev"]

    constraints, parents = [], []
    for edge in requirers(finding.component):
        parent = by_purl.get(edge.from_purl)
        if parent is None or not edge.version_req:
            continue
        if parent.is_root:
            constraints.append(
                Constraint(requirement=edge.version_req, evidence_ids=edge.evidence_ids)
            )
            continue
        parents.append(
            Parent(
                package=parent.name,
                current_version=parent.version,
                requirement=edge.version_req,
                constraints=[
                    Constraint(requirement=e.version_req, evidence_ids=e.evidence_ids)
                    for e in requirers(parent.purl)
                    if e.version_req
                ],
                location=lockfile,
                evidence_ids=edge.evidence_ids,
            )
        )
    base = next(
        (
            c
            for c in baseline_components
            if c.name == purl.name and c.ecosystem == purl.type and c.version != purl.version
        ),
        None,
    )
    evidence = list(
        dict.fromkeys(
            [
                *row.get("evidence_ids", []),
                *finding.evidence_ids,
                *(e for b in fixed.values() for e in b),
            ]
        )
    )
    return RemediationRequest(
        finding_id=row["finding_id"],
        component=finding.component,
        evidence_ids=evidence,
        fixed_versions=[Boundary(version=v, evidence_ids=e) for v, e in sorted(fixed.items())],
        constraints=constraints,
        parents=parents,
        location=lockfile,
        baseline=Boundary(version=base.version, evidence_ids=base.evidence_ids) if base else None,
    )
