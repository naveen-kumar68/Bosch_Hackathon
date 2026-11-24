import json
from pathlib import Path

from guardian.detect.models import Finding, Vulnerability
from guardian.models import Component, Edge
from guardian.remediate.candidates import CandidateGenerator
from guardian.remediate.priority_adapter import to_remediation_input, wants_remediation
from guardian.remediate.registry import RegistrySnapshot, cargo_index

DATA = json.loads((Path(__file__).parent / "fixtures/remediate/cargo.json").read_text("utf-8"))


def comp(name, version, root=False, ev="EV-C"):
    return Component(
        purl=f"pkg:cargo/{name}@{version}",
        name=name,
        version=version,
        ecosystem="cargo",
        source="crates.io",
        is_root=root,
        evidence_ids=[ev],
    )


def scenario():
    app, parent, child = (
        comp("app", "0.1.0", root=True),
        comp("parent", "1.0.0"),
        comp("child", "0.4.0"),
    )
    edges = [
        Edge(
            from_purl=app.purl,
            to_purl=parent.purl,
            kind="normal",
            version_req="^1.0.0",
            evidence_ids=["EV-PARENT-MANIFEST"],
        ),
        Edge(
            from_purl=parent.purl,
            to_purl=child.purl,
            kind="normal",
            version_req="=0.4.0",
            evidence_ids=["EV-PARENT-LOCK"],
        ),
        Edge(
            from_purl=app.purl,
            to_purl=child.purl,
            kind="dev",
            version_req="^0",
            evidence_ids=["EV-DEV"],
        ),
    ]
    finding = Finding(
        finding_id="F-1",
        type="vulnerability",
        component=child.purl,
        description="d",
        evidence_ids=["EV-F"],
        severity="high",
        severity_rule="cvss",
        confidence="high",
    )
    vuln = Vulnerability(
        id="RUSTSEC-2024-0001",
        aliases=[],
        component=child.purl,
        evidence_ids=["EV-ADVISORY"],
        sources=["osv"],
        fixed_versions=["0.4.2", "0.5.1"],
    )
    row = {"finding_id": "F-1", "priority": "P0", "evidence_ids": ["EV-P"]}
    return [app, parent, child], edges, finding, vuln, row


def test_priority_row_becomes_request_without_changing_it():
    components, edges, finding, vuln, row = scenario()
    before = dict(row)
    request = to_remediation_input(
        row,
        finding,
        [vuln],
        components,
        edges,
        baseline_components=[comp("child", "0.3.9", ev="EV-BASELINE")],
    )
    assert row == before
    assert request.component == "pkg:cargo/child@0.4.0" and request.location.file == "Cargo.lock"
    assert [(b.version, b.evidence_ids) for b in request.fixed_versions] == [
        ("0.4.2", ["EV-ADVISORY"]),
        ("0.5.1", ["EV-ADVISORY"]),
    ]
    assert request.evidence_ids == ["EV-P", "EV-F", "EV-ADVISORY"]
    assert request.baseline.version == "0.3.9" and request.baseline.evidence_ids == ["EV-BASELINE"]
    (parent,) = request.parents  # the dev edge is excluded; the root is not a "parent"
    assert (parent.package, parent.current_version, parent.requirement) == (
        "parent",
        "1.0.0",
        "=0.4.0",
    )
    assert [c.requirement for c in parent.constraints] == ["^1.0.0"]


def test_end_to_end_priority_to_candidates_uses_team_generator():
    components, edges, finding, vuln, row = scenario()
    request = to_remediation_input(row, finding, [vuln], components, edges)
    snapshot = RegistrySnapshot(
        [
            cargo_index("child", DATA["child"], "EV-INDEX"),
            cargo_index("parent", DATA["parent"], "EV-PARENT-INDEX"),
        ]
    )
    options = CandidateGenerator(snapshot).candidates(request)
    assert options[-1].kind == "escalate"
    assert all(o.finding_id == "F-1" for o in options)


def test_only_p0_p1_get_remediation():
    assert wants_remediation({"priority": "P0"}) and wants_remediation({"priority": "P1"})
    assert not wants_remediation({"priority": "P2"}) and not wants_remediation({})
