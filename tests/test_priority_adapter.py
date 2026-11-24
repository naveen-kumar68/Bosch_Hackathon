from guardian.detect.models import Finding, Vulnerability
from guardian.models import Component, Edge
from guardian.remediate import candidates
from guardian.remediate.priority_adapter import to_remediation_input, wants_remediation
from guardian.remediate.registry import StaticIndex, VersionInfo


def comp(name, version, root=False, direct=False):
    return Component(
        purl=f"pkg:cargo/{name}@{version}",
        name=name,
        version=version,
        ecosystem="cargo",
        source="crates.io",
        is_root=root,
        is_direct=direct,
        evidence_ids=["EV-C"],
    )


def scenario():
    app, mid, leaf = (
        comp("app", "0.1.0", root=True),
        comp("middle", "0.4.0", direct=True),
        comp("leaf", "1.2.3"),
    )
    edges = [
        Edge(
            from_purl=app.purl,
            to_purl=mid.purl,
            kind="normal",
            version_req="^0.4",
            evidence_ids=["EV-E"],
        ),
        Edge(
            from_purl=mid.purl,
            to_purl=leaf.purl,
            kind="normal",
            version_req="^1.2",
            evidence_ids=["EV-E"],
        ),
        Edge(
            from_purl=app.purl,
            to_purl=leaf.purl,
            kind="dev",
            version_req="^1",
            evidence_ids=["EV-E"],
        ),
    ]
    finding = Finding(
        finding_id="F-1",
        type="vulnerability",
        component=leaf.purl,
        description="d",
        paths=[[app.purl, mid.purl, leaf.purl]],
        evidence_ids=["EV-F"],
        severity="high",
        severity_rule="cvss",
        confidence="high",
    )
    vuln = Vulnerability(
        id="RUSTSEC-2024-0001",
        aliases=["CVE-2024-1"],
        component=leaf.purl,
        evidence_ids=["EV-V"],
        sources=["osv"],
        fixed_versions=["1.2.4"],
    )
    row = {
        "finding_id": "F-1",
        "priority": "P0",
        "score": 90,
        "decision": "fix_now",
        "evidence_ids": ["EV-P"],
        "dev_only": False,
        "imported": True,
    }
    return [app, mid, leaf], edges, finding, vuln, row


def test_priority_row_becomes_remediation_input_without_recomputing():
    components, edges, finding, vuln, row = scenario()
    pf = to_remediation_input(
        row, finding, [vuln], components, edges, baseline_components=[comp("leaf", "1.0.0")]
    )
    assert (pf.package, pf.version, pf.ecosystem, pf.priority) == ("leaf", "1.2.3", "cargo", "P0")
    assert pf.fixed_versions == ["1.2.4"] and set(pf.advisory_ids) == {
        "RUSTSEC-2024-0001",
        "CVE-2024-1",
    }
    assert pf.evidence_ids == ["EV-P", "EV-F", "EV-V"]
    assert pf.baseline_version == "1.0.0" and pf.severity == "high"
    assert [(e.parent, e.child, e.req, e.is_root) for e in pf.edges] == [
        ("app", "middle", "^0.4", True),
        ("middle", "leaf", "^1.2", False),
    ]  # dev edge off the path is excluded


def test_end_to_end_priority_to_options():
    components, edges, finding, vuln, row = scenario()
    index = StaticIndex({"leaf": [VersionInfo("1.2.3"), VersionInfo("1.2.5")]})
    options = candidates(to_remediation_input(row, finding, [vuln], components, edges), index)
    assert [o.kind for o in options] == ["upgrade", "escalate"]
    assert options[0].target_version == "1.2.5"


def test_only_p0_p1_get_remediation():
    assert wants_remediation({"priority": "P0"}) and wants_remediation({"priority": "P1"})
    assert not wants_remediation({"priority": "P2"}) and not wants_remediation({})


def test_unchecked_finding_without_advisory_is_not_labelled_vulnerability():
    components, edges, finding, _vuln, row = scenario()
    pf = to_remediation_input(
        row, finding.model_copy(update={"type": "typosquat_added"}), [], components, edges
    )
    assert pf.type == "typosquat_added" and pf.fixed_versions == []
