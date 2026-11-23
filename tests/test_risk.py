from pathlib import Path

import pytest

from guardian.detect.depdiff import inventory_diff
from guardian.detect.models import Assessment
from guardian.detect.risk import load_rules, vulnerability_severity
from guardian.models import Component


def component(version="1", source="crates.io", checksum="a", direct=False):
    return Component(
        purl=f"pkg:cargo/example@{version}",
        name="example",
        version=version,
        ecosystem="cargo",
        source=source,
        checksum=checksum,
        is_direct=direct,
        evidence_ids=["fixture"],
    )


def test_integrity_and_source_switch():
    result = inventory_diff([component()], [component(source="path", checksum="b")])
    assert {v["type"] for v in result["integrity"]} == {"source_changed", "checksum_changed"}


def test_downgrade_and_parallel_version_set():
    result = inventory_diff([component("2"), component("3")], [component("1", direct=True)])
    assert result["counts"]["changed"] == 1
    assert result["changed"][0]["direction"] == "downgraded"
    assert len(result["new_direct"]) == 1


def test_kev_never_lowered_and_build_not_lowered():
    assert vulnerability_severity(5, True, 0, ["dev"])[0] == "critical"
    assert vulnerability_severity(8, False, 0.2, ["build"])[0] == "critical"
    assert vulnerability_severity(8, False, 0, ["dev"])[0] == "medium"
    assert vulnerability_severity(8, False, 0, ["dev", "build"])[0] == "high"


def test_ai_schema_cannot_contain_severity_override():
    with pytest.raises(ValueError):
        Assessment(
            finding_id="F-1",
            verdict="benign",
            confidence=1,
            rationale="Example",
            cited_evidence_ids=["e"],
            severity="info",
        )


def test_all_rules_have_rationale():
    assert len(load_rules(Path("rules/severity.yaml"))) >= 25
