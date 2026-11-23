"""Opt-in checks against captured real scanner outputs and completed risk reports."""

import hashlib
import json
import os
import tomllib
from pathlib import Path

import pytest

from guardian.detect.models import Finding
from guardian.detect.vulns import deduplicate, parse_audit, parse_osv
from guardian.models import ScanResult

pytestmark = pytest.mark.skipif(
    os.environ.get("GUARDIAN_INTEGRATION") != "1", reason="Requires completed real risk scans"
)
ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    raw = path.read_bytes()
    return json.loads(
        raw.decode("utf-16") if raw.startswith(b"\xff\xfe") else raw.decode("utf-8-sig")
    )


def test_real_alias_union_matches_standalone_scanners():
    output = ROOT / "out/kuksa-databroker"
    scan = ScanResult.model_validate_json((output / "scan.json").read_text(encoding="utf-8"))
    observed = deduplicate(
        parse_osv(read_json(output / "risk-probes/osv.json"), scan.components, "osv")
        + parse_audit(read_json(output / "risk-probes/cargo-audit.json"), scan.components, "audit")
    )
    actual = read_json(output / "vulnerabilities.json")
    assert {(v.component, frozenset([v.id, *v.aliases])) for v in observed} == {
        (v["component"], frozenset([v["id"], *v["aliases"]]))
        for v in actual
        if set(v["sources"]) & {"osv", "cargo-audit"}
    }


def test_diff_counts_reconcile_with_lockfile_sets():
    def package_sets(target, ref):
        document = tomllib.loads(
            (ROOT / "workspace/targets" / f"{target}@{ref}" / "Cargo.lock").read_text(
                encoding="utf-8"
            )
        )
        return {(p["name"], p["version"]) for p in document["package"]}

    old = package_sets("kuksa-val-0.4.1", "0.4.1")
    new = package_sets("kuksa-databroker", "0.7.2")
    old_names, new_names = {p[0] for p in old}, {p[0] for p in new}
    diff = read_json(ROOT / "out/kuksa-databroker/dependency-diff.json")
    assert {(p["name"], p["version"]) for p in diff["added"]} == {
        p for p in new if p[0] not in old_names
    }
    assert {(p["name"], p["version"]) for p in diff["removed"]} == {
        p for p in old if p[0] not in new_names
    }
    expected_changed = {
        name
        for name in old_names & new_names
        if {v for n, v in old if n == name} != {v for n, v in new if n == name}
    }
    assert {p["name"] for p in diff["changed"]} == expected_changed
    assert diff["counts"]["changed"] == len(expected_changed)


@pytest.mark.parametrize("target", ["kuksa-databroker", "kuksa-python-sdk"])
def test_real_findings_have_verified_evidence_and_lf(target):
    output = ROOT / "out" / target
    records = {r["id"]: r for r in read_json(output / "evidence.json")}
    findings = [Finding.model_validate(v) for v in read_json(output / "findings.json")]
    assert findings
    for finding in findings:
        assert finding.evidence_ids
        for identifier in finding.evidence_ids:
            record = records[identifier]
            base = ROOT if record.get("path_base") == "repository" else output
            assert (
                hashlib.sha256((base / record["raw_path"]).read_bytes()).hexdigest()
                == record["sha256"]
            )
        if finding.type == "vulnerability":
            assert finding.paths
            assert finding.details["id"]
            assert "fixed_versions" in finding.details
    for filename in ["findings.json", "findings.sarif", "risk_report.md", "risk_report.html"]:
        assert b"\r\n" not in (output / filename).read_bytes()


def test_python_missing_hash_pins():
    items = read_json(ROOT / "out/kuksa-python-sdk/findings.json")
    assert len([f for f in items if f["type"] == "pin_without_hash"]) == 16
    scan = ScanResult.model_validate_json(
        (ROOT / "out/kuksa-python-sdk/scan.json").read_text(encoding="utf-8")
    )
    current = {component.purl for component in scan.components}
    assert all(f["component"] in current for f in items if f["type"] == "guarddog")
