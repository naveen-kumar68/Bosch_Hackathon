"""Opt-in checks against captured real scanner outputs and completed risk reports."""

import hashlib
import json
import os
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
