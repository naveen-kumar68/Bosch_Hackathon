import json
import sqlite3

from guardian.detect.models import Finding
from guardian.detect.report import write_reports
from guardian.evidence import Recorder


def test_reports_and_storage_retain_evidence(tmp_path):
    root = tmp_path
    output = root / "out" / "fixture"
    recorder = Recorder(output)
    evidence = recorder.note("observed source")
    item = Finding(
        finding_id="F-example",
        type="source_changed",
        component="pkg:cargo/a@1",
        description="Source changed <review>",
        evidence_ids=[evidence],
        severity="high",
        severity_rule="source_changed",
        confidence="medium",
        paths=[["pkg:cargo/root@1", "pkg:cargo/a@1"]],
    )
    write_reports(output, [item], recorder.records, [], recorder.root, 0)
    findings = json.loads((output / "findings.json").read_text())
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence_ids"] == [evidence]
    assert "&lt;review&gt;" in (output / "risk_report.html").read_text()
    assert b"\r\n" not in (output / "risk_report.md").read_bytes()
    assert json.loads((output / "findings.sarif").read_text())["version"] == "2.1.0"
    with sqlite3.connect(output / "graph.sqlite") as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM risk_evidence").fetchone()[0] == 1


def test_new_evidence_paths_are_relative_posix(tmp_path):
    recorder = Recorder(tmp_path)
    recorder.note("test")
    record = recorder.records[0]
    assert record.path_base == "repository"
    assert "\\" not in record.raw_path and "\\" not in record.cwd
    assert not record.raw_path.startswith("/")
