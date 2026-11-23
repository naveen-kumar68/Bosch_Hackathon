import html
import json
import os
import sqlite3
from collections import Counter

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_reports(output, findings, evidence, vulnerabilities, root, calls):
    findings = sorted(
        findings, key=lambda f: (ORDER[f.severity], f.type, f.component, f.finding_id)
    )
    records = {record.id: record for record in evidence}
    for finding in findings:
        if not finding.evidence_ids or not set(finding.evidence_ids) <= records.keys():
            raise ValueError("Finding has invalid evidence references")

    def write(name, data):
        (output / name).write_text(data, encoding="utf-8", newline="\n")

    write(
        "findings.json", json.dumps([f.model_dump(mode="json") for f in findings], indent=2) + "\n"
    )
    write(
        "vulnerabilities.json",
        json.dumps([v.model_dump() for v in vulnerabilities], indent=2) + "\n",
    )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Supply Chain Guardian"}},
                "results": [
                    {
                        "ruleId": f.severity_rule,
                        "level": "error"
                        if f.severity in {"critical", "high"}
                        else "warning"
                        if f.severity == "medium"
                        else "note",
                        "message": {"text": f.description},
                        "properties": f.model_dump(mode="json"),
                    }
                    for f in findings
                ],
            }
        ],
    }
    write("findings.sarif", json.dumps(sarif, indent=2) + "\n")
    lines = [
        "# Risk report",
        "",
        "Initial deterministic severity; reachability and final prioritisation are deferred.",
        "",
        f"Findings by severity: {dict(Counter(f.severity for f in findings))}",
        f"Findings by type: {dict(Counter(f.type for f in findings))}",
        f"Judge API calls: {calls}",
    ]
    cards = []
    for f in findings:
        lines += [
            "",
            f"## {f.finding_id}: {f.severity.upper()} — {f.type}",
            "",
            f.description,
            f"Component: `{f.component}`",
            f"Rule: `{f.severity_rule}`; confidence: {f.confidence}",
            "",
            "Dependency paths:",
        ]
        lines += ["- " + " → ".join(p) for p in f.paths] or ["Not a package dependency finding."]
        links = []
        for identifier in f.evidence_ids:
            record = records[identifier]
            path = (
                root / record.raw_path
                if record.path_base == "repository"
                else output / record.raw_path
            )
            url = os.path.relpath(path, output).replace("\\", "/")
            links.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(identifier)}</a>')
            lines.append(
                f"- Evidence [{identifier}]({url}): {record.tool} {record.version}; SHA256 `{record.sha256}`"
            )
        assessment = ""
        if f.ai_assessment:
            label = (
                "AI inference (recorded test response)"
                if f.ai_assessment.origin == "recorded_test"
                else "AI inference"
            )
            assessment = (
                "<h4>" + label + "</h4><p>" + html.escape(f.ai_assessment.rationale) + "</p>"
            )
            lines += ["", "### " + label, f.ai_assessment.rationale]
        cards.append(
            f"<article><h3>{html.escape(f.finding_id)} · {f.severity.upper()} · {html.escape(f.type)}</h3>"
            f"<p>{html.escape(f.description)}</p><code>{html.escape(f.component)}</code>"
            f"<p>Rule: {html.escape(f.severity_rule)} · confidence: {f.confidence}</p>"
            "<details><summary>Dependency paths</summary><pre>"
            + html.escape("\n".join(" → ".join(p) for p in f.paths))
            + "</pre></details>"
            "<p>Evidence: " + ", ".join(links) + "</p>" + assessment + "</article>"
        )
    write("risk_report.md", "\n".join(lines) + "\n")
    write(
        "risk_report.html",
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        "<title>Supply Chain Guardian risk report</title><style>body{font:16px system-ui;max-width:1100px;"
        "margin:40px auto;padding:20px;background:#f5f7fa;color:#172336}article{background:white;"
        "padding:24px;margin:20px 0;border:1px solid #ccd5e0;border-radius:8px}pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere}code{overflow-wrap:anywhere}h4{color:#704000}</style><h1>Risk report</h1>"
        "<p>Initial deterministic severity. AI assessments are labelled separately.</p>"
        + "".join(cards)
        + "</html>",
    )
    with sqlite3.connect(output / "graph.sqlite") as conn:
        for table in ("findings", "vulnerabilities", "risk_evidence"):
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            conn.execute(f"DELETE FROM {table}")
        conn.executemany(
            "INSERT INTO findings VALUES (?,?)",
            [(f.finding_id, f.model_dump_json()) for f in findings],
        )
        conn.executemany(
            "INSERT INTO vulnerabilities VALUES (?,?)",
            [(v.component + "#" + v.id, v.model_dump_json()) for v in vulnerabilities],
        )
        conn.executemany(
            "INSERT INTO risk_evidence VALUES (?,?)",
            [(r.id, r.model_dump_json()) for r in evidence],
        )
    return findings
