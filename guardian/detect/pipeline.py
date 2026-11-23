import hashlib
import json
import sqlite3
from pathlib import Path

import yaml

from guardian.acquire import acquire
from guardian.detect.cicd import inspect_directory
from guardian.detect.container import inspect_dockerfile, inventory_drift
from guardian.detect.correlate import new_build_capability
from guardian.detect.depdiff import inventory_diff
from guardian.detect.enrich import enrich
from guardian.detect.http import CachedHTTP
from guardian.detect.models import Finding
from guardian.detect.packages import inspect_packages
from guardian.detect.report import write_reports
from guardian.detect.risk import load_rules, vulnerability_severity
from guardian.detect.scanners import run_json, scan_vulnerabilities
from guardian.evidence import Recorder
from guardian.graph.query import paths
from guardian.graph.store import load
from guardian.llm.judge import Judge
from guardian.models import Evidence, ScanResult
from guardian.pipeline import validate_evidence


def detect(target, baseline, root: Path, *, offline=False, judge_enabled=False):
    baseline = baseline or target.baseline
    if baseline and not (root / "out" / baseline / "scan.json").is_file():
        from guardian.config import load_targets
        from guardian.pipeline import scan as scan_target

        scan_target(load_targets(root / "targets.yaml")[baseline], root)
    output = root / "out" / target.name
    scan = ScanResult.model_validate_json((output / "scan.json").read_text(encoding="utf-8"))
    validate_evidence(scan, output)
    recorder = Recorder(output)
    # Keep the last completed report's evidence valid while a new run is in progress.
    database = output / "graph.sqlite"
    with sqlite3.connect(database) as connection:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='risk_evidence'"
        ).fetchone():
            recorder.import_records(
                [
                    Evidence.model_validate_json(row[0])
                    for row in connection.execute("SELECT data FROM risk_evidence")
                ],
                output,
            )
    recorder.import_records(scan.evidence, output)
    source, revision, _acquisition = acquire(target, root / "workspace/targets", recorder)
    if revision != scan.revision:
        raise ValueError("Scan revision differs from acquisition; rescan required")
    graph = load(output / "graph.sqlite")
    rules_path = root / "rules/severity.yaml"
    rules = load_rules(rules_path)
    rules_evidence = recorder.file(rules_path, "Initial severity policy")
    http = CachedHTTP(root / "workspace/cache/http", recorder, offline=offline)
    findings = []

    def add(
        kind,
        component,
        description,
        evidence,
        details=None,
        heuristic=False,
        severity=None,
        rule=None,
        needs_judgement=False,
    ):
        rule = rule or kind
        content = [kind, component, description, details or {}]
        identifier = (
            "F-" + hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:12]
        )
        finding_paths = list(paths(graph, component)) if component in graph else []
        finding = Finding(
            finding_id=identifier,
            type=kind,
            component=component,
            description=description,
            paths=finding_paths,
            evidence_ids=sorted({*evidence, rules_evidence}),
            severity=severity or rules[rule]["severity"],
            severity_rule=rule,
            confidence="low" if heuristic else "medium",
            details=details or {},
            needs_judgement=needs_judgement,
        )
        if not any(f.finding_id == identifier for f in findings):
            findings.append(finding)
        return finding

    roots = sorted(c.purl for c in scan.components if c.is_root)
    project = roots[0]
    extra_sboms = (
        [root / "out/kuksa-databroker-image/shipped-sbom.json"]
        if target.name == "kuksa-databroker"
        else []
    )
    vulnerabilities = scan_vulnerabilities(source, output, scan, recorder, extra_sboms=extra_sboms)
    enrich(vulnerabilities, scan.components, http)
    by_purl = {c.purl: c for c in scan.components}
    for vulnerability in vulnerabilities:
        severity, severity_rule = vulnerability_severity(
            vulnerability.cvss_score,
            vulnerability.kev,
            vulnerability.epss,
            by_purl[vulnerability.component].scopes,
        )
        finding = add(
            "vulnerability",
            vulnerability.component,
            vulnerability.id + " affects " + vulnerability.component,
            vulnerability.evidence_ids,
            vulnerability.model_dump(),
            severity=severity,
            rule="vulnerability",
        )
        finding.details["severity_calculation"] = severity_rule
        finding.confidence = "high" if len(set(vulnerability.sources)) >= 2 else "medium"
        for flag in vulnerability.flags:
            if flag in rules:
                add(
                    flag,
                    vulnerability.component,
                    flag + " advisory: " + vulnerability.id,
                    vulnerability.evidence_ids,
                    {"advisory": vulnerability.id},
                )
    previous = None
    if baseline:
        previous = ScanResult.model_validate_json(
            (root / "out" / baseline / "scan.json").read_text(encoding="utf-8")
        )
        previous_id = recorder.file(
            root / "out" / baseline / "scan.json", "Baseline resolved inventory"
        )
        current_id = recorder.file(output / "scan.json", "Current resolved inventory")
        diff = inventory_diff(previous.components, scan.components)
        (output / "dependency-diff.json").write_text(
            json.dumps(diff, indent=2), encoding="utf-8", newline="\n"
        )
        for kind in ("added", "removed"):
            for item in diff[kind]:
                add(
                    "dependency_" + kind,
                    item["purl"],
                    f"Dependency {kind}: {item['name']}@{item['version']}",
                    [previous_id, current_id],
                    item,
                )
        for item in diff["changed"]:
            for purl in item["components"]:
                direction = item["direction"]
                add(
                    "dependency_" + direction,
                    purl,
                    "Version set changed for " + item["name"],
                    [previous_id, current_id],
                    item,
                )
        for item in diff["integrity"]:
            add(
                item["type"],
                item["component"],
                "Dependency integrity observation: " + item["type"],
                [previous_id, current_id],
                item,
            )
        for purl in diff["new_direct"]:
            add("new_direct_dependency", purl, "New direct dependency", [previous_id, current_id])
    capabilities = inspect_packages(scan, previous, http, recorder, root, add)
    for correlated in new_build_capability(
        previous.edges if previous else [], scan.edges, scan.components, capabilities
    ):
        add(
            "new_build_dependency_with_network_capability",
            correlated["component"],
            "New build dependency gained network or process capability",
            correlated["evidence_ids"],
            correlated,
            rule="new_build_dep_network",
            heuristic=True,
            needs_judgement=True,
        )
    for item in inspect_directory(source):
        identifier = recorder.file(source / item["file"], "Static workflow rule source")
        add(item["type"], project, item["message"], [identifier], item)
    workflows = source / ".github/workflows"
    if workflows.exists():
        document, evidence = run_json(
            recorder,
            [
                "zizmor",
                "--offline",
                "--no-config",
                "--no-exit-codes",
                "--collect",
                "all",
                "--format",
                "sarif",
                str(workflows),
            ],
            accepted=(0,),
        )
        (output / "zizmor.sarif").write_text(
            json.dumps(document, indent=2), encoding="utf-8", newline="\n"
        )
        recorder.note("Independent zizmor workflow results retained for correlation", [evidence])
        for result in document.get("runs", [{}])[0].get("results", []):
            location = result.get("locations", [{}])[0].get("physicalLocation", {})
            filename = location.get("artifactLocation", {}).get("uri", "")
            start = location.get("region", {}).get("startLine", 1)
            end = location.get("region", {}).get("endLine", start)
            mapping = {
                "zizmor/unpinned-uses": "action_unpinned",
                "zizmor/excessive-permissions": "workflow_permissions",
            }
            matches = [
                f
                for f in findings
                if f.type == mapping.get(result["ruleId"])
                and f.details.get("file") == filename
                and start <= f.details.get("line", 0) <= end
            ]
            if matches:
                for matched in matches:
                    matched.evidence_ids = sorted(set(matched.evidence_ids) | {evidence})
                    matched.confidence = "high"
                    matched.details["zizmor_rule"] = result["ruleId"]
            else:
                add(
                    "workflow_zizmor",
                    project,
                    result["message"]["text"],
                    [evidence],
                    {
                        "rule": result["ruleId"],
                        "file": filename,
                        "line": start,
                        "tool_level": result.get("level"),
                    },
                    severity={"error": "high", "warning": "medium", "note": "low"}.get(
                        result.get("level"), "medium"
                    ),
                )
    for path in sorted(source.rglob("*Dockerfile*")):
        if not path.is_file():
            continue
        identifier = recorder.file(path, "Container build recipe")
        for item in inspect_dockerfile(path.read_text(encoding="utf-8")):
            item["file"] = path.relative_to(source).as_posix()
            add(item["type"], project, "Container base: " + item["image"], [identifier], item)
    for component in scan.components:
        if component.has_hash is False:
            add(
                "pin_without_hash",
                component.purl,
                "Python requirement pin lacks artifact hashes",
                component.evidence_ids,
            )
    for file in source.glob("*requirements*.txt"):
        for line, text in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            if any(
                option in text for option in ("--extra-index-url", "--index-url", "--find-links")
            ):
                identifier = recorder.file(file, "Python index configuration")
                add(
                    "nondefault_index",
                    project,
                    "Python requirements specify a package source",
                    [identifier],
                    {"file": file.relative_to(source).as_posix(), "line": line},
                )
    image = root / "out/kuksa-databroker-image"
    if target.name == "kuksa-databroker" and (image / "shipped-sbom.json").is_file():
        shipped, observed = image / "shipped-sbom.json", image / "sbom.cdx.json"
        ids = [
            recorder.file(shipped, "Shipped image SBOM"),
            recorder.file(observed, "Syft image SBOM"),
        ]
        drift = inventory_drift(
            json.loads(shipped.read_text(encoding="utf-8")),
            json.loads(observed.read_text(encoding="utf-8")),
        )
        (output / "sbom-drift.json").write_text(
            json.dumps(drift, indent=2), encoding="utf-8", newline="\n"
        )
        if any(drift.values()):
            add("sbom_drift", project, "Shipped and observed image inventories differ", ids, drift)
    settings = yaml.safe_load((root / "guardian.yaml").read_text(encoding="utf-8"))["judge"]
    recorder.file(root / "guardian.yaml", "Judge call and input budget configuration")
    judge = Judge(
        root / "workspace/cache/judge.sqlite",
        recorder,
        env_file=root / ".env",
        max_calls=settings["max_judge_calls"],
        max_input_chars=settings["max_input_chars"],
    )
    if judge_enabled:
        for finding in findings:
            snippet = finding.details.get("hit", {}).get("snippet", "")
            finding.ai_assessment = judge.assess(finding, {r.id for r in recorder.records}, snippet)
    for record in recorder.records:
        base = root if record.path_base == "repository" else output
        if hashlib.sha256((base / record.raw_path).read_bytes()).hexdigest() != record.sha256:
            raise ValueError("Raw evidence integrity mismatch")
    recorder.save()
    return write_reports(output, findings, recorder.records, vulnerabilities, root, judge.calls)
