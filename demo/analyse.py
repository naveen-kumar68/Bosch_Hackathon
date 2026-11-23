"""Generate static-only planted findings from the already captured locked graph."""

import hashlib
import json
from pathlib import Path

from guardian.detect.capability import inspect_sources
from guardian.detect.cicd import inspect_workflow
from guardian.detect.correlate import new_build_capability
from guardian.detect.depdiff import inventory_diff
from guardian.detect.http import CachedHTTP
from guardian.detect.models import Finding
from guardian.detect.report import write_reports
from guardian.detect.risk import load_rules
from guardian.detect.typosquat import candidates, popular_names
from guardian.evidence import Recorder
from guardian.graph.build import build_graph
from guardian.graph.query import paths
from guardian.llm.judge import Judge
from guardian.models import Evidence, Resolution, ScanResult, Target


def analyse(root, *, live_judge=False, complete=None):
    output = root / "out/planted"
    resolution = Resolution.model_validate_json(
        (output / "resolution.json").read_text(encoding="utf-8")
    )
    evidence = [
        Evidence.model_validate(item)
        for item in json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    ]
    recorder = Recorder(output)
    recorder.import_records(evidence, output)
    baseline_path = root / "out/kuksa-databroker/scan.json"
    baseline = ScanResult.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    baseline_id = recorder.file(baseline_path, "Planted scenario baseline")
    scenario = root / "demo/planted"
    scenario_id = recorder.file(scenario / "PLANTED.json", "Controlled planted scenario")
    rules_path = root / "rules/severity.yaml"
    policy_id = recorder.file(rules_path, "Initial severity rules")
    rules = load_rules(rules_path)
    scan = ScanResult(
        target=Target(name="planted", source="local-fixture", ref="fixture"),
        revision="local-fixture",
        components=resolution.components,
        edges=resolution.edges,
        path_context=resolution.path_context,
        evidence=recorder.records,
    )
    graph = build_graph(scan)
    findings = []

    def add(kind, component, description, ids, details=None, rule=None, judge=False):
        rule = rule or kind
        identifier = (
            "F-"
            + hashlib.sha256(
                json.dumps([kind, component, details], sort_keys=True).encode()
            ).hexdigest()[:12]
        )
        findings.append(
            Finding(
                finding_id=identifier,
                type=kind,
                component=component,
                description=description,
                paths=list(paths(graph, component)),
                evidence_ids=sorted({*ids, policy_id, scenario_id}),
                severity=rules[rule]["severity"],
                severity_rule=rule,
                confidence="low" if judge else "medium",
                details=details or {},
                needs_judgement=judge,
            )
        )

    diff = inventory_diff(baseline.components, scan.components)
    for item in diff["integrity"]:
        add(
            item["type"],
            item["component"],
            "Planted integrity observation",
            [baseline_id, scenario_id],
            item,
        )
    http = CachedHTTP(root / "workspace/cache/http", recorder, offline=True)
    names, popularity_evidence = popular_names(http, "cargo")
    capability_hits = {}
    for component in scan.components:
        if component.name != "serde_derve":
            continue
        matches = candidates(component.name, names)
        if matches:
            add(
                "typosquat_added",
                component.purl,
                "Planted look-alike package name",
                popularity_evidence,
                {"matches": matches},
                judge=True,
            )
        hits = inspect_sources(scenario / "vendor/serde_derve")
        for hit in hits:
            hit["evidence_id"] = recorder.file(
                scenario / "vendor/serde_derve" / hit["file"], "Planted static source"
            )
            add(
                "capability_added",
                component.purl,
                "Planted capability: " + hit["capability"],
                [hit["evidence_id"]],
                {"hit": hit},
                judge=True,
            )
        capability_hits[component.purl] = hits
    for item in new_build_capability(baseline.edges, scan.edges, scan.components, capability_hits):
        add(
            "new_build_dependency",
            item["parent"],
            "Planted parent added a build dependency",
            item["evidence_ids"],
            {"dependency": item["component"]},
        )
        add(
            "new_build_dependency_with_network_capability",
            item["component"],
            "Planted new build dependency has network capability",
            item["evidence_ids"],
            item,
            rule="new_build_dep_network",
            judge=True,
        )
    workflow = scenario / ".github/workflows/planted.yml"
    workflow_id = recorder.file(workflow, "Planted workflow")
    project = next(c.purl for c in scan.components if c.name == "databroker")
    for item in inspect_workflow(
        workflow.read_text(encoding="utf-8"), ".github/workflows/planted.yml"
    ):
        add(item["type"], project, item["message"], [workflow_id], item)
    judge = Judge(
        root / "workspace/cache/planted-judge.sqlite",
        recorder,
        env_file=root / ".env",
        complete=complete,
    )
    if live_judge or complete:
        # Build-time capability findings receive the limited judgement budget first.
        for item in sorted(findings, key=lambda item: item.severity != "critical"):
            snippets = item.details.get("hit", {}).get("snippet", "")
            if item.type == "new_build_dependency_with_network_capability":
                snippets = (scenario / "vendor/serde_derve/build.rs").read_text(encoding="utf-8")
            item.ai_assessment = judge.assess(item, {r.id for r in recorder.records}, snippets)
    recorder.save()
    write_reports(output, findings, recorder.records, [], root, judge.calls)
    return findings


if __name__ == "__main__":
    print("Planted findings:", len(analyse(Path(__file__).resolve().parents[1])))
