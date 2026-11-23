"""Adapter orchestration with standards validation and evidence integrity checks."""

import hashlib
import json
from pathlib import Path

from guardian.acquire import acquire
from guardian.adapters import adapters
from guardian.evidence import Recorder
from guardian.graph.build import build_graph
from guardian.graph.export import export, summary
from guardian.graph.store import save
from guardian.models import ScanResult, Target


def validate_evidence(scan: ScanResult, output: Path) -> None:
    records = {record.id: record for record in scan.evidence}
    if scan.path_context:
        context = scan.path_context
        ids = context.get("evidence_ids", [])
        purls = {component.purl for component in scan.components}
        root_purls = {component.purl for component in scan.components if component.is_root}
        pairs = {(edge.from_purl, edge.to_purl) for edge in scan.edges}
        if not ids or not set(ids) <= records.keys():
            raise ValueError("Invalid path-context evidence")
        for node in context["nodes"].values():
            if (
                node["purl"] not in purls
                or not node["evidence_ids"]
                or not set(node["evidence_ids"]) <= records.keys()
            ):
                raise ValueError("Invalid path-context node")
        for source, destination in context["edges"]:
            if (
                context["nodes"][source]["purl"],
                context["nodes"][destination]["purl"],
            ) not in pairs:
                raise ValueError("Path-context edge absent from resolved graph")
        if any(context["nodes"][root]["purl"] not in root_purls for root in context["roots"]):
            raise ValueError("Invalid path-context root")
    for item in [*scan.components, *scan.edges]:
        if not item.evidence_ids or not set(item.evidence_ids) <= records.keys():
            raise ValueError("Missing or invalid evidence reference")
    for record in scan.evidence:
        path = (output / record.raw_path).resolve()
        if not path.is_relative_to(output.resolve()):
            raise ValueError("Evidence path escapes output directory")
        if hashlib.sha256(path.read_bytes()).hexdigest() != record.sha256:
            raise ValueError(f"Evidence hash mismatch: {record.id}")


def scan(target: Target, root: Path) -> ScanResult:
    output = root / "out" / target.name
    recorder = Recorder(output)
    path, revision, acquisition = acquire(target, root / "workspace/targets", recorder)
    selected = [adapter for adapter in adapters() if adapter.detect(path, target)]
    if len(selected) != 1:
        raise ValueError(f"Expected one ecosystem adapter, found {len(selected)}")
    adapter = selected[0]
    resolution = adapter.resolve(path, target, revision, recorder)
    for component in resolution.components:
        component.evidence_ids.append(acquisition)
    adapter.sbom(path, target, revision, recorder)
    for filename in ("sbom.cdx.json", "sbom.spdx.json"):
        recorder.file(output / filename, "Generated standards document")
    cdx = json.loads((output / "sbom.cdx.json").read_text(encoding="utf-8-sig"))
    spdx = json.loads((output / "sbom.spdx.json").read_text(encoding="utf-8-sig"))
    if spdx.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Expected SPDX 2.3")
    recorder.run(
        [
            "cyclonedx",
            "validate",
            "--input-file",
            str(output / "sbom.cdx.json"),
            "--input-version",
            "v" + cdx["specVersion"].replace(".", "_"),
            "--fail-on-errors",
        ]
    )
    recorder.run(["pyspdxtools", "--infile", str(output / "sbom.spdx.json")])
    for label, count in [
        ("CycloneDX top-level", len(cdx.get("components", []))),
        ("SPDX", len(spdx.get("packages", []))),
    ]:
        if count != len(resolution.components):
            warning = (
                f"{label} component count {count} differs from resolver inventory "
                f"{len(resolution.components)} (including local roots)."
            )
            resolution.warnings.append(warning)
    for warning in resolution.warnings:
        recorder.note(warning)
    result = ScanResult(
        target=target,
        revision=revision,
        components=resolution.components,
        edges=resolution.edges,
        evidence=recorder.records,
        path_context=resolution.path_context,
        warnings=resolution.warnings,
    )
    validate_evidence(result, output)
    graph = build_graph(result)
    for component in result.components:
        data = graph.nodes[component.purl]
        component.is_direct, component.depth = data["is_direct"], data["depth"]
        component.scopes = data["scopes"]
    save(output / "graph.sqlite", graph, result)
    export(graph, output)
    (output / "summary.md").write_text(summary(graph, result.warnings), encoding="utf-8")
    (output / "scan.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return result
