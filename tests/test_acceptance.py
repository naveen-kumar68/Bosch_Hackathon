"""Opt-in checks against completed real scans: GUARDIAN_INTEGRATION=1 pytest."""

import json
import os
import tomllib
from pathlib import Path

import pytest

from guardian.graph.query import paths
from guardian.graph.store import load
from guardian.models import ScanResult
from guardian.pipeline import validate_evidence
from tests.test_cargo_adapter import cargo_output, oracle_paths

pytestmark = pytest.mark.skipif(
    os.environ.get("GUARDIAN_INTEGRATION") != "1", reason="Requires completed real target scans"
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "target", ["kuksa-databroker", "kuksa-val-0.4.1", "kuksa-python-sdk", "kuksa-databroker-image"]
)
def test_outputs_and_all_evidence(target):
    directory = ROOT / "out" / target
    scan = ScanResult.model_validate_json((directory / "scan.json").read_text(encoding="utf-8"))
    validate_evidence(scan, directory)
    for name in [
        "sbom.cdx.json",
        "sbom.spdx.json",
        "graph.json",
        "graph.graphml",
        "graph.html",
        "inventory.csv",
        "summary.md",
        "graph.sqlite",
    ]:
        assert (directory / name).stat().st_size > 0
    graph = json.loads((directory / "graph.json").read_text())
    ids = {record.id for record in scan.evidence}
    for item in graph["nodes"] + graph["edges"]:
        assert item["evidence_ids"] and set(item["evidence_ids"]) <= ids
    validations = [
        e
        for e in scan.evidence
        if e.tool in {"cyclonedx", "pyspdxtools"}
        and ("validate" in e.command or "--infile" in e.command)
    ]
    assert {v.tool for v in validations} == {"cyclonedx", "pyspdxtools"}
    assert all(v.returncode == 0 for v in validations)


@pytest.mark.parametrize(
    "target,ref,count", [("kuksa-databroker", "0.7.2", 496), ("kuksa-val-0.4.1", "0.4.1", 355)]
)
def test_exact_lockfile_inventory(target, ref, count):
    lock = tomllib.loads(
        (ROOT / "workspace/targets" / f"{target}@{ref}" / "Cargo.lock").read_text()
    )
    scan = ScanResult.model_validate_json((ROOT / "out" / target / "scan.json").read_text())
    assert len(lock["package"]) == len(scan.components) == count
    assert {(p["name"], p["version"]) for p in lock["package"]} == {
        (c.name, c.version) for c in scan.components
    }


@pytest.mark.parametrize("member", ["databroker", "databroker-proto", "databroker-cli"])
def test_direct_dependencies_match_manifest(member):
    path = ROOT / "workspace/targets/kuksa-databroker@0.7.2"
    manifest = tomllib.loads((path / member / "Cargo.toml").read_text())
    scan = ScanResult.model_validate_json((ROOT / "out/kuksa-databroker/scan.json").read_text())
    nodes = {c.purl: c for c in scan.components}
    root = next(c.purl for c in scan.components if c.name == member and c.is_root)
    expected = set()
    sections = [manifest, *manifest.get("target", {}).values()]
    for section in sections:
        for table, kind in [
            ("dependencies", "normal"),
            ("dev-dependencies", "dev"),
            ("build-dependencies", "build"),
        ]:
            for name, entry in section.get(table, {}).items():
                package = entry.get("package", name) if isinstance(entry, dict) else name
                expected.add((package, kind))
    actual = {(nodes[e.to_purl].name, e.kind) for e in scan.edges if e.from_purl == root}
    assert actual == expected


@pytest.mark.parametrize("crate", ["anstyle-query", "same-file", "multimap", "num-conv"])
def test_real_transitive_paths_match_cargo_tree(crate):
    directory = ROOT / "workspace/targets/kuksa-databroker@0.7.2"
    graph = load(ROOT / "out/kuksa-databroker/graph.sqlite")
    tree = cargo_output(
        [
            "tree",
            "--locked",
            "--all-features",
            "-i",
            crate,
            "-e",
            "normal,build,dev",
            "--target",
            "all",
            "--prefix",
            "depth",
            "--no-dedupe",
            "--format",
            "{p}",
        ],
        directory,
    )
    roots = {data["name"] for _, data in graph.nodes(data=True) if data["is_root"]}
    expected = oracle_paths(tree, roots)
    actual = {
        tuple((graph.nodes[n]["name"], graph.nodes[n]["version"]) for n in p)
        for p in paths(graph, crate)
    }
    assert expected
    assert expected == actual


def test_image_digest_and_shipped_sbom():
    directory = ROOT / "out/kuksa-databroker-image"
    scan = ScanResult.model_validate_json((directory / "scan.json").read_text())
    assert scan.revision.startswith("sha256:")
    assert scan.target.revision == scan.revision
    assert json.loads((directory / "shipped-sbom.json").read_text())["bomFormat"] == "CycloneDX"
    commands = [record.command for record in scan.evidence]
    assert any("create" in command for command in commands)
    assert any("cp" in command for command in commands)
    assert not any("run" in command for command in commands)
