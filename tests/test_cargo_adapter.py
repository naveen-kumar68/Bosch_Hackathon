import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from guardian.adapters.cargo import parse_metadata
from guardian.evidence import Recorder, tool_path
from guardian.graph.build import build_graph
from guardian.graph.query import paths
from guardian.models import ScanResult, Target


def cargo_output(arguments, directory):
    cargo = tool_path("cargo")
    env = os.environ.copy()
    env["PATH"] = str(Path(cargo).parent) + os.pathsep + env["PATH"]
    return subprocess.run(
        [cargo, *arguments],
        cwd=directory,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    ).stdout


def oracle_paths(output, roots):
    stack = []
    result = set()
    for line in output.splitlines():
        match = re.match(r"^(\d+)(\S+) v([^ ]+)", line)
        if not match:
            continue
        depth = int(match[1])
        stack = stack[:depth] + [(match[2], match[3])]
        if match[2] in roots:
            result.add(tuple(reversed(stack)))
    return result


@pytest.fixture
def cargo_fixture(fixture_dir, tmp_path):
    directory = fixture_dir / "cargo"
    metadata = json.loads(
        cargo_output(["metadata", "--format-version", "1", "--locked"], directory)
    )
    lock = tomllib.loads((directory / "Cargo.lock").read_text())
    recorder = Recorder(tmp_path)
    evidence = recorder.note("fixture cargo metadata")
    resolution = parse_metadata(metadata, lock, [evidence])
    scan = ScanResult(
        target=Target(name="fixture", source="fixture", ref="1"),
        revision="1",
        components=resolution.components,
        edges=resolution.edges,
        evidence=recorder.records,
    )
    return directory, build_graph(scan)


@pytest.mark.parametrize("crate", ["leaf-one", "leaf-two", "leaf-three"])
def test_paths_match_independent_cargo_tree(cargo_fixture, crate):
    directory, graph = cargo_fixture
    tree = cargo_output(
        [
            "tree",
            "--locked",
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
    assert actual == expected


def test_build_flags_and_parallel_kinds(cargo_fixture):
    _, graph = cargo_fixture
    nodes = {d["name"]: d for _, d in graph.nodes(data=True)}
    assert nodes["fixture-app"]["has_build_script"]
    assert nodes["leaf-two"]["is_proc_macro"]
    assert any(edge["kind"] == ["build", "dev", "normal"] for _, _, edge in graph.edges(data=True))
