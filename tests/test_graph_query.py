import json

import networkx as nx
import pytest

from guardian.graph.build import build_graph
from guardian.graph.export import export
from guardian.graph.query import paths, reverse_dependencies
from guardian.graph.store import load, save


def test_diamond_paths_scopes_and_depth(sample_scan):
    graph = build_graph(sample_scan)
    result = list(paths(graph, "leaf"))
    assert len(result) == 2
    assert all(path[0] == "pkg:generic/app@1" for path in result)
    assert graph.nodes["pkg:generic/leaf@1"]["depth"] == 2
    assert graph.nodes["pkg:generic/leaf@1"]["scopes"] == ["build", "dev", "prod"]
    assert not graph.nodes["pkg:generic/leaf@1"]["is_direct"]
    assert len(reverse_dependencies(graph, "leaf")["pkg:generic/leaf@1"]) == 3
    edge = graph.edges["pkg:generic/app@1", "pkg:generic/a@1"]
    assert edge["kind"] == ["build", "normal"]
    assert len(edge["relationships"]) == 2


def test_cycle_terminates_without_repeated_nodes(sample_scan):
    from guardian.models import Edge

    sample_scan.edges.append(
        Edge(
            from_purl="pkg:generic/leaf@1",
            to_purl="pkg:generic/a@1",
            kind="normal",
            evidence_ids=[sample_scan.evidence[0].id],
        )
    )
    graph = build_graph(sample_scan)
    assert all(len(p) == len(set(p)) for p in paths(graph, "leaf"))


def test_persistence_exports_and_evidence_links(sample_scan, tmp_path):
    graph = build_graph(sample_scan)
    save(tmp_path / "graph.sqlite", graph, sample_scan)
    assert nx.utils.graphs_equal(graph, load(tmp_path / "graph.sqlite"))
    export(graph, tmp_path)
    document = json.loads((tmp_path / "graph.json").read_text())
    ids = {record.id for record in sample_scan.evidence}
    for item in document["nodes"] + document["edges"]:
        assert item["evidence_ids"] and set(item["evidence_ids"]) <= ids
    assert len(nx.read_graphml(tmp_path / "graph.graphml")) == 4
    for filename in ("graph.html", "inventory.csv"):
        assert (tmp_path / filename).stat().st_size > 0


def test_missing_references_rejected(sample_scan):
    sample_scan.edges[0].to_purl = "pkg:generic/absent@1"
    with pytest.raises(ValueError, match="missing component"):
        build_graph(sample_scan)
