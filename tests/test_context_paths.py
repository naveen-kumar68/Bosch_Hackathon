from guardian.adapters.cargo import parse_context_tree
from guardian.graph.build import build_graph
from guardian.graph.query import paths, reverse_dependencies


def test_distinct_subtrees_with_identical_features_do_not_mix(sample_scan):
    # app->a->leaf and app->b->a. A package-only graph invents app->b->a->leaf.
    from guardian.models import Edge

    evidence = sample_scan.evidence[0].id
    sample_scan.edges = [
        Edge(
            from_purl=f"pkg:generic/{a}@1",
            to_purl=f"pkg:generic/{b}@1",
            kind="normal",
            evidence_ids=[evidence],
        )
        for a, b in [("app", "a"), ("a", "leaf"), ("app", "b"), ("b", "a")]
    ]
    tree = "0app v1|\n1a v1|feature\n2leaf v1|\n1b v1|\n2a v1|feature\n"
    sample_scan.path_context = parse_context_tree(tree, sample_scan.components, evidence)
    graph = build_graph(sample_scan)
    assert list(paths(graph, "leaf")) == [
        ["pkg:generic/app@1", "pkg:generic/a@1", "pkg:generic/leaf@1"]
    ]
    assert "pkg:generic/b@1" not in reverse_dependencies(graph, "leaf")["pkg:generic/leaf@1"]
