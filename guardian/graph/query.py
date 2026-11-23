from collections.abc import Iterator

import networkx as nx


def match(graph: nx.DiGraph, query: str) -> list[str]:
    matches = [
        node for node, data in graph.nodes(data=True) if node == query or data["name"] == query
    ]
    if not matches:
        raise ValueError(f"No component matches {query!r}")
    return sorted(matches)


def paths(graph: nx.DiGraph, query: str) -> Iterator[list[str]]:
    """All simple root-to-package paths, streamed without a hidden limit."""
    if graph.graph.get("path_context"):
        context = graph.graph["path_context"]
        resolved = nx.DiGraph()
        resolved.add_nodes_from(context["nodes"])
        resolved.add_edges_from(context["edges"])
        destinations = set(match(graph, query))
        seen = set()
        for node, data in context["nodes"].items():
            if data["purl"] not in destinations:
                continue
            for root in context["roots"]:
                candidates = [[root]] if root == node else nx.all_simple_paths(resolved, root, node)
                for candidate in candidates:
                    projected = tuple(context["nodes"][item]["purl"] for item in candidate)
                    if len(set(projected)) == len(projected) and projected not in seen:
                        seen.add(projected)
                        yield list(projected)
        return
    for destination in match(graph, query):
        for root, data in graph.nodes(data=True):
            if data["is_root"]:
                if root == destination:
                    yield [root]
                else:
                    yield from nx.all_simple_paths(graph, root, destination)


def reverse_dependencies(graph: nx.DiGraph, query: str) -> dict[str, list[str]]:
    if graph.graph.get("path_context"):
        return {
            node: sorted({ancestor for path in paths(graph, node) for ancestor in path[:-1]})
            for node in match(graph, query)
        }
    return {node: sorted(nx.ancestors(graph, node)) for node in match(graph, query)}
