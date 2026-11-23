from collections import deque

import networkx as nx

from guardian.models import ScanResult


def build_graph(scan: ScanResult) -> nx.DiGraph:
    graph = nx.DiGraph(target=scan.target.name, revision=scan.revision)
    if scan.path_context:
        graph.graph["path_context"] = scan.path_context
    valid = {record.id for record in scan.evidence}
    for component in scan.components:
        if not set(component.evidence_ids) <= valid:
            raise ValueError(f"Invalid node evidence: {component.purl}")
        attributes = component.model_dump()
        if graph.has_node(component.purl):
            raise ValueError(f"Duplicate component purl: {component.purl}")
        graph.add_node(component.purl, **attributes)
    for edge in scan.edges:
        if not set(edge.evidence_ids) <= valid:
            raise ValueError("Invalid edge evidence")
        if edge.from_purl not in graph or edge.to_purl not in graph:
            raise ValueError("Edge references a missing component")
        if not graph.has_edge(edge.from_purl, edge.to_purl):
            graph.add_edge(
                edge.from_purl,
                edge.to_purl,
                kind=[],
                version_req=[],
                evidence_ids=[],
                relationships=[],
            )
        data = graph.edges[edge.from_purl, edge.to_purl]
        data["relationships"].append(edge.model_dump())
        for key, values in [
            ("kind", [edge.kind]),
            ("version_req", [edge.version_req]),
            ("evidence_ids", edge.evidence_ids),
        ]:
            data[key] = sorted(set(data[key]) | set(values))
    roots = [node for node, data in graph.nodes(data=True) if data["is_root"]]
    depths: dict[str, int] = {}
    for root in roots:
        for node, depth in nx.single_source_shortest_path_length(graph, root).items():
            depths[node] = min(depth, depths.get(node, depth))
    for node, data in graph.nodes(data=True):
        data["depth"] = depths.get(node)
        data["is_direct"] = not data["is_root"] and any(graph.has_edge(r, node) for r in roots)
        data["scopes"] = []
    # Propagate scope through reachability. A dev/build boundary remains non-prod.
    queue = deque((root, "prod") for root in roots)
    seen = set()
    while queue:
        node, scope = queue.popleft()
        if (node, scope) in seen:
            continue
        seen.add((node, scope))
        graph.nodes[node]["scopes"] = sorted(set(graph.nodes[node]["scopes"]) | {scope})
        for child in graph.successors(node):
            for kind in graph.edges[node, child]["kind"]:
                next_scope = scope if kind in {"normal", "contains"} else kind
                if scope != "prod":
                    next_scope = scope
                queue.append((child, next_scope))
    return graph
