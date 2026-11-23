import csv
import html
import json
from collections import Counter
from pathlib import Path

import networkx as nx
from pyvis.network import Network


def export(graph: nx.DiGraph, output: Path) -> None:
    (output / "graph.json").write_text(
        json.dumps(nx.node_link_data(graph, edges="edges"), indent=2),
        encoding="utf-8",
        newline="\n",
    )
    serializable = nx.DiGraph(
        **{
            key: json.dumps(value) if isinstance(value, (dict, list)) else value
            for key, value in graph.graph.items()
        }
    )
    for node, data in graph.nodes(data=True):
        serializable.add_node(
            node,
            **{
                key: json.dumps(value)
                if isinstance(value, (list, dict))
                else ""
                if value is None
                else value
                for key, value in data.items()
            },
        )
    for a, b, data in graph.edges(data=True):
        serializable.add_edge(a, b, **{key: json.dumps(value) for key, value in data.items()})
    nx.write_graphml(serializable, output / "graph.graphml")
    with (output / "inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = list(next(iter(graph.nodes(data=True)))[1]) if graph else ["purl"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for _, data in graph.nodes(data=True):
            row = {
                key: json.dumps(value) if isinstance(value, list) else value
                for key, value in data.items()
            }
            # CSV values are data, never spreadsheet formulas.
            writer.writerow(
                {
                    key: "'" + value
                    if isinstance(value, str) and value.startswith(("=", "+", "-", "@"))
                    else value
                    for key, value in row.items()
                }
            )
    network = Network(height="850px", width="100%", directed=True, cdn_resources="in_line")
    for node, data in graph.nodes(data=True):
        network.add_node(
            node,
            label=f"{data['name']}\n{data['version']}",
            title=html.escape(node),
            size=26 if data["is_root"] else 12,
            color="#e8a33d" if data["is_root"] else "#66a9dd",
        )
    for a, b, data in graph.edges(data=True):
        network.add_edge(a, b, title=html.escape(", ".join(data["kind"])))
    network.barnes_hut()
    network.set_options(
        '{"physics":{"stabilization":{"iterations":150}},'
        '"interaction":{"navigationButtons":true,"keyboard":true}}'
    )
    rendered = network.generate_html()
    (output / "graph.html").write_text(rendered, encoding="utf-8", newline="\n")


def summary(graph: nx.DiGraph, warnings: list[str]) -> str:
    nodes = list(graph.nodes(data=True))
    roots = sum(d["is_root"] for _, d in nodes)
    direct = sum(d["is_direct"] for _, d in nodes)
    transitive = sum(
        not d["is_root"] and not d["is_direct"] and d["depth"] is not None for _, d in nodes
    )
    unreachable = sum(d["depth"] is None for _, d in nodes)
    ecosystems = Counter(d["ecosystem"] for _, d in nodes)
    kinds = Counter(kind for _, _, d in graph.edges(data=True) for kind in d["kind"])
    flags = {
        "Build scripts": [n for n, d in nodes if d["has_build_script"]],
        "Proc macros": [n for n, d in nodes if d["is_proc_macro"]],
        "Non-registry sources": [
            n for n, d in nodes if d["source"] not in {"registry", "crates.io", "pypi"}
        ],
        "Pins without hashes": [n for n, d in nodes if d["has_hash"] is False],
    }
    lines = [
        f"# {graph.graph['target']}",
        "",
        f"Revision: `{graph.graph['revision']}`",
        "",
        f"Total components (including roots): {len(nodes)}",
        f"Roots: {roots}",
        f"Direct dependencies: {direct}",
        f"Transitive dependencies: {transitive}",
        f"Unreachable inventory components: {unreachable}",
        f"Edges (unique pairs): {graph.number_of_edges()}",
        f"Max depth: {max((d['depth'] or 0 for _, d in nodes), default=0)}",
        "",
        f"By ecosystem: {dict(sorted(ecosystems.items()))}",
        f"Edges by kind (a pair can have multiple kinds): {dict(sorted(kinds.items()))}",
    ]
    for label, packages in flags.items():
        lines += ["", f"## {label}: {len(packages)}", ""]
        lines += [f"- `{purl}`" for purl in sorted(packages)] or ["None."]
    lines += ["", "## Warnings", ""] + ([f"- {w}" for w in warnings] or ["None."])
    return "\n".join(lines) + "\n"
