import json
import sqlite3
from pathlib import Path

import networkx as nx

from guardian.models import ScanResult


def save(path: Path, graph: nx.DiGraph, scan: ScanResult) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (purl TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS edges (
                source TEXT REFERENCES nodes(purl), target TEXT REFERENCES nodes(purl),
                data TEXT NOT NULL, PRIMARY KEY(source, target));
            CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, data TEXT NOT NULL);
        """)
        connection.execute("DELETE FROM edges")
        connection.execute("DELETE FROM nodes")
        connection.execute("DELETE FROM evidence")
        connection.execute("DELETE FROM metadata")
        connection.executemany(
            "INSERT INTO nodes VALUES (?, ?)",
            [(n, json.dumps(d)) for n, d in graph.nodes(data=True)],
        )
        connection.executemany(
            "INSERT INTO edges VALUES (?, ?, ?)",
            [(a, b, json.dumps(d)) for a, b, d in graph.edges(data=True)],
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?)",
            [(e.id, e.model_dump_json()) for e in scan.evidence],
        )
        connection.execute("INSERT INTO metadata VALUES (?, ?)", ("graph", json.dumps(graph.graph)))


def load(path: Path) -> nx.DiGraph:
    if not path.is_file():
        raise ValueError(f"No scan database: {path}")
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
        graph = nx.DiGraph(
            **json.loads(
                connection.execute("SELECT data FROM metadata WHERE key='graph'").fetchone()[0]
            )
        )
        for node, data in connection.execute("SELECT purl, data FROM nodes"):
            graph.add_node(node, **json.loads(data))
        for source, target, data in connection.execute("SELECT source,target,data FROM edges"):
            graph.add_edge(source, target, **json.loads(data))
    return graph
