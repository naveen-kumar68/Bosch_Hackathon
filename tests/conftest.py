from pathlib import Path

import pytest

from guardian.evidence import Recorder
from guardian.models import Component, Edge, ScanResult, Target


@pytest.fixture
def fixture_dir():
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_scan(tmp_path):
    recorder = Recorder(tmp_path)
    evidence = recorder.note("fixture observation")
    components = [
        Component(
            purl=f"pkg:generic/{name}@1",
            name=name,
            version="1",
            ecosystem="generic",
            source="registry",
            is_root=name == "app",
            evidence_ids=[evidence],
        )
        for name in ("app", "a", "b", "leaf")
    ]
    edges = [
        Edge(
            from_purl=f"pkg:generic/{a}@1",
            to_purl=f"pkg:generic/{b}@1",
            kind=kind,
            evidence_ids=[evidence],
        )
        for a, b, kind in [
            ("app", "a", "normal"),
            ("app", "b", "dev"),
            ("a", "leaf", "normal"),
            ("b", "leaf", "normal"),
            ("app", "a", "build"),
        ]
    ]
    return ScanResult(
        target=Target(name="fixture", source="fixture", ref="1"),
        revision="1",
        components=components,
        edges=edges,
        evidence=recorder.records,
    )
