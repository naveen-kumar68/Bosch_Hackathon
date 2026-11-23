import hashlib

import pytest

from guardian.graph.build import build_graph
from guardian.pipeline import validate_evidence


def test_evidence_hash_and_timestamp(sample_scan, tmp_path):
    validate_evidence(sample_scan, tmp_path)
    record = sample_scan.evidence[0]
    assert record.timestamp.utcoffset().total_seconds() == 0
    from pathlib import Path

    base = Path(__file__).resolve().parents[1] if record.path_base == "repository" else tmp_path
    raw = base / record.raw_path
    assert hashlib.sha256(raw.read_bytes()).hexdigest() == record.sha256
    raw.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="hash mismatch"):
        validate_evidence(sample_scan, tmp_path)


def test_invalid_evidence_rejected(sample_scan):
    sample_scan.components[0].evidence_ids = ["missing"]
    with pytest.raises(ValueError, match="Invalid node evidence"):
        build_graph(sample_scan)


def test_edge_evidence_rejected(sample_scan):
    sample_scan.edges[0].evidence_ids = ["missing"]
    with pytest.raises(ValueError, match="Invalid edge evidence"):
        build_graph(sample_scan)
