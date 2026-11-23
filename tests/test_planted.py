from pathlib import Path

from guardian.detect.capability import inspect_sources
from guardian.detect.cicd import inspect_workflow
from guardian.detect.correlate import new_build_capability
from guardian.detect.depdiff import inventory_diff
from guardian.detect.risk import load_rules
from guardian.detect.typosquat import candidates
from guardian.models import Component, Edge


def test_planted_anomalies_have_expected_types_and_severity(tmp_path):
    evidence = ["fixture-source"]
    old = Component(
        purl="pkg:cargo/arrayref@0.3.9",
        name="arrayref",
        version="0.3.9",
        ecosystem="cargo",
        source="crates.io",
        checksum="a" * 64,
        evidence_ids=evidence,
    )
    new = old.model_copy(
        update={
            "purl": "pkg:cargo/arrayref@0.3.9?repository_url=local",
            "source": "path",
            "checksum": None,
        }
    )
    typo = Component(
        purl="pkg:cargo/serde_derve@1.0.0?repository_url=local",
        name="serde_derve",
        version="1.0.0",
        ecosystem="cargo",
        source="path",
        has_build_script=True,
        evidence_ids=evidence,
    )
    (tmp_path / "build.rs").write_text(
        "// Hackathon test fixture; never execute.\n"
        'TcpStream::connect("127.0.0.1:9");\nstd::env::vars();\nbase64::decode("fixture");\n'
    )
    diff = inventory_diff([old], [new, typo])
    integrity = {item["type"] for item in diff["integrity"]}
    assert {"source_changed", "registry_checksum_missing"} <= integrity
    assert candidates(typo.name, ["serde_derive"])[0]["distance"] == 1
    hits = inspect_sources(tmp_path)
    assert {hit["capability"] for hit in hits} >= {"network", "environment", "decode"}
    for hit in hits:
        hit["evidence_id"] = evidence[0]
    edge = Edge(from_purl=new.purl, to_purl=typo.purl, kind="build", evidence_ids=evidence)
    correlated = new_build_capability([], [edge], [new, typo], {typo.purl: hits})
    assert len(correlated) == 1
    rules = load_rules(Path("rules/severity.yaml"))
    assert rules[correlated[0]["type"]]["severity"] == "critical"
    assert rules["source_changed"]["severity"] == "high"
    assert rules["typosquat_added"]["severity"] == "high"
    workflow = inspect_workflow(
        "permissions: {}\nsteps:\n - uses: actions/checkout@v4", "fixture.yml"
    )
    assert workflow[0]["type"] == "action_unpinned"
    assert rules[workflow[0]["type"]]["severity"] == "medium"
