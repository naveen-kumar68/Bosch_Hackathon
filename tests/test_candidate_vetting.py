import ast
import hashlib
import io
import tarfile
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

# Simulate the lead's bootstrap wiring. Production Module 2 imports only its
# binding contracts; these are the actual existing detector functions, not copies.
from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import metadata_changes, new_dependencies
from guardian.detect.typosquat import candidates as typosquat_candidates
from guardian.detect.vulns import parse_osv
from guardian.llm.claims import AIClaim, FactReference
from guardian.remediate import api
from guardian.remediate.detectors import CapturedDetectors
from guardian.remediate.models import Change, FixOption
from guardian.remediate.vet_contracts import CapturedVersion, DetectorBindings, VetPolicy
from guardian.remediate.vetting import Vetter
from guardian.verify.api import check
from guardian.verify.facts import build

NOW = datetime(2026, 11, 24, 12, tzinfo=UTC)


def archive(text="fn main() {}", name="pkg/build.rs"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as target:
        content = text.encode()
        member = tarfile.TarInfo(name)
        member.size = len(content)
        target.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def capture(version, **changes):
    artifact = archive()
    document = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "safe", "version": version, "ecosystem": "crates.io"},
                        "vulnerabilities": [],
                    }
                ]
            }
        ]
    }
    value = CapturedVersion(
        ecosystem="cargo",
        package="safe",
        version=version,
        metadata={
            "published": "2026-11-01T12:00:00+00:00",
            "yanked": False,
            "publisher": 7,
            "trusted_publishing": True,
            "source": "registry:crates.io",
        },
        metadata_evidence_ids=(f"EV-META-{version}",),
        history=[
            {
                "name": "safe",
                "vers": "1.0.0",
                "deps": [],
                "cksum": hashlib.sha256(artifact).hexdigest(),
            },
            {
                "name": "safe",
                "vers": "1.0.1",
                "deps": [],
                "cksum": hashlib.sha256(artifact).hexdigest(),
            },
        ],
        history_evidence_ids=("EV-INDEX",),
        osv_document=document,
        osv_evidence_ids=("EV-OSV",),
        artifact=artifact,
        registry_sha256=hashlib.sha256(artifact).hexdigest(),
        artifact_evidence_ids=(f"EV-ARTIFACT-{version}",),
        checksum_evidence_ids=("EV-INDEX",),
    )
    return replace(value, **changes)


def with_artifact(value, data):
    history = deepcopy(value.history)
    checksum = hashlib.sha256(data).hexdigest()
    for row in history:
        if row["vers"] == value.version:
            row["cksum"] = checksum
    return replace(value, artifact=data, registry_sha256=checksum, history=history)


def candidate(**changes):
    value = FixOption(
        option_id="O-12345678",
        finding_id="F-001",
        kind="minimal_upgrade",
        component="pkg:cargo/safe@1.0.0",
        target_version="1.0.1",
        changes=[
            Change(
                file="Cargo.lock",
                package="safe",
                from_version="1.0.0",
                to_version="1.0.1",
                operation="lock_update",
            )
        ],
        evidence_ids=["EV-FINDING"],
    )
    return value.model_copy(update=changes, deep=True)


def service(tmp_path, versions=None, *, scanner=None, trusted=None, age=7, missing_evidence=()):
    versions = versions or [capture("1.0.0"), capture("1.0.1")]
    known = {"EV-POLICY", "EV-FINDING", "EV-SG", "EV-POPULAR", "EV-INDEX", "EV-OSV"}
    for value in versions:
        known.update(
            [
                *value.metadata_evidence_ids,
                *value.history_evidence_ids,
                *value.osv_evidence_ids,
                *value.artifact_evidence_ids,
                *value.checksum_evidence_ids,
            ]
        )
    known.difference_update(missing_evidence)
    semgrep_calls = []

    def semgrep(directory, **kwargs):
        semgrep_calls.append(directory)
        return scanner(directory, **kwargs) if scanner else ({"results": [], "errors": []}, "EV-SG")

    bindings = DetectorBindings(
        parse_osv=parse_osv,
        metadata_changes=metadata_changes,
        new_dependencies=new_dependencies,
        typosquat_candidates=typosquat_candidates,
        verified_extract=verified_extract,
        inspect_sources=inspect_sources,
        capability_diff=capability_diff,
        semgrep=semgrep,
        evidence_exists=lambda identifier: identifier in known,
    )
    detectors = CapturedDetectors(
        versions,
        bindings,
        scratch=tmp_path,
        popular_names={"cargo": ["serde_derive"]},
        popularity_evidence={"cargo": ["EV-POPULAR"]},
    )
    policy = VetPolicy(
        evidence_ids=["EV-POLICY"],
        min_popular_names=1,
        trusted_publishers=trusted or {},
        min_release_age_days=age,
    )
    return Vetter(detectors, policy, now=NOW), semgrep_calls


def statuses(option):
    return {check.check: check.status for check in option.vetting_checks}


def test_clean_candidate_passes_real_detectors_with_evidence(tmp_path):
    vetter, scans = service(tmp_path)
    original = candidate()
    before = original.model_dump()
    result = vetter.vet([original])[0]
    assert result.vetting == "passed" and result.vetting_reasons == []
    assert set(statuses(result)) == {
        "vulnerability",
        "release",
        "publisher_provenance",
        "dependency_diff",
        "typosquat",
        "integrity",
        "capability_diff",
    }
    assert all(value == "passed" for value in statuses(result).values())
    assert all(c.evidence_ids and "EV-POLICY" in c.evidence_ids for c in result.vetting_checks)
    assert {"EV-OSV", "EV-SG", "EV-INDEX"} <= set(result.evidence_ids)
    assert original.model_dump() == before and original.vetting == "pending"
    assert len(scans) == 2 and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "published, yanked, expected",
    [
        ("2026-11-18T12:00:00Z", False, "rejected"),
        ("2026-11-17T12:00:00Z", False, "passed"),
        ("2026-11-25T12:00:00Z", False, "rejected"),
        ("2026-11-01T12:00:00Z", True, "rejected"),
        ("2026-11-01T12:00:00Z", None, "rejected"),
        ("2026-11-01T12:00:00", False, "rejected"),
    ],
)
def test_release_age_boundary_future_yanked_unknown(tmp_path, published, yanked, expected):
    after = capture("1.0.1")
    after = replace(after, metadata={**after.metadata, "published": published, "yanked": yanked})
    vetter, _ = service(tmp_path, [capture("1.0.0"), after])
    assert statuses(vetter.vet([candidate()])[0])["release"] == expected


def test_configurable_age_uses_captured_policy(tmp_path):
    after = capture("1.0.1")
    after = replace(after, metadata={**after.metadata, "published": "2026-11-18T12:00:00Z"})
    vetter, _ = service(tmp_path, [capture("1.0.0"), after], age=3)
    assert vetter.vet([candidate()])[0].vetting == "passed"


@pytest.mark.parametrize(
    "change",
    [
        {"publisher": 8},
        {"publisher": None},
        {"publisher": ""},
        {"trusted_publishing": False},
        {"trusted_publishing": None},
        {"source": "registry:other"},
    ],
)
def test_publisher_provenance_unknown_or_regression_reject(tmp_path, change):
    after = capture("1.0.1")
    after = replace(after, metadata={**after.metadata, **change})
    vetter, _ = service(tmp_path, [capture("1.0.0"), after])
    assert statuses(vetter.vet([candidate()])[0])["publisher_provenance"] == "rejected"


def test_explicitly_trusted_publisher_allowed(tmp_path):
    after = capture("1.0.1")
    after = replace(after, metadata={**after.metadata, "publisher": 8})
    vetter, _ = service(tmp_path, [capture("1.0.0"), after], trusted={"cargo:safe": [8]})
    assert vetter.vet([candidate()])[0].vetting == "passed"


def test_candidate_vulnerability_and_wrong_version_scope_reject(tmp_path):
    after = capture("1.0.1")
    document = deepcopy(after.osv_document)
    document["results"][0]["packages"][0]["vulnerabilities"] = [{"id": "CVE-2026-12345"}]
    vetter, _ = service(tmp_path, [capture("1.0.0"), replace(after, osv_document=document)])
    result = vetter.vet([candidate()])[0]
    assert statuses(result)["vulnerability"] == "rejected"
    assert any("CVE-2026-12345" in reason for reason in result.vetting_reasons)
    document["results"][0]["packages"][0]["package"]["version"] = "9.9.9"
    vetter, _ = service(tmp_path, [capture("1.0.0"), replace(after, osv_document=document)])
    assert statuses(vetter.vet([candidate()])[0])["vulnerability"] == "rejected"
    vetter, _ = service(tmp_path, [capture("1.0.0"), replace(after, osv_document={"results": []})])
    assert statuses(vetter.vet([candidate()])[0])["vulnerability"] == "rejected"


def test_new_typosquatted_build_dependency_from_planted_scenario_rejected(tmp_path):
    # Reuse the planted demo's exact dependency name; do not execute prepare.py.
    source = (Path(__file__).parents[1] / "demo/prepare.py").read_text("utf-8")
    assert "[build-dependencies.serde_derve]" in source
    after = capture("1.0.1")
    history = deepcopy(after.history)
    history[1]["deps"] = [{"name": "serde_derve", "req": "1.0.0", "kind": "build"}]
    vetter, _ = service(tmp_path, [capture("1.0.0"), replace(after, history=history)])
    result = vetter.vet([candidate()])[0]
    assert result.vetting == "rejected" and statuses(result)["typosquat"] == "rejected"
    check = next(c for c in result.vetting_checks if c.check == "dependency_diff")
    assert "new_build_dependency:serde_derve" in check.flags
    assert "EV-POPULAR" in result.evidence_ids


def test_planted_build_script_capability_diff_rejects_no_execution(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("target code must not execute")
    )
    source = ast.parse((Path(__file__).parents[1] / "demo/prepare.py").read_text("utf-8"))
    build_source = next(
        node.value
        for node in ast.walk(source)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "fn look_alike_only_never_called" in node.value
    )
    data = archive(build_source)
    after = with_artifact(capture("1.0.1"), data)
    vetter, _ = service(tmp_path, [capture("1.0.0"), after])
    result = vetter.vet([candidate()])[0]
    assert statuses(result)["integrity"] == "passed"
    assert statuses(result)["capability_diff"] == "rejected"
    assert any("network" in reason and "environment" in reason for reason in result.vetting_reasons)


def test_checksum_mismatch_stops_target_scan(tmp_path):
    after = replace(capture("1.0.1"), registry_sha256="0" * 64)
    vetter, scans = service(tmp_path, [capture("1.0.0"), after])
    result = vetter.vet([candidate()])[0]
    assert result.vetting == "rejected" and statuses(result)["integrity_static"] == "rejected"
    assert len(scans) == 1  # baseline only; mismatched target never reaches static rules


def test_archive_traversal_rejected_and_no_file_escaped(tmp_path):
    data = archive("bad", "../escape.rs")
    after = with_artifact(capture("1.0.1"), data)
    vetter, _ = service(tmp_path, [capture("1.0.0"), after])
    assert vetter.vet([candidate()])[0].vetting == "rejected"
    assert not (tmp_path / "escape.rs").exists() and list(tmp_path.iterdir()) == []


def test_scanner_failure_rejects_and_unknown_new_semgrep_rule_rejects(tmp_path):
    for document in [{"results": [], "errors": [{"message": "failed"}]}, {"results": []}]:
        vetter, _ = service(
            tmp_path, scanner=lambda *a, captured=document, **k: (captured, "EV-SG")
        )
        assert vetter.vet([candidate()])[0].vetting == "rejected"
    count = []

    def scanner(*args, **kwargs):
        count.append(1)
        return {
            "results": [] if len(count) == 1 else [{"check_id": "unknown-new-rule"}],
            "errors": [],
        }, "EV-SG"

    vetter, _ = service(tmp_path, scanner=scanner)
    assert statuses(vetter.vet([candidate()])[0])["capability_diff"] == "rejected"


def test_missing_data_and_ledger_evidence_fail_closed(tmp_path, monkeypatch):
    vetter, _ = service(tmp_path, [capture("1.0.0")])
    assert vetter.vet([candidate()])[0].vetting == "rejected"
    vetter, _ = service(tmp_path, missing_evidence=["EV-SG"])
    result = vetter.vet([candidate()])[0]
    assert result.vetting == "rejected" and any(
        "ledger" in reason for reason in result.vetting_reasons
    )
    monkeypatch.setattr(api, "_vetter", None)
    assert api.vet([candidate()])[0].vetting == "rejected"


def test_rejected_options_retained_escalate_unchanged_and_reruns_stable(tmp_path):
    vetter, _ = service(tmp_path)
    original = candidate()
    escalate = candidate(option_id="O-00000001", kind="escalate", changes=[], target_version=None)
    bad = candidate(option_id="O-87654321", target_version="9.9.9")
    results = vetter.vet([original, bad, escalate])
    assert [o.option_id for o in results] == [o.option_id for o in [original, bad, escalate]]
    assert (
        results[0].vetting == "passed"
        and results[1].vetting == "rejected"
        and results[2] == escalate
    )
    assert results == vetter.vet([original, bad, escalate])
    assert bad.vetting == "pending"
    ids = {e for option in results for e in option.evidence_ids}
    index = build([{"id": e} for e in ids], [], results)
    selected = results[0]
    claim = AIClaim(
        kind="plan",
        chosen_option_id=selected.option_id,
        facts_used=[
            FactReference(
                type="option_id", value=selected.option_id, evidence_id=selected.evidence_ids[0]
            )
        ],
        cited_evidence_ids=[selected.evidence_ids[0]],
    )
    assert check(claim, index=index).verified
    rejected = results[1]
    claim.chosen_option_id = rejected.option_id
    claim.facts_used = [
        FactReference(
            type="option_id", value=rejected.option_id, evidence_id=rejected.evidence_ids[0]
        )
    ]
    claim.cited_evidence_ids = [rejected.evidence_ids[0]]
    assert not check(claim, index=index).verified


def test_parent_bump_vets_each_changed_package(tmp_path):
    # A compromised parent cannot pass just because the child's target is clean.
    vetter, _ = service(tmp_path)
    original = candidate(kind="parent_bump")
    original.changes.append(
        Change(
            file="Cargo.lock",
            package="parent",
            from_version="1.0.0",
            to_version="1.0.1",
            operation="lock_update",
        )
    )
    result = vetter.vet([original])[0]
    assert result.vetting == "rejected"
    assert any(
        c.check == "availability" and "parent@1.0.1" in c.component for c in result.vetting_checks
    )


def test_policy_needs_ledger_evidence_and_timezone(tmp_path):
    with pytest.raises(ValueError, match="policy evidence"):
        service(tmp_path, missing_evidence=["EV-POLICY"])
    vetter, _ = service(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        Vetter(vetter.detectors, vetter.policy, now=datetime(2026, 11, 24))


def test_supplied_hash_without_matching_index_record_cannot_authorise_inspection(tmp_path):
    data = archive('fn main() { let _ = std::net::TcpStream::connect("127.0.0.1:9"); }')
    after = replace(
        capture("1.0.1"), artifact=data, registry_sha256=hashlib.sha256(data).hexdigest()
    )
    vetter, scans = service(tmp_path, [capture("1.0.0"), after])
    result = vetter.vet([candidate()])[0]
    assert result.vetting == "rejected" and len(scans) == 1
    assert statuses(result)["integrity_static"] == "rejected"


def test_missing_dependency_history_and_popularity_coverage_reject(tmp_path):
    after = replace(capture("1.0.1"), history=None)
    vetter, _ = service(tmp_path, [capture("1.0.0"), after])
    assert statuses(vetter.vet([candidate()])[0])["dependency_screening"] == "rejected"
    after = capture("1.0.1")
    history = deepcopy(after.history)
    history[1]["deps"] = [{"name": "another", "req": "1", "kind": "build"}]
    vetter, _ = service(tmp_path, [capture("1.0.0"), replace(after, history=history)])
    vetter.detectors.popular_names = {}
    assert statuses(vetter.vet([candidate()])[0])["dependency_screening"] == "rejected"


def test_pypi_artifact_hash_binding_and_unknown_publisher_reject(tmp_path):
    versions = []
    for version in ["1.0.0", "1.0.1"]:
        value = capture(version)
        document = deepcopy(value.osv_document)
        document["results"][0]["packages"][0]["package"]["ecosystem"] = "PyPI"
        versions.append(
            replace(
                value,
                ecosystem="pypi",
                osv_document=document,
                metadata={
                    **value.metadata,
                    "publisher": None,
                    "source": "registry:pypi",
                    "files": [{"digests": {"sha256": value.registry_sha256}}],
                },
                checksum_evidence_ids=value.metadata_evidence_ids,
            )
        )
    vetter, _ = service(tmp_path, versions)
    original = candidate(component="pkg:pypi/safe@1.0.0")
    result = vetter.vet([original])[0]
    assert statuses(result)["integrity"] == "passed"
    assert statuses(result)["publisher_provenance"] == "rejected"


def test_vetting_api_uses_configured_service_and_rejects_invalid_source_identity(
    tmp_path, monkeypatch
):
    vetter, _ = service(tmp_path)
    monkeypatch.setattr(api, "_vetter", None)
    api.configure_vetting(vetter)
    assert api.vet([candidate()])[0].vetting == "passed"
    bad = candidate(changes=[])
    assert statuses(api.vet([bad])[0])["identity"] == "rejected"
