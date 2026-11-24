import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.llm.claims import AIClaim, ClaimContent, Fact, FactReference
from guardian.llm.completion import CompletionClient, Provider
from guardian.verify import api
from guardian.verify.checker import Verifier
from guardian.verify.facts import FactIndex, build

FIXTURES = Path(__file__).parent / "fixtures/verifier/cases.json"
DATA = json.loads(FIXTURES.read_text("utf-8"))


@pytest.fixture
def index():
    return build(DATA["ledger"], DATA["findings"], DATA["options"])


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda case: case["name"])
def test_module4_placeholder_cases(index, case):
    claim = AIClaim.model_validate(case["claim"])
    before = claim.model_dump()
    checked = Verifier(index).check(claim)
    assert checked.verified is case["valid"], checked.errors
    if not case["valid"]:
        assert case["error"] in checked.errors
        assert checked.needs_human_review
    else:
        assert checked.errors == []
    assert claim.model_dump() == before  # deterministic check returns a copy


def explain(text="Needs review.", **kwargs):
    return AIClaim(
        kind="explain", summary=text, facts_used=[], cited_evidence_ids=["EV-001"], **kwargs
    )


def test_no_cross_evidence_laundering(index):
    claim = explain("Fixed version is `1.2.4`.")
    claim.facts_used = [FactReference(type="fixed_version", value="1.2.4", evidence_id="EV-001")]
    assert "EV-001 does not support fixed_version 1.2.4" in Verifier(index).check(claim).errors


def test_all_errors_are_collected_and_verification_recomputed(index):
    claim = explain("CVE-2026-99999 has CVSS 9.9.", verified=True, errors=["stale"])
    claim.cited_evidence_ids = ["EV-999"]
    checked = Verifier(index).check(claim)
    assert not checked.verified
    assert checked.errors == [
        "Unknown evidence ID EV-999",
        "Unlisted fact CVE-2026-99999",
        "Unlisted fact 9.9",
    ]
    assert "stale" not in checked.errors


def test_empty_citations_and_unknown_fact_evidence(index):
    claim = explain()
    claim.cited_evidence_ids = []
    claim.facts_used = [FactReference(type="score", value=0.1, evidence_id="EV-999")]
    errors = Verifier(index).check(claim).errors
    assert "Claim has no cited evidence IDs" in errors
    assert "Unknown evidence ID EV-999" in errors
    assert "Fact evidence ID EV-999 is not cited" in errors


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Use 9.9.9.", "Unlisted fact 9.9.9"),
        ("Review GHSA-aaaa-bbbb-cccc.", "Unlisted fact GHSA-aaaa-bbbb-cccc"),
        ("Review RUSTSEC-2026-9999.", "Unlisted fact RUSTSEC-2026-9999"),
        ("Review PYSEC-2026-123.", "Unlisted fact PYSEC-2026-123"),
        ("Inspect `imaginary-crate`.", "Unlisted fact imaginary-crate"),
        ("Path: root → safe-crate → invented.", "Unlisted fact root → safe-crate → invented"),
    ],
)
def test_plain_text_and_sentence_boundaries(index, text, expected):
    assert expected in Verifier(index).check(explain(text)).errors


def test_pair_validation_does_not_mix_unrelated_package_and_version(index):
    index.add_evidence(
        "EV-004",
        [
            {"type": "package", "value": "other"},
            {"type": "version", "value": "2.0.0"},
            {"type": "purl", "value": "pkg:cargo/other@2.0.0"},
        ],
    )
    claim = explain("Inspect `safe-crate@2.0.0`.")
    claim.cited_evidence_ids.append("EV-004")
    claim.facts_used = [
        FactReference(type="package", value="safe-crate", evidence_id="EV-001"),
        FactReference(type="version", value="2.0.0", evidence_id="EV-004"),
    ]
    assert "Unknown package version safe-crate@2.0.0" in Verifier(index).check(claim).errors


def test_atomic_purl_and_path_facts(index):
    claim = explain("Inspect `pkg:cargo/safe-crate@1.2.3`.")
    claim.facts_used = [
        FactReference(type="purl", value="pkg:cargo/safe-crate@1.2.3", evidence_id="EV-001")
    ]
    assert Verifier(index).check(claim).verified
    path = "pkg:cargo/root@0.1.0 → pkg:cargo/safe-crate@1.2.3"
    index.add_evidence("EV-001", [{"type": "path", "value": path}])
    claim.summary = f"Path: `{path}`."
    claim.facts_used = [FactReference(type="path", value=path, evidence_id="EV-001")]
    assert Verifier(index).check(claim).verified


def test_score_numeric_equality_and_type_separation(index):
    claim = explain("CVSS is `8.20`.")
    claim.facts_used = [FactReference(type="score", value=8.2, evidence_id="EV-001")]
    assert Verifier(index).check(claim).verified
    wrong_type = FactReference(type="version", value="8.2", evidence_id="EV-001")
    assert not index.supports(wrong_type)


def test_every_text_field_is_scanned(index):
    claim = explain()
    claim.open_questions = ["Is CVE-2026-99999 present?"]
    claim.trade_offs = ["Use `9.9.9`."]
    claim.rollback_steps = ["Inspect `imaginary-crate`."]
    claim.key_points = ["CVSS 9.9."]
    errors = Verifier(index).check(claim).errors
    assert "Unlisted fact CVE-2026-99999" in errors
    assert "Unlisted fact 9.9.9" in errors
    assert "Unlisted fact imaginary-crate" in errors
    assert "Unlisted fact 9.9" in errors


def test_escalate_is_allowed_without_passed_vetting(index):
    claim = AIClaim(
        kind="plan",
        chosen_option_id="O-00000003",
        facts_used=[FactReference(type="option_id", value="O-00000003", evidence_id="EV-001")],
        cited_evidence_ids=["EV-001"],
    )
    assert Verifier(index).check(claim).verified
    claim.chosen_option_id = "O-ffffffff"
    assert "Unknown option ID O-ffffffff" in Verifier(index).check(claim).errors


def test_only_judge_flags_and_only_plan_choices(index):
    claim = explain()
    claim.flags = {"runs_network": True}
    claim.chosen_option_id = "O-00000001"
    errors = Verifier(index).check(claim).errors
    assert "Only Judge may report flags" in errors
    assert "Only Plan may choose an option" in errors


def test_builder_accepts_current_models_without_inventing_support():
    from guardian.detect.models import Finding

    finding = Finding(
        finding_id="F-001",
        type="vulnerability",
        component="pkg:cargo/safe@1.0.0",
        description="Fixed in 2.0.0",
        evidence_ids=["EV-001", "EV-002"],
        severity="high",
        severity_rule="vulnerability",
        confidence="high",
    )
    index = build([{"id": "EV-001"}, {"id": "EV-002"}], [finding])
    assert index.known_names == {"safe"} and index.known_versions == {"1.0.0"}
    assert index.by_evidence == {"EV-001": set(), "EV-002": set()}


def test_explicit_derived_observations_require_real_evidence():
    observation = {"type": "score", "value": 8.2, "evidence_id": "EV-001"}
    index = build([{"id": "EV-001"}], [{"facts": [observation]}])
    assert index.supports(FactReference(**observation))
    with pytest.raises(ValueError, match="Unknown observation evidence"):
        build([], [{"facts": [observation]}])
    with pytest.raises(ValueError, match="Unknown option evidence"):
        build([], [], [DATA["options"][0]])


def test_sources_do_not_read_llm_assessments():
    index = build(
        [{"id": "EV-001"}],
        [
            {
                "ai_assessment": {
                    "facts_used": [
                        {"type": "package", "value": "invented", "evidence_id": "EV-001"}
                    ]
                }
            }
        ],
    )
    assert "invented" not in index.known_names


def test_fact_types_are_strict_and_claim_cannot_set_deterministic_fields():
    for value in ["8.2", True, float("nan"), float("inf")]:
        with pytest.raises(ValidationError):
            Fact(type="score", value=value)
    for name in ["severity", "priority", "decision", "confidence", "verified", "errors"]:
        with pytest.raises(ValidationError):
            ClaimContent(
                kind="judge", facts_used=[], cited_evidence_ids=["EV-001"], **{name: "low"}
            )


def test_check_api_requires_index_and_preserves_review(index, monkeypatch):
    monkeypatch.setattr(api, "_index", None)
    with pytest.raises(RuntimeError, match="not configured"):
        api.check(explain())
    api.configure(index)
    assert api.check(explain()).verified
    assert api.check(explain(needs_human_review=True)).needs_human_review
    assert api.check(explain(), index=FactIndex()).errors == ["Unknown evidence ID EV-001"]


def test_previous_errors_prompt_is_redacted_and_changes_cache_key(tmp_path, index):
    calls = []
    payload = DATA["cases"][0]["claim"]

    def transport(provider, request):
        calls.append(json.loads(json.dumps(request)))
        return {
            "choices": [{"message": {"content": json.dumps(payload)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }

    provider = Provider("recorded", "https://example.test/v1", "fixture", "fixture-only")
    client = CompletionClient(tmp_path / "cache.sqlite", [provider], transport=transport)
    messages = [{"role": "user", "content": {"finding_id": "F-001"}}]
    secret = "gsk_" + "A1b2C3d4" * 4
    original = ["EV-001 does not support fixed_version 9.9.9", "token=" + secret]
    output, _, cached = client.complete(
        "explain", messages, ClaimContent, "run", previous_errors=original
    )
    sent = json.dumps(calls[0])
    assert not cached and secret not in sent
    assert "fixed_version 9.9.9" in sent and "<VERIFIER_ERRORS>" in sent
    assert "every concrete fact" in sent and "backticks" in sent
    assert Verifier(index).check(output).verified
    assert client.complete("explain", messages, ClaimContent, "run", previous_errors=original)[2]
    assert not client.complete("explain", messages, ClaimContent, "run")[2]
    assert len(calls) == 2 and original[1].endswith(secret)


def test_invalid_previous_errors_do_not_call_provider(tmp_path):
    client = CompletionClient(
        tmp_path / "cache.sqlite", [], transport=lambda p, r: pytest.fail("must not call")
    )
    with pytest.raises(TypeError, match="list of strings"):
        client.complete("explain", [], ClaimContent, "run", previous_errors="not a list")


def test_numeric_fact_cannot_claim_a_different_type(index):
    claim = explain("Fixed version is `8.2`.")
    claim.facts_used = [FactReference(type="score", value=8.2, evidence_id="EV-001")]
    assert "Unlisted fact 8.2" in Verifier(index).check(claim).errors
    index.add_evidence("EV-001", [{"type": "version", "value": "0.12"}])
    claim.summary = "EPSS is `0.12`."
    claim.facts_used = [FactReference(type="version", value="0.12", evidence_id="EV-001")]
    assert "Unlisted fact 0.12" in Verifier(index).check(claim).errors


def test_single_evidence_identity_pair_without_purl():
    index = build(
        [
            {
                "id": "EV-001",
                "facts": [
                    {"type": "package", "value": "safe"},
                    {"type": "version", "value": "1.0.0"},
                ],
            }
        ]
    )
    assert ("safe", "1.0.0") in index.known_pairs
    claim = explain("Inspect `safe@1.0.0`.")
    claim.facts_used = [
        FactReference(type="package", value="safe", evidence_id="EV-001"),
        FactReference(type="version", value="1.0.0", evidence_id="EV-001"),
    ]
    assert Verifier(index).check(claim).verified


def test_conflicting_option_vetting_is_rejected():
    with pytest.raises(ValueError, match="Conflicting trusted option"):
        build(
            DATA["ledger"], [], [DATA["options"][0], {**DATA["options"][0], "vetting": "rejected"}]
        )


def test_legacy_judge_accepts_redacted_previous_errors(tmp_path):
    from guardian.detect.models import Finding
    from guardian.evidence import Recorder
    from guardian.llm.judge import Judge

    calls = []

    def recorded(payload):
        calls.append(payload)
        return json.dumps(
            {
                "finding_id": "F-001",
                "verdict": "suspicious",
                "confidence": 0.9,
                "rationale": "Needs review.",
                "cited_evidence_ids": ["EV-001"],
            }
        )

    item = Finding(
        finding_id="F-001",
        type="capability_added",
        component="pkg:cargo/safe@1.0.0",
        description="Needs review.",
        evidence_ids=["EV-001"],
        severity="high",
        severity_rule="capability_added",
        confidence="low",
        needs_judgement=True,
    )
    judge = Judge(tmp_path / "cache.sqlite", Recorder(tmp_path / "out"), complete=recorded)
    secret = "gsk_" + "A1b2C3d4" * 4
    errors = ["Unknown evidence ID EV-999", "token=" + secret]
    assert judge.assess(item, {"EV-001"}, previous_errors=errors)
    assert calls[0]["previous_errors"][0] == errors[0]
    assert secret not in json.dumps(calls[0])
    judge.assess(item, {"EV-001"}, previous_errors=errors)
    assert len(calls) == 1 and item.severity == "high"
