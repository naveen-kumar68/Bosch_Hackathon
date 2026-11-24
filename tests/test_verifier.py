from pathlib import Path

import pytest

from guardian.verify import AIClaim, FactUsed, check
from guardian.verify.fixtures import load_cases, load_scenario, run_cases

FIXTURES = Path(__file__).parent / "fixtures" / "verifier"
CASES = run_cases(FIXTURES)


@pytest.mark.parametrize("case,result", CASES, ids=[c["name"] for c, _ in CASES])
def test_fixture_case(case, result):
    if case["expect"] == "pass":
        assert result.verified and not result.errors
    else:
        assert not result.verified
        assert case["error"] in result.errors  # exact, human-readable message


def test_counts_match_spec():
    cases = load_cases(FIXTURES)
    assert sum(c["expect"] == "pass" for c in cases) == 3
    assert sum(c["expect"] == "fail" for c in cases) == 10


def test_errors_are_collected_not_short_circuited():
    index = load_scenario(FIXTURES)
    claim = AIClaim(
        kind="explain",
        text="`ghost` fixed in 9.9.9 per CVE-2099-1234.",
        cited_evidence_ids=["EV-404"],
    )
    result = check(claim, index)
    assert {
        "unknown evidence EV-404",
        "unknown package ghost",
        "unlisted fact 9.9.9",
        "unlisted fact CVE-2099-1234",
    } <= set(result.errors)


def test_name_at_version_must_be_known_and_listed():
    index = load_scenario(FIXTURES)
    ok = AIClaim(
        kind="explain",
        text="Pinned `leafcrate@1.2.3`.",
        facts_used=[
            FactUsed(type="package", value="leafcrate", evidence_id="EV-010"),
            FactUsed(type="version", value="1.2.3", evidence_id="EV-010"),
        ],
        cited_evidence_ids=["EV-010"],
    )
    assert check(ok, index).verified
    bad = ok.model_copy(update={"text": "Pinned `leafcrate@7.7.7`."})
    assert "unlisted fact 7.7.7" in check(bad, index).errors


def test_escalate_needs_no_vetting_and_input_not_mutated():
    index = load_scenario(FIXTURES)
    claim = AIClaim(kind="plan", chosen_option_id="O-eeeeeeee", cited_evidence_ids=["EV-021"])
    assert check(claim, index).verified
    assert claim.verified is False and claim.errors == []


def test_repair_messages_include_errors_only_when_given():
    from guardian.verify.repair import with_repair

    base = [{"role": "user", "content": "{}"}]
    assert with_repair(base, None) == base
    out = with_repair(base, ["unlisted fact 9.8"])
    assert len(out) == 2 and "unlisted fact 9.8" in out[1]["content"]
    assert len(base) == 1
