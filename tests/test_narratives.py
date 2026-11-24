import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.llm import api
from guardian.llm.completion import Budget, ClientConfig, CompletionClient, Provider
from guardian.llm.explain import Narrator
from guardian.verify.api import check
from guardian.verify.facts import build

RECORDINGS = json.loads(
    (Path(__file__).parent / "llm_recordings/structured.json").read_text("utf-8")
)


def finding():
    return {
        "finding_id": "F-001",
        "type": "capability_added",
        "component": "pkg:cargo/safe@1.0.0",
        "severity": "critical",
        "priority": "P0",
        "score_breakdown": [],
        "paths": [],
        "decision": "needs_human",
        "evidence_ids": ["EV-FIND"],
    }


def run():
    return {
        "run_id": "run-001",
        "status": "complete",
        "counts": [{"name": "findings", "value": 2, "evidence_ids": ["EV-RUN"]}],
        "top_findings": [],
        "plans": [],
        "validations": [],
        "evidence_ids": ["EV-RUN"],
    }


def brief():
    return {
        "finding": finding(),
        "observations": [{"type": "package", "value": "safe", "evidence_id": "EV-FIND"}],
        "evidence_ids": ["EV-FIND"],
    }


def service(tmp_path, *, respond=None, config=None):
    index = build(
        [
            {
                "id": "EV-RUN",
                "facts": [{"type": "status", "value": "complete"}, {"type": "count", "value": 2}],
            },
            {
                "id": "EV-FIND",
                "facts": [
                    {"type": "package", "value": "safe"},
                    {"type": "version", "value": "1.0.0"},
                    {"type": "purl", "value": "pkg:cargo/safe@1.0.0"},
                ],
            },
            {"id": "EV-OUTSIDE", "facts": [{"type": "count", "value": 99}]},
        ],
        [finding()],
    )
    calls = []

    def transport(provider, request):
        calls.append(deepcopy(request))
        name = request["response_format"].get("json_schema", {}).get("name", "")
        role = "brief" if name == "BriefResponse" else "explain"
        value = respond(role) if respond else RECORDINGS[role]
        return {
            "choices": [{"message": {"content": json.dumps(value)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }

    client = CompletionClient(
        tmp_path / "cache.sqlite",
        [Provider("fixture", "https://example.test/v1", "fixture", "fixture-only")],
        config,
        transport=transport,
    )
    return Narrator(client, index, budget_key="run"), calls


def test_explain_and_brief_verified_cache_zero_calls(tmp_path):
    narrator, calls = service(tmp_path)
    inputs = run(), brief()
    before = deepcopy(inputs)
    summary = narrator.explain(inputs[0])
    investigation = narrator.explain_brief(inputs[1])
    assert summary.verified and investigation.verified
    assert len(summary.summary.split()) <= 200 and len(investigation.summary.split()) <= 120
    assert summary.origin == investigation.origin == "recorded_test"
    narrator.explain(inputs[0])
    narrator.explain_brief(inputs[1])
    assert len(calls) == 2 and all(c.cached and c.usage.calls == 0 for c in narrator.trace[-2:])
    assert inputs == before and calls[0]["reasoning_effort"] == "low"


@pytest.mark.parametrize("role,limit", [("explain", 200), ("brief", 120)])
def test_word_limit_and_decision_fields_rejected(tmp_path, role, limit):
    narrator, calls = service(
        tmp_path, respond=lambda name: {**RECORDINGS[name], "summary": "word " * (limit + 1)}
    )
    result = narrator.explain(run()) if role == "explain" else narrator.explain_brief(brief())
    assert result is None and len(calls) == 2


def test_fake_count_and_out_of_context_evidence_rejected(tmp_path):
    answer = deepcopy(RECORDINGS["explain"])
    answer["summary"] = "There are 99 findings."
    answer["facts_used"] = [{"type": "count", "value": 99, "evidence_id": "EV-OUTSIDE"}]
    answer["cited_evidence_ids"] = ["EV-OUTSIDE"]
    narrator, _ = service(tmp_path, respond=lambda role: answer)
    claim = narrator.explain(run())
    assert (
        not claim.verified and "Claim cited evidence outside its structured context" in claim.errors
    )
    assert not check(claim, index=narrator.index).verified
    answer["facts_used"] = []
    narrator, _ = service(tmp_path / "other", respond=lambda role: answer)
    assert "Unlisted fact 99" in narrator.explain(run()).errors


def test_ai_off_and_budget_returns_none_without_input_errors(tmp_path, monkeypatch):
    narrator, calls = service(tmp_path, config=ClientConfig(run_budget=Budget(max_calls=0)))
    assert narrator.explain(run()) is None and calls == []
    narrator.enabled = False
    assert narrator.explain({"raw_code": "ignored while off"}) is None
    assert narrator.explain_brief({}) is None
    monkeypatch.setattr(api, "_narrator", None)
    assert api.explain(run()) is None and api.explain_brief(brief()) is None
    api.configure_explain(narrator)
    assert api.explain(run()) is None


def test_raw_code_and_ai_prose_are_excluded(tmp_path):
    narrator, calls = service(tmp_path)
    for extra in [{"snippet": "code"}, {"judge_text": "prior AI"}]:
        with pytest.raises(ValidationError):
            narrator.explain({**run(), **extra})
    with pytest.raises(ValidationError):
        narrator.explain_brief({**brief(), "raw_logs": "code"})
    assert calls == []


def test_input_counts_and_observations_need_support(tmp_path):
    narrator, calls = service(tmp_path)
    invalid = run()
    invalid["counts"][0]["value"] = 99
    with pytest.raises(ValueError, match="count requires typed|count requires|count.*typed"):
        narrator.explain(invalid)
    invalid = brief()
    invalid["observations"][0]["value"] = "invented"
    with pytest.raises(ValueError, match="unsupported"):
        narrator.explain_brief(invalid)
    assert calls == []


def test_redacted_repair_errors_and_facade(tmp_path):
    narrator, calls = service(tmp_path)
    secret = "gsk_" + "A1b2C3d4" * 4
    assert api.explain(
        run(), service=narrator, previous_errors=["Unlisted fact 99", secret]
    ).verified
    assert secret not in json.dumps(calls) and "<VERIFIER_ERRORS>" in json.dumps(calls)
    assert api.explain_brief(brief(), service=narrator).verified
