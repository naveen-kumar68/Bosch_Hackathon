import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.llm import api
from guardian.llm.completion import Budget, ClientConfig, CompletionClient, Provider
from guardian.llm.second_opinion import SecondOpinion
from guardian.verify.api import check
from guardian.verify.facts import build

RECORDED = json.loads(
    (Path(__file__).parent / "llm_recordings/second_opinion.json").read_text("utf-8")
)["response"]


def finding(i=1):
    return {
        "finding_id": f"F-{i:03}",
        "type": "capability_added",
        "component": "pkg:cargo/safe@1.0.0",
        "severity": "critical",
        "priority": "P0",
        "score_breakdown": [],
        "paths": [],
        "decision": "needs_human",
        "evidence_ids": ["EV-FIND"],
    }


def service(tmp_path, respond=None):
    index = build(
        [{"id": "EV-FIND", "facts": [{"type": "purl", "value": "pkg:cargo/safe@1.0.0"}]}],
        [finding()],
    )
    calls = []

    def transport(provider, request):
        calls.append(deepcopy(request))
        return {
            "choices": [{"message": {"content": json.dumps(respond() if respond else RECORDED)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }

    config = ClientConfig(run_budget=Budget(max_calls=20), role_budget=Budget(max_calls=20))
    client = CompletionClient(
        tmp_path / "cache.sqlite",
        [Provider("fixture", "https://example.test/v1", "fixture", "fixture-only")],
        config,
        transport=transport,
    )
    return SecondOpinion(client, index, budget_key="run"), calls


def test_p0_only_independent_and_disagreement_requires_review(tmp_path):
    service_instance, calls = service(tmp_path)
    pf = finding()
    before = deepcopy(pf)
    claim = service_instance.second_opinion(pf)
    assert claim.verified and claim.opinion_disagrees is True and claim.needs_human_review
    assert pf == before and pf["priority"] == "P0" and pf["severity"] == "critical"
    claim.needs_human_review = False
    assert check(claim, index=service_instance.index).needs_human_review
    non_p0 = {**pf, "priority": "P1"}
    assert service_instance.second_opinion(non_p0) is None and len(calls) == 1
    packet = json.loads(next(m["content"] for m in calls[0]["messages"] if m["role"] == "user"))
    assert "rationale" not in packet["context"] and "judge" not in packet["context"]


def test_three_request_cap_shared_across_service_instances_and_cache_free(tmp_path):
    instance, calls = service(tmp_path)
    for i in range(1, 4):
        assert instance.second_opinion(finding(i)).verified
    assert instance.second_opinion(finding(4)) is None and len(calls) == 3
    other = SecondOpinion(instance.client, instance.index, budget_key="run")
    assert other.second_opinion(finding(5)) is None and len(calls) == 3
    assert other.second_opinion(finding()).verified and other.trace[-1].cached
    assert len(calls) == 3 and other.trace[-1].usage.calls == 0


@pytest.mark.parametrize(
    "opinion,disagrees", [("critical", False), ("high", True), ("needs_review", None)]
)
def test_agreement_and_needs_review(tmp_path, opinion, disagrees):
    instance, _ = service(tmp_path, respond=lambda: {**RECORDED, "risk_opinion": opinion})
    claim = instance.second_opinion(finding())
    assert claim.verified and claim.opinion_disagrees is disagrees and claim.needs_human_review


def test_unknown_evidence_unverified_and_no_severity_override(tmp_path):
    instance, _ = service(tmp_path, respond=lambda: {**RECORDED, "cited_evidence_ids": ["EV-FAKE"]})
    claim = instance.second_opinion(finding())
    assert not claim.verified and "Unknown evidence ID EV-FAKE" in claim.errors
    instance, calls = service(tmp_path / "bad", respond=lambda: {**RECORDED, "severity": "low"})
    assert instance.second_opinion(finding()) is None and len(calls) == 2


def test_raw_code_prior_ai_text_and_ai_off(tmp_path, monkeypatch):
    instance, calls = service(tmp_path)
    for extra in [
        {"judge_text": "untrusted prior answer"},
        {"plan_text": "prior answer"},
        {"snippet": "source"},
    ]:
        with pytest.raises(ValidationError):
            instance.second_opinion({**finding(), **extra})
    assert calls == []
    instance.enabled = False
    assert instance.second_opinion({}) is None
    monkeypatch.setattr(api, "_opinion", None)
    assert api.second_opinion(finding()) is None
    api.configure_second_opinion(instance)
    assert api.second_opinion(finding()) is None


def test_redacted_repair_errors(tmp_path):
    instance, calls = service(tmp_path)
    secret = "gsk_" + "A1b2C3d4" * 4
    assert api.second_opinion(finding(), service=instance, previous_errors=[secret]).verified
    assert secret not in json.dumps(calls) and "<VERIFIER_ERRORS>" in json.dumps(calls)
