import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.llm import api
from guardian.llm.claims import AIClaim
from guardian.llm.completion import Budget, ClientConfig, CompletionClient, Provider
from guardian.llm.plan import Planner
from guardian.remediate.models import Change, FixOption
from guardian.verify.api import check
from guardian.verify.facts import build

RECORDED = json.loads((Path(__file__).parent / "llm_recordings/plan.json").read_text("utf-8"))[
    "response"
]


def finding():
    return {
        "finding_id": "F-001",
        "type": "vulnerability",
        "component": "pkg:cargo/safe@1.2.3",
        "severity": "high",
        "priority": "P1",
        "score_breakdown": [{"name": "cvss", "value": 8.1, "evidence_ids": ["EV-FIND"]}],
        "paths": [["root", "pkg:cargo/safe@1.2.3"]],
        "decision": "needs_human",
        "evidence_ids": ["EV-FIND"],
    }


def options():
    return [
        FixOption(
            option_id="O-11111111",
            finding_id="F-001",
            kind="minimal_upgrade",
            component="pkg:cargo/safe@1.2.3",
            target_version="1.2.4",
            vetting="passed",
            changes=[
                Change(
                    file="Cargo.lock",
                    package="safe",
                    from_version="1.2.3",
                    to_version="1.2.4",
                    operation="lock_update",
                )
            ],
            evidence_ids=["EV-FIX"],
            reasons=["Smallest compatible captured upgrade."],
        ),
        FixOption(
            option_id="O-22222222",
            finding_id="F-001",
            kind="minimal_upgrade",
            component="pkg:cargo/safe@1.2.3",
            target_version="9.9.9",
            vetting="rejected",
            evidence_ids=["EV-REJECT"],
            vetting_reasons=["New network capability."],
        ),
        FixOption(
            option_id="O-33333333",
            finding_id="F-001",
            kind="escalate",
            component="pkg:cargo/safe@1.2.3",
            evidence_ids=["EV-FIND"],
        ),
    ]


def service(tmp_path, *, supplied=None, respond=None, config=None, indexed=None):
    supplied = options() if supplied is None else supplied
    ledger = [
        {
            "id": "EV-FIND",
            "facts": [
                {"type": "purl", "value": "pkg:cargo/safe@1.2.3"},
                {"type": "package", "value": "safe"},
                {"type": "version", "value": "1.2.3"},
                {"type": "score", "value": 8.1},
            ],
        },
        {
            "id": "EV-FIX",
            "facts": [
                {"type": "fixed_version", "value": "1.2.4"},
                {"type": "purl", "value": "pkg:cargo/safe@1.2.4"},
            ],
        },
        {"id": "EV-REJECT", "facts": [{"type": "fixed_version", "value": "9.9.9"}]},
        {"id": "EV-OUTSIDE", "facts": [{"type": "fixed_version", "value": "8.8.8"}]},
    ]
    index = build(ledger, [finding()], supplied if indexed is None else indexed)
    calls = []

    def transport(provider, request):
        calls.append(deepcopy(request))
        content = respond() if respond else deepcopy(RECORDED)
        return {
            "choices": [{"message": {"content": json.dumps(content)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }

    client = CompletionClient(
        tmp_path / "cache.sqlite",
        [Provider("fixture", "https://example.test/v1", "fixture", "fixture-only")],
        config,
        transport=transport,
    )
    return Planner(client, index, budget_key="run"), calls, supplied


def test_plan_chooses_passed_option_and_cache_costs_zero_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Plan must never execute"))
    planner, calls, choices = service(tmp_path)
    pf = finding()
    before = deepcopy(pf), [o.model_dump() for o in choices]
    claim = planner.plan(pf, choices)
    assert claim.verified and claim.kind == "plan" and claim.chosen_option_id == "O-11111111"
    assert claim.origin == "recorded_test" and claim.needs_human_review
    assert planner.trace[0].usage.calls == 1
    repeat = planner.plan(pf, choices)
    assert len(calls) == 1 and planner.trace[-1].cached and planner.trace[-1].usage.calls == 0
    assert repeat.model_dump() == claim.model_dump()
    assert (pf, [o.model_dump() for o in choices]) == before
    packet = json.loads(next(m["content"] for m in calls[0]["messages"] if m["role"] == "user"))
    assert packet["finding"]["priority"] == "P1" and packet["finding"]["decision"] == "needs_human"
    assert {o["vetting"] for o in packet["options"]} == {"passed", "rejected", "pending"}
    assert calls[0]["temperature"] == 0 and calls[0]["reasoning_effort"] == "medium"


def test_no_passed_fix_escalates_without_llm_and_is_labelled_deterministic(tmp_path):
    choices = options()
    choices[0].vetting = "rejected"
    choices[2].vetting = "passed"  # escalation is not a passed fix
    planner, calls, choices = service(tmp_path, supplied=choices)
    claim = planner.plan(finding(), choices)
    assert claim.chosen_option_id == "O-33333333" and claim.verified
    assert claim.origin == "deterministic" and calls == [] and planner.trace == []
    assert check(claim, index=planner.index).verified


@pytest.mark.parametrize("status", ["rejected", "pending"])
def test_model_choosing_unvetted_option_is_rejected(tmp_path, status):
    choices = options()
    choices[1].vetting = status
    answer = {
        **deepcopy(RECORDED),
        "chosen_option_id": "O-22222222",
        "rationale": "Choose O-22222222.",
        "facts_used": [{"type": "option_id", "value": "O-22222222", "evidence_id": "EV-REJECT"}],
        "cited_evidence_ids": ["EV-REJECT"],
    }
    planner, calls, choices = service(tmp_path, supplied=choices, respond=lambda: answer)
    claim = planner.plan(finding(), choices)
    assert not claim.verified and len(calls) == 1
    assert f"Option O-22222222 is not vetted: {status}" in claim.errors
    assert not check(claim, index=planner.index).verified


def test_unseen_version_and_package_rejected(tmp_path):
    answer = deepcopy(RECORDED)
    answer["rationale"] = "Use `imaginary-crate` at `7.7.7`."
    answer["facts_used"] += [
        {"type": "package", "value": "imaginary-crate", "evidence_id": "EV-FIX"},
        {"type": "fixed_version", "value": "7.7.7", "evidence_id": "EV-FIX"},
    ]
    planner, _, choices = service(tmp_path, respond=lambda: answer)
    claim = planner.plan(finding(), choices)
    assert not claim.verified and "Unknown package imaginary-crate" in claim.errors
    assert "EV-FIX does not support fixed_version 7.7.7" in claim.errors


def test_known_version_with_supported_evidence_passes(tmp_path):
    answer = deepcopy(RECORDED)
    answer["rationale"] = "Choose O-11111111 with fixed version `1.2.4`."
    answer["facts_used"].append(
        {"type": "fixed_version", "value": "1.2.4", "evidence_id": "EV-FIX"}
    )
    planner, _, choices = service(tmp_path, respond=lambda: answer)
    assert planner.plan(finding(), choices).verified


def test_unrelated_global_option_and_evidence_cannot_be_used(tmp_path):
    choices = options()
    outside = choices[0].model_copy(
        update={"option_id": "O-44444444", "finding_id": "F-OTHER", "evidence_ids": ["EV-OUTSIDE"]},
        deep=True,
    )
    answer = {
        **deepcopy(RECORDED),
        "chosen_option_id": "O-44444444",
        "rationale": "Choose O-44444444.",
        "facts_used": [{"type": "option_id", "value": "O-44444444", "evidence_id": "EV-OUTSIDE"}],
        "cited_evidence_ids": ["EV-OUTSIDE"],
    }
    planner, _, choices = service(
        tmp_path, supplied=choices, indexed=[*choices, outside], respond=lambda: answer
    )
    claim = planner.plan(finding(), choices)
    assert not claim.verified
    assert "Plan chose an option outside its supplied options" in claim.errors
    assert "Plan cited evidence outside its supplied context" in claim.errors
    restored = AIClaim.model_validate_json(claim.model_dump_json())
    assert not check(restored, index=planner.index).verified


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", "low"),
        ("priority", "P3"),
        ("decision", "auto_ok"),
        ("confidence", 1.0),
        ("origin", "deterministic"),
        ("plan_source", {}),
        ("rationale", "word " * 81),
    ],
)
def test_invalid_schema_never_becomes_an_allowed_plan(tmp_path, field, value):
    answer = {**deepcopy(RECORDED), field: value}
    planner, calls, choices = service(tmp_path, respond=lambda: answer)
    claim = planner.plan(finding(), choices)
    assert len(calls) == 2
    assert (
        claim.verified
        and claim.origin == "deterministic"
        and claim.chosen_option_id == "O-33333333"
    )
    assert planner.events == ["Plan facts-only fallback: LLMOutputError"]


def test_budget_or_provider_failure_escalates_without_guessed_fix(tmp_path):
    planner, calls, choices = service(tmp_path, config=ClientConfig(run_budget=Budget(max_calls=0)))
    claim = planner.plan(finding(), choices)
    assert claim.verified and claim.chosen_option_id == "O-33333333" and calls == []
    assert "BudgetExceeded" in planner.events[0]
    planner.client.config.run_budget = Budget()
    planner.client.providers = []
    assert planner.plan(finding(), choices).origin == "deterministic" and calls == []


def test_disabled_and_unconfigured_api_and_explicit_services(tmp_path, monkeypatch):
    planner, calls, choices = service(tmp_path)
    planner.enabled = False
    assert planner.plan(finding(), choices).chosen_option_id == "O-33333333" and calls == []
    monkeypatch.setattr(api, "_planner", None)
    assert api.plan(finding(), choices) is None
    api.configure_plan(planner)
    assert api.plan(finding(), choices).origin == "deterministic"
    assert api.plan(finding(), choices, service=planner).verified


def test_previous_errors_are_redacted_and_semantic_repairs_are_external(tmp_path):
    answer = deepcopy(RECORDED)
    answer["rationale"] = "Use `7.7.7`."
    planner, calls, choices = service(tmp_path, respond=lambda: answer)
    failed = planner.plan(finding(), choices)
    assert not failed.verified and len(calls) == 1
    secret = "gsk_" + "A1b2C3d4" * 4
    repaired = planner.plan(finding(), choices, previous_errors=[*failed.errors, "token=" + secret])
    assert not repaired.verified and len(calls) == 2
    assert secret not in json.dumps(calls)
    assert "<VERIFIER_ERRORS>" in json.dumps(calls[-1])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda pf: pf.update(snippet="raw target code"),
        lambda pf: pf.update(ai_assessment={"rationale": "prior Judge text"}),
        lambda pf: pf["score_breakdown"][0].update(code="raw target code"),
    ],
)
def test_raw_code_and_arbitrary_ai_payloads_are_not_accepted(tmp_path, mutate):
    planner, calls, choices = service(tmp_path)
    pf = finding()
    mutate(pf)
    with pytest.raises(ValidationError):
        planner.plan(pf, choices)
    assert calls == []


def test_scope_mismatch_missing_escalation_duplicate_and_stale_vetting_fail_before_export(tmp_path):
    planner, calls, choices = service(tmp_path)
    with pytest.raises(ValueError, match="exactly one escalation"):
        planner.plan(finding(), choices[:2])
    with pytest.raises(ValueError, match="unique option"):
        planner.plan(finding(), [*choices, choices[0]])
    changed = deepcopy(choices)
    changed[0].vetting = "rejected"
    with pytest.raises(ValueError, match="fact-index vetting"):
        planner.plan(finding(), changed)
    changed = deepcopy(choices)
    changed[0].finding_id = "F-OTHER"
    with pytest.raises(ValueError, match="another finding"):
        planner.plan(finding(), changed)
    assert calls == []


def test_option_action_and_evidence_cannot_change_under_old_passed_state(tmp_path):
    planner, calls, choices = service(tmp_path)
    changed = deepcopy(choices)
    changed[0].target_version = "8.8.8"
    with pytest.raises(ValueError, match="snapshot does not match"):
        planner.plan(finding(), changed)
    changed = deepcopy(choices)
    changed[0].vetting_reasons = ["different proof"]
    with pytest.raises(ValueError, match="snapshot does not match"):
        planner.plan(finding(), changed)
    assert calls == []


def test_old_plan_invalidated_after_indexed_option_snapshot_changes(tmp_path):
    planner, _, choices = service(tmp_path)
    claim = planner.plan(finding(), choices)
    assert claim.verified
    from dataclasses import replace

    planner.index.options["O-11111111"] = replace(
        planner.index.options["O-11111111"], fingerprint="changed"
    )
    assert (
        "Plan option snapshot no longer matches the fact index"
        in check(claim, index=planner.index).errors
    )
