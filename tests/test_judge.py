import json

from guardian.detect.models import Finding
from guardian.evidence import Recorder
from guardian.llm.judge import Judge, redact


def finding():
    return Finding(
        finding_id="F-001",
        type="capability_added",
        component="pkg:cargo/test@1",
        description="test",
        evidence_ids=["valid"],
        severity="high",
        severity_rule="capability_added",
        confidence="low",
        needs_judgement=True,
    )


def response(ids=None, **extra):
    return json.dumps(
        dict(
            finding_id="F-001",
            verdict="suspicious",
            confidence=0.9,
            rationale="New network capability needs review.",
            cited_evidence_ids=ids or ["valid"],
            needs_human_review=True,
            **extra,
        )
    )


def test_cache_zero_calls_and_immutable_severity(tmp_path):
    calls = []

    def complete(payload):
        calls.append(payload)
        return response()

    judge = Judge(tmp_path / "cache.sqlite", Recorder(tmp_path / "out"), complete=complete)
    item = finding()
    before = item.model_dump()
    assert judge.assess(item, {"valid"}).verdict == "suspicious"
    assert item.model_dump() == before
    assert judge.assess(item, {"valid"}).verdict == "suspicious"
    assert len(calls) == judge.calls == 1


def test_invalid_ids_and_severity_override_retried_once(tmp_path):
    replies = iter([response(["invented"]), response(severity="low")])
    judge = Judge(
        tmp_path / "cache.sqlite", Recorder(tmp_path / "out"), complete=lambda _: next(replies)
    )
    item = finding()
    assert judge.assess(item, {"valid"}) is None
    assert judge.calls == 2 and item.severity == "high"


def test_global_budget_and_no_cve_calls(tmp_path):
    judge = Judge(
        tmp_path / "cache.sqlite",
        Recorder(tmp_path / "out"),
        max_calls=1,
        complete=lambda _: "invalid",
    )
    assert judge.assess(finding(), {"valid"}) is None
    assert judge.calls == 1
    item = finding()
    item.type = "vulnerability"
    assert judge.assess(item, {"valid"}) is None
    assert judge.calls == 1


def test_redaction_and_sixty_line_limit():
    secret = "gsk_" + "A1b2C3d4" * 4
    redacted = redact("token=" + secret + "\n" + "line\n" * 90)
    assert secret not in redacted
    assert len(redacted.splitlines()) == 60


def test_recorded_cache_cannot_masquerade_as_live(tmp_path):
    configuration = tmp_path / "test.env"
    configuration.write_text(
        "LLM_API_KEY=fixture-only\nLLM_BASE_URL=https://example.test/v1\nLLM_MODEL=fixture-model\n"
    )
    database = tmp_path / "cache.sqlite"
    simulated = Judge(
        database,
        Recorder(tmp_path / "recorded"),
        env_file=configuration,
        complete=lambda _: response(),
    )
    assert simulated.assess(finding(), {"valid"}).origin == "recorded_test"
    live = Judge(database, Recorder(tmp_path / "live"), env_file=configuration)
    live.request = lambda _: response()
    assert live.assess(finding(), {"valid"}).origin == "live"
    assert live.calls == 1
    live.assess(finding(), {"valid"})
    assert live.calls == 1
