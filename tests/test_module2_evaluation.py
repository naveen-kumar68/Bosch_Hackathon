import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from guardian.llm import cli_ext
from guardian.llm.claims import AIClaim
from guardian.llm.evaluation import hallucination_count, injection_resistance, verify_catch_rate
from guardian.verify import api as verify_api
from guardian.verify.facts import build

ROOT = Path(__file__).parent


def test_offline_verifier_and_injection_metrics():
    verifier = verify_catch_rate(ROOT / "fixtures/verifier")
    assert (
        verifier["caught"],
        verifier["wrong"],
        verifier["accepted_correct"],
        verifier["correct"],
    ) == (10, 10, 3, 3)
    assert verifier["catch_rate"] == verifier["correct_accept_rate"] == 1
    assert all(case["expected_error_matched"] for case in verifier["cases"])
    injection = injection_resistance(ROOT / "fixtures/inject")
    assert (injection["passed"], injection["total"]) == (3, 3)
    assert injection["mode"] == "recorded_replay" and not injection["live_model_tested"]


def test_hallucinations_rechecked_not_trusting_verified_flag(monkeypatch):
    index = build([{"id": "EV-1"}])
    spoof = AIClaim(
        kind="explain",
        summary="CVE-2026-99999 is present.",
        facts_used=[],
        cited_evidence_ids=["EV-1"],
        verified=True,
    )
    assert hallucination_count([spoof], index=index) == 1
    spoof.verified = False
    assert hallucination_count([spoof], index=index) == 0
    spoof.verified = True
    monkeypatch.setattr(verify_api, "_index", None)
    with pytest.raises(RuntimeError, match="not configured"):
        hallucination_count([spoof])


def test_recording_requires_manual_opt_in_and_is_blocked_in_ci(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="--record"):
        cli_ext.record_fixture(tmp_path / "missing", tmp_path / "output.json", "explain")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(
        cli_ext,
        "create_completion_client",
        lambda *a, **k: pytest.fail("CI must never load provider configuration"),
    )
    with pytest.raises(ValueError, match="prohibited in CI"):
        cli_ext.record_fixture(
            tmp_path / "missing", tmp_path / "output.json", "explain", record=True
        )


def test_manual_recording_with_mocked_provider_only(tmp_path, monkeypatch):
    from guardian.llm.completion import CompletionClient, Provider

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    payload = {
        "ledger": [
            {
                "id": "EV-RUN",
                "facts": [{"type": "status", "value": "complete"}, {"type": "count", "value": 1}],
            }
        ],
        "input": {
            "run_id": "fixture",
            "status": "complete",
            "counts": [{"name": "findings", "value": 1, "evidence_ids": ["EV-RUN"]}],
            "top_findings": [],
            "plans": [],
            "validations": [],
            "evidence_ids": ["EV-RUN"],
        },
    }
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(payload), encoding="utf-8")
    response = {
        "summary": "Run is `complete` with 1 finding.",
        "key_points": [],
        "facts_used": [
            {"type": "status", "value": "complete", "evidence_id": "EV-RUN"},
            {"type": "count", "value": 1, "evidence_id": "EV-RUN"},
        ],
        "cited_evidence_ids": ["EV-RUN"],
    }

    def factory(database):
        return CompletionClient(
            database,
            [Provider("fixture", "https://example.invalid", "fixture", "fixture-only")],
            transport=lambda p, r: {
                "choices": [{"message": {"content": json.dumps(response)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    output = tmp_path / "tests/llm_recordings/manual.json"
    saved = cli_ext.record_fixture(
        input_file, output, "explain", record=True, root=tmp_path, client_factory=factory
    )
    assert saved["verified"] and saved["origin"] == "recorded_test"
    assert json.loads(output.read_text("utf-8"))["response"] == response
    assert b"\r\n" not in output.read_bytes()
    with pytest.raises(ValueError, match="tests/llm_recordings"):
        cli_ext.record_fixture(
            input_file,
            tmp_path / "outside.json",
            "explain",
            record=True,
            root=tmp_path,
            client_factory=factory,
        )


def test_cli_hook_and_help_do_not_request_a_provider():
    root = typer.Typer()
    cli_ext.register(root)
    result = CliRunner().invoke(root, ["llm", "record", "--help"])
    assert result.exit_code == 0 and "--record" in result.output and "--payload" in result.output
