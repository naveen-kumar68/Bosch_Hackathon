import subprocess

from typer.testing import CliRunner

from guardian.llm import cli_ext
from guardian.llm.demo import run_demo


def test_demo_runs_offline_with_no_hallucinations(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no execution"))
    )
    result = run_demo()
    assert {c["kind"] for c in result["claims"]} == {
        "judge",
        "plan",
        "explain",
        "brief",
        "second_opinion",
    }
    assert all(c["verified"] for c in result["claims"])
    assert result["accepted_hallucinations"] == 0
    assert result["verifier"]["catch_rate"] == 1 and result["injection"]["passed"] == 3
    assert result["live_provider_tested"] is False and result["target_code_executed"] is False


def test_demo_command_prints_report():
    out = CliRunner().invoke(cli_ext.app, ["demo"])
    assert out.exit_code == 0
    assert "Accepted hallucinations: 0" in out.output and "VERIFIED" in out.output
