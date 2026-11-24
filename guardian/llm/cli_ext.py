"""Manual local-only recording hook; never modifies the shared guardian CLI."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated

import typer

from guardian.llm.client import create_completion_client
from guardian.llm.explain import Narrator
from guardian.llm.judge_schema import JudgeBatch, JudgeItem
from guardian.llm.judge_verified import VerifiedJudge
from guardian.llm.plan import Planner
from guardian.llm.plan_schema import PlanResponse
from guardian.llm.sanitise import sanitise
from guardian.llm.second_opinion import OpinionResponse, SecondOpinion
from guardian.llm.structured_schema import BriefResponse, ExplainResponse
from guardian.remediate.models import FixOption
from guardian.verify.facts import build

app = typer.Typer(help="Manual, local-only LLM fixture recording.")
SCHEMAS = {
    "plan": PlanResponse,
    "explain": ExplainResponse,
    "brief": BriefResponse,
    "second_opinion": OpinionResponse,
}


def record_fixture(payload_file, output, role, *, record=False, root=None, client_factory=None):
    if not record:
        raise ValueError("Manual recording requires --record")
    if any(
        os.environ.get(key, "").lower() not in {"", "0", "false", "no"}
        for key in ("CI", "GITHUB_ACTIONS")
    ):
        raise ValueError("Live recording is prohibited in CI")
    root = (root or Path(__file__).resolve().parents[2]).resolve()
    output = Path(output).resolve()
    if output.suffix != ".json" or not output.is_relative_to(root / "tests/llm_recordings"):
        raise ValueError("Recording output must be under tests/llm_recordings")
    if role not in {*SCHEMAS, "judge"}:
        raise ValueError("Unknown recording role")
    payload = json.loads(Path(payload_file).read_text("utf-8"))
    data = payload["input"]
    options = [FixOption.model_validate(option) for option in payload.get("options", [])]
    findings = (
        data
        if role == "judge"
        else (
            data.get("top_findings", [])
            if role == "explain"
            else [data["finding"] if role == "brief" else data]
        )
    )
    index = build(payload["ledger"], findings, options)
    cache_root = root / "workspace/cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="manual-record-", dir=cache_root) as directory:
        database = Path(directory) / "record.sqlite"
        client = (
            client_factory(database)
            if client_factory
            else create_completion_client(database, env_file=root / ".env")
        )
        if role == "judge":
            claims = VerifiedJudge(client, index, budget_key="manual").judge(
                data, snippets=payload.get("snippets", {})
            )
            response = JudgeBatch(
                items=[
                    JudgeItem.model_validate(c.model_dump(include=set(JudgeItem.model_fields)))
                    for c in claims
                ]
            ).model_dump()
        else:
            if role == "plan":
                claim = Planner(client, index, budget_key="manual").plan(data, options)
            elif role == "second_opinion":
                claim = SecondOpinion(client, index, budget_key="manual").second_opinion(data)
            else:
                service = Narrator(client, index, budget_key="manual")
                claim = service.explain(data) if role == "explain" else service.explain_brief(data)
            if claim is None or claim.origin == "deterministic":
                raise ValueError("Recording produced no provider response")
            claims = [claim]
            response = (
                SCHEMAS[role]
                .model_validate(claim.model_dump(include=set(SCHEMAS[role].model_fields)))
                .model_dump()
            )
        if not claims:
            raise ValueError("Recording produced no claims")
        saved = sanitise(
            {
                "_note": "Manual provider recording; verification is recorded, not assumed.",
                "role": role,
                "origin": claims[0].origin,
                "response": response,
                "verified": all(c.verified for c in claims),
                "usage": asdict(client.runs["manual"]),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(saved, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    return saved


@app.command("record")
def record_command(
    payload: Annotated[Path, typer.Option("--payload")],
    output: Annotated[Path, typer.Option("--output")],
    role: Annotated[str, typer.Option("--role")],
    record: Annotated[bool, typer.Option("--record")] = False,
):
    """Explicit --record only. Keep keys in ignored .env; inspect the payload locally."""
    try:
        result = record_fixture(payload, output, role, record=record)
    except Exception as exc:  # noqa: BLE001 -- never expose SDK error metadata/credentials
        raise typer.BadParameter(f"Recording failed: {type(exc).__name__}") from None
    typer.echo(f"Recorded {role}; verified={result['verified']}")


def register(root_app):
    root_app.add_typer(app, name="llm")


if __name__ == "__main__":
    app()
