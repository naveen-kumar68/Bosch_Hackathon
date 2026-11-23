from pathlib import Path
from typing import Annotated

import typer

from guardian.acquire import acquire
from guardian.config import load_targets
from guardian.evidence import Recorder
from guardian.graph.query import paths, reverse_dependencies
from guardian.graph.store import load
from guardian.models import ScanResult
from guardian.pipeline import scan as run_scan

app = typer.Typer(no_args_is_help=True, help="Evidence-backed supply chain inventory.")


@app.command("judge-ping")
def judge_ping(config: Path = Path("targets.yaml")):
    """Make one minimal provider/model verification call; never prints credentials."""
    import importlib.metadata

    from dotenv import dotenv_values
    from openai import APIError

    from guardian.llm.client import create_client

    root = config.resolve().parent
    client = create_client(root / ".env")
    model = dotenv_values(root / ".env")["LLM_MODEL"]
    recorder = Recorder(root / "out/provider-check")
    try:
        response = client.chat.completions.create(
            model=model,
            max_completion_tokens=128,
            reasoning_effort="medium",
            messages=[{"role": "user", "content": "Reply with OK."}],
        )
    except APIError:
        recorder.note("Provider/model ping failed; credential data intentionally omitted")
        typer.echo("Provider/model ping failed. See out/provider-check/evidence.json.", err=True)
        raise typer.Exit(1) from None
    recorder.capture(
        response.model_dump_json().encode(),
        tool="openai",
        version=importlib.metadata.version("openai"),
        command=["judge-ping", model],
        cwd=root,
        description="Single provider/model verification call",
    )
    typer.echo("Provider/model ping succeeded.")


@app.command()
def detect(
    target: Annotated[str, typer.Option()],
    baseline: str | None = None,
    config: Path = Path("targets.yaml"),
    offline: bool = False,
    judge: bool = False,
):
    """Run deterministic risk checks and optional bounded AI assessments."""
    from guardian.detect.pipeline import detect as run_detect

    findings = run_detect(
        target_config(target, config),
        baseline,
        config.resolve().parent,
        offline=offline,
        judge_enabled=judge,
    )
    typer.echo(f"{target}: {len(findings)} findings")


@app.command()
def finding(identifier: str, target: str = "kuksa-databroker", config: Path = Path("targets.yaml")):
    """Show a finding with its evidence records and dependency paths."""
    import json
    import sqlite3

    target_config(target, config)
    database = config.resolve().parent / "out" / target / "graph.sqlite"
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        row = connection.execute("SELECT data FROM findings WHERE id=?", (identifier,)).fetchone()
        if not row:
            raise typer.BadParameter("Finding ID not found")
        item = json.loads(row[0])
        item["evidence_chain"] = [
            json.loads(
                connection.execute("SELECT data FROM risk_evidence WHERE id=?", (eid,)).fetchone()[
                    0
                ]
            )
            for eid in item["evidence_ids"]
        ]
    typer.echo(json.dumps(item, indent=2))


def target_config(name: str, config: Path):
    targets = load_targets(config)
    if name not in targets:
        raise typer.BadParameter(f"Unknown target {name!r}; choose {', '.join(targets)}")
    return targets[name]


@app.command()
def fetch(target: Annotated[str, typer.Option()], config: Path = Path("targets.yaml")):
    """Acquire a pinned repository or image without executing its code."""
    specification = target_config(target, config)
    root = config.resolve().parent
    _, revision, _ = acquire(
        specification, root / "workspace/targets", Recorder(root / "out" / target)
    )
    typer.echo(f"{target}: {revision}")


@app.command()
def scan(target: Annotated[str, typer.Option()], config: Path = Path("targets.yaml")):
    """Resolve, generate and validate SBOMs, then persist/export the evidence graph."""
    try:
        result = run_scan(target_config(target, config), config.resolve().parent)
    except (ValueError, RuntimeError, FileNotFoundError) as error:
        typer.echo(f"Scan failed: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(f"{target}: {len(result.components)} components, {len(result.edges)} relationships")
    typer.echo(str(config.resolve().parent / "out" / target / "summary.md"))


@app.command()
def path(
    query: str,
    target: str = "kuksa-databroker",
    reverse: bool = False,
    config: Path = Path("targets.yaml"),
):
    """Print every simple root-to-package path, or all reverse dependencies."""
    target_config(target, config)
    graph = load(config.resolve().parent / "out" / target / "graph.sqlite")
    if reverse:
        for destination, ancestors in reverse_dependencies(graph, query).items():
            typer.echo(destination)
            for ancestor in ancestors:
                typer.echo(f"  <- {ancestor}")
    else:
        for dependency_path in paths(graph, query):
            typer.echo(" -> ".join(dependency_path))


@app.command()
def summary(target: Annotated[str, typer.Option()], config: Path = Path("targets.yaml")):
    """Print the summary from a completed scan."""
    target_config(target, config)
    typer.echo(
        (config.resolve().parent / "out" / target / "summary.md").read_text(encoding="utf-8")
    )


@app.command()
def schemas(output: Path = Path("out/schemas")):
    """Export the evidence contract for future integrations."""
    import json

    output.mkdir(parents=True, exist_ok=True)
    (output / "scan-result.schema.json").write_text(
        json.dumps(ScanResult.model_json_schema(), indent=2), encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    app()
