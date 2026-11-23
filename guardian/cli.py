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
        json.dumps(ScanResult.model_json_schema(), indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    app()
