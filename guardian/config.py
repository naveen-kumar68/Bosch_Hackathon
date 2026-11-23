"""Target configuration and paths; no ecosystem-specific policy."""

from pathlib import Path

import yaml

from guardian.models import Target


def load_targets(path: Path) -> dict[str, Target]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    targets = [Target.model_validate(item) for item in data["targets"]]
    if len({t.name for t in targets}) != len(targets):
        raise ValueError("Duplicate target names")
    return {target.name: target for target in targets}


def contained_path(parent: Path, relative: str) -> Path:
    path = (parent / relative).resolve()
    if not path.is_relative_to(parent.resolve()):
        raise ValueError(f"Path escapes its workspace: {relative}")
    return path
