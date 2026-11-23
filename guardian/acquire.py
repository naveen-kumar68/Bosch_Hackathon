"""Acquire immutable targets without running their code."""

import json
import re
from pathlib import Path

from guardian.config import contained_path
from guardian.evidence import Recorder
from guardian.models import Target


def acquire(target: Target, workspace: Path, recorder: Recorder) -> tuple[Path, str, str]:
    workspace.mkdir(parents=True, exist_ok=True)
    if target.kind == "image":
        reference = (
            f"{target.source}@{target.revision}"
            if target.revision
            else (f"{target.source}:{target.ref}")
        )
        recorder.run(["docker", "pull", reference])
        raw, evidence, _ = recorder.run(["docker", "image", "inspect", reference])
        digests = json.loads(raw)[0]["RepoDigests"]
        matching = [item for item in digests if item.startswith(target.source + "@sha256:")]
        if not matching:
            raise ValueError("Image inspection did not return the requested repository digest")
        digest = matching[0].split("@", 1)[1]
        if target.revision and digest != target.revision:
            raise ValueError("Image digest differs from the pinned target revision")
        return workspace, digest, evidence
    if not target.revision or not re.fullmatch(r"[0-9a-f]{40}", target.revision):
        raise ValueError("Repository target requires a full immutable commit SHA")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", target.ref):
        raise ValueError("Unsafe target ref")
    path = contained_path(workspace, f"{target.name}@{target.ref}")
    if not path.exists():
        recorder.run(
            [
                "git",
                "-c",
                "core.hooksPath=",
                "clone",
                "--config",
                "core.autocrlf=false",
                "--config",
                "core.longpaths=true",
                "--depth",
                "1",
                "--branch",
                target.ref,
                "--",
                target.source,
                str(path),
            ]
        )
    recorder.run(["git", "config", "core.autocrlf", "false"], cwd=path)
    recorder.run(["git", "config", "core.longpaths", "true"], cwd=path)
    remote, _, _ = recorder.run(["git", "remote", "get-url", "origin"], cwd=path)
    if remote.strip().removesuffix(".git") != target.source.removesuffix(".git"):
        raise ValueError("Existing target checkout has a different origin")
    revision, evidence, _ = recorder.run(["git", "rev-parse", "HEAD"], cwd=path)
    if revision.strip() != target.revision:
        raise ValueError("Target checkout does not match the pinned commit")
    dirty, _, _ = recorder.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=path)
    if dirty.strip():
        raise ValueError("Target checkout has modified tracked files")
    return contained_path(path, target.subdirectory), revision.strip(), evidence
