"""Only trusted scanner containers execute; target mounts are read-only."""

import hashlib
import json
from pathlib import Path

from guardian.detect.scanners import run_json

SEMGREP = "semgrep/semgrep@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1"
GUARDDOG = "ghcr.io/datadog/guarddog@sha256:3dbc783f65f508b95222101cb2cd84d1d5f3e3675e42d6f1329bb9b8a99c8998"


def container_command(image, mounts):
    name = "guardian-scanner-" + hashlib.sha256((image + str(mounts)).encode()).hexdigest()[:16]
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--cpus",
        "2",
        "--user",
        "1000:1000",
        "--env",
        "HOME=/tmp",
        "--tmpfs",
        "/tmp:rw,nosuid,size=256m",
    ]
    for source, destination in mounts:
        command += ["--mount", f"type=bind,source={source.resolve()},target={destination},readonly"]
    return [*command, image]


def semgrep(directory: Path, rules: Path, recorder, *, proc_macro=False):
    command = container_command(SEMGREP, [(directory, "/src"), (rules, "/rules")])
    command += [
        "semgrep",
        "scan",
        "--config",
        "/rules",
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        "--no-git-ignore",
        "--include",
        "build.rs",
        "--include",
        "setup.py",
        *(["--include", "*.rs"] if proc_macro else []),
        "/src",
    ]
    try:
        return run_json(recorder, command, accepted=(0,), timeout=180)
    except RuntimeError:
        name = command[command.index("--name") + 1]
        recorder.run(["docker", "rm", "--force", name], check=False)
        raise


def guarddog(archive: Path, recorder):
    command = container_command(GUARDDOG, [(archive.parent, "/artifacts")])
    command += ["pypi", "scan", "/artifacts/" + archive.name, "--output-format", "json"]
    try:
        raw, evidence, status = recorder.run(command, check=False, timeout=180)
    except RuntimeError:
        name = command[command.index("--name") + 1]
        recorder.run(["docker", "rm", "--force", name], check=False)
        raise
    # No --exit-non-zero-on-finding is supplied, so a nonzero status is a tool failure.
    if status != 0:
        raise RuntimeError(f"GuardDog failed; evidence {evidence}")
    return json.loads(raw), evidence
