"""Only trusted scanner containers execute; target mounts are read-only."""

import hashlib
import json
from pathlib import Path

from guardian.detect.scanners import run_json
from guardian.models import Evidence

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
    selected = set(directory.rglob("build.rs")) | set(directory.rglob("setup.py"))
    if proc_macro:
        selected.update(directory.rglob("*.rs"))
    inputs = [
        (path.relative_to(directory).as_posix(), path.read_bytes())
        for path in sorted(selected)
        if path.is_file()
    ]
    if not inputs:
        return {"results": [], "errors": []}, recorder.note(
            "No selected build-time source files in verified artifact"
        )
    digest = hashlib.sha256(SEMGREP.encode())
    for name, data in inputs:
        digest.update(name.encode())
        digest.update(hashlib.sha256(data).digest())
    for path in sorted(rules.glob("*.yaml")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    key = digest.hexdigest()
    cache = recorder.root / "workspace/cache/semgrep" / (key + ".json")
    if cache.exists():
        saved = json.loads(cache.read_text(encoding="utf-8"))
        original = Evidence.model_validate(saved["evidence"])
        raw = recorder.root / original.raw_path
        if (
            saved["input_key"] != key
            or hashlib.sha256(raw.read_bytes()).hexdigest() != original.sha256
        ):
            raise ValueError("Semgrep cache evidence integrity mismatch")
        recorder.import_records([original], recorder.root)
        recorder.file(cache, "Cached Semgrep result for identical source, rules and scanner image")
        return json.loads(raw.read_bytes()), original.id
    staging = recorder.root / "workspace/static-inputs" / key
    for name, data in inputs:
        destination = staging / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    command = container_command(SEMGREP, [(staging, "/src"), (rules, "/rules")])
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
        result, evidence_id = run_json(recorder, command, accepted=(0,), timeout=180)
        original = next(record for record in recorder.records if record.id == evidence_id)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(
            json.dumps({"input_key": key, "evidence": original.model_dump(mode="json")}),
            encoding="utf-8",
            newline="\n",
        )
        return result, evidence_id
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
