"""Capture exact commands and immutable raw bytes for every observed fact."""

import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from guardian import __version__
from guardian.models import Evidence


def tool_path(name: str) -> str:
    local = Path(__file__).resolve().parents[1] / ".tools"
    candidates = {
        "syft": local / "syft" / "syft.exe",
        "cyclonedx": local / "cyclonedx-win-x64.exe",
        "cargo-cyclonedx": local / "cargo-cyclonedx" / "cargo-cyclonedx.exe",
    }
    if name in candidates and candidates[name].is_file():
        return str(candidates[name])
    sibling = Path(sys.executable).parent / (name + (".exe" if os.name == "nt" else ""))
    if sibling.is_file():
        return str(sibling)
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt" and name in {"cargo", "rustc"}:
        rust = Path.home() / ".rustup/toolchains/stable-x86_64-pc-windows-msvc/bin"
        if (rust / f"{name}.exe").is_file():
            return str(rust / f"{name}.exe")
    if os.name == "nt" and name == "uv":
        uv = Path.home() / "anaconda3/Scripts/uv.exe"
        if uv.is_file():
            return str(uv)
    raise FileNotFoundError(f"Required tool is not installed or on PATH: {name}")


class Recorder:
    def __init__(self, output: Path):
        self.output = output.resolve()
        self.raw = self.output / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.records: list[Evidence] = []
        self.versions: dict[str, str] = {}

    def capture(
        self,
        data: bytes,
        *,
        tool: str,
        version: str,
        command: list[str],
        cwd: Path,
        description: str = "",
        returncode: int = 0,
    ) -> str:
        identifier = uuid.uuid4().hex
        path = self.raw / f"{identifier}.raw"
        path.write_bytes(data)
        self.records.append(
            Evidence(
                id=identifier,
                tool=tool,
                version=version,
                command=command,
                timestamp=datetime.now(UTC),
                sha256=hashlib.sha256(data).hexdigest(),
                raw_path=path.relative_to(self.output).as_posix(),
                cwd=str(cwd.resolve()),
                returncode=returncode,
                description=description,
            )
        )
        self.save()
        return identifier

    def file(self, path: Path, description: str = "") -> str:
        return self.capture(
            path.read_bytes(),
            tool="guardian.read",
            version=__version__,
            command=["guardian.read", str(path.resolve())],
            cwd=path.parent,
            description=description,
        )

    def note(self, message: str, inputs: list[str] | None = None) -> str:
        return self.capture(
            json.dumps({"message": message, "input_evidence_ids": inputs or []}).encode(),
            tool="guardian",
            version=__version__,
            command=["guardian", "derive"],
            cwd=self.output,
            description=message,
        )

    def run(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        timeout: int = 900,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int]:
        name = command[0]
        executable = tool_path(name)
        actual = [executable, *map(str, command[1:])]
        process_env = os.environ.copy()
        process_env.update({"GIT_TERMINAL_PROMPT": "0", "PYTHONUTF8": "1"})
        process_env["PATH"] = str(Path(executable).parent) + os.pathsep + process_env["PATH"]
        if env:
            process_env.update(env)
        location = (cwd or self.output).resolve()
        if name not in self.versions:
            if name == "pyspdxtools":
                self.versions[name] = importlib.metadata.version("spdx-tools")
            else:
                args = [executable, "version"] if name == "syft" else [executable, "--version"]
                if name == "cargo-cyclonedx":
                    args = [executable, "cyclonedx", "--version"]
                version = (
                    subprocess.run(
                        args,
                        capture_output=True,
                        cwd=self.output,
                        env=process_env,
                        timeout=30,
                        check=True,
                    )
                    .stdout.decode("utf-8", errors="replace")
                    .strip()
                )
                self.versions[name] = version
        completed = subprocess.run(
            actual,
            check=False,
            cwd=location,
            capture_output=True,
            env=process_env,
            timeout=timeout,
        )
        identifier = self.capture(
            completed.stdout,
            tool=name,
            version=self.versions[name],
            command=actual,
            cwd=location,
            returncode=completed.returncode,
        )
        if completed.stderr:
            self.capture(
                completed.stderr,
                tool=name,
                version=self.versions[name],
                command=actual,
                cwd=location,
                returncode=completed.returncode,
                description="stderr",
            )
        stdout = completed.stdout.decode("utf-8", errors="replace")
        if check and completed.returncode:
            raise RuntimeError(
                f"{name} failed ({completed.returncode}); evidence {identifier}: "
                + completed.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        return stdout, identifier, completed.returncode

    def save(self) -> None:
        (self.output / "evidence.json").write_text(
            json.dumps([r.model_dump(mode="json") for r in self.records], indent=2),
            encoding="utf-8",
        )
