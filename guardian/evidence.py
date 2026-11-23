"""Capture exact commands and immutable raw bytes for every observed fact."""

import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
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
        "cargo-audit": local / "cargo-audit" / "bin" / "cargo-audit.exe",
        "osv-scanner": local / "osv-scanner_windows_amd64.exe",
        "grype": local / "grype" / "grype.exe",
        "zizmor": local / "zizmor" / "zizmor.exe",
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
        self.root = Path(__file__).resolve().parents[1]
        self.raw = self.output / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.records: list[Evidence] = []
        self.versions: dict[str, str] = {}

    def import_records(self, records: list[Evidence], source_output: Path) -> None:
        for record in records:
            if any(existing.id == record.id for existing in self.records):
                continue
            base = self.root if record.path_base == "repository" else source_output
            raw = (base / record.raw_path).resolve()
            cwd = Path(record.cwd)
            if not cwd.is_absolute():
                cwd = self.root / cwd
            self.records.append(
                record.model_copy(
                    update={
                        "raw_path": Path(os.path.relpath(raw, self.root)).as_posix(),
                        "path_base": "repository",
                        "cwd": Path(os.path.relpath(cwd, self.root)).as_posix(),
                        "command": [self.display_argument(arg) for arg in record.command],
                    }
                )
            )

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
        digest = hashlib.sha256(data).hexdigest()
        identity = [
            tool,
            version,
            [self.display_argument(arg) for arg in command],
            Path(os.path.relpath(cwd.resolve(), self.root)).as_posix(),
            description,
            returncode,
            digest,
        ]
        identifier = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:32]
        if any(record.id == identifier for record in self.records):
            return identifier
        path = self.raw / f"{identifier}.raw"
        path.write_bytes(data)
        self.records.append(
            Evidence(
                id=identifier,
                tool=tool,
                version=version,
                command=[self.display_argument(arg) for arg in command],
                timestamp=datetime.now(UTC),
                sha256=digest,
                raw_path=Path(os.path.relpath(path, self.root)).as_posix(),
                path_base="repository",
                cwd=Path(os.path.relpath(cwd.resolve(), self.root)).as_posix(),
                returncode=returncode,
                description=description,
            )
        )
        self.save()
        return identifier

    def display_argument(self, value: str) -> str:
        value = str(value)
        for prefix in (str(self.root) + "\\", self.root.as_posix() + "/"):
            value = value.replace(prefix, "")
        if ":\\" in value and "=" not in value:
            path = Path(value)
            if path.is_absolute():
                return Path(os.path.relpath(path, self.root)).as_posix()
        return value.replace("\\", "/")

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
                args = (
                    [executable, "version"]
                    if name in {"syft", "grype"}
                    else [executable, "--version"]
                )
                if name == "cargo-cyclonedx":
                    args = [executable, "cyclonedx", "--version"]
                if name == "cargo-audit":
                    args = [executable, "audit", "--version"]
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
        try:
            completed = subprocess.run(
                actual,
                check=False,
                cwd=location,
                capture_output=True,
                env=process_env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            identifier = self.capture(
                error.stdout or b"",
                tool=name,
                version=self.versions[name],
                command=actual,
                cwd=location,
                returncode=124,
                description="Timed out; partial stdout",
            )
            if error.stderr:
                self.capture(
                    error.stderr,
                    tool=name,
                    version=self.versions[name],
                    command=actual,
                    cwd=location,
                    returncode=124,
                    description="Timed out; partial stderr",
                )
            raise RuntimeError(
                f"{name} timed out after {timeout}s; evidence {identifier}"
            ) from None
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
            newline="\n",
        )
