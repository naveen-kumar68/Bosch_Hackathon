"""Static workflow checks; never invokes workflow commands."""

import re
from pathlib import Path


def inspect_workflow(text: str, filename: str) -> list[dict]:
    hits = []

    def add(kind, line, message):
        hits.append({"type": kind, "file": filename, "line": line, "message": message})

    if not re.search(r"(?m)^\s*permissions\s*:", text):
        add("workflow_permissions", 1, "No explicit workflow or job permissions block")
    for line, content in enumerate(text.splitlines(), 1):
        code = content.split("#", 1)[0]
        action = re.search(r"\buses\s*:\s*['\"]?([^\s'\"]+)", code)
        if action:
            reference = action[1]
            if not reference.startswith("./"):
                pinned = (
                    "@sha256:" in reference
                    if reference.startswith("docker://")
                    else bool(re.search(r"@[a-fA-F0-9]{40}$", reference))
                )
                if not pinned:
                    add("action_unpinned", line, reference)
        if re.search(r"\bcargo\s+install\b", code) and (
            "--locked" not in code or not re.search(r"--version(?:=|\s+)\d", code)
        ):
            add("cargo_install_unlocked", line, "cargo install lacks --locked or a version")
        if re.search(r"\bpip(?:3)?\s+install\b", code) and "git+" in code:
            refs = re.findall(r"git\+[^\s'\"]+", code)
            if any(not re.search(r"@[0-9a-fA-F]{40}(?:#.*)?$", ref) for ref in refs):
                add("pip_git_mutable", line, "Git installation is not pinned to a full commit")
        if re.search(r"\bcurl\b.*\|\s*(?:ba)?sh\b", code):
            add("curl_pipe_shell", line, "Network response is piped to a shell")
        if re.search(r"permissions\s*:\s*write-all", code):
            add("workflow_permissions", line, "Workflow requests write-all")
    if (
        "pull_request_target" in text
        and "actions/checkout" in text
        and re.search(r"github\.event\.pull_request\.(?:head|merge_commit_sha)", text)
    ):
        add("untrusted_checkout", 1, "pull_request_target checks out pull request-controlled code")
    return hits


def inspect_directory(path: Path) -> list[dict]:
    hits = []
    for file in sorted((path / ".github/workflows").glob("*")):
        if file.suffix in {".yml", ".yaml"}:
            hits.extend(
                inspect_workflow(
                    file.read_text(encoding="utf-8"), file.relative_to(path).as_posix()
                )
            )
    return hits
