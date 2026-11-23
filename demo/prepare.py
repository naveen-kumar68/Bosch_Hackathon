"""Prepare an inert local scenario; never builds, executes or publishes packages."""

import json
import shutil
import tomllib
from pathlib import Path

from guardian.detect.capability import verified_extract
from guardian.detect.http import CachedHTTP
from guardian.evidence import Recorder


def prepare(root: Path):
    source = root / "workspace/targets/kuksa-databroker@0.7.2"
    destination = root / "demo/planted"
    if destination.exists():
        raise ValueError("demo/planted already exists; preserving it for review")
    recorder = Recorder(root / "out/planted-preparation")
    lock = tomllib.loads((source / "Cargo.lock").read_text(encoding="utf-8"))
    package = next(p for p in lock["package"] if p["name"] == "arrayref")
    http = CachedHTTP(root / "workspace/cache/http", recorder)
    data, evidence = http.get("https://static.crates.io/crates/arrayref/arrayref-0.3.9.crate")
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(".git", "target", "guardian-sbom.json", "__pycache__"),
    )
    verified_extract(data, package["checksum"], destination / "vendor")
    recorder.note("Vendored original crate verified before modification", [evidence])
    vendor = destination / "vendor/arrayref-0.3.9"
    with (vendor / "Cargo.toml").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            '\n[build-dependencies.serde_derve]\nversion = "1.0.0"\npath = "../serde_derve"\n'
        )
    typo = destination / "vendor/serde_derve"
    (typo / "src").mkdir(parents=True)
    (typo / "Cargo.toml").write_text(
        '[package]\nname="serde_derve"\nversion="1.0.0"\nedition="2021"\n',
        encoding="utf-8",
        newline="\n",
    )
    (typo / "src/lib.rs").write_text(
        "// Hackathon test fixture; never build or run.\n", encoding="utf-8", newline="\n"
    )
    (typo / "build.rs").write_text(
        """// Hackathon test fixture. Inert main; never build or run.
#[allow(dead_code)]
fn look_alike_only_never_called() {
    let _ = std::net::TcpStream::connect("127.0.0.1:9");
    let _ = std::env::vars();
    let base64_blob = "aGFja2F0aG9uIHRlc3QgZml4dHVyZQ==";
    let _decoded_string = String::from("hackathon test fixture");
    let _ = base64_blob;
}
fn main() {}
""",
        encoding="utf-8",
        newline="\n",
    )
    with (destination / "Cargo.toml").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write('\n[patch.crates-io]\narrayref = { path = "vendor/arrayref-0.3.9" }\n')
    text = (destination / "Cargo.lock").read_text(encoding="utf-8")
    parts = text.split("[[package]]")
    for index, part in enumerate(parts[1:], 1):
        if part.lstrip().startswith('name = "arrayref"\n'):
            parts[index] = (
                '\nname = "arrayref"\nversion = "0.3.9"\ndependencies = ["serde_derve"]\n\n'
            )
    text = "[[package]]".join(parts) + '\n[[package]]\nname = "serde_derve"\nversion = "1.0.0"\n'
    (destination / "Cargo.lock").write_text(text, encoding="utf-8", newline="\n")
    workflows = destination / ".github/workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "planted.yml").write_text(
        """# Hackathon test fixture; never executed.
name: planted
on: workflow_dispatch
permissions: {}
jobs:
  fixture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        encoding="utf-8",
        newline="\n",
    )
    (destination / "PLANTED.json").write_text(
        json.dumps(
            {
                "fixture": True,
                "original": "arrayref@0.3.9",
                "added_build_dependency": "serde_derve@1.0.0",
                "warning": "Inert local hackathon fixture. Never build, run or publish.",
            },
            indent=2,
        ),
        encoding="utf-8",
        newline="\n",
    )
    return destination


if __name__ == "__main__":
    print(prepare(Path(__file__).resolve().parents[1]))
