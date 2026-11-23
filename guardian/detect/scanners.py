import json
from pathlib import Path

from guardian.detect.vulns import deduplicate, parse_audit, parse_grype, parse_osv, parse_pip


def run_json(recorder, command, *, accepted=(0, 1), timeout=900, env=None):
    raw, evidence, code = recorder.run(command, check=False, timeout=timeout, env=env)
    if code not in accepted:
        raise RuntimeError(f"{command[0]} failed; see evidence {evidence}")
    try:
        return json.loads(raw), evidence
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON from {command[0]}; evidence {evidence}") from error


def scan_vulnerabilities(source: Path, output: Path, scan, recorder, *, extra_sboms=()):
    observations = []
    lock = source / "Cargo.lock"
    requirements = source / "requirements.txt"
    input_file = lock if lock.exists() else requirements
    if input_file.exists():
        document, evidence = run_json(
            recorder,
            [
                "osv-scanner",
                "scan",
                "source",
                "--lockfile",
                str(input_file),
                "--no-call-analysis",
                "rust",
                "--no-resolve",
                "--format",
                "json",
            ],
        )
        observations.extend(parse_osv(document, scan.components, evidence))
        if lock.exists():
            document, evidence = run_json(
                recorder, ["cargo-audit", "audit", "--file", str(lock), "--json"]
            )
            recorder.note(
                "RustSec database snapshot: " + json.dumps(document.get("database", {})), [evidence]
            )
            observations.extend(parse_audit(document, scan.components, evidence))
        else:
            # --no-deps and --disable-pip forbid dependency resolution/install code.
            document, evidence = run_json(
                recorder,
                ["pip-audit", "-r", str(requirements), "--no-deps", "--disable-pip", "-f", "json"],
            )
            observations.extend(parse_pip(document, scan.components, evidence))
    documents = [output / "sbom.cdx.json", output / "shipped-sbom.json", *extra_sboms]
    for document_path in dict.fromkeys(documents):
        if document_path.is_file():
            document, evidence = run_json(
                recorder, ["grype", "sbom:" + str(document_path), "-o", "json"], accepted=(0,)
            )
            recorder.note(
                "Grype database snapshot: "
                + json.dumps(document.get("descriptor", {}).get("db", {})),
                [evidence],
            )
            observations.extend(parse_grype(document, scan.components, evidence))
            unmatched = [
                match["artifact"]["name"] + "@" + match["artifact"]["version"]
                for match in document.get("matches", [])
                if not any(
                    (c.name, c.version) == (match["artifact"]["name"], match["artifact"]["version"])
                    for c in scan.components
                )
            ]
            if unmatched:
                recorder.note(
                    "Shipped SBOM advisory packages absent from resolved graph: "
                    + json.dumps(sorted(set(unmatched))),
                    [evidence],
                )
    return deduplicate(observations)
