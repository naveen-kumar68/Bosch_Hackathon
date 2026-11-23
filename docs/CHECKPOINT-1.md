# Checkpoint 1 verification

Verified on native Windows on 2026-11-23, replacing WSL2 at the owner's request.
Exact tool versions are in `../tools.lock.md`; Python resolution is in `../uv.lock`.

## Commands

```powershell
. .\scripts\activate-tools.ps1
uv sync --locked
uv run guardian scan --target kuksa-databroker
uv run guardian scan --target kuksa-val-0.4.1
uv run guardian scan --target kuksa-python-sdk
uv run guardian scan --target kuksa-databroker-image
$env:GUARDIAN_INTEGRATION='1'
uv run pytest -q
uv run ruff check guardian tests
uv run ruff format --check guardian tests
uv run guardian path --target kuksa-databroker num-conv
uv run guardian path --reverse mdurl --target kuksa-python-sdk
```

## Observed results

| Target | Components including roots | Roots | Direct | Transitive | Unique edges | Depth |
|---|---:|---:|---:|---:|---:|---:|
| kuksa-databroker | 496 | 5 | 42 | 449 | 1632 | 8 |
| kuksa-val-0.4.1 | 355 | 4 | 28 | 323 | 953 | 7 |
| kuksa-python-sdk | 17 | 1 | 7 | 9 | 19 | 4 |
| kuksa-databroker-image | 1 | 1 | 0 | 0 | 0 | 0 |

Rust inventory counts equal Cargo.lock package counts, including local crates.
The main target has 71 build-script and 37 proc-macro packages; baseline has 62
and 22 respectively. All 16 Python dependency pins lack hashes.

Both SBOM formats passed independent validation for all four targets. Every
listed output exists under `out/<target>/`: CycloneDX, SPDX, graph JSON, GraphML,
HTML, CSV, summary, SQLite, scan JSON, evidence JSON, and raw outputs.
The image also contains an extracted `shipped-sbom.json` with 319 components.
Syft identified zero packages in the image; the graph retains the image root.
This is inventory coverage information, not proof the image has no dependencies.

The full regression suite passed: **34 tests**. It compares four actual
transitive crates (`anstyle-query`, `same-file`, `multimap`, `num-conv`) against
independent reverse Cargo tree output, checks direct dependencies against all
three requested manifests, validates raw evidence hashes, and checks outputs.
CI runs offline fixture tests on Windows and Ubuntu using SHA-pinned actions.

## Path resolution

All Cargo features and all platforms are included. Cargo metadata supplies the
inventory and typed dependency edges. A fully expanded Cargo tree additionally
supplies resolution-context subtrees for path queries. Identical subtrees are
hashed and shared; incompatible feature/build contexts are never joined merely
because they share a package PURL. Package-level visualization edges remain an
aggregate; use `guardian path` for context-preserving paths.

## Limitations and remaining visual check

SBOM generators and SPDX conversion report fewer packages than the resolver;
the exact count differences are warnings in summary.md with evidence records.
Python conditional pins are retained as cross-platform inventory. Registry
artifact code is never installed, built, or run. No LLM is called.

The graph HTML is generated with inline visualization assets. A screenshot has
not yet been captured: browser access was unavailable and desktop automatic
approval review subsequently failed due to the account usage limit. Visual QA
and the screenshot acceptance item remain pending; this document does not claim
that item passed. Open `out/kuksa-databroker/graph.html` to inspect the artifact.
