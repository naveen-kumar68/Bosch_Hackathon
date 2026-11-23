# Supply Chain Guardian

Supply Chain Guardian is a Bosch hackathon project for building an evidence-backed
software supply-chain inventory and identifying changes that may need review.

## Current scope

- Checkpoint 1 acquires pinned source revisions and produces an SBOM and dependency
  graph.
- Checkpoint 2 adds deterministic dependency and build-time risk checks, including
  vulnerability, registry, workflow, container, and source-capability signals.
- Findings are written as JSON, SARIF, Markdown, and HTML reports, with evidence
  and typed risk relationships retained in SQLite.
- An optional, bounded LLM judge can assess selected findings. Static analysis is
  the default; scan signals are review candidates, not proof of malicious intent,
  exploitability, or reachability.

Checkpoint 2's remaining validation items and known limitations are tracked in
[docs/CHECKPOINT-2.md](docs/CHECKPOINT-2.md). The planted scenario is a local,
inert test fixture; it is not built, executed, or published.

## Requirements

- Windows PowerShell (the current development workflow)
- Python 3.12 and [uv](https://docs.astral.sh/uv/)
- Git
- Docker Desktop for the pinned containerized static scanners

Some acquisition and registry checks require network access. Live LLM assessment
is optional and requires a compatible API endpoint and key.

## Setup

From the repository root:

```powershell
. .\scripts\activate-tools.ps1
uv sync --locked
```

For optional live LLM assessments, copy `.env.example` to `.env` and set
`LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL`. Keep credentials in the ignored
`.env` file; never commit them.

## Run

```powershell
uv run guardian detect --target kuksa-databroker --baseline kuksa-val-0.4.1
uv run guardian detect --target kuksa-python-sdk
uv run guardian finding <finding-id> --target kuksa-databroker
```

The `detect` command runs deterministic checks and writes generated output under
`out/`. Optional LLM assessment is enabled separately with `--judge`; it should
only be used when the outgoing redacted payload is approved. See
[docs/CHECKPOINT-2.md](docs/CHECKPOINT-2.md) for the documented planted-fixture
workflow, acceptance evidence, and limitations.

## Validate

```powershell
uv run pytest -q
uv run ruff check guardian tests demo
uv run ruff format --check guardian tests demo
```

Pinned scanner versions and checksums are recorded in [tools.lock.md](tools.lock.md);
Python dependency versions and hashes are in [uv.lock](uv.lock).
