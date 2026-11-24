# How to run Supply Chain Guardian

Windows + PowerShell. Python 3.12 is required (the project pins `>=3.12,<3.13`).

## 1. One-time setup

```
python -m pip install uv
python -m uv sync --python 3.12
```

This creates `.venv` with every pinned library from `uv.lock`.

## 2. Module 2 demo (AI trust layer + remediation) — works offline

No API key, no network, no scanner tools needed.

```
.venv\Scripts\python -m guardian.llm.cli_ext demo          # readable report
.venv\Scripts\python -m guardian.llm.cli_ext demo --json   # machine-readable
```

It runs the planted-demo source through fix candidates, vetting, the Judge, Plan, Explain,
brief and second opinion using a recorded-shape mock provider, then prints every claim with
its verified status. Expected result:

```
O-…  minimal_upgrade  target=1.0.1  vetting=passed
[VERIFIED] judge / plan / explain / brief / second_opinion
Accepted hallucinations: 0 | verifier caught 10/10 wrong, accepted 3/3 correct | injection 3/3
live provider tested: False | target code executed: False
```

(`guardian llm demo` will work once the lead adds the `cli_ext` plugin hook to `guardian/cli.py`.)

## 3. Tests

```
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m pytest -q --deselect tests/test_cargo_adapter.py   # if cargo is not installed
.venv\Scripts\python -m ruff check guardian tests
```

No test calls a live LLM or the network.

## 4. Full pipeline (Module 1) — needs extra tools

```
.venv\Scripts\guardian.exe --help
.venv\Scripts\guardian.exe scan --target kuksa-python-sdk     # targets are in targets.yaml
.venv\Scripts\guardian.exe detect --target kuksa-python-sdk
.venv\Scripts\guardian.exe summary --target kuksa-python-sdk
```

These need the pinned scanner tools listed in `tools.lock.md` (Syft, CycloneDX CLI,
cargo-cyclonedx, Cargo/Rust, Docker Desktop, plus osv-scanner, Grype, Semgrep, GuardDog).
Binaries go in the ignored `.tools/` folder; then run `. .\scripts\activate-tools.ps1` in
PowerShell. Without them `scan` stops with `Required tool is not installed or on PATH: syft`.
It needs network access to clone the target repository and fetch advisories.

## 5. Optional live AI

Copy `.env.example` to `.env` and fill in `LLM_API_KEY`, `LLM_BASE_URL` (https) and `LLM_MODEL`.
`guardian judge-ping` checks the provider with one minimal call. Keys stay in the ignored
`.env` and are never printed or committed.

## Troubleshooting

- `Requires a different Python`: use `python -m uv sync --python 3.12` (not 3.13/3.14).
- `No such command 'llm'`: use `python -m guardian.llm.cli_ext …` until the CLI hook is merged.
- `Could not find "cargo"`: install Rust (rustup) or deselect the cargo tests.
