# Checkpoint 2: Risk detection

Status: deterministic scans and live planted Judge checks completed. The pushed Checkpoint 2 changes passed GitHub Actions on Windows and Ubuntu. The final report screenshot remains pending; Checkpoint 3 has not started.

## Commands

```powershell
. .\scripts\activate-tools.ps1
uv sync --locked
uv run guardian detect --target kuksa-databroker --baseline kuksa-val-0.4.1
uv run guardian detect --target kuksa-python-sdk
uv run guardian judge-ping
uv run python -m demo.prepare
uv run python -m demo.analyse
$env:GUARDIAN_INTEGRATION='1'
$env:GUARDIAN_PLANTED_INTEGRATION='1'
uv run pytest -q
uv run ruff check guardian tests demo
uv run ruff format --check guardian tests demo
```

The planted fixture is already prepared locally; prepare refuses to overwrite it. Live assessments were invoked through demo.analyse.analyse(root, live_judge=True) after explicit approval of the redacted Groq payloads. Ordinary demo module execution is static-only. The real-target detect commands above run deterministic checks; --judge enables bounded optional assessments.

## Observed numbers

| Target | Findings | By initial severity |
|---|---:|---|
| kuksa-databroker | 1222 | {'high': 18, 'medium': 191, 'low': 526, 'info': 487} |
| kuksa-python-sdk | 79 | {'medium': 11, 'low': 53, 'info': 15} |
| planted | 13 | {'critical': 1, 'high': 3, 'medium': 9} |

Counts are findings, not distinct packages. No prioritisation scores or reachability conclusions are assigned here.

### kuksa-databroker

| Finding type | Count |
|---|---:|
| action_unpinned | 85 |
| capability_added | 21 |
| cargo_install_unlocked | 3 |
| dependency_added | 168 |
| dependency_changed | 1 |
| dependency_removed | 33 |
| dependency_upgraded | 285 |
| mutable_base_image | 6 |
| new_build_dependency | 3 |
| new_dependency | 479 |
| new_direct_dependency | 17 |
| pip_git_mutable | 3 |
| publisher_changed | 36 |
| recent_release | 5 |
| sbom_drift | 1 |
| typosquat_added | 3 |
| unmaintained | 4 |
| unsound | 9 |
| unstable_base_image | 2 |
| vulnerability | 16 |
| workflow_permissions | 2 |
| workflow_zizmor | 40 |
### kuksa-python-sdk

| Finding type | Count |
|---|---:|
| capability_added | 4 |
| dependency_added | 6 |
| dependency_removed | 2 |
| dependency_upgraded | 7 |
| guarddog | 5 |
| mutable_base_image | 2 |
| new_dependency | 36 |
| new_direct_dependency | 1 |
| pin_without_hash | 16 |
### planted

| Finding type | Count |
|---|---:|
| action_unpinned | 1 |
| capability_added | 7 |
| new_build_dependency | 1 |
| new_build_dependency_with_network_capability | 1 |
| registry_checksum_missing | 1 |
| source_changed | 1 |
| typosquat_added | 1 |

## Acceptance evidence

1. Main detect command completed and wrote findings.json, findings.sarif, risk_report.md and risk_report.html. SQLite retains findings, vulnerabilities, evidence and typed risk-node relationships.
2. The alias-deduplicated native scanner union matches standalone OSV and cargo-audit captures in test_detection_acceptance.py. There are 16 advisory/package records (including maintenance/unsound warnings), not 16 CVEs. The unique CVE is CVE-2023-49092. Each vulnerability finding has paths, fixed-version information or an explicit absence, and evidence.
3. Independent Cargo.lock name/version sets reconcile with 168 added entries, 33 removed entries and 252 changed package names. A changed name may have multiple current versions, so changed-finding count is different. The test checks both membership and version sets.
4. Real workflow checks found 85 unpinned action references, 3 incomplete Cargo installations and 3 mutable Git-based Python installations. Zizmor results are retained, correlated where rule/location match, and otherwise normalized independently.
5. Container checks found 6 mutable base references and 2 unstable references including debian:sid-slim. SBOM drift reports 307 unique shipped identities absent from the Syft-observed inventory, zero extra and zero version mismatches. Syft identifying zero packages is a coverage gap, not proof that the image is dependency-free.
6. SDK detect completed with its generic configured previous-release baseline (0.5.2); all 16 pins without hashes were flagged. Registry SHA256 fallback for Python artifacts was explicitly approved and is recorded separately from the missing locked hash.
7. The inert planted copy resolves with locked Cargo metadata/tree: 497 components and 1,663 relationships. Tests assert source/checksum/name/network/env/decode/workflow anomalies and expected severity. The live Judge marked the Critical new-build-dependency pattern suspicious; its citations resolve to actual evidence.
8. Recorded-response tests reject invalid citations and severity overrides, enforce at most 5 calls per scan, separate live and recorded caches, and verify cache reuse. The final fresh live planted run used 5 calls and its unchanged cached rerun used 0. The provider/model ping also succeeded. No live API is used in CI.
9. Integration tests verify finding references and SHA256 of every referenced raw file. Evidence uses repository-relative POSIX paths for application output; cross-drive test output explicitly declares an output-relative base.
10. Latest full local acceptance run: 74 tests passed (including real target and planted integration checks). Six Semgrep rules passed inside the pinned offline scanner container. GitHub Actions passed on Windows and Ubuntu for the pushed Checkpoint 2 implementation.
11. This document includes commands, counts, examples and limitations. The required screenshot is PENDING: browser host was unavailable and subsequent workspace app approval timed out. No visual QA pass is claimed.

## False positives and limitations

- gix-note resembles gix-date/gix-quote; gix-zlib resembles gix-glob; vergen-gix resembles vergen-git2/vergen-lib. These are heuristic review candidates, not evidence of impersonation. Captured registry fields show the two gix candidates link to the Gitoxide repository. Exact popularity matches and the reviewed pair allowlist are excluded.
- filetime 0.2.30 build.rs calls rustc --version (line 14) to select compiler configuration. It also matches the Command import on line 2. This is normal build-tool activity despite the process-capability rule hit.
- defmt 1.2.0 build.rs writes its linker script into OUT_DIR (lines 13-14). The generic write rule needs contextual review; it does not establish an out-of-tree write.
- Capability scans are static patterns, including possible comment/import matches; they do not prove execution, exploitability or malicious intent. Dependency history includes optional/platform-specific edges. These remain visible for later reachability analysis.
- Missing PyPI dependency, publisher and trusted-publishing fields remain unknown. Age and registry facts use captured cached responses; cache times and advisory DB snapshots are evidence.
- Shipped-SBOM advisories absent from the current repository graph are retained as raw Grype evidence with an explicit unmatched-package note; no dependency path is invented for them.
- Registry timeouts/DNS failures interrupted earlier attempts. Cached metadata/artifacts were retained; a later resumed expanded run completed. Native scanners use 180-second HTTP reads and static scanner limits; scanner timeouts retain partial evidence and clean up task-created containers.
- Large all-path reports can be bulky. Main-target AI assessments are optional and were not live-run; all deterministic findings remain available for human review. Live proof was performed on the approved planted payload only.
- Native Windows was owner-approved. New target clones disable autocrlf and enable longpaths. Text outputs use LF; original raw tool bytes are retained for hashing. Target source is never built or run.

## Exact versions

Full Python artifact pins/hashes: uv.lock. Scanner versions, release checksums and Docker image digests: tools.lock.md. The API provider is configuration, not a package dependency. Secrets stay only in ignored .env.

## Three captured example evidence chains

These examples link to local generated artifacts, which are intentionally git-ignored. The main target remains provisional until the expanded run completes.

### F-a2c6fab20207 — kuksa-databroker
Type: `vulnerability`; severity: **medium**; confidence: `high`.
Component: `pkg:cargo/ansi_term@0.12.1`.
Rule: `vulnerability`.
Inspect all paths: `uv run guardian finding F-a2c6fab20207 --target kuksa-databroker`.
Example path: pkg:cargo/databroker-cli@0.7.2?repository_url=local ? pkg:cargo/ansi_term@0.12.1
- [639aca62a1882a59dd31a897efd6ce4c](../out/kuksa-databroker/raw/639aca62a1882a59dd31a897efd6ce4c.raw): `osv-scanner` version `osv-scanner version: 2.7.1
osv-scalibr version: 0.5.3
commit: 02f96a40691c2d155fdda799af436e111231e365
built at: 2026-11-09T03:39:40Z`; UTC `2026-11-23T13:46:32.067188Z`; SHA256 `db41d5ea4a42917e04494ad4df280670c314508c8cf647e08e6b786d7efbb26d`.
  Command: `[".tools/osv-scanner_windows_amd64.exe", "scan", "source", "--lockfile", "workspace/targets/kuksa-databroker@0.7.2/Cargo.lock", "--no-call-analysis", "rust", "--no-resolve", "--format", "json"]`; cwd: `out/kuksa-databroker`.
- [a4c24a56a2c7423c87a22e58ff885369](../out/kuksa-databroker/raw/a4c24a56a2c7423c87a22e58ff885369.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T13:46:28.404437Z`; SHA256 `49d027e73d3e29f0d3656c55b34438079ecb1644cdc521b4ebfc9c1a48bb4d21`.
  Command: `["guardian.read", "rules/severity.yaml"]`; cwd: `rules`.
- [bb30018fd8bfa6976dc67ec9be25f9f6](../out/kuksa-databroker/raw/bb30018fd8bfa6976dc67ec9be25f9f6.raw): `cargo-audit` version `cargo-audit-audit 0.23.0`; UTC `2026-11-23T13:46:36.795466Z`; SHA256 `64d640075312cf122337c5d0b0a76ba5e8f34fe1001e5091e6e92cabf27b993b`.
  Command: `[".tools/cargo-audit/bin/cargo-audit.exe", "audit", "--file", "workspace/targets/kuksa-databroker@0.7.2/Cargo.lock", "--json"]`; cwd: `out/kuksa-databroker`.
- [ecb56f8be89cc7133ecc3b3d38bac2c5](../out/kuksa-databroker/raw/ecb56f8be89cc7133ecc3b3d38bac2c5.raw): `httpx` version `0.28.1`; UTC `2026-11-23T13:47:05.169774Z`; SHA256 `12c9ca4c5350ecacdf22bdce91b4ffcf06b8c8dc9c69b8bfb4c1a21be7a5fe50`.
  Command: `["GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"]`; cwd: `workspace/cache/http`.

### F-9f92630cc682 — kuksa-python-sdk
Type: `pin_without_hash`; severity: **low**; confidence: `medium`.
Component: `pkg:pypi/cmd2@4.2.1`.
Rule: `pin_without_hash`.
Inspect all paths: `uv run guardian finding F-9f92630cc682 --target kuksa-python-sdk`.
Example path: pkg:pypi/kuksa-client@0.6.0?repository_url=local ? pkg:pypi/cmd2@4.2.1
- [7c37aee0c6334dfc9900b5b1cc601f8f](../out/kuksa-python-sdk/raw/7c37aee0c6334dfc9900b5b1cc601f8f.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T10:46:04.615531Z`; SHA256 `d5444124b2d112529905996a04b2106be3127e6107ba060b108351626b6993fa`.
  Command: `["guardian.read", "workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client/requirements.txt"]`; cwd: `workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client`.
- [a33c6ae25e5f421b94101aed673f958d](../out/kuksa-python-sdk/raw/a33c6ae25e5f421b94101aed673f958d.raw): `git` version `git version 2.49.0.windows.1`; UTC `2026-11-23T10:46:04.451924Z`; SHA256 `0f49a6a3a270f708fdbc64e267612ef07ae0841ff76b18075933ecad4838a117`.
  Command: `["../../../../../Program Files/Git/cmd/git.EXE", "rev-parse", "HEAD"]`; cwd: `workspace/targets/kuksa-python-sdk@0.6.0`.
- [a4c24a56a2c7423c87a22e58ff885369](../out/kuksa-python-sdk/raw/a4c24a56a2c7423c87a22e58ff885369.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T13:09:09.557183Z`; SHA256 `49d027e73d3e29f0d3656c55b34438079ecb1644cdc521b4ebfc9c1a48bb4d21`.
  Command: `["guardian.read", "rules/severity.yaml"]`; cwd: `rules`.
- [a9cb73a42d0f45b0a185757933c5a153](../out/kuksa-python-sdk/raw/a9cb73a42d0f45b0a185757933c5a153.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T10:46:04.606245Z`; SHA256 `ee18e88a54dc083776fa163935d24101ec3b51fbcd166402be92e3e08684c971`.
  Command: `["guardian.read", "workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client/pyproject.toml"]`; cwd: `workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client`.
- [f66252769cbe45979a91fc71ca370a06](../out/kuksa-python-sdk/raw/f66252769cbe45979a91fc71ca370a06.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T10:46:04.588388Z`; SHA256 `2bd9e3a083f6e9463f069af1df5da9a4662feb60633fc52b9c264002912575c3`.
  Command: `["guardian.read", "workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client/setup.cfg"]`; cwd: `workspace/targets/kuksa-python-sdk@0.6.0/kuksa-client`.

### F-49b02b5696a8 — planted
Type: `new_build_dependency_with_network_capability`; severity: **critical**; confidence: `low`.
Component: `pkg:cargo/serde_derve@1.0.0?repository_url=local`.
Rule: `new_build_dep_network`.
Inspect all paths: `uv run guardian finding F-49b02b5696a8 --target planted`.
Example path: pkg:cargo/databroker-cli@0.7.2?repository_url=local ? pkg:cargo/linefeed@0.6.0 ? pkg:cargo/dirs@1.0.5 ? pkg:cargo/redox_users@0.3.5 ? pkg:cargo/rust-argon2@0.8.3 ? pkg:cargo/blake2b_simd@0.5.11 ? pkg:cargo/arrayref@0.3.9?repository_url=local ? pkg:cargo/serde_derve@1.0.0?repository_url=local
- [06700d4e110dc2bf4a11aacefa291d00](../out/planted/raw/06700d4e110dc2bf4a11aacefa291d00.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T13:03:12.688240Z`; SHA256 `49d027e73d3e29f0d3656c55b34438079ecb1644cdc521b4ebfc9c1a48bb4d21`.
  Command: `["guardian.read", "rules/severity.yaml"]`; cwd: `rules`.
- [250a790dd7c95168b0239b0547fee019](../out/planted/raw/250a790dd7c95168b0239b0547fee019.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T12:57:01.057482Z`; SHA256 `374d5361fb7a25838f615e6395e67c645d5bfccbbe08b534f3d9bb0861bd899c`.
  Command: `["guardian.read", "demo/planted/Cargo.lock"]`; cwd: `demo/planted`.
- [4405eac28e0a168cd331ed3c35e932bd](../out/planted/raw/4405eac28e0a168cd331ed3c35e932bd.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T14:22:45.228110Z`; SHA256 `53aeaa277e8818763b5943baed16d8d25329ef8081bb235f850888466f35be1c`.
  Command: `["guardian.read", "demo/planted/vendor/serde_derve/build.rs"]`; cwd: `demo/planted/vendor/serde_derve`.
- [57abe2c209f3777db639514eecd56ea7](../out/planted/raw/57abe2c209f3777db639514eecd56ea7.raw): `guardian.read` version `0.1.0`; UTC `2026-11-23T13:03:12.683114Z`; SHA256 `00d7c160d497f47da8e57d6155fcca4ed04dc15198f763960ca3372066f4c1f0`.
  Command: `["guardian.read", "demo/planted/PLANTED.json"]`; cwd: `demo/planted`.
- [9c5c3b5bac6075552a763c7202590924](../out/planted/raw/9c5c3b5bac6075552a763c7202590924.raw): `cargo` version `cargo 1.91.1 (ea2d97820 2025-10-10)`; UTC `2026-11-23T12:57:04.139996Z`; SHA256 `511a413807f460ae226261e068551236027fdd82dc3d023c68a4b651abc4605f`.
  Command: `["../../../.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/cargo.exe", "metadata", "--format-version", "1", "--locked", "--all-features", "--manifest-path", "demo/planted/Cargo.toml"]`; cwd: `out/planted`.
AI inference (live): **suspicious**. The package serde_derve introduces a new build‑time dependency that appears to open a network connection to 127.0.0.1:9 and contains base64‑encoded data, suggesting possible exfiltration or remote code execution. The code is heavily redacted, making intent unclear.
