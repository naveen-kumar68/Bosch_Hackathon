# Checkpoint 2 progress

Status: toolchain pinned; first deterministic detectors implemented. Full risk
pipeline, Judge, reports and acceptance verification remain incomplete.

Checkpoint 1 is the base branch of this work, with PR #1 open and unmerged.
Native Windows remains the owner-approved environment. Rust context-preserving
path queries now pass four real-crate oracle comparisons; 34 acceptance and
fixture tests pass, as do lint and formatting.

## Decisions pending

- Owner approved pinned scanner-only Docker images with read-only target data.
  Target code remains prohibited from execution. Both scanner smoke checks passed.
- Live Judge verification needs provider configuration in the ignored `.env`.
  No key is requested in chat and no live call has been made.
- Graph screenshot remains pending because desktop approval review hit an
  account usage limit. This does not block tool discovery or deterministic tests.

No Checkpoint 2 acceptance criterion is claimed complete at this stage.

## Implemented and verified so far

- Finding, Vulnerability and strictly validated AI-assessment contracts.
- Editable severity rules with rationale; KEV stays Critical, and build scopes
  never receive the dev-only reduction.
- Inventory set comparison, version direction, source/checksum conflict checks.
- Transitive advisory-alias union retaining every evidence source.
- Rate-limited metadata cache with snapshot timestamps and integrity verification.
- Static workflow and Dockerfile checks and shipped-vs-observed SBOM comparison.
- Tests for alias bridges, multi-version identity, cache reuse/tampering, severity,
  workflow findings, Docker stages and drift identity.

Latest checks: 31 tests passed, 14 real-scan acceptance tests skipped by default;
ruff lint and formatting passed. Checkpoint 1's full 34-test run passed before
these additions, including actual Rust path comparisons. Its PR CI passed on
Windows and Ubuntu.

Preliminary real workflow rule hits: 85 unpinned action references, 3 incomplete
Cargo tool installations, 3 mutable Python Git installs, and 2 files with missing
or excessive permission declarations. These are custom rule hits pending zizmor
correlation and final finding normalization; multiline commands need review.
Image drift: 307 unique shipped package identities missing from Syft observation,
0 extra and 0 mismatched. The shipped SBOM has 319 entries before identity grouping.

OSV produced parseable JSON for the 496-package main lockfile. Standalone
cargo-audit capture is still running; vulnerability union verification is pending.
Grype database update completed successfully. No Judge calls have been made.

## Remaining work

Scanner adapters and merged vulnerability enrichment; live registry field checks,
per-version registry diff, popularity datasets, capability artifact verification
and static rules, GuardDog correlation, planted scenario, Judge redaction/cache,
CLI orchestration, SQLite finding persistence, SARIF and risk reports, full
acceptance checks, screenshots and final PR. Provider configuration is still absent.
