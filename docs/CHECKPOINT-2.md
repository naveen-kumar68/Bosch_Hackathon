# Checkpoint 2 progress

Status: expanded deterministic pipeline and recorded-response Judge tests are
implemented. Full live acceptance verification remains incomplete.

## Latest verification (2026-11-23)

`guardian detect` and `guardian finding` now exist. The first completed Rust run
wrote normalized findings, SARIF, SQLite records and Markdown/HTML reports.
Its 635 findings are **provisional** because expanded registry/capability checks
were connected subsequently. Severity counts: High 9, Medium 121, Low 18,
Info 487. Type counts: vulnerability 16; unsound 9; unmaintained 4;
action_unpinned 85; cargo_install_unlocked 3; pip_git_mutable 3;
mutable_base_image 6; unstable_base_image 2; workflow_permissions 2;
sbom_drift 1; new_direct_dependency 17; dependency_added 168;
dependency_removed 33; dependency_upgraded 286.

The no-baseline Python run emitted 18 provisional findings, including all 16
pins without hashes. The newly configured SDK 0.5.2 baseline and expanded
artifact checks still need a fresh successful run. These are initial severity
findings, not Checkpoint 3 priority rankings.

The full local suite passed **70 tests**, including real scanner-union comparison,
raw evidence integrity checks for both reports, LF checks, Rust path oracles,
recorded-response Judge guardrails and planted-rule tests. Six Semgrep rule tests
also passed in its pinned, network-isolated non-root scanner container. CI now
includes the same scanner-rule test and remains free of live LLM calls.

The independent OSV/RustSec alias union matched the report. CVE-2023-49092 appears
among 16 advisory/package records, alongside RustSec and GHSA identities. The
records and full paths are in `out/kuksa-databroker/vulnerabilities.json` and
`findings.json`; standalone probes remain in `risk-probes/`.

Popularity caches contain 5,000 Cargo and 15,000 PyPI names. Live crates.io fields
verified: created_at, published_by.id, yanked, checksum, trustpub_data. PyPI file
metadata supplies digests.sha256 and upload_time_iso_8601, but does not establish
publisher identity or trusted publishing; these stay unknown.

The planted local copy resolved with locked metadata/tree: 497 components and
1,663 relationships. No fixture code was built or executed. Tests cover source
change, missing prior-registry checksum, look-alike name, network/env/decode
capabilities, Critical new-build capability correlation and a tag-pinned action.
A full planted report and live Judge result are still pending.

Expanded registry analysis timed out twice at 60 seconds. The owner approved a
180-second timeout and a cache-backed retry; that attempt subsequently stopped
on DNS resolution failure (`getaddrinfo failed`). Rust registry requests are
paused with cached observations retained. The owner
also approved using the captured PyPI SHA256 when a pin lacks hashes; the missing
lockfile-hash finding remains separate. Partial metadata/artifacts are retained
and are not presented as a complete scan. Prior completed report evidence is
retained while a new run is in progress. New evidence IDs are content-derived
to support Judge cache reuse across unchanged reruns.

Live Judge acceptance is blocked because `.env` has no replacement key. A
key-empty Groq configuration was prepared locally; `.env.example` remains empty
of values. The exposed key must not be reused. No live Judge call has been made. Recorded responses verify
invalid-ID rejection, severity protection, two-attempt handling, call budget,
redaction and cache hits. Screenshots and final expanded-run counts remain pending.

Native Windows rules: new clones set core.autocrlf=false and core.longpaths=true;
application text output uses explicit LF; evidence paths use repo-relative POSIX
notation, including imported records. Raw tool bytes are preserved for hashing.
Checkpoint 3 has not started; its confirmed thresholds remain future work.

The actual planted report test also passes using recorded responses, with a
suspicious verdict citing valid evidence IDs and a cached rerun making zero
additional calls. Recorded report paragraphs are explicitly labelled as recorded
test responses and do not satisfy the live Judge acceptance item. Budget-excluded
findings are cached as exclusions so a rerun cannot leak extra calls beyond the
original selection. `guardian.yaml` sets the per-scan call and input budget.

The SDK baseline is configured generically through Target.baseline (0.5.2).
The Python expanded run encountered a Semgrep timeout on grpcio's full archive;
scanning was narrowed to setup.py/build.rs and proc-macro Rust source and retried.
Timed-out scanner containers are explicitly cleaned up; partial stdout/stderr
are retained as failed evidence rather than discarded.

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
