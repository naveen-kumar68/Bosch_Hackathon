# Module 2 — Phase 4 candidates

Phase 5 adds evidence-bearing vetting through `api.vet`; see
[VETTING.md](VETTING.md) for the detector bindings, checks and integration limits.

`api.candidates(pf)` / `CandidateGenerator(snapshot).candidates(pf)` produces
declarative `FixOption` objects. No LLM, HTTP, files, subprocesses, target builds
or commands are involved. Nothing is applied. Every option starts with
`vetting="pending"`; Phase 2's verifier rejects a Plan choosing a pending fix.
Phase 5 must vet non-escalate options before they can be offered as allowed fixes.

The shared contracts remain absent. `models.py` contains provisional Module 2
types. The input is a `RemediationRequest` projection of PrioritisedFinding,
including finding ID, versioned Cargo/PyPI component PURL, evidence IDs, captured
fix boundaries, incoming constraints/parents, baseline and edit locations.
Shared priority, severity or decisions are not changed. Unsupported/missing
registry information yields escalation. Invalid input schemas raise validation
errors instead of manufacturing evidence or file locations.

## Selection

- **minimal_upgrade:** smallest stable available version newer than current,
  meeting a captured fix boundary and all supplied incoming constraints.
- **parent_bump:** when a direct upgrade is blocked, find the smallest available
  newer parent version whose captured dependency requirements admit a candidate.
  All other current parents and the parent's own incoming constraints must
  permit the change. This is a one-parent proposal, not a general graph solver.
- **rollback:** propose the exact captured baseline when it is older, available,
  stable and explicitly not yanked. It is not assumed secure or compatible;
  these checks remain pending.
- **escalate:** always present, contains no edits and supports manual review.

Fix boundaries are lower bounds within the same release line (Rust major, or
minor for major zero; Python epoch/major). They do not establish that all later
versions are vulnerability-free. Later advisory intervals/reintroductions,
publisher changes, release age, checksums and capability/dependency risks must
be checked in Phase 5. No candidate is labelled vetted or safe in this phase.

Unknown yanked status, yanked releases, prereleases and malformed registry
versions are excluded from automatic proposals. Unsupported constraints cause
escalation. Python interpreter constraints are honoured; when a release declares
requires_python, the caller must supply the target Python version. Host Python
or Windows is never assumed to be the target environment.

Locations are explicit POSIX paths relative to the target repository. A change
describes package, old/new versions and lock_update (Cargo.lock) or replace_pin
(manifest/requirements/setup.cfg). It is data for Module 3, not shell text or an
applied patch. Editable root pins must be distinguished from other incoming
constraints: a Python pin being replaced is not an immutable compatibility cap.
Callers must provide the complete active constraint set; this code does not
infer it from files or guess unseen parents.

Option IDs are `O-` plus eight SHA256 hex characters of the finding/component,
kind, target version and sorted declarative changes. Capture timestamps and
evidence IDs do not change action identity. Every option retains sorted finding,
advisory, registry, baseline and relevant constraint evidence IDs. Escalation
uses the finding evidence. Outputs and ordering are deterministic.

## Captured registry adapters and version handling

`RegistrySnapshot` owns independent copies of normalized package records.
`cargo_index(name, rows, evidence_id)` accepts captured crates index rows;
`pypi_index(name, document, evidence_id, version_documents=...)` accepts captured
PyPI JSON. Neither adapter fetches a URL or executes package metadata.
Per-version PyPI requires_dist evidence is required for parent bumps. Unknown
dependency metadata or relevant conditional/extra/direct-URL requirements are
not silently ignored: those parent releases cannot be proposed automatically.
Cargo optional/target-specific/foreign-registry child edges are similarly conservative until an
adapter supplies explicitly resolved active requirements.

The small Rust parser implements the common caret/default, tilde, wildcard,
comparison and comma-intersection forms described in the
[Cargo reference](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html).
It compares SemVer prerelease identifiers and ignores build metadata for
precedence; it does not execute Cargo. Unsupported syntax is rejected. Parser
tests cover Cargo's pre-1.0 and prerelease rules. Automatic options currently
exclude prereleases even when a requirement explicitly permits them.

Python uses the already-installed and locked **packaging 26.3** for
[PEP 440 specifiers](https://packaging.pypa.io/en/stable/specifiers.html) and
requires_dist parsing. No dependency was added. The lead should record these
version-handling choices in shared docs/TECH_STACK.md.

## Integration requests and limits

- Lead: supply shared PrioritisedFinding/FixOption contracts and map the
  provisional request fields, option kinds, target_version, changes and evidence.
- Lead: supply captured registry/advisory/graph projections through the agreed
  read-only contracts. Register one generator per run or pass a snapshot explicitly.
- Lead: wire candidates into orchestration/storage/UI, showing pending candidates
  as unvetted. Module 3 owns applying and testing a selected, allowed option.
- Module 4: replace the marked synthetic Cargo fixture in
  tests/fixtures/remediate/ with shared examples; PyPI captured-shape fixtures
  currently live in the owned test module.

This is not full Cargo/pip resolution or a claim that a proposed environment will
build. Multi-parent coordinated upgrades, environment markers, artifact-specific
Python compatibility, Rust MSRV/features/platform resolution, arbitrary source
repositories and broad source rewrites require additional adapters or manual
review. Build/validation remains Module 3's sandbox responsibility. Phase 5 is
not implemented by Phase 4.
