# Module 2 — Phase 5 vetting

`Vetter(detectors, policy, now=aware_timestamp).vet(options)` returns copies of
every input option in the same order. Non-escalate options become passed or
rejected, with `vetting_checks`, per-check evidence/flags, and rejected reasons.
Rejected options are retained for display. Source options, priorities, severity
and decisions are never changed. Escalation is retained unchanged.

`api.configure_vetting(service)` enables `api.vet(options)`; an explicit service
can also be passed per call. Without a service, all non-escalate options are
rejected with an evidence-bearing availability check. No option silently passes.

## Detector contracts and trust

The shared detector API and contracts have not landed. `vet_contracts.py`
therefore defines provisional, module-owned bindings and captured-version data.
The lead's bootstrap must bind the existing parse_osv, metadata_changes,
new_dependencies, typosquat.candidates, verified_extract, inspect_sources,
capability_diff and a Semgrep wrapper. Production Module 2 does not import
private detector modules or copy their rules. Tests bind the real existing
functions to exercise this bridge, with a mocked Semgrep JSON/evidence response.

`CapturedDetectors` owns independent snapshots of collector-supplied versions.
It makes no HTTP requests or target builds. Captures must contain authentic
version-bound registry metadata, dependency history, OSV results, artifact bytes,
registry hashes and evidence IDs. A bound `evidence_exists(id) -> bool` must
consult the run's evidence ledger. Policy evidence must already exist; missing
evidence referenced by any check causes rejection. The caller must verify the
authenticity/integrity of decoded captures against their raw evidence bytes.

Artifact bytes may be obtained by the lead's existing safe downloader; this
adapter does not fetch attacker-selected URLs. The bound existing extractor
checks SHA256 before extracting, rejects unsafe archives and enforces its size
limit. Scratch directories are isolated under an explicit root and removed
after inspection. Target code is never imported, built or executed.

## Checks for every changed package

Parent-bump options vet both child and parent targets; an unavailable parent
capture rejects the whole option. The primary change must bind the option's
component, current version and target version.

1. **Vulnerability:** a captured OSV scanner-shaped result must explicitly cover
   the candidate name/version/ecosystem, including an empty vulnerabilities list
   for a clean lookup. An absent/empty result is unknown, not clean. The existing
   parser's advisory IDs must match the captured candidate advisory IDs.
2. **Release:** age must be at least `min_release_age_days` (default 7), using an
   explicit aware evaluation time. Future/naive/unknown dates, yanked releases
   and unknown yank status are rejected.
3. **Publisher/provenance/source:** publisher must be known and unchanged or
   explicitly trusted under the policy's `ecosystem:package` key. Publishing
   provenance must be known and not regress; registry source must be known and
   unchanged. PyPI's current missing publisher/provenance fields cause rejection,
   not an assumption of trust.
4. **Dependency diff:** call the existing per-version detector on complete
   captured history. New dependencies and new build dependencies are flagged.
   Foreign-registry dependencies, missing versions or unknown history fail closed.
   New benign dependencies can pass screening with flags; this is not a proof
   that every transitive dependency is safe.
5. **Names:** screen every new dependency name with the existing typosquat
   detector and a captured popularity corpus (default minimum 5,000 distinct
   names). A match rejects the option, including the planted serde_derve build
   dependency. Fixtures explicitly use a smaller corpus under recorded policy.
6. **Integrity/static capability diff:** expected hashes must bind to the exact
   Cargo index version's cksum or a PyPI artifact digest, with checksum evidence
   from that source. A supplied matching hash alone is insufficient. Verify each
   artifact before its extraction and regex/Semgrep inspection, then call the
   existing capability_diff. New network/process/env/obfuscation, any new
   Semgrep rule, or any other newly reported capability causes rejection.

Static inspection is deliberately conservative: all Rust source is inspected
to cover proc-macros as well as build.rs, and Python uses the existing setup.py
coverage. It may reject benign runtime capability changes. Scanner failures,
missing captures and incomplete coverage reject rather than authorize a fix.

## Integration requests and limits

- Lead: publish shared detector API/contracts, replacing these provisional
  bindings without changing their fail-closed behavior. Supply captured lookup
  data and query/evidence provenance; no live data collector was added here.
- Lead: bind Semgrep to the existing scanner wrapper with its pinned image,
  rules, recorder and sandbox controls. No scanner container is launched by tests.
- Lead: record the policy snapshot in the ledger, supply trusted publisher lists
  and evaluation time, and wire vetted options/checks into orchestration/UI/storage.
- Lead/Module 3: re-vet stale or changed evidence before applying a fix; validation
  still runs only in the target-code sandbox. Results are relative to captured
  snapshots and static rule coverage, not a guarantee against all malicious code.
- Module 4: supply shared vetting fixtures. The tests reuse the existing planted
  demo's dependency name and extract its inert Rust string with AST reading;
  demo/prepare.py and target code are never executed.

The captured API currently consumes OSV scanner-shaped JSON; other advisory
services/API response shapes need lead-owned normalization. Custom build script
paths, dynamic Python hooks, platform/feature reachability and behavior hidden
inside an already-present capability category remain limitations of the existing
static detectors. Full dependency resolution/build compatibility and applying
changes remain Module 3's responsibility. Phase 6's AI Plan is not implemented.
