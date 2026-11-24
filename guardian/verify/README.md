# Module 2 — Phase 2 verifier

`Verifier(index).check(claim)` and `api.check(claim, index=index)` return a new
`AIClaim`. They recompute `verified` and `errors` without mutating the input.
Errors are accumulated in a stable order and failed claims require human review.
The optional `api.configure(index)` supports `check(claim)`; concurrent runs
should pass indexes explicitly rather than using global configuration.

The shared contracts have not landed. `guardian/llm/claims.py` contains provisional
Module 2 models. `ClaimContent` is the provider-output schema; it requires
`facts_used` and `cited_evidence_ids` and forbids severity, priority, decision,
confidence and verifier-owned fields. `AIClaim` adds verification/review results.
Later phases will provide stricter role-specific shapes and word limits.

## Trust boundary and facts

`build(ledger, findings, options)` accepts trusted mappings or Pydantic records.
It does not read repositories, execute tools, call APIs, interpret arbitrary
evidence prose or parse an AI answer into trusted facts.

- A ledger row has `id` (or `evidence_id`) and optionally `facts: [{type,value}]`.
  Existing Evidence models register their IDs but currently have no typed facts.
- Trusted finding/option adapters can supply `facts` observations containing
  `type`, `value`, and `evidence_id`. Every referenced evidence ID must exist.
- Finding `component` PURLs and structured package/version fields populate known
  identities. Their descriptions and `ai_assessment` never establish support.
  The builder does not copy every finding fact into every referenced evidence ID.
- Options use `option_id`, `kind`, `vetting`, and `evidence_ids`. The option's
  existence is registered against its evidence; its versions/capabilities must
  still be supplied as explicit observations. Unknown evidence and conflicting
  option vetting are rejected.

Facts have these types: package, version, purl, advisory_id, fixed_version, path,
score, option_id, flag. Values are strings except scores, which are finite
numbers. Numeric equality ignores insignificant trailing zeros; paths normalise
spacing around `→`. Package/version pairs come from PURLs, structured records, or
an evidence record with exactly one package and one current version.

## Checks

1. All cited evidence exists; at least one citation is required.
2. Each fact is supported by its own evidence ID, which must also be cited.
3. Text fields are scanned for CVE/GHSA/RUSTSEC/PYSEC IDs, name@version pairs,
   backticks, version-like strings, decimal scores, `a → b` paths, and option IDs.
   Detected facts must be listed. Explicit score/version wording requires the
   corresponding fact type. Paths and PURLs are atomic facts.
4. Package names/versions are known; name@version pairs cannot mix identities
   from unrelated components. Option IDs exist.
5. Plan may choose a passed option or the trusted escalate option. Rejected,
   pending and missing-vetting options cannot be chosen as fixes.
6. Judge flags and flag facts use only the seven specified names. Other roles
   cannot emit Judge flags; only Plan can choose an option.

Example: a claim citing EV-021 for a made-up fixed version yields
`EV-021 does not support fixed_version 1.2.4`, even when EV-021 exists and a
different evidence record happens to mention that version. A valid citation
alone never establishes support.

## Repairs and fixtures

Both common completion entry points accept `previous_errors: list[str] | None`.
The legacy Judge's `assess` also accepts it, without changing its legacy schema
or its behavior when no errors are supplied.
Errors are redacted, delimited and included as data requesting a corrected
answer. Claim prompts require every concrete fact in `facts_used` and backticked
package names/versions. Different errors produce different cache inputs. The
client does not perform factual repair loops: Module 1's orchestrator must call
the verifier after each correction and cap factual repairs at two.

The 10 wrong + 3 correct fixtures in `tests/fixtures/verifier/cases.json` are
marked `# TODO(Module 4): replace.` They cover fake advisories, wrong versions,
invented packages/paths, unlisted numbers, unknown/uncited evidence, unvetted
options and unknown flags. Additional tests cover type confusion, provenance,
atomic paths/PURLs, identity pairs and redacted repair prompts. No live LLM is
used. Shared `fixtures/verifier/` was absent and is outside this module's edit
scope, so placeholders live under its tests.

## Limits and integration requests

This is bounded syntactic grounding, not semantic proof of arbitrary prose.
Negation, causal claims, unmarked package prose, integer counts and relations
between supported facts require stricter schemas or further checks. A verified
claim remains AI inference; human-review requirements are preserved. Static flag
names are checked, but this phase does not prove a model's behavioral inference.

Lead requests:
- Supply/adapt the shared AIClaim/Fact/FixOption contracts to these provisional
  fields, including verifier-owned fields and role output schemas.
- Provide a ledger adapter with explicit, provenance-correct typed observations.
  ID-only current Evidence records deliberately produce no supported facts.
- Provide unambiguous score metric identities (CVSS versus EPSS), dependency
  identity pairs, aliases, counts and option kind/vetting fields in contracts.
- Wire run-specific fact indexes and the max-two-repair loop into orchestration;
  render facts only after failed verification. Role migrations start in Phase 3.
- Module 4 should replace the marked placeholder fixtures with shared examples.
