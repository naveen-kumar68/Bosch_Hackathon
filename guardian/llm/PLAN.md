# Module 2 — Phase 6 Plan

`Planner(client, index, budget_key=run_id).plan(pf, options)` returns an AIClaim
after `verify.api.check`. Use the same run-scoped CompletionClient and current
fact index as the other roles. `api.configure_plan(planner)` enables
`api.plan(pf, options)`; an explicit service can be supplied per call.

The shared contracts are still absent. `plan_schema.py` defines a strict
provisional PrioritisedFinding projection: finding_id, type, versioned component
PURL, severity, P0/P1/P2/P3 priority, score_breakdown terms (name/value/evidence),
paths, decision and evidence IDs. Decision strings currently match Module 4's
auto_ok / needs_human / block_candidate. The lead must map its final contracts.
Unknown fields, raw snippets/code, detector details and previous AI assessments
are not accepted in this projection. Typed strings still come from trusted
adapters; a schema cannot prove that arbitrary prose is not code.

## Closed option set and evidence

Exactly one escalation option must exist and contain no changes. Every option
must belong to this finding/component, have a unique ID, and match the current
fact index's kind, vetting state and full option snapshot fingerprint. This
includes action, target version, evidence and vetting proof. Changing an option
under an old passed label fails before export. Rebuild the index after Phase 5
vetting; do not use an index of the old pending candidates.

The model receives structured finding data, all options (including rejected
ones), changes, vetting states/reasons and evidence IDs, constraints preferring
the smallest compatible change and avoiding unnecessary major jumps, and
indexed typed facts. Full per-check audit records are not duplicated into the
prompt, but are bound in the runtime fingerprint. Only the finding/options'
evidence context is forwarded. The common client redacts strings and enforces
its input/call/token budgets. Oversized context degrades to escalation; it is
not silently truncated into an unsupported recommendation.

No raw source snippets or Judge/other AI prose is forwarded. The prompt in
`prompts/plan.txt` requests a supplied passed option or escalation, <=80 rationale
words, trade_offs, descriptive rollback_steps, facts_used and cited_evidence_ids.
It prohibits code/commands and changes to deterministic decision fields. Output
schemas exclude severity, priority, confidence, decision, origin and runtime
provenance. No tools, shell commands, target edits or execution API exist here.

Every output is verified. Rejected/pending/unknown choices, unsupported versions,
invented packages, unlisted facts and invalid citations fail. Runtime PlanSource
binds finding ID, supplied option IDs, snapshot fingerprints and evidence scope;
it is never model output. Even globally known options/evidence outside this
context cannot be used. These checks and fingerprints persist after a claim is
serialized and later re-verified. A changed indexed snapshot invalidates the plan.

## Deterministic escalation and failures

When no non-escalate fix has vetting=passed, code selects the existing escalation
option without invoking the LLM. The result cites indexed option evidence and is
verified like any other plan. Its origin is deterministic, not live/recorded AI.
No new option or evidence is invented.

With a configured index, disabled AI, an absent client, budget exhaustion,
unavailable providers or invalid schema after the common client's one repair
also select deterministic escalation and require human review. An unconfigured
global facade returns None (facts-only), because it has no index with which to
verify an escalation. Invalid input schemas, missing escalation, conflicting
options or unindexed evidence raise input errors before any provider call.

A schema-valid but factually invalid answer remains an unverified AIClaim with
its errors; it is not silently treated as a valid plan. `previous_errors` is
accepted and redacted by the common client. Module 1 owns at most two factual
repairs and the facts-only UI after failure. The planner itself performs no
factual repair loop. `trace` contains usage/cache data for successful structured
responses; `events` records only generic transport failure types. Cache hits
still re-run the verifier and consume zero additional calls.

## Tests and lead integration

Synthetic recorded-shape responses are in tests/llm_recordings/plan.json. Tests
cover choosing a passed option, rejecting rejected/pending choices and invented
versions/packages, zero-call escalation, budget/provider/AI-off paths, schema
guardrails, external repair prompts, raw-input exclusion, closed context,
snapshot tampering, cache and serialized re-verification. No live LLM or target
code is run. Findings, options, severities, priorities and decisions stay unchanged.

Lead requests:
- Supply the shared PrioritisedFinding/AIClaim/Plan schemas and map this strict
  projection, score terms and decision literals.
- Extend runtime AIClaim origin with deterministic and supply PlanSource fields.
  Render deterministic escalation as code-generated, never as an AI answer.
- Build a current, provenance-correct typed fact index from vetted options,
  including option snapshot fingerprints. Final Plan wrappers must retain the
  closed-context and stale-proof checks.
- Wire the Planner, orchestration, traces, storage and facts-only rendering.
  Recheck current policy/vetting before Module 3 applies anything; selecting a
  passed proposal does not authorize execution or override policy.

Verification remains the bounded typed-fact/token check described in
../verify/README.md. It does not prove arbitrary semantic claims or the safety
of free-form instructions. Human review stays enabled, and descriptive rollback
text is not executable. Full compatibility/build validation remains Module 3's
responsibility. Phase 7 Explain/brief is not included here.
