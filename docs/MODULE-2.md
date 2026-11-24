# Supply Chain Guardian — Module 2 handoff

This is the completed Module 2 implementation guide, ready for Module 4 to
publish as docs/MODULE-2.md. That shared docs directory, contracts, orchestration,
UI and CLI root remain outside Module 2's edit ownership. Component completion
does not mean the existing application has been migrated to the new APIs.

## Trust model and APIs

Tools and trusted code supply evidence, priorities, policy decisions and fix
options. LLMs classify, choose from allowed options, or explain structured facts.
They receive no side-effect tools, never apply changes, and cannot set severity,
priority, deterministic confidence or policy decisions. Failed or disabled AI
leaves deterministic findings intact. Provider-output schemas never contain
runtime verified/origin/source fields.

The facade in guardian/llm/api.py exposes judge, plan, explain, explain_brief and
second_opinion. Services can be configured explicitly or passed per call; one
CompletionClient and a stable budget key must be shared for each run. The
unconfigured facade performs no provider request. Explain/brief/opinion return
None when AI is off or unavailable. Judge returns no claims. A configured Plan
selects the existing escalation option deterministically when no vetted fix
exists or AI is unavailable; its origin is deterministic, not an AI answer.

Shared schemas have not landed. Owned provisional models live in claims.py,
plan_schema.py, structured_schema.py and remediate/models.py. The lead must map
them to the final contracts rather than bypass verification for compatibility.

## Client, prompts and budgets

The common complete(role,messages,schema,budget_key) entry point uses strict
JSON-schema mode or configured JSON mode, followed by Pydantic validation. It
allows one JSON/schema repair with sanitised error locations/types. Role APIs
also accept previous_errors for the lead's separate max-two factual repair loop.
The client has ordered provider fallback on 429/5xx, Retry-After handling, and
bounded waits; provider errors do not expose request metadata or credentials.

Module-owned config.json defaults: five attempts per run and per role, 150,000
input / 10,000 output tokens, 1,500 completion tokens per attempt, 24,000 request
characters, 4,096 characters and 60 lines per Judge snippet. Second opinion has
a hard ceiling of three actual attempts per run, even if configured higher.
Retries/fallback count; cache hits consume zero calls/tokens/cost. Input token
reservations use a conservative UTF-8 byte estimate; unavailable usage is marked
estimated. Actual provider usage and configured prices determine reported cost.
Free-tier configured prices default to zero; paid prices must be supplied.

Temperature is zero. Judge/Plan/opinion reasoning is medium; Explain/brief low.
Provider-independent SQLite keys include logical model, role, schema version,
schema/input and generation settings; live and injected-test caches are isolated.
All connections are explicitly closed, including temporary recording/eval caches
on Windows. Budgets live in the shared client and do not span processes/restarts.

Prompts: prompts/judge.txt (exact required untrusted-code warning), plan.txt,
explain.txt, brief.txt and second_opinion.txt. Names are allowlisted; snippets and
text are redacted offline with detect-secrets plus credential-prefix masking.
No redactor guarantees detection of every secret. Only Judge receives bounded
untrusted code. Plan/narratives/opinion use strict structured projections.

## Fact verification

The index maps evidence IDs to explicit typed facts: package, version, PURL,
advisory ID, fixed version, path, score, option ID, flag, count and status. Count
and status are provisional extensions needed to ground run summaries. Trusted
adapters must supply provenance-correct observations. Finding prose and AI text
never manufacture support, and a fact is not attached to every finding citation.

The Verifier checks evidence existence, typed fact membership under that exact
evidence, listed text tokens, known identities/pairs, option vetting, allowed
Judge flags, role-specific evidence scope and immutable Plan snapshots. Example:
`EV-021 does not support fixed_version 1.2.4` rejects a real but irrelevant
citation. Unknown/unlisted facts and invented versions also fail. Counts in
narratives are checked as integers after masking other structured token forms.

AIClaim records verified/errors and preserves human-review requirements. These
are bounded grounding checks, not proof of arbitrary prose semantics, causal
claims, negation, metric identity or the truth of every behavioral inference.
The UI must show facts only after failed verification and must not equate a
verified inference with permission to execute a fix.

## Judge, options and planning

Judge batches at most five eligible ambiguous findings, never vulnerabilities.
Distance-2 typosquats and medium GuardDog findings are eligible. Its schema
requires seven boolean flags, verdict, <=60-word rationale, facts and citations.
Every output passes the Verifier. Verified mentions_instructions_to_ai with
snippet provenance deterministically creates an additional High
prompt_injection_attempt / suspicious_change finding. Existing severities never
decrease; an unverified claim creates no derived finding.

Remediation candidates are deterministic: minimum compatible stable upgrades,
single-parent bumps when needed, captured baseline rollback and escalation.
Rust uses the owned Cargo SemVer subset; Python uses already-locked packaging
26.3. Output changes are declarative POSIX-relative edits, never shell commands.
Candidates start pending; they are not safe fixes just because they meet a
captured fix boundary. See remediate/README.md for supported range syntax/limits.

Vetting reuses existing functions through injected detector contracts and checks
each changed package. It covers candidate OSV scope, >=7-day age by default,
yanked/unknown status, publisher/source/provenance, dependency/name diffs, exact
index/PyPI-bound hashes, safe extraction and regex/Semgrep capability gains.
Missing evidence or scanner failures reject. Rejected options remain visible
with check evidence/reasons. All Rust source is conservatively inspected; custom
build paths, dynamic Python hooks and existing capability categories remain
coverage limits. Unknown current PyPI ownership/provenance blocks automatic fixes.
No live collector or scanner bootstrap was added. See remediate/VETTING.md.

Plan sees all supplied options with vetting results/reasons, never raw code or
Judge prose. It can choose only passed options or escalation. An option action or
vetting proof changed under an old ID fails snapshot checks. The output includes
<=80-word rationale, trade-offs and descriptive rollback steps. It never applies
commands; Module 3 alone applies/tests allowed options in the target sandbox.

## Summaries, briefs and opinions

Explain outputs <=200 summary words plus key points; brief outputs <=120 words
plus open questions. Inputs include structured run status/counts, top P0/P1
findings, decisions, verified plan choices and validation statuses. No prior AI
prose is accepted. Module 3 must render briefs under AI inference (unverified)
unless verified; disabled AI renders AI layer off / facts only.

Second opinion is P0-only and has its own structured prompt without Judge/Plan
text. It outputs a bounded risk enum and facts/citations. A severity difference
of at least one level forces human review, and opinion_disagrees is recomputed
by code. Priority, severity and policy decisions remain unchanged.

## Recorded fixtures, golden test and evaluation

tests/llm_recordings contains synthetic recorded-shape responses for every role,
explicitly labelled as not live transcripts. No test calls the live provider.
The offline golden test reads the inert Rust string from demo/prepare.py through
AST constants without executing it, wraps it in synthetic captured registry
metadata, generates/vets a candidate with real deterministic detector functions,
and runs all five role services using mocked responses. Semgrep is mocked.
It also checks cache reruns and rejects an adversarial unsupported Plan answer.

evaluation.py exports verify_catch_rate(fixtures_dir),
injection_resistance(fixtures_dir) and hallucination_count(claims,index=...).
The last helper re-verifies accepted claims instead of trusting their verified
flag; unconfigured verification raises rather than manufacturing a zero score.
Correctly rejected responses are counted separately from accepted hallucinations.
Injection metrics explicitly report recorded_replay and live_model_tested=false.
The current verifier corpus is 10 wrong + 3 correct marked Module 4 placeholders;
the injection corpus is three recorded replay cases. These small fixture metrics
are not estimates of real-model attack resistance or general hallucination rates.

Run the full suite with GUARDIAN_INTEGRATION=1 and
GUARDIAN_PLANTED_INTEGRATION=1 using `uv run --locked pytest -q`. Set
GUARDIAN_MODULE2_EVAL_OUTPUT to a JSON path under out/ to save the golden report.
The test controller must preserve/restore generated planted reports as existing
integration tests overwrite them. No target code compilation/execution is used.

## Manual local recording

`python -m guardian.llm.cli_ext --record --role explain --payload INPUT.json
--output tests/llm_recordings/explain.live.json` runs the actual guarded service.
The payload contains input and ledger rows with typed facts; Plan also supplies
options and Judge may supply snippets. Inspect this payload locally before
running. Credentials remain only in ignored .env. CI/GITHUB_ACTIONS recording is
blocked, and omitting --record fails before credentials/provider access. Output
is restricted to tests/llm_recordings JSON and includes actual origin/verification
status; an unverified recording is never declared verified by the recorder.
Temporary live caches ensure manual refresh does not return a prior cache entry.
The cli_ext.register(root_app) hook is ready for the lead; shared cli.py is untouched.

## Remaining owner integration

Module 1 must publish/adapt shared contracts, typed ledger/query projections,
run-scoped client/index lifecycle, detector/scanner bootstrap, orchestration,
max-two factual repairs, policy rechecks, persistence and UI/CLI wiring. The
Checkpoint 2 Judge remains the old Assessment adapter until that migration; it
does not provide the new role protections. Module 4 must replace provisional
fixtures and publish this guide at docs/MODULE-2.md, plus shared stack/rule updates.
Live provider/scanner evaluation and full-application acceptance remain separate
from these completed, offline-tested Module 2 components.

## Run it

```
python -m uv sync --python 3.12
.venv\Scripts\python -m guardian.llm.cli_ext demo          # whole Module 2 flow, offline
.venv\Scripts\python -m guardian.llm.cli_ext demo --json   # same, machine-readable
.venv\Scripts\python -m pytest -q                          # tests; no test calls a live LLM
```

The demo runs the planted-demo source through candidates, vetting, Judge, Plan, Explain,
brief and second opinion with a recorded-shape mock provider, then prints every claim with
its verified status, the accepted-hallucination count (0), the verifier catch rate (10/10
wrong caught, 3/3 correct accepted) and injection resistance (3/3). No network, no live
LLM, no target code is executed.

## Change requests for the lead (shared files this module may not edit)

- `guardian/cli.py`: discover each module's `cli_ext.register(app)` so `guardian llm demo`
  and `guardian llm record` appear (iterate `guardian.*.cli_ext`).
- `pyproject.toml`: pin `packaging` (currently only transitive). `docs/TECH_STACK.md`: record
  the in-house Cargo semver parser (`guardian/remediate/versions.py`).
- `rules/severity.yaml`: add `prompt_injection_attempt` (High). `rules/replacements.yaml`: optional.
- `guardian/detect/pipeline.py`: switch the Checkpoint 2 `Judge` to `VerifiedJudge`.
- Land `guardian/contracts`; replace the provisional models listed above.
- Priority integration: `guardian/remediate/priority_adapter.py` builds a `RemediationRequest`
  from the priority row and scan data (P0/P1 only); adjust once the real priority output lands.
