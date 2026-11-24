# Module 2 — Phase 7 summaries and investigation briefs

`Narrator(client, index, budget_key=run_id)` provides `explain(run)` and
`explain_brief(brief_struct)`. The facade exposes the same functions after
`api.configure_explain(service)` or with an explicit service. Disabled AI, no
client, exhausted budgets, unavailable providers and irreparable schema failures
return None; callers render "AI layer off" or facts only. The disabled path does
not validate input or access credentials. No live provider calls occur in tests.

Inputs are strict structured projections in structured_schema.py. A run includes
status, named counts, top P0/P1 findings, verified plan choices without AI text,
decisions and validation statuses/evidence. Briefs carry a deterministic finding
and typed observations. No raw source, logs, arbitrary dictionaries, Judge prose
or Plan rationale is accepted. Trusted adapters must populate these projections;
the types cannot semantically distinguish arbitrary prose hidden inside strings.

Explain returns a <=200-word summary, key_points, facts_used and citations.
Brief returns a <=120-word summary, open_questions, facts_used and citations.
The common client handles temperature, role-specific reasoning, budgets, cache,
redaction and one JSON/schema repair. `previous_errors` supports the lead's
external factual repair loop. Every output becomes AIClaim and is checked by
verify.api.check, including a persisted structured-source evidence scope.
Unverified claims retain exact errors and require human review.

Counts and statuses are provisional typed facts: count is a non-negative integer;
status is a non-empty string. Run status/count inputs require matching typed
evidence before export. The Verifier also scans standalone narrative integers
after masking advisories, versions, decimals, PURLs, paths and option IDs; they
must be listed in facts_used. Existing fact-token/semantic limitations still
apply: numeric membership does not prove metric identity or causal relations.

Lead/Module 3 requests: map shared run/brief contracts to these projections,
record status/count observations in the ledger, extend shared Fact/AIClaim with
count/status and structured-source fields, and wire services/storage/traces.
Module 3 must render brief text under "AI inference (unverified)" unless verified;
the AI-off path renders "AI layer off". No shared UI or pipeline was modified.
