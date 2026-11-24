# Module 2 — Phase 8 independent P0 opinions

`SecondOpinion(client,index,budget_key=run_id).second_opinion(pf)` accepts the
strict deterministic PlanFinding projection. Non-P0 inputs, disabled AI and
unavailable/budget/schema-failed providers return None. The facade is available
after api.configure_second_opinion or with an explicit service. No snippets,
Judge prose or Plan text are accepted. Its separate prompt is
prompts/second_opinion.txt.

Output is risk_opinion (low/medium/high/critical/needs_review), facts_used and
citations. It becomes an AIClaim with persisted structured evidence scope and
is always verified. The common client enforces a hard maximum of three actual
second_opinion provider attempts per run, even if configured higher. Retries
and provider fallback count; cache hits cost zero. Sharing one run-scoped client
prevents recreating the role service from resetting the budget. Creating new
clients or run IDs is the lead's lifecycle responsibility.

The verifier recomputes opinion_disagrees by ordinal severity difference. A
difference of one level or more forces needs_human_review, even if the prior
claim's review flag was false. needs_review also requires review. Agreeing
opinions retain the existing conservative human-review default. Nothing changes
the finding's severity, priority, confidence or policy decision.

Lead requests: add runtime opinion_disagrees and source severity/priority to
shared AIClaim contracts, configure the service with the existing run client and
index, persist trace/cache usage, and render disagreement without overriding
deterministic prioritisation. Synthetic recorded tests check P0 filtering,
agreement/disagreement, independent structured input, strict schemas and the
shared three-attempt bound; they are not a live model accuracy evaluation.
