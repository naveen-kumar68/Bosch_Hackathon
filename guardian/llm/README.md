# Module 2 client — Phase 1

Phase 2 adds `claims.py`, a deterministic verifier in `guardian/verify/`, and
optional `previous_errors` on both completion entry points. See
`../verify/README.md` for provisional contracts, evidence adapter requirements,
repair ownership and limitations. Existing Judge migration remains Phase 3.

`client.complete(role, messages, schema, budget_key)` returns a Pydantic model,
`Usage`, and a cache-hit boolean. This validates structure, not factual accuracy.
The Verifier and AIClaim adapter belong to later phases. The existing Checkpoint 2
Judge remains unchanged until Phase 3.

Create a client with `create_completion_client(database)` and install it with
`configure_completion(client)`, or call a `CompletionClient` directly. Use one
client for the run and the same `budget_key` for every role in that run. Do not
recreate clients per finding; budgets are in memory and do not span processes or
survive restarts. Module 1 must own that lifecycle. No request happens at creation.
Catch `BudgetExceeded`, `LLMOutputError`, and `ProviderUnavailable` and show facts
only. No live request is made by the tests.

## Configuration

`config.json` is local to this module; it does not change shared configuration.
Credentials are loaded only from the ignored `.env`. The default provider uses
`LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL`. No provider is enabled when these
are missing. The default zero prices describe the configured free tier; configure
actual per-million-token prices before using a paid endpoint.

Add providers to the ordered `providers` array to enable fallback, using unique
`name`, `key_env`, `url_env`, and `model_env` entries. Set `json_schema` to the
provider's supported mode: true sends a strict JSON schema, false sends JSON mode
with the schema in the prompt. Both modes undergo Pydantic validation. All
providers in a list must implement the same logical `model_name`; change that
alias when changing the logical model. A schema hash and `schema_version` also
isolate cache entries.

Defaults: temperature 0; Judge/Plan reasoning medium, Explain/brief low;
1,500 output tokens per attempt; five attempts per run and per role; 150,000 input
and 10,000 output tokens per run/role; 24,000 request characters; 4,096 characters
and 60 lines per explicitly identified snippet. Configure `role_budgets` to
override any role's default budget. Retries and provider fallback consume budget.

On 429/5xx, the client waits and retries once, then waits before trying the next
provider. `Retry-After` supports seconds and HTTP dates. Other provider failures
try the next provider directly. Waits above the configured 60-second ceiling
fail closed. Invalid JSON/schema gets one repair with sanitised validation error
types and locations, without reflecting the raw answer or exception text.

## Trust boundaries

Send user data as structured dictionaries (JSON strings are also decoded), with
package names in `name`, `package`, or `package_name`, and snippets in `snippet`
or `code`. Names outside the specified allowlist become `<invalid-name>`. Free
Judge user text is treated as a snippet. Callers must provide only structured
data to other roles; this transport cannot determine whether arbitrary prose is
source code. Never put whole repositories or credentials in messages.

Text is redacted offline using detect-secrets, its actual entropy thresholds,
and common credential-prefix patterns. No credential verification requests are
allowed. Detection cannot guarantee finding every possible secret. Outputs are
redacted and schema-validated again before return and cache persistence.

Cache keys are provider-independent hashes of the logical model, role, schema
version/schema, canonical sanitised messages and generation settings. Live and
injected test transports use separate namespaces. Only successful validated
outputs are cached. Cache hits report zero calls/tokens/cost and the original
serving provider. Raw inputs and keys are never stored in the cache.

The client reserves UTF-8 byte-based input token estimates, framing allowance,
and the full output cap before a request. Successful reported usage replaces
reservations. Missing usage and failures retain conservative estimates; estimated
cost is marked with `Usage.estimated`. Free-tier prices yield zero cost. Input
token estimates are deliberately conservative and are not a model tokenizer.

## Requests for the lead

- Initialise and share the run-scoped client and stable run budget key across roles.
- Integrate the module-owned config into the shared config lifecycle if needed.
- Supply AIClaim contracts and usage/tracing fields; Phase 1 returns `Usage`
  separately and does not edit shared contracts or the CLI.
- Provide any additional provider settings locally. The shipped configuration
  enables only the existing environment provider; fallback is covered by mocks.
