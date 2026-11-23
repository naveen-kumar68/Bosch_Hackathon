# Checkpoint 2 progress

Status: tool verification in progress; risk detectors not implemented yet.

Checkpoint 1 is the base branch of this work, with PR #1 open and unmerged.
Native Windows remains the owner-approved environment. Rust context-preserving
path queries now pass four real-crate oracle comparisons; 34 acceptance and
fixture tests pass, as do lint and formatting.

## Decisions pending

- Owner approved pinned scanner-only Docker images with read-only target data.
  Target code remains prohibited from execution. Scanner smoke checks pending.
- Live Judge verification needs provider configuration in the ignored `.env`.
  No key is requested in chat and no live call has been made.
- Graph screenshot remains pending because desktop approval review hit an
  account usage limit. This does not block tool discovery or deterministic tests.

No Checkpoint 2 acceptance criterion is claimed complete at this stage.
