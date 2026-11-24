"""Shared bounded transport for structured explanation/opinion roles."""

from dataclasses import dataclass
from pathlib import Path

from guardian.llm import completion as transport_module
from guardian.llm.claims import AIClaim, StructuredSource
from guardian.llm.completion import (
    BudgetExceeded,
    CompletionClient,
    LLMOutputError,
    ProviderUnavailable,
    Usage,
)
from guardian.verify import api as verify_api
from guardian.verify.facts import FactIndex


def evidence_scope(value):
    ids = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_ids":
                ids.update(item)
            elif key == "evidence_id":
                ids.add(item)
            else:
                ids.update(evidence_scope(item))
    elif isinstance(value, list):
        for item in value:
            ids.update(evidence_scope(item))
    return ids


@dataclass
class RoleCall:
    role: str
    subject_id: str
    usage: Usage
    cached: bool


class StructuredRoleService:
    def __init__(
        self, client: CompletionClient | None, index: FactIndex, *, budget_key: str, enabled=True
    ):
        self.client, self.index, self.budget_key, self.enabled = client, index, budget_key, enabled
        self.trace: list[RoleCall] = []
        self.events: list[str] = []

    @property
    def available(self):
        return self.enabled and self.client is not None

    def _source(self, kind, projection, subject_id, finding_id=None, severity=None, priority=None):
        evidence = sorted(evidence_scope(projection.model_dump()))
        if not evidence or not set(evidence) <= self.index.by_evidence.keys():
            raise ValueError("Structured context requires indexed evidence")
        return StructuredSource(
            kind=kind,
            subject_id=subject_id,
            finding_id=finding_id,
            evidence_ids=evidence,
            severity=severity,
            priority=priority,
        )

    def _run(self, projection, schema, source, previous_errors):
        packet = {
            "context": projection.model_dump(),
            "facts": [fact.model_dump() for fact in self.index.references(source.evidence_ids)],
        }
        prompt = (
            Path(__file__)
            .with_name("prompts")
            .joinpath(source.kind + ".txt")
            .read_text("utf-8")
            .strip()
        )
        try:
            output, usage, cached = self.client.complete(
                source.kind,
                [{"role": "system", "content": prompt}, {"role": "user", "content": packet}],
                schema,
                self.budget_key,
                previous_errors=previous_errors,
            )
        except (BudgetExceeded, ProviderUnavailable, LLMOutputError) as exc:
            self.events.append(f"{source.kind} facts-only fallback: {type(exc).__name__}")
            return None
        self.trace.append(RoleCall(source.kind, source.subject_id, usage, cached))
        claim = AIClaim(kind=source.kind, finding_id=source.finding_id, **output.model_dump())
        claim.origin = (
            "live" if self.client.transport is transport_module.sdk_transport else "recorded_test"
        )
        claim.structured_source = source
        return verify_api.check(claim, index=self.index)
