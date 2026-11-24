"""Choose only code-made, vetted options; no target edits or execution surface."""

from dataclasses import dataclass
from pathlib import Path

from packageurl import PackageURL

from guardian.llm import completion as transport_module
from guardian.llm.claims import AIClaim, FactReference, PlanSource
from guardian.llm.completion import (
    BudgetExceeded,
    CompletionClient,
    LLMOutputError,
    ProviderUnavailable,
    Usage,
)
from guardian.llm.plan_schema import PlanFinding, PlanResponse
from guardian.remediate.models import FixOption
from guardian.verify import api as verify_api
from guardian.verify.facts import FactIndex, option_fingerprint, record

SYSTEM = Path(__file__).with_name("prompts").joinpath("plan.txt").read_text("utf-8").strip()


@dataclass
class PlanCall:
    finding_id: str
    usage: Usage
    cached: bool


class Planner:
    def __init__(
        self,
        client: CompletionClient | None,
        index: FactIndex,
        *,
        budget_key: str,
        enabled: bool = True,
    ):
        self.client, self.index = client, index
        self.budget_key, self.enabled = budget_key, enabled
        self.trace: list[PlanCall] = []
        self.events: list[str] = []

    def plan(self, pf, options, *, previous_errors: list[str] | None = None) -> AIClaim:
        if previous_errors is not None and (
            not isinstance(previous_errors, list)
            or not all(isinstance(error, str) for error in previous_errors)
        ):
            raise TypeError("previous_errors must be a list of strings")
        finding = PlanFinding.model_validate(record(pf))
        parsed = sorted(
            [FixOption.model_validate(record(option)) for option in options],
            key=lambda option: option.option_id,
        )
        source, escalation = self._scope(finding, parsed)
        if not any(option.kind != "escalate" and option.vetting == "passed" for option in parsed):
            return self._escalate(
                source, escalation, "No vetted fix is available; request human review."
            )
        if not self.enabled or self.client is None:
            return self._escalate(source, escalation, "AI Plan is off; request human review.")
        facts = [
            FactReference(
                type=kind, value=float(value) if kind == "score" else value, evidence_id=identifier
            ).model_dump()
            for identifier in sorted(source.evidence_ids)
            for kind, value in sorted(self.index.by_evidence[identifier])
        ]
        # Only explicitly projected fields are sent: no Judge prose, raw detector
        # details, snippets or arbitrary payload objects can enter this message.
        packet = {
            "finding": finding.model_dump(),
            "options": [option.model_dump(exclude={"vetting_checks"}) for option in parsed],
            "constraints": {
                "prefer_smallest_change": True,
                "avoid_major_jumps_unless_needed": True,
            },
            "facts": facts,
        }
        try:
            output, usage, cached = self.client.complete(
                "plan",
                [{"role": "system", "content": SYSTEM}, {"role": "user", "content": packet}],
                PlanResponse,
                self.budget_key,
                previous_errors=previous_errors,
            )
        except (BudgetExceeded, ProviderUnavailable, LLMOutputError) as exc:
            self.events.append(f"Plan facts-only fallback: {type(exc).__name__}")
            return self._escalate(
                source, escalation, "AI Plan is unavailable; request human review."
            )
        self.trace.append(PlanCall(finding.finding_id, usage, cached))
        claim = AIClaim(kind="plan", finding_id=finding.finding_id, **output.model_dump())
        claim.origin = (
            "live" if self.client.transport is transport_module.sdk_transport else "recorded_test"
        )
        claim.plan_source = source
        return verify_api.check(claim, index=self.index)

    def _scope(self, finding, options):
        purl = PackageURL.from_string(finding.component)
        if not purl.version:
            raise ValueError("Plan finding requires a versioned component")
        ids = [option.option_id for option in options]
        if len(set(ids)) != len(ids):
            raise ValueError("Plan requires unique option IDs")
        escalation = [option for option in options if option.kind == "escalate"]
        if len(escalation) != 1 or escalation[0].changes:
            raise ValueError("Plan requires exactly one escalation option with no changes")
        for option in options:
            if option.finding_id != finding.finding_id or option.component != finding.component:
                raise ValueError("Plan option belongs to another finding or component")
            indexed = self.index.options.get(option.option_id)
            if indexed is None or indexed.kind != option.kind or indexed.vetting != option.vetting:
                raise ValueError("Plan options must match current fact-index vetting states")
            if indexed.fingerprint != option_fingerprint(record(option)):
                raise ValueError("Plan option snapshot does not match the fact index")
            for identifier in option.evidence_ids:
                fact = FactReference(
                    type="option_id", value=option.option_id, evidence_id=identifier
                )
                if not self.index.supports(fact):
                    raise ValueError("Plan option evidence is not indexed")
        evidence = sorted(
            {
                *finding.evidence_ids,
                *(e for term in finding.score_breakdown for e in term.evidence_ids),
                *(e for option in options for e in option.evidence_ids),
            }
        )
        if not set(evidence) <= self.index.by_evidence.keys():
            raise ValueError("Plan context references unindexed evidence")
        return PlanSource(
            finding_id=finding.finding_id,
            component=finding.component,
            option_ids=ids,
            option_fingerprints={
                option.option_id: option_fingerprint(record(option)) for option in options
            },
            evidence_ids=evidence,
        ), escalation[0]

    def _escalate(self, source, escalation, rationale):
        identifier = min(escalation.evidence_ids)
        claim = AIClaim(
            kind="plan",
            finding_id=source.finding_id,
            chosen_option_id=escalation.option_id,
            rationale=rationale,
            trade_offs=[],
            rollback_steps=["Request human review before changing dependencies."],
            facts_used=[
                FactReference(type="option_id", value=escalation.option_id, evidence_id=identifier)
            ],
            cited_evidence_ids=[identifier],
            origin="deterministic",
            plan_source=source,
        )
        return verify_api.check(claim, index=self.index)
