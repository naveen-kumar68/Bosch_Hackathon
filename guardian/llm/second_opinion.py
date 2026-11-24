"""Independent structured P0 opinions; no Judge or Plan prose enters this role."""

from typing import Literal

from pydantic import Field

from guardian.llm.claims import FactReference
from guardian.llm.plan_schema import PlanFinding
from guardian.llm.structured import StructuredRoleService
from guardian.llm.structured_schema import Model
from guardian.verify.facts import record


class OpinionResponse(Model):
    risk_opinion: Literal["low", "medium", "high", "critical", "needs_review"]
    facts_used: list[FactReference]
    cited_evidence_ids: list[str] = Field(min_length=1)


class SecondOpinion(StructuredRoleService):
    def second_opinion(self, pf, *, previous_errors=None):
        if not self.available:
            return None
        projection = PlanFinding.model_validate(record(pf))
        if projection.priority != "P0":
            return None
        source = self._source(
            "second_opinion",
            projection,
            projection.finding_id,
            projection.finding_id,
            projection.severity,
            projection.priority,
        )
        return self._run(projection, OpinionResponse, source, previous_errors)
