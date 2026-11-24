"""Verified summaries from structured facts; disabled AI returns None."""

from guardian.llm.claims import FactReference
from guardian.llm.structured import StructuredRoleService
from guardian.llm.structured_schema import BriefInput, BriefResponse, ExplainResponse, RunSummary
from guardian.verify.facts import record


class Narrator(StructuredRoleService):
    def explain(self, run, *, previous_errors=None):
        if not self.available:
            return None
        projection = RunSummary.model_validate(record(run))
        source = self._source("explain", projection, projection.run_id)
        if not any(
            self.index.supports(
                FactReference(type="status", value=projection.status, evidence_id=e)
            )
            for e in projection.evidence_ids
        ):
            raise ValueError("Run status requires typed evidence")
        for count in projection.counts:
            if not any(
                self.index.supports(FactReference(type="count", value=count.value, evidence_id=e))
                for e in count.evidence_ids
            ):
                raise ValueError("Run count requires typed evidence")
        return self._run(projection, ExplainResponse, source, previous_errors)

    def explain_brief(self, brief_struct, *, previous_errors=None):
        if not self.available:
            return None
        projection = BriefInput.model_validate(record(brief_struct))
        if any(not self.index.supports(fact) for fact in projection.observations):
            raise ValueError("Brief observation is unsupported")
        source = self._source(
            "brief", projection, projection.finding.finding_id, projection.finding.finding_id
        )
        return self._run(projection, BriefResponse, source, previous_errors)
