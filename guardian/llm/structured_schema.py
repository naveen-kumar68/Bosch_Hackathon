"""Strict code-only projections; no logs, source snippets or AI prose."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian.llm.claims import FactReference
from guardian.llm.plan_schema import PlanFinding


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class RunCount(Model):
    name: str
    value: int = Field(ge=0)
    evidence_ids: list[str] = Field(min_length=1)


class ChosenPlan(Model):
    finding_id: str
    chosen_option_id: str = Field(pattern=r"^O-[0-9a-f]{8}$")
    verified: Literal[True]
    evidence_ids: list[str] = Field(min_length=1)


class ValidationSummary(Model):
    option_id: str = Field(pattern=r"^O-[0-9a-f]{8}$")
    status: Literal["passed", "failed", "not_run", "inconclusive", "blocked"]
    evidence_ids: list[str] = Field(min_length=1)


class RunSummary(Model):
    run_id: str
    status: Literal["complete", "partial", "failed", "blocked", "running"]
    counts: list[RunCount]
    top_findings: list[PlanFinding]
    plans: list[ChosenPlan]
    validations: list[ValidationSummary]
    evidence_ids: list[str] = Field(min_length=1)

    @field_validator("top_findings")
    @classmethod
    def top_priorities(cls, values):
        if any(f.priority not in {"P0", "P1"} for f in values):
            raise ValueError("Run summary top findings must be P0 or P1")
        return values


class BriefInput(Model):
    finding: PlanFinding
    observations: list[FactReference]
    evidence_ids: list[str] = Field(min_length=1)


class ExplainResponse(Model):
    summary: str
    key_points: list[str]
    facts_used: list[FactReference]
    cited_evidence_ids: list[str] = Field(min_length=1)

    @field_validator("summary")
    @classmethod
    def word_limit(cls, value):
        if len(value.split()) > 200:
            raise ValueError("Run summary exceeds 200 words")
        return value


class BriefResponse(Model):
    summary: str
    open_questions: list[str]
    facts_used: list[FactReference]
    cited_evidence_ids: list[str] = Field(min_length=1)

    @field_validator("summary")
    @classmethod
    def word_limit(cls, value):
        if len(value.split()) > 120:
            raise ValueError("Brief exceeds 120 words")
        return value
