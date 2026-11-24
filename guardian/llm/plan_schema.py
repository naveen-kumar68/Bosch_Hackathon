"""Strict provisional Plan projections; raw detector details/code are excluded."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian.llm.claims import FactReference


class ScoreTerm(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    name: str
    value: int | float
    evidence_ids: list[str] = Field(min_length=1)


class PlanFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    finding_id: str = Field(min_length=1)
    type: str
    component: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    priority: Literal["P0", "P1", "P2", "P3"]
    score_breakdown: list[ScoreTerm]
    paths: list[list[str]]
    decision: Literal["block_candidate", "needs_human", "auto_ok"]
    evidence_ids: list[str] = Field(min_length=1)


class PlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    chosen_option_id: str = Field(pattern=r"^O-[0-9a-f]{8}$")
    rationale: str
    trade_offs: list[str]
    rollback_steps: list[str]
    facts_used: list[FactReference]
    cited_evidence_ids: list[str] = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def rationale_limit(cls, value):
        if len(value.split()) > 80:
            raise ValueError("Plan rationale exceeds 80 words")
        return value
