"""Provisional Module 2 shapes; replace with shared contracts when they land.

ClaimContent is provider output. AIClaim adds verifier-owned fields which must
never be requested from an LLM. This file does not modify guardian/contracts.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

FactType = Literal[
    "package",
    "version",
    "purl",
    "advisory_id",
    "fixed_version",
    "path",
    "score",
    "option_id",
    "flag",
    "count",
    "status",
]


class Fact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False, frozen=True)
    type: FactType
    value: str | int | float | bool

    @field_validator("value")
    @classmethod
    def typed_value(cls, value, info):
        if info.data.get("type") == "score":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("Score facts require a finite number")
        elif info.data.get("type") == "count":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("Count facts require a non-negative integer")
        elif not isinstance(value, str) or not value.strip():
            raise ValueError("Non-score facts require a non-empty string")
        return value


class FactReference(Fact):
    evidence_id: str = Field(min_length=1)


class ClaimContent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    kind: Literal["judge", "plan", "explain", "brief", "second_opinion"]
    finding_id: str | None = None
    facts_used: list[FactReference]
    cited_evidence_ids: list[str]
    verdict: Literal["benign", "suspicious", "malicious", "unknown"] | None = None
    flags: dict[str, bool] = Field(default_factory=dict)
    rationale: str = ""
    summary: str = ""
    key_points: list[str] = Field(default_factory=list)
    trade_offs: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    chosen_option_id: str | None = None
    risk_opinion: Literal["low", "medium", "high", "critical", "needs_review"] | None = None


class JudgeSource(BaseModel):
    """Runtime provenance supplied by code, never by a provider response."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    finding_id: str
    component: str
    evidence_ids: list[str]
    snippet_evidence_ids: list[str]
    paths: list[list[str]] = Field(default_factory=list)
    response_errors: list[str] = Field(default_factory=list)


class PlanSource(BaseModel):
    """Runtime Plan scope, never fields in a provider response schema."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    finding_id: str
    component: str
    option_ids: list[str]
    option_fingerprints: dict[str, str]
    evidence_ids: list[str]


class StructuredSource(BaseModel):
    """Code-owned scope for structured narrative/opinion roles."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["explain", "brief", "second_opinion"]
    subject_id: str
    finding_id: str | None = None
    evidence_ids: list[str]
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    priority: Literal["P0", "P1", "P2", "P3"] | None = None


class AIClaim(ClaimContent):
    verified: bool = False
    errors: list[str] = Field(default_factory=list)
    needs_human_review: bool = True
    origin: Literal["live", "recorded_test", "deterministic"] = "live"
    judge_source: JudgeSource | None = None
    plan_source: PlanSource | None = None
    structured_source: StructuredSource | None = None
    opinion_disagrees: bool | None = None
