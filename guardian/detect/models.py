from typing import Literal

from pydantic import Field, field_validator

from guardian.models import Model

Severity = Literal["info", "low", "medium", "high", "critical"]


class Assessment(Model):
    label: Literal["AI inference"] = "AI inference"
    origin: Literal["live", "recorded_test"] = "live"
    finding_id: str
    verdict: Literal["benign", "suspicious", "malicious", "unknown"]
    confidence: float = Field(ge=0, le=1)
    rationale: str
    cited_evidence_ids: list[str] = Field(min_length=1)
    needs_human_review: bool = True

    @field_validator("rationale")
    @classmethod
    def limit_words(cls, value):
        if len(value.split()) > 80:
            raise ValueError("Rationale exceeds 80 words")
        return value


class Finding(Model):
    finding_id: str
    type: str
    component: str
    description: str
    paths: list[list[str]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)
    severity: Severity
    severity_rule: str
    confidence: Literal["high", "medium", "low"]
    ai_assessment: Assessment | None = None
    needs_judgement: bool = False
    needs_human_review: bool = True
    details: dict = Field(default_factory=dict)


class Vulnerability(Model):
    id: str
    aliases: list[str]
    component: str
    evidence_ids: list[str] = Field(min_length=1)
    sources: list[str] = Field(min_length=1)
    vectors: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    severity: Severity = "medium"
    cvss_score: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool | None = None
