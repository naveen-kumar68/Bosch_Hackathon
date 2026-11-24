"""Deterministic additional findings; never edits or resolves source findings."""

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian.llm.claims import AIClaim
from guardian.llm.completion import canonical


class Finding(BaseModel):
    """Provisional shared Finding projection, pending the lead's contracts."""

    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str
    type: Literal["prompt_injection_attempt"] = "prompt_injection_attempt"
    category: Literal["suspicious_change"] = "suspicious_change"
    component: str
    description: str = "AI Judge flagged possible prompt injection in package code."
    paths: list[list[str]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)
    severity: Literal["high"] = "high"
    severity_rule: Literal["prompt_injection_attempt"] = "prompt_injection_attempt"
    confidence: Literal["low"] = "low"
    needs_human_review: bool = True
    needs_judgement: bool = False
    details: dict = Field(default_factory=dict)


def findings_from_judge(claims: list[AIClaim]) -> list[Finding]:
    findings = {}
    for claim in claims:
        source = claim.judge_source
        if (
            claim.kind != "judge"
            or not claim.verified
            or claim.errors
            or source is None
            or claim.finding_id != source.finding_id
            or source.response_errors
            or claim.flags.get("mentions_instructions_to_ai") is not True
        ):
            continue
        evidence = sorted(
            set(source.snippet_evidence_ids)
            & set(claim.cited_evidence_ids)
            & set(source.evidence_ids)
        )
        if not evidence:
            continue
        identity = ["prompt_injection_attempt", source.finding_id, source.component, evidence]
        identifier = "F-" + hashlib.sha256(canonical(identity).encode("utf-8")).hexdigest()[:12]
        findings[identifier] = Finding(
            finding_id=identifier,
            component=source.component,
            paths=[list(path) for path in source.paths],
            evidence_ids=evidence,
            details={
                "source_finding_id": source.finding_id,
                "origin": claim.origin,
                "label": "AI inference",
                "derived_by": "guardian.llm.derived",
            },
        )
    return [findings[key] for key in sorted(findings)]
