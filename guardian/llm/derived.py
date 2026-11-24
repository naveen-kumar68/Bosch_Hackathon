"""Deterministic code that turns Judge claims into findings. The AI never sets severity."""

import hashlib
import re

from guardian.detect.models import Finding
from guardian.verify.models import AIClaim

INJECTION_MARKERS = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)"
    r"|mark\s+(?:this\s+)?(?:as\s+)?(?:safe|benign)"
    r"|you\s+are\s+(?:an?\s+)?(?:ai|assistant|language model)"
    r"|(?:system|assistant)\s*(?:prompt|message)\s*:"
    r"|\bAI\s+(?:reviewer|scanner|assistant)\b"
    r"|\bnote\s+to\s+(?:the\s+)?(?:ai|llm|model|reviewer)\b"
    r"|[\"']verdict[\"']\s*:"
    r"|(?:^|\n)\W*(?:assistant|ai|llm|model|reviewer)\s*:"
    r"|report\s+success",
    re.IGNORECASE,
)


def injection_markers(text: str) -> bool:
    return bool(INJECTION_MARKERS.search(text or ""))


def findings_from_judge(claims: list[AIClaim]) -> list[Finding]:
    """One High prompt_injection_attempt per claim that flags instructions aimed at an AI."""
    derived = []
    for claim in claims:
        if claim.kind != "judge" or not claim.flags.get("mentions_instructions_to_ai"):
            continue
        evidence_ids = claim.payload.get("evidence_ids") or []
        if not evidence_ids:
            continue
        component = claim.payload.get("component", "unknown")
        digest = hashlib.sha256(f"prompt_injection:{claim.subject_id}".encode()).hexdigest()[:8]
        derived.append(
            Finding(
                finding_id=f"F-PI-{digest}",
                type="prompt_injection_attempt",
                component=component,
                description=(
                    "Package code contains text addressed to an AI or reviewer "
                    f"(source finding {claim.subject_id})."
                ),
                evidence_ids=list(evidence_ids),
                severity="high",
                severity_rule="prompt_injection_attempt",
                confidence="medium",
                needs_human_review=True,
                details={"category": "suspicious_change", "source_finding": claim.subject_id},
            )
        )
    return derived
