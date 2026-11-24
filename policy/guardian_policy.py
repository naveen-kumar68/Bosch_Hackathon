"""Approval rules for Supply Chain Guardian (plain Python, no OPA needed).

decision is one of: "block_candidate", "needs_human", "auto_ok".
  block   : integrity_mismatch, or AI judged the code malicious
  human   : P0, confidence < 0.7, AI-only finding, or anything blocked
  auto    : P3 with confidence >= 0.8 and no human needed
  default : needs_human
"""


def _flags(finding):
    return finding.get("flags") or {}


def is_block(finding):
    return (
        finding.get("type") == "integrity_mismatch"
        or _flags(finding).get("ai_verdict") == "malicious"
    )


def needs_human(finding):
    confidence = finding.get("confidence")
    return (
        finding.get("priority") == "P0"
        or (confidence is not None and confidence < 0.7)
        or _flags(finding).get("ai_only") is True
        or is_block(finding)
    )


def is_auto(finding):
    confidence = finding.get("confidence")
    return (
        finding.get("priority") == "P3"
        and confidence is not None
        and confidence >= 0.8
        and not needs_human(finding)
    )


def decide(finding):
    if is_block(finding):
        return "block_candidate"
    if needs_human(finding):
        return "needs_human"
    if is_auto(finding):
        return "auto_ok"
    return "needs_human"


def reasons(finding):
    out = []
    confidence = finding.get("confidence")
    if finding.get("type") == "integrity_mismatch":
        out.append("integrity mismatch (same version, different contents)")
    if _flags(finding).get("ai_verdict") == "malicious":
        out.append("AI judged the code malicious")
    if finding.get("priority") == "P0":
        out.append("P0 priority")
    if confidence is not None and confidence < 0.7:
        out.append("confidence below 0.7")
    if _flags(finding).get("ai_only") is True:
        out.append("finding rests only on AI inference")
    return out