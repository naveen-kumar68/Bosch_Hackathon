"""Quarantined Judge: the only role that sees untrusted code. Advisory, never lowers severity."""

import re
from pathlib import Path

from guardian.llm.completion import BudgetExceeded, LLMOutputError, ProviderUnavailable
from guardian.llm.derived import injection_markers
from guardian.llm.judge_schema import JudgeBatch
from guardian.llm.sanitise import package_name, redact
from guardian.verify import AIClaim, FactsIndex, check
from guardian.verify.facts import split_component
from guardian.verify.repair import with_repair

PROMPTS = Path(__file__).with_name("prompts")
BATCH_SIZE = 5
MAX_LINES = 56  # leaves room for the two delimiter lines inside the client's 60-line cap
MAX_CHARS = 3900  # leaves room for delimiters inside the client's 4096-char cap
DELIMITER = re.compile(r"</?\s*UNTRUSTED_CODE\s*>", re.IGNORECASE)


def prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def quarantine_snippet(text: str) -> str:
    """Redact, neutralise delimiter spoofing, bound size, then wrap in clear delimiters."""
    body = DELIMITER.sub("[delimiter removed]", redact("\n".join(text.splitlines()[:MAX_LINES])))
    return "<UNTRUSTED_CODE>\n" + body[:MAX_CHARS] + "\n</UNTRUSTED_CODE>"


def eligible(finding) -> bool:
    return bool(finding.needs_judgement) and finding.type != "vulnerability"


class QuarantinedJudge:
    def __init__(self, client, budget_key: str, index: FactsIndex):
        self.client, self.budget_key, self.index = client, budget_key, index

    def _item(self, finding, snippet):
        return {
            "finding_id": finding.finding_id,
            "type": finding.type,
            "package": package_name(split_component(finding.component)[0]),
            "rule": finding.severity_rule,
            "evidence_ids": finding.evidence_ids,
            "snippet": quarantine_snippet(snippet),
        }

    def assess(
        self,
        items: list[tuple],
        previous_errors: dict[str, list[str]] | None = None,
    ) -> list[AIClaim]:
        """items: (finding, raw snippet). Returns checked claims; skips batches when AI is off."""
        claims: list[AIClaim] = []
        eligible_items = [(f, s) for f, s in items if eligible(f)]
        for start in range(0, len(eligible_items), BATCH_SIZE):
            batch = eligible_items[start : start + BATCH_SIZE]
            errors = [e for f, _ in batch for e in (previous_errors or {}).get(f.finding_id, [])]
            messages = with_repair(
                [
                    {"role": "system", "content": prompt("judge.txt")},
                    {"role": "system", "content": prompt("judge_rules.txt")},
                    {"role": "user", "content": {"findings": [self._item(f, s) for f, s in batch]}},
                ],
                errors,
            )
            try:
                parsed, _usage, _cached = self.client.complete(
                    "judge", messages, JudgeBatch, self.budget_key
                )
            except (BudgetExceeded, LLMOutputError, ProviderUnavailable):
                continue  # facts-only for this batch
            claims.extend(self._claims(parsed, batch))
        return claims

    def _claims(self, parsed: JudgeBatch, batch) -> list[AIClaim]:
        by_id = {f.finding_id: (f, s) for f, s in batch}
        seen, out = set(), []
        for item in parsed.items:
            if item.finding_id not in by_id or item.finding_id in seen:
                continue
            seen.add(item.finding_id)
            finding, snippet = by_id[item.finding_id]
            flags = item.flags.model_dump()
            forced = injection_markers(snippet) and not flags["mentions_instructions_to_ai"]
            if forced:  # code may only raise flags, never lower them
                flags["mentions_instructions_to_ai"] = True
            claim = AIClaim(
                kind="judge",
                subject_id=finding.finding_id,
                text=item.rationale,
                facts_used=item.facts_used,
                cited_evidence_ids=item.cited_evidence_ids,
                flags=flags,
                payload={
                    "verdict": item.verdict,
                    "component": finding.component,
                    "evidence_ids": list(finding.evidence_ids),
                    "flag_forced_by_code": forced,
                },
            )
            checked = check(claim, self.index)
            stray = sorted(set(item.cited_evidence_ids) - set(finding.evidence_ids))
            if stray:
                errors = [
                    *checked.errors,
                    f"evidence {', '.join(stray)} is not part of this finding",
                ]
                checked = checked.model_copy(update={"verified": False, "errors": errors})
            out.append(checked)
        return out
