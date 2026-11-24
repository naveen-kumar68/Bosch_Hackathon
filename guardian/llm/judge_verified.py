"""Verified batch Judge. All inputs come from caller-owned trusted adapters.

The Checkpoint 2 Judge remains a legacy adapter until the lead migrates shared
pipeline/report contracts. This implementation never returns that Assessment.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field

from guardian.llm import completion as transport_module
from guardian.llm.claims import AIClaim, JudgeSource
from guardian.llm.completion import (
    BudgetExceeded,
    CompletionClient,
    LLMOutputError,
    ProviderUnavailable,
    Usage,
    canonical,
)
from guardian.llm.derived import injection_markers
from guardian.llm.judge_schema import JudgeBatch
from guardian.llm.sanitise import package_name, snippet
from guardian.verify import api as verify_api
from guardian.verify.facts import FactIndex, fact_value, record

SYSTEM = Path(__file__).with_name("prompts").joinpath("judge.txt").read_text("utf-8").strip()
CAPABILITY_TYPES = frozenset(
    {
        "capability_added",
        "capability_changed",
        "new_build_dependency_with_network_capability",
    }
)


class Candidate(BaseModel):
    """Provisional Finding projection; does not read or trust AI assessments."""

    model_config = ConfigDict(extra="ignore", strict=True)
    finding_id: str = Field(min_length=1, max_length=128)
    type: str
    component: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    severity_rule: str
    evidence_ids: list[str] = Field(min_length=1)
    paths: list[list[str]] = Field(default_factory=list)
    details: dict = Field(default_factory=dict)
    needs_judgement: bool = False


class Snippet(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str
    evidence_id: str = Field(min_length=1)


@dataclass
class JudgeCall:
    finding_ids: list[str]
    usage: Usage
    cached: bool


def eligible(candidate: Candidate) -> bool:
    if not candidate.needs_judgement:
        return False
    if candidate.type in CAPABILITY_TYPES:
        return True
    if candidate.type in {"typosquat", "typosquat_added"}:
        matches = candidate.details.get("matches", [])
        return isinstance(matches, list) and any(
            isinstance(hit, dict) and type(hit.get("distance")) is int and hit["distance"] == 2
            for hit in matches
        )
    return candidate.type == "guarddog" and candidate.severity == "medium"


class VerifiedJudge:
    def __init__(
        self, client: CompletionClient, index: FactIndex, *, budget_key: str, enabled: bool = True
    ):
        self.client, self.index = client, index
        self.budget_key, self.enabled = budget_key, enabled
        self.trace: list[JudgeCall] = []
        self.events: list[str] = []

    def _packet(self, candidate: Candidate, code: Snippet | None):
        allowed = set(candidate.evidence_ids)
        if not allowed <= self.index.by_evidence.keys():
            self.events.append(f"Judge skipped {candidate.finding_id}: unknown source evidence")
            return None
        if candidate.type in CAPABILITY_TYPES and code is None:
            self.events.append(f"Judge skipped {candidate.finding_id}: snippet evidence required")
            return None
        if code and code.evidence_id not in allowed:
            self.events.append(f"Judge skipped {candidate.finding_id}: snippet evidence not bound")
            return None
        try:
            purl = PackageURL.from_string(candidate.component)
        except ValueError:
            self.events.append(f"Judge skipped {candidate.finding_id}: invalid component")
            return None
        name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
        matches = []
        if candidate.type in {"typosquat", "typosquat_added"}:
            matches = [
                {"package_name": package_name(hit["popular_name"]), "distance": 2}
                for hit in candidate.details.get("matches", [])
                if isinstance(hit, dict)
                and hit.get("distance") == 2
                and isinstance(hit.get("popular_name"), str)
            ][:5]
        relevant_names = {name, *(match["package_name"] for match in matches)}
        observations = [
            {
                "type": kind,
                "value": fact_value(kind, value),
                "evidence_id": identifier,
            }
            for identifier in sorted(allowed)
            for kind, value in sorted(self.index.by_evidence[identifier])
            if kind != "package" or value in relevant_names
        ]
        packet = {
            "finding_id": candidate.finding_id,
            "type": candidate.type,
            "metadata": {
                "package_name": package_name(name),
                "version": purl.version,
                "ecosystem": purl.type,
            },
            "rule": candidate.severity_rule,
            "severity": candidate.severity,
            "paths": candidate.paths[:5],
            "evidence_ids": sorted(allowed),
            "facts": observations[:64],
            "facts_truncated": len(observations) > 64,
        }
        if matches:
            packet["metadata"]["matches"] = matches
        if code:
            body = snippet(code.text, min(4096, self.client.config.max_snippet_chars))
            # JSON encoding already prevents structural breakout. Neutralise literal
            # delimiters too, so a comment cannot visually impersonate the end marker.
            body = body.replace("<UNTRUSTED_PACKAGE_CODE", "[escaped begin marker]")
            body = body.replace("</UNTRUSTED_PACKAGE_CODE", "[escaped end marker]")
            body = body[: min(4096, self.client.config.max_snippet_chars)]
            packet["snippet_evidence_id"] = code.evidence_id
            packet["untrusted_code"] = (
                "<UNTRUSTED_PACKAGE_CODE>\n" + body + "\n</UNTRUSTED_PACKAGE_CODE>"
            )
        return packet

    def judge(
        self,
        findings: Iterable,
        *,
        snippets: Mapping[str, Snippet | dict] | None = None,
        previous_errors: list[str] | None = None,
    ) -> list[AIClaim]:
        if not self.enabled:
            return []
        snippets = snippets or {}
        selected = []
        seen = set()
        for value in findings:
            candidate = Candidate.model_validate(record(value))
            if not eligible(candidate):
                continue
            if candidate.finding_id in seen:
                raise ValueError("Judge input contains duplicate finding IDs")
            seen.add(candidate.finding_id)
            code = snippets.get(candidate.finding_id)
            if code is not None and not isinstance(code, Snippet):
                code = Snippet.model_validate(code)
            packet = self._packet(candidate, code)
            if packet is not None:
                selected.append((candidate, code, packet))
        selected.sort(key=lambda entry: entry[0].finding_id)
        results = []
        batch = []
        # Reserve room for both schema occurrences, common instructions and framing.
        payload_limit = (
            self.client.config.max_input_chars
            - 2 * len(canonical(JudgeBatch.model_json_schema()))
            - 2500
        )
        for entry in selected:
            tentative = [item[2] for item in [*batch, entry]]
            if batch and (len(batch) == 5 or len(canonical({"items": tentative})) > payload_limit):
                results.extend(self._assess_batch(batch, previous_errors))
                batch = []
            batch.append(entry)
        if batch:
            results.extend(self._assess_batch(batch, previous_errors))
        return results

    def _assess_batch(self, batch, previous_errors):
        ids = [entry[0].finding_id for entry in batch]
        messages = [
            {"role": "system", "content": SYSTEM},
            {
                "role": "user",
                "content": {
                    "task": "Assess every supplied item exactly once. Return no other finding IDs. "
                    "Use all seven boolean flags, at most 60 rationale words per item, "
                    "and cite the supplied snippet evidence when code is present. "
                    "Do not set severity, priority, decision or confidence.",
                    "items": [entry[2] for entry in batch],
                },
            },
        ]
        try:
            output, usage, cached = self.client.complete(
                "judge", messages, JudgeBatch, self.budget_key, previous_errors=previous_errors
            )
        except (BudgetExceeded, ProviderUnavailable, LLMOutputError) as exc:
            self.events.append(f"Judge facts-only fallback: {type(exc).__name__}")
            return []
        self.trace.append(JudgeCall(ids, usage, cached))
        returned_ids = [item.finding_id for item in output.items]
        identity_errors = []
        if len(set(returned_ids)) != len(returned_ids):
            identity_errors.append("Judge response contains duplicate finding IDs")
        if set(returned_ids) != set(ids):
            identity_errors.append("Judge response finding IDs do not match the requested batch")
        by_id = {item.finding_id: item for item in output.items}
        results = []
        for candidate, code, _ in batch:
            item = by_id.get(candidate.finding_id)
            if item is None:
                content = {
                    "verdict": "unknown",
                    "flags": {},
                    "rationale": "",
                    "facts_used": [],
                    "cited_evidence_ids": candidate.evidence_ids,
                }
            else:
                content = item.model_dump(exclude={"finding_id"})
            if code is not None and injection_markers(code.text):
                # A fooled model must not hide an attack: code can only raise this flag.
                content["flags"] = {**content["flags"], "mentions_instructions_to_ai": True}
                self.events.append(f"Judge flag raised by code for {candidate.finding_id}")
            claim = AIClaim(kind="judge", finding_id=candidate.finding_id, **content)
            claim.origin = (
                "live"
                if self.client.transport is transport_module.sdk_transport
                else "recorded_test"
            )
            claim.judge_source = JudgeSource(
                finding_id=candidate.finding_id,
                component=candidate.component,
                evidence_ids=list(candidate.evidence_ids),
                snippet_evidence_ids=[code.evidence_id] if code else [],
                paths=[list(path) for path in candidate.paths],
                response_errors=list(identity_errors),
            )
            checked = verify_api.check(claim, index=self.index)
            checked.needs_human_review = True
            results.append(checked)
        return results
