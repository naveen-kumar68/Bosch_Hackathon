"""Syntactic factual-grounding checks. This is not a semantic theorem prover."""

import re

from guardian.llm.claims import AIClaim, ClaimContent
from guardian.verify.facts import FactIndex, number, value_key

ALLOWED_FLAGS = frozenset(
    {
        "runs_network",
        "downloads_and_executes",
        "reads_env_or_secrets",
        "writes_outside_build_dir",
        "obfuscated",
        "mentions_instructions_to_ai",
        "benign_build_step",
    }
)
ADVISORY = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
    r"|RUSTSEC-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)\b",
    re.IGNORECASE,
)
VERSION = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?(?!\w|\.\d)")
DECIMAL = re.compile(r"(?<![\w.])\d+\.\d+(?!\w|\.\d)")
NAME_VERSION = re.compile(
    r"(?<![\w@/])(@?[A-Za-z0-9][A-Za-z0-9/._:+-]*)@"
    r"(\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?)"
)
BACKTICK = re.compile(r"`([^`\n]+)`")
OPTION_ID = re.compile(r"\bO-[0-9a-fA-F]{8}\b")
PURL = re.compile(r"\bpkg:[^\s`→]+")
NODE = r"@?[A-Za-z0-9][A-Za-z0-9@/._:+-]*"
PATH = re.compile(rf"{NODE}(?:\s*→\s*{NODE})+")
TEXT_FIELDS = (
    "rationale",
    "summary",
    "key_points",
    "trade_offs",
    "rollback_steps",
    "open_questions",
)
VERSION_CONTEXT = re.compile(
    r"(?:version|release|upgrade to|fixed in)(?:\s+is)?\s*[:=]?\s*`?$", re.IGNORECASE
)
SCORE_CONTEXT = re.compile(r"(?:CVSS|EPSS|score)(?:\s+(?:is|of))?\s*[:=]?\s*`?$", re.IGNORECASE)


class Verifier:
    def __init__(self, index: FactIndex):
        self.index = index

    def check(self, claim: AIClaim | ClaimContent) -> AIClaim:
        # Discard any previous verdict, including model-supplied verified=true.
        data = claim.model_dump(exclude={"verified", "errors", "needs_human_review"})
        result = AIClaim.model_validate(data)
        errors = []

        def error(message):
            if message not in errors:
                errors.append(message)

        cited = set(result.cited_evidence_ids)
        if not cited:
            error("Claim has no cited evidence IDs")
        for identifier in sorted(cited):
            if identifier not in self.index.by_evidence:
                error(f"Unknown evidence ID {identifier}")
        listed = set()
        for fact in result.facts_used:
            listed.add((fact.type, value_key(fact.type, fact.value)))
            if fact.evidence_id not in self.index.by_evidence:
                error(f"Unknown evidence ID {fact.evidence_id}")
            elif not self.index.supports(fact):
                error(f"{fact.evidence_id} does not support {fact.type} {fact.value}")
            if fact.evidence_id not in cited:
                error(f"Fact evidence ID {fact.evidence_id} is not cited")

        def has(value, kinds=None):
            return any(
                (kinds is None or kind in kinds) and stored == value for kind, stored in listed
            )

        def token(value, kinds=None):
            if not has(value, kinds):
                error(f"Unlisted fact {value}")

        text_parts = []
        for field in TEXT_FIELDS:
            value = getattr(result, field)
            text_parts.extend(value if isinstance(value, list) else [value])
        for text in text_parts:
            for match in PATH.finditer(text):
                path = match.group().rstrip(".,;:")
                token(value_key("path", path), {"path"})
            # Paths and PURLs are atomic typed facts; do not require their
            # embedded versions/nodes to be re-listed as separate facts.
            without_paths = PATH.sub(lambda m: " " * len(m.group()), text)
            for match in PURL.finditer(without_paths):
                token(match.group().rstrip(".,;:"), {"purl"})
            standalone = PURL.sub(lambda m: " " * len(m.group()), without_paths)
            for match in ADVISORY.finditer(standalone):
                token(match.group(), {"advisory_id"})
            for match in NAME_VERSION.finditer(standalone):
                name, version = match.groups()
                if name.startswith("pkg:"):
                    continue  # a PURL is an atomic typed fact, checked above
                token(name, {"package"})
                token(version, {"version", "fixed_version"})
                if name not in self.index.known_names:
                    error(f"Unknown package {name}")
                if (name, version) not in self.index.known_pairs:
                    error(f"Unknown package version {name}@{version}")
            for match in VERSION.finditer(standalone):
                value = match.group().rstrip(".,;:")
                prefix = standalone[max(0, match.start() - 40) : match.start()]
                if VERSION_CONTEXT.search(prefix):
                    token(value, {"version", "fixed_version"})
                    continue
                if SCORE_CONTEXT.search(prefix):
                    try:
                        token(number(value), {"score"})
                    except ArithmeticError:
                        error(f"Unlisted fact {value}")
                    continue
                if not has(value, {"version", "fixed_version"}):
                    try:
                        if not has(number(value), {"score"}):
                            error(f"Unlisted fact {value}")
                    except ArithmeticError:
                        error(f"Unlisted fact {value}")
            for match in DECIMAL.finditer(standalone):
                value = match.group()
                if not has(value, {"version", "fixed_version"}):
                    token(number(value), {"score"})
            for match in OPTION_ID.finditer(text):
                token(match.group(), {"option_id"})
            for match in BACKTICK.finditer(text):
                value = match.group(1).strip()
                if NAME_VERSION.fullmatch(value):
                    continue  # checked as a pair above
                if "→" in value:
                    value = value_key("path", value)
                numeric_score = DECIMAL.fullmatch(value) and has(number(value), {"score"})
                if not has(value) and not numeric_score:
                    error(f"Unlisted fact {value}")

        for fact in result.facts_used:
            if fact.type == "package" and fact.value not in self.index.known_names:
                error(f"Unknown package {fact.value}")
            if (
                fact.type in {"version", "fixed_version"}
                and fact.value not in self.index.known_versions
            ):
                error(f"Unknown version {fact.value}")
            if fact.type == "option_id" and fact.value not in self.index.options:
                error(f"Unknown option ID {fact.value}")
            if fact.type == "flag" and fact.value not in ALLOWED_FLAGS:
                error(f"Unknown Judge flag {fact.value}")

        if result.kind == "plan":
            identifier = result.chosen_option_id
            option = self.index.options.get(identifier)
            if option is None:
                error(f"Unknown option ID {identifier}")
            else:
                token(identifier, {"option_id"})
                if option.kind != "escalate" and option.vetting != "passed":
                    error(f"Option {identifier} is not vetted: {option.vetting}")
        elif result.chosen_option_id is not None:
            error("Only Plan may choose an option")
        for flag in sorted(result.flags):
            if flag not in ALLOWED_FLAGS:
                error(f"Unknown Judge flag {flag}")
        if result.flags and result.kind != "judge":
            error("Only Judge may report flags")
        source = result.judge_source
        if source is not None:
            if result.kind != "judge" or result.finding_id != source.finding_id:
                error("Judge source does not match the claim")
            for message in source.response_errors:
                error(message)
            if not cited <= set(source.evidence_ids):
                error("Judge cited evidence outside its finding")
            if not set(source.snippet_evidence_ids) <= set(source.evidence_ids):
                error("Judge snippet evidence is not bound to its finding")
            if not set(source.snippet_evidence_ids) <= cited:
                error("Judge did not cite its snippet evidence")
            if not source.snippet_evidence_ids and any(result.flags.values()):
                error("Judge behavioral flags require snippet evidence")
        result.errors = errors
        result.verified = not errors
        # Verification proves bounded grounding checks, not safety or semantic truth.
        result.needs_human_review = bool(errors) or getattr(claim, "needs_human_review", True)
        return result
