"""Plain-code verification of AI claims. Every error is exact and human-readable."""

import re

from guardian.verify.facts import ADVISORY, FactsIndex, norm
from guardian.verify.models import ALLOWED_FLAGS, FACT_TYPES, AIClaim

_NAME = r"[\w@./:+-]+"
PATH = re.compile(rf"`?{_NAME}`?(?:\s*(?:→|->)\s*`?{_NAME}`?)+")
NAME_AT_VERSION = re.compile(r"`?([A-Za-z_][\w./+-]*)@(v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.]+)*)`?")
BACKTICK = re.compile(r"`([^`\n]+)`")
VERSION = re.compile(r"(?<![\w.@/-])v?\d+\.\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.]+)*(?![\w])")
OPTION = re.compile(r"\bO-[0-9a-f]{8}\b")
DECIMAL = re.compile(r"(?<![\w.])\d+\.\d+(?!\.?\w)")


def _mask(text: str, pattern: re.Pattern, handle) -> str:
    def repl(match):
        handle(match)
        return " " * len(match.group(0))

    return pattern.sub(repl, text)


def check(claim: AIClaim, index: FactsIndex) -> AIClaim:
    errors: list[str] = []
    add = errors.append

    # 1. Every cited evidence ID exists.
    cited = list(claim.cited_evidence_ids)
    if not cited and not claim.facts_used:
        add("claim cites no evidence")
    for evidence_id in cited + [f.evidence_id for f in claim.facts_used if f.evidence_id]:
        if not index.has_evidence(evidence_id):
            add(f"unknown evidence {evidence_id}")

    # 2. Every facts_used entry is supported by its cited evidence.
    listed: set[tuple[str, str]] = set()
    for fact in claim.facts_used:
        if fact.type not in FACT_TYPES:
            add(f"unknown fact type {fact.type}")
            continue
        listed.add((fact.type, norm(fact.type, fact.value)))
        if fact.evidence_id is None:
            if fact.type == "flag":
                if fact.value not in ALLOWED_FLAGS:
                    add(f"unknown flag {fact.value}")
            else:
                add(f"{fact.type} {fact.value} cites no evidence")
        elif index.has_evidence(fact.evidence_id) and not index.supports(
            fact.evidence_id, fact.type, fact.value
        ):
            add(f"{fact.evidence_id} does not support {fact.type} {fact.value}")
        if fact.type == "package" and norm("package", fact.value) not in index.packages:
            add(f"unknown package {fact.value}")
        if fact.type == "option_id" and fact.value not in index.options:
            add(f"unknown option {fact.value}")

    def is_listed(*kinds_values) -> bool:
        return any((k, norm(k, v)) in listed for k, v in kinds_values)

    def version_listed(v):
        return is_listed(("version", v), ("fixed_version", v))

    # 3. Free-text scan: every concrete token must be listed in facts_used.
    text = claim.text

    def on_path(m):
        value = norm("path", m.group(0))
        if not is_listed(("path", value)):
            add(f"unlisted fact {value}")

    def on_advisory(m):
        if not is_listed(("advisory_id", m.group(0))):
            add(f"unlisted fact {m.group(0)}")

    def on_name_version(m):
        name, version = m.group(1), m.group(2)
        if norm("package", name) not in index.packages:
            add(f"unknown package {name}")
        elif not is_listed(("package", name)):
            add(f"unlisted fact {name}")
        if not version_listed(version):
            add(f"unlisted fact {norm('version', version)}")

    def on_backtick(m):
        token = m.group(1).strip()
        if VERSION.fullmatch(token) or re.fullmatch(r"v?\d+\.\d+(?:\.\d+)*", token):
            if not version_listed(token):
                add(f"unlisted fact {norm('version', token)}")
        elif OPTION.fullmatch(token):
            if token not in index.options:
                add(f"unknown option {token}")
            elif not is_listed(("option_id", token)):
                add(f"unlisted fact {token}")
        elif token in ALLOWED_FLAGS:
            if not is_listed(("flag", token)):
                add(f"unlisted fact {token}")
        elif ADVISORY.fullmatch(token):
            if not is_listed(("advisory_id", token)):
                add(f"unlisted fact {token}")
        elif norm("package", token) not in index.packages:
            add(f"unknown package {token}")
        elif not is_listed(("package", token)):
            add(f"unlisted fact {token}")

    def on_version(m):
        if not version_listed(m.group(0)):
            add(f"unlisted fact {norm('version', m.group(0))}")

    def on_option(m):
        if m.group(0) not in index.options:
            add(f"unknown option {m.group(0)}")
        elif not is_listed(("option_id", m.group(0))):
            add(f"unlisted fact {m.group(0)}")

    def on_decimal(m):
        if not is_listed(("score", m.group(0))) and not version_listed(m.group(0)):
            add(f"unlisted fact {m.group(0)}")

    for pattern, handler in (
        (PATH, on_path),
        (ADVISORY, on_advisory),
        (NAME_AT_VERSION, on_name_version),
        (BACKTICK, on_backtick),
        (VERSION, on_version),
        (OPTION, on_option),
        (DECIMAL, on_decimal),
    ):
        text = _mask(text, pattern, handler)

    # 5. Chosen option exists and is vetted (or escalate).
    if claim.chosen_option_id is not None:
        option = index.options.get(claim.chosen_option_id)
        if option is None:
            add(f"unknown option {claim.chosen_option_id}")
        elif option["kind"] != "escalate" and option["vetting"] != "passed":
            add(f"option {claim.chosen_option_id} is not vetted (vetting={option['vetting']})")

    # 6. Judge flags come only from the allowed set.
    for flag in claim.flags:
        if flag not in ALLOWED_FLAGS:
            add(f"unknown flag {flag}")

    errors = list(dict.fromkeys(errors))
    return claim.model_copy(update={"verified": not errors, "errors": errors})
