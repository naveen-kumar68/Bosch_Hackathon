"""Trusted observations -> evidence-ID fact sets; no raw-text guessing or I/O."""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal

from packageurl import PackageURL
from pydantic import BaseModel

from guardian.llm.claims import Fact, FactReference


def record(value) -> dict:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError("Trusted source records must be mappings or Pydantic models")


def number(value) -> str:
    return format(Decimal(str(value)).normalize(), "f")


def value_key(kind: str, value) -> str:
    if kind == "score":
        return number(value)
    if kind == "path":
        return " → ".join(part.strip() for part in value.split("→"))
    return str(value)


@dataclass(frozen=True)
class Option:
    option_id: str
    kind: str
    vetting: str | None
    fingerprint: str | None = None


def option_fingerprint(row: dict) -> str:
    """Bind a trusted option's action and vetting proof, excluding extra fact annotations."""
    fields = (
        "option_id",
        "finding_id",
        "kind",
        "component",
        "target_version",
        "changes",
        "evidence_ids",
        "reasons",
        "vetting",
        "vetting_reasons",
        "vetting_checks",
    )
    payload = {key: row.get(key) for key in fields}
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


@dataclass
class FactIndex:
    by_evidence: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    known_names: set[str] = field(default_factory=set)
    known_versions: set[str] = field(default_factory=set)
    known_pairs: set[tuple[str, str]] = field(default_factory=set)
    options: dict[str, Option] = field(default_factory=dict)

    def add_evidence(self, evidence_id: str, facts: Iterable[Fact | dict] = ()):
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("Evidence ID must be non-empty")
        values = self.by_evidence.setdefault(evidence_id, set())
        for item in facts:
            fact = item if isinstance(item, Fact) else Fact.model_validate(item)
            values.add((fact.type, value_key(fact.type, fact.value)))
            if fact.type == "package":
                self.known_names.add(fact.value)
            elif fact.type in {"version", "fixed_version"}:
                self.known_versions.add(fact.value)
            elif fact.type == "purl":
                self.add_component(fact.value)
        packages = {value for kind, value in values if kind == "package"}
        versions = {value for kind, value in values if kind == "version"}
        if len(packages) == len(versions) == 1:
            self.known_pairs.add((next(iter(packages)), next(iter(versions))))

    def supports(self, fact: FactReference) -> bool:
        return (fact.type, value_key(fact.type, fact.value)) in self.by_evidence.get(
            fact.evidence_id, set()
        )

    def add_component(self, component: str):
        if not component.startswith("pkg:"):
            return
        try:
            purl = PackageURL.from_string(component)
        except ValueError:
            return
        name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
        self.known_names.add(name)
        if purl.version:
            self.known_versions.add(purl.version)
            self.known_pairs.add((name, purl.version))


def build(ledger: Iterable, findings: Iterable = (), options: Iterable = ()) -> FactIndex:
    """Index trusted facts, identities and vetted options.

    Ledger rows: existing Evidence records register IDs; an adapter may add a
    `facts` list of {type,value}. Finding/option adapters may provide `facts` as
    {type,value,evidence_id} observations. Never pass LLM output as these sources.
    Unknown observation evidence IDs are an error, not silently manufactured.
    Existing finding summaries populate known identities but cannot manufacture
    citation support for their prose or attach every fact to every evidence ID.
    """
    index = FactIndex()
    for item in ledger:
        row = record(item)
        index.add_evidence(row.get("id", row.get("evidence_id")), row.get("facts", []))
    for source, is_option in ((findings, False), (options, True)):
        for item in source:
            row = record(item)
            component = row.get("component", row.get("purl"))
            if isinstance(component, str):
                index.add_component(component)
            name = row.get("package_name", row.get("package"))
            version = row.get("version")
            if isinstance(name, str):
                index.known_names.add(name)
                if isinstance(version, str):
                    index.known_pairs.add((name, version))
            if isinstance(version, str):
                index.known_versions.add(version)
            for observation in row.get("facts", []):
                fact = FactReference.model_validate(observation)
                if fact.evidence_id not in index.by_evidence:
                    raise ValueError(f"Unknown observation evidence ID {fact.evidence_id}")
                index.add_evidence(fact.evidence_id, [Fact(type=fact.type, value=fact.value)])
            if is_option:
                identifier, kind = row.get("option_id"), row.get("kind")
                if not isinstance(identifier, str) or not re.fullmatch(
                    r"O-[0-9a-f]{8}", identifier
                ):
                    raise ValueError(
                        "Trusted option requires O- plus eight lowercase hex characters"
                    )
                if not isinstance(kind, str):
                    raise ValueError("Trusted option requires a kind")
                option = Option(identifier, kind, row.get("vetting"), option_fingerprint(row))
                if identifier in index.options and index.options[identifier] != option:
                    raise ValueError(f"Conflicting trusted option {identifier}")
                index.options[identifier] = option
                for evidence_id in row.get("evidence_ids", []):
                    if evidence_id not in index.by_evidence:
                        raise ValueError(f"Unknown option evidence ID {evidence_id}")
                    index.add_evidence(evidence_id, [Fact(type="option_id", value=identifier)])
    return index
