"""Typed fact index: evidence_id -> set of (type, value). Built only from tool output."""

import re
from decimal import Decimal, InvalidOperation

from packageurl import PackageURL

ADVISORY = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|RUSTSEC-\d{4}-\d{4}|PYSEC-\d{4}-\d+)\b",
    re.IGNORECASE,
)
ARROW = re.compile(r"\s*(?:→|->)\s*")


def norm(kind: str, value) -> str:
    text = str(value).strip().strip("`")
    if kind in {"version", "fixed_version"}:
        return text[1:] if text[:1] in "vV" and text[1:2].isdigit() else text
    if kind == "advisory_id":
        return text.upper()
    if kind == "score":
        try:
            return format(Decimal(text).normalize(), "f")
        except InvalidOperation:
            return text
    if kind == "path":
        return " → ".join(p.strip().strip("`") for p in ARROW.split(text))
    if kind == "package":
        return text.lower()
    return text


def _get(obj, name, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def split_component(component: str) -> tuple[str, str | None, str | None]:
    """Return (name, version, purl) from a purl, name@version or bare name."""
    if component.startswith("pkg:"):
        try:
            p = PackageURL.from_string(component)
            return p.name, p.version, component
        except ValueError:
            return component, None, None
    name, sep, version = component.rpartition("@")
    if sep and name and version[:1].isdigit():
        return name, version, None
    return component, None, None


class FactsIndex:
    def __init__(self):
        self.evidence: dict[str, set[tuple[str, str]]] = {}
        self.packages: set[str] = set()
        self.versions: set[str] = set()
        self.options: dict[str, dict] = {}
        self.advisories: set[str] = set()

    def has_evidence(self, evidence_id: str) -> bool:
        return evidence_id in self.evidence

    def add(self, evidence_ids, kind: str, value) -> None:
        if value is None or value == "":
            return
        value = norm(kind, value)
        for evidence_id in evidence_ids:
            self.evidence.setdefault(evidence_id, set()).add((kind, value))
        if kind == "package":
            self.packages.add(value)
        elif kind in {"version", "fixed_version"}:
            self.versions.add(value)
        elif kind == "advisory_id":
            self.advisories.add(value)

    def supports(self, evidence_id: str, kind: str, value) -> bool:
        return (kind, norm(kind, value)) in self.evidence.get(evidence_id, set())

    def add_package(self, evidence_ids, component: str) -> None:
        name, version, purl = split_component(component)
        self.add(evidence_ids, "package", name)
        self.add(evidence_ids, "version", version)
        self.add(evidence_ids, "purl", purl)

    def add_component(self, component) -> None:
        ids = _get(component, "evidence_ids", [])
        self.add(ids, "package", _get(component, "name"))
        self.add(ids, "version", _get(component, "version"))
        self.add(ids, "purl", _get(component, "purl"))

    def add_path(self, evidence_ids, path) -> None:
        names = [split_component(str(p))[0] for p in path]
        for name in names:
            self.add(evidence_ids, "package", name)
        self.add(evidence_ids, "path", " → ".join(names))
        self.add(evidence_ids, "path", " → ".join(str(p) for p in path))

    def add_finding(self, finding) -> None:
        ids = _get(finding, "evidence_ids", [])
        self.add_package(ids, _get(finding, "component", ""))
        for path in _get(finding, "paths", []) or []:
            self.add_path(ids, path)
        self._scan_details(ids, _get(finding, "details", {}) or {})

    def _scan_details(self, ids, value, key="") -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                self._scan_details(ids, v, str(k))
        elif isinstance(value, list):
            for v in value:
                self._scan_details(ids, v, key)
        elif isinstance(value, str):
            for match in ADVISORY.findall(value):
                self.add(ids, "advisory_id", match)
            if key.startswith("fixed"):
                self.add(ids, "fixed_version", value)

    def add_vulnerability(self, vuln) -> None:
        ids = _get(vuln, "evidence_ids", [])
        self.add_package(ids, _get(vuln, "component", ""))
        for advisory in [_get(vuln, "id"), *(_get(vuln, "aliases", []) or [])]:
            self.add(ids, "advisory_id", advisory)
        for fixed in _get(vuln, "fixed_versions", []) or []:
            self.add(ids, "fixed_version", fixed)
        for field in ("cvss_score", "epss", "epss_percentile"):
            self.add(ids, "score", _get(vuln, field))

    def add_option(self, option) -> None:
        ids = _get(option, "evidence_ids", [])
        option_id = _get(option, "option_id")
        self.options[option_id] = {
            "kind": _get(option, "kind"),
            "vetting": _get(option, "vetting"),
            "evidence_ids": list(ids),
        }
        self.add(ids, "option_id", option_id)
        self.add(ids, "package", _get(option, "package"))
        for field in ("from_version", "target_version"):
            self.add(ids, "version", _get(option, field))
        for step in _get(option, "steps", []) or []:
            self.add(ids, "package", step.get("package"))
            self.add(ids, "version", step.get("from_version"))
            self.add(ids, "version", step.get("target_version"))

    @classmethod
    def build(cls, *, components=(), findings=(), vulnerabilities=(), options=(), evidence_ids=()):
        index = cls()
        for evidence_id in evidence_ids:
            index.evidence.setdefault(evidence_id, set())
        for component in components:
            index.add_component(component)
        for finding in findings:
            index.add_finding(finding)
        for vuln in vulnerabilities:
            index.add_vulnerability(vuln)
        for option in options:
            index.add_option(option)
        return index
