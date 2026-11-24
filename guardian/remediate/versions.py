"""Small Cargo SemVer subset; unsupported requirements fail closed.

Syntax follows Cargo's specifying-dependencies reference. Python uses the
already-installed packaging library instead of reimplementing PEP 440.
"""

import re
from dataclasses import dataclass
from functools import total_ordering

from packaging.specifiers import SpecifierSet
from packaging.version import Version

SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


@total_ordering
@dataclass(frozen=True, eq=False)
class SemVer:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str):
        match = SEMVER.fullmatch(text)
        if not match:
            raise ValueError("Unsupported Cargo version")
        major, minor, patch, pre, _ = match.groups()
        identifiers = tuple(pre.split(".")) if pre else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in identifiers):
            raise ValueError("Invalid SemVer prerelease identifier")
        return cls(int(major), int(minor), int(patch), identifiers)

    @property
    def core(self):
        return self.major, self.minor, self.patch

    def __eq__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return (self.core, self.pre) == (other.core, other.pre)

    def __lt__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        if self.core != other.core:
            return self.core < other.core
        if not self.pre or not other.pre:
            return bool(self.pre) and not other.pre
        for left, right in zip(self.pre, other.pre, strict=False):
            if left == right:
                continue
            if left.isdigit() and right.isdigit():
                return int(left) < int(right)
            if left.isdigit() != right.isdigit():
                return left.isdigit()
            return left < right
        return len(self.pre) < len(other.pre)

    def __hash__(self):
        return hash((self.core, self.pre))


def _upper(parts, position):
    return SemVer(*(parts[:position] + [parts[position] + 1] + [0] * (2 - position)))


def _comparator(text):
    match = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?\s*(\S+)", text.strip())
    if not match:
        raise ValueError("Unsupported Cargo requirement")
    op, raw = match.groups()
    op = op or "^"
    if raw == "*" and op == "^":
        return lambda version: True, None
    if "*" in raw:
        if op != "^" or not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?\.\*", raw):
            raise ValueError("Unsupported Cargo wildcard")
        partial = [int(p) for p in raw.split(".")[:-1]]
        parts = partial + [0] * (3 - len(partial))
        low, high = SemVer(*parts), _upper(parts, len(partial) - 1)
        return lambda version: low <= version < high, None
    partial = re.fullmatch(r"(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?", raw)
    if partial:
        values = [int(p) for p in partial.groups() if p is not None]
        count = len(values)
        parts = values + [0] * (3 - count)
        low = SemVer(*parts)
    else:
        low = SemVer.parse(raw)
        count, parts = 3, list(low.core)
    high = _upper(parts, count - 1)
    if op == "^":
        position = next((i for i, value in enumerate(parts[:count]) if value), count - 1)
        high = _upper(parts, position)
        return lambda version: low <= version < high, low
    if op == "~":
        high = _upper(parts, 0 if count == 1 else 1)
        return lambda version: low <= version < high, low
    if op == "=":
        return (lambda version: version == low) if count == 3 else (
            lambda version: low <= version < high
        ), low
    if op == ">=":
        return lambda version: version >= low, low
    if op == ">":
        return (lambda version: version > low) if count == 3 else (
            lambda version: version >= high
        ), low
    if op == "<":
        return lambda version: version < low, low
    return (lambda version: version <= low) if count == 3 else (lambda version: version < high), low


def cargo_matches(version: str, requirement: str) -> bool:
    if not requirement.strip():
        raise ValueError("Empty Cargo requirement is unsupported")
    parsed = SemVer.parse(version)
    comparators = [_comparator(part) for part in requirement.split(",")]
    if parsed.pre and not any(
        low and low.pre and low.core == parsed.core for _, low in comparators
    ):
        return False
    return all(predicate(parsed) for predicate, _ in comparators)


def parse(ecosystem: str, version: str):
    return SemVer.parse(version) if ecosystem == "cargo" else Version(version)


def matches(ecosystem: str, version: str, requirement: str) -> bool:
    return (
        cargo_matches(version, requirement)
        if ecosystem == "cargo"
        else (Version(version) in SpecifierSet(requirement))
    )


def stable(ecosystem: str, version: str) -> bool:
    parsed = parse(ecosystem, version)
    return (
        not parsed.pre
        if ecosystem == "cargo"
        else not (parsed.is_prerelease or parsed.is_devrelease)
    )
