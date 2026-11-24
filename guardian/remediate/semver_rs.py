"""Small Cargo semver parser: versions and requirement strings (caret, tilde, wildcard, ops)."""

import re
from functools import total_ordering

_VERSION = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class Version:
    def __init__(self, text: str):
        m = _VERSION.match(text.strip())
        if not m:
            raise ValueError(f"Invalid version: {text}")
        self.parts = tuple(int(p) if p is not None else 0 for p in m.groups()[:3])
        self.pre = tuple(m.group(4).split(".")) if m.group(4) else ()
        self.text = text.strip()

    def _key(self):
        # A release sorts after any of its prereleases.
        pre = tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in self.pre)
        return (self.parts, 1 if not self.pre else 0, pre)

    def __eq__(self, other):
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return f"Version({self.text!r})"

    @property
    def is_prerelease(self):
        return bool(self.pre)

    def compat_key(self):
        """Cargo's incompatibility boundary: major, or 0.minor, or 0.0.patch."""
        major, minor, patch = self.parts
        return (major,) if major else (0, minor) if minor else (0, 0, patch)


def _partial(text: str):
    m = _VERSION.match(text.strip())
    if not m:
        raise ValueError(f"Invalid requirement: {text}")
    given = [g for g in m.groups()[:3] if g is not None]
    return Version(text), len(given)


def _bump(parts, index):
    out = list(parts[: index + 1])
    out[index] += 1
    return Version(".".join(str(p) for p in out + [0] * (2 - index)))


def _comparators(token: str):
    token = token.strip()
    if token in {"", "*"}:
        return []
    op = "^"
    for candidate in (">=", "<=", "=", ">", "<", "^", "~"):
        if token.startswith(candidate):
            op, token = candidate, token[len(candidate) :].strip()
            break
    wild = re.match(r"^(\d+)(?:\.(\d+))?\.[*xX]$", token)
    if wild:
        token = ".".join(g for g in wild.groups() if g is not None)
        op = "="
    version, n = _partial(token)
    lo = Version(
        ".".join(str(p) for p in version.parts)
        + (f"-{'.'.join(version.pre)}" if version.pre else "")
    )
    major, minor, _patch = version.parts
    if op == "^":
        if major > 0 or n == 1:
            hi = _bump(version.parts, 0)
        elif minor > 0 or n == 2:
            hi = _bump(version.parts, 1)
        else:
            hi = _bump(version.parts, 2)
        return [(">=", lo), ("<", hi)]
    if op == "~":
        hi = _bump(version.parts, 0 if n == 1 else 1)
        return [(">=", lo), ("<", hi)]
    if op == "=":
        return [(">=", lo), ("<", _bump(version.parts, n - 1))] if n < 3 else [("=", lo)]
    if op == ">" and n < 3:
        return [(">=", _bump(version.parts, n - 1))]
    if op == "<=" and n < 3:
        return [("<", _bump(version.parts, n - 1))]
    return [(op, lo)]


class Requirement:
    def __init__(self, text: str):
        self.text = text.strip()
        self.comparators = [c for part in self.text.split(",") for c in _comparators(part)]

    def matches(self, version: Version) -> bool:
        if version.is_prerelease and "-" not in self.text:
            return False
        ops = {
            ">=": lambda a, b: a >= b,
            ">": lambda a, b: a > b,
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            "=": lambda a, b: a == b,
        }
        return all(ops[op](version, bound) for op, bound in self.comparators)
