"""Deterministic checks over explicitly indexed evidence facts."""

from guardian.verify.api import check, configure
from guardian.verify.facts import FactIndex, build

__all__ = ["FactIndex", "build", "check", "configure"]
