"""Contract-facing facade; explicit indexes are preferable for concurrent runs."""

from guardian.llm.claims import AIClaim, ClaimContent
from guardian.verify.checker import Verifier
from guardian.verify.facts import FactIndex

_index: FactIndex | None = None


def configure(index: FactIndex):
    global _index
    _index = index


def check(claim: AIClaim | ClaimContent, *, index: FactIndex | None = None) -> AIClaim:
    selected = index if index is not None else _index
    if selected is None:
        raise RuntimeError("Verifier fact index is not configured")
    return Verifier(selected).check(claim)
