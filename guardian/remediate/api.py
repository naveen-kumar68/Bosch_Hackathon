"""Contract-facing deterministic candidates API; no implicit network access."""

from guardian.remediate.candidates import CandidateGenerator
from guardian.remediate.registry import RegistrySnapshot

_generator: CandidateGenerator | None = None


def configure(registry: RegistrySnapshot):
    global _generator
    _generator = CandidateGenerator(registry)


def candidates(pf, *, registry: RegistrySnapshot | None = None):
    generator = CandidateGenerator(registry) if registry is not None else _generator
    return (generator or CandidateGenerator(RegistrySnapshot())).candidates(pf)
