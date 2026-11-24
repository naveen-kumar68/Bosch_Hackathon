"""Contract-facing deterministic candidates API; no implicit network access."""

from guardian.remediate.candidates import CandidateGenerator
from guardian.remediate.models import VettingCheck
from guardian.remediate.registry import RegistrySnapshot
from guardian.remediate.vetting import Vetter

_generator: CandidateGenerator | None = None
_vetter: Vetter | None = None


def configure(registry: RegistrySnapshot):
    global _generator
    _generator = CandidateGenerator(registry)


def candidates(pf, *, registry: RegistrySnapshot | None = None):
    generator = CandidateGenerator(registry) if registry is not None else _generator
    return (generator or CandidateGenerator(RegistrySnapshot())).candidates(pf)


def configure_vetting(service: Vetter):
    global _vetter
    _vetter = service


def vet(options, *, service: Vetter | None = None):
    selected = service if service is not None else _vetter
    if selected is not None:
        return selected.vet(options)
    result = [option.model_copy(deep=True) for option in options]
    for option in result:
        if option.kind != "escalate":
            option.vetting = "rejected"
            option.vetting_reasons = ["Vetting service unavailable; candidate rejected"]
            option.vetting_checks = [
                VettingCheck(
                    check="availability",
                    component=option.component,
                    status="rejected",
                    reasons=list(option.vetting_reasons),
                    evidence_ids=list(option.evidence_ids),
                )
            ]
    return result
