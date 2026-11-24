"""Module 2 role facade. Explicit services support independent concurrent runs."""

from guardian.llm.explain import Narrator
from guardian.llm.judge_verified import VerifiedJudge
from guardian.llm.plan import Planner

_judge: VerifiedJudge | None = None
_planner: Planner | None = None
_narrator: Narrator | None = None


def configure_judge(service: VerifiedJudge):
    global _judge
    _judge = service


def judge(findings, *, snippets=None, previous_errors=None, service: VerifiedJudge | None = None):
    selected = service if service is not None else _judge
    if selected is None:
        return []  # AI layer off; no implicit live client or credentials access
    return selected.judge(findings, snippets=snippets, previous_errors=previous_errors)


def configure_plan(service: Planner):
    global _planner
    _planner = service


def plan(pf, options, *, previous_errors=None, service: Planner | None = None):
    selected = service if service is not None else _planner
    if selected is None:
        return None  # facts-only; no configured index exists to verify an escalation claim
    return selected.plan(pf, options, previous_errors=previous_errors)


def configure_explain(service: Narrator):
    global _narrator
    _narrator = service


def explain(run, *, previous_errors=None, service: Narrator | None = None):
    selected = service if service is not None else _narrator
    return None if selected is None else selected.explain(run, previous_errors=previous_errors)


def explain_brief(brief_struct, *, previous_errors=None, service: Narrator | None = None):
    selected = service if service is not None else _narrator
    return (
        None
        if selected is None
        else selected.explain_brief(brief_struct, previous_errors=previous_errors)
    )
