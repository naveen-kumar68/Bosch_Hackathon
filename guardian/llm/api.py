"""Module 2 role facade. Explicit services support independent concurrent runs."""

from guardian.llm.judge_verified import VerifiedJudge

_judge: VerifiedJudge | None = None


def configure_judge(service: VerifiedJudge):
    global _judge
    _judge = service


def judge(findings, *, snippets=None, previous_errors=None, service: VerifiedJudge | None = None):
    selected = service if service is not None else _judge
    if selected is None:
        return []  # AI layer off; no implicit live client or credentials access
    return selected.judge(findings, snippets=snippets, previous_errors=previous_errors)
