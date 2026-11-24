"""A fooled model (benign, no flags) must not hide an injection; Module 4's real fixtures."""

import json
from pathlib import Path

import pytest

from guardian.llm.derived import findings_from_judge, injection_markers
from tests.test_verified_judge import answer, finding, service, snippets

MODULE4 = Path(__file__).parents[1] / "fixtures" / "inject"
CASES = json.loads((MODULE4 / "expected.json").read_text("utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_fooled_model_still_raises_high_finding(tmp_path, case):
    original = finding()
    judge, _ = service(tmp_path, [original])  # default answers: benign-looking, all flags false
    text = (MODULE4 / case["file"]).read_text("utf-8")
    claims = judge.judge([original], snippets=snippets([original], text))
    assert len(claims) == 1 and claims[0].flags[case["must_flag"]] is True
    assert any("raised by code" in e for e in judge.events)
    derived = findings_from_judge(claims)
    assert case["finding_still_raised"] and len(derived) == 1
    assert derived[0].severity == "high" and original["severity"] == "critical"


def test_clean_snippet_is_not_flagged(tmp_path):
    original = finding()
    judge, _ = service(tmp_path, [original])
    claims = judge.judge([original], snippets=snippets([original], 'fn main() { println!("hi"); }'))
    assert claims[0].flags["mentions_instructions_to_ai"] is False
    assert findings_from_judge(claims) == [] and not injection_markers("let x = 1;")
    assert answer({"finding_id": "F-001", "evidence_ids": ["EV-CODE-001"]})["verdict"] == "unknown"
