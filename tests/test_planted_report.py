import json
import os
from pathlib import Path

import pytest

from demo.analyse import analyse


@pytest.mark.skipif(
    os.environ.get("GUARDIAN_PLANTED_INTEGRATION") != "1",
    reason="Requires generated local planted fixture and captured metadata",
)
def test_recorded_judge_on_actual_planted_report():
    root = Path(__file__).resolve().parents[1]
    calls = []

    def recorded(payload):
        calls.append(payload)
        return json.dumps(
            {
                "finding_id": payload["finding_id"],
                "verdict": "suspicious",
                "confidence": 0.95,
                "rationale": "New build-time network access warrants investigation.",
                "cited_evidence_ids": payload["evidence_ids"][:1],
                "needs_human_review": True,
            }
        )

    findings = analyse(root, complete=recorded)
    critical = next(f for f in findings if f.type == "new_build_dependency_with_network_capability")
    assert critical.severity == "critical"
    assert critical.ai_assessment.verdict == "suspicious"
    assert set(critical.ai_assessment.cited_evidence_ids) <= set(critical.evidence_ids)
    assert len(calls) <= 5
    first = len(calls)
    analyse(root, complete=recorded)
    assert len(calls) == first
