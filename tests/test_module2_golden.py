"""Offline golden flow over inert planted source; never builds/runs target code."""

import ast
import hashlib
import io
import json
import os
import tarfile
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import metadata_changes, new_dependencies
from guardian.detect.typosquat import candidates as typosquat_candidates
from guardian.detect.vulns import parse_osv
from guardian.llm.completion import Budget, ClientConfig, CompletionClient, Provider
from guardian.llm.evaluation import hallucination_count, injection_resistance, verify_catch_rate
from guardian.llm.explain import Narrator
from guardian.llm.judge_schema import JudgeFlags
from guardian.llm.judge_verified import VerifiedJudge
from guardian.llm.plan import Planner
from guardian.llm.second_opinion import SecondOpinion
from guardian.remediate.candidates import CandidateGenerator
from guardian.remediate.detectors import CapturedDetectors
from guardian.remediate.registry import RegistrySnapshot, cargo_index
from guardian.remediate.vet_contracts import CapturedVersion, DetectorBindings, VetPolicy
from guardian.remediate.vetting import Vetter
from guardian.verify.facts import build


def archive(text="fn main() {}"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        data = text.encode()
        member = tarfile.TarInfo("pkg/build.rs")
        member.size = len(data)
        output.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def capture(version):
    data = archive()
    return CapturedVersion(
        ecosystem="cargo",
        package="safe",
        version=version,
        metadata={
            "published": "2026-11-01T12:00:00Z",
            "yanked": False,
            "publisher": 7,
            "trusted_publishing": True,
            "source": "registry:crates.io",
        },
        metadata_evidence_ids=(f"EV-META-{version}",),
        osv_document={
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "safe",
                                "version": version,
                                "ecosystem": "crates.io",
                            },
                            "vulnerabilities": [],
                        }
                    ]
                }
            ]
        },
        osv_evidence_ids=("EV-OSV",),
        history_evidence_ids=("EV-INDEX",),
        artifact=data,
        registry_sha256=hashlib.sha256(data).hexdigest(),
        artifact_evidence_ids=(f"EV-ARTIFACT-{version}",),
        checksum_evidence_ids=("EV-INDEX",),
    )


def with_artifact(value, data):
    return replace(value, artifact=data, registry_sha256=hashlib.sha256(data).hexdigest())


def vetting_service(scratch, versions):
    known = {"EV-FINDING", "EV-POLICY", "EV-INDEX", "EV-OSV", "EV-SG", "EV-FIX"}
    for version in versions:
        known.update([*version.metadata_evidence_ids, *version.artifact_evidence_ids])
    bindings = DetectorBindings(
        parse_osv,
        metadata_changes,
        new_dependencies,
        typosquat_candidates,
        verified_extract,
        inspect_sources,
        capability_diff,
        lambda *a, **k: ({"results": [], "errors": []}, "EV-SG"),
        lambda e: e in known,
    )
    detectors = CapturedDetectors(versions, bindings, scratch=scratch)
    return Vetter(
        detectors, VetPolicy(evidence_ids=["EV-POLICY"]), now=datetime(2026, 11, 24, 12, tzinfo=UTC)
    ), None


def test_full_recorded_planted_flow_has_no_accepted_hallucinations(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Target execution prohibited")),
    )
    root = Path(__file__).parents[1]
    source = ast.parse((root / "demo/prepare.py").read_text("utf-8"))
    planted = next(
        node.value
        for node in ast.walk(source)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "fn look_alike_only_never_called" in node.value
    )
    before = with_artifact(capture("1.0.0"), archive(planted))
    after = capture("1.0.1")
    # Synthetic package identity wraps the real inert planted source bytes.
    # Captured target version removes those capabilities; no live registry claim.
    history = [
        {
            "name": "safe",
            "vers": "1.0.0",
            "deps": [],
            "yanked": False,
            "cksum": before.registry_sha256,
        },
        {
            "name": "safe",
            "vers": "1.0.1",
            "deps": [],
            "yanked": False,
            "cksum": after.registry_sha256,
        },
    ]
    before, after = replace(before, history=history), replace(after, history=history)
    snapshot = RegistrySnapshot([cargo_index("safe", history, "EV-INDEX")])
    request = {
        "finding_id": "F-001",
        "component": "pkg:cargo/safe@1.0.0",
        "evidence_ids": ["EV-FINDING"],
        "fixed_versions": [{"version": "1.0.1", "evidence_ids": ["EV-FIX"]}],
        "location": {"file": "Cargo.lock"},
    }
    candidates = CandidateGenerator(snapshot).candidates(request)
    vetter, _ = vetting_service(tmp_path / "inspection", [before, after])
    exists = vetter.detectors.bindings.evidence_exists
    vetter.detectors.bindings = replace(
        vetter.detectors.bindings, evidence_exists=lambda e: e == "EV-FIX" or exists(e)
    )
    vetted = vetter.vet(candidates)
    chosen = next(option for option in vetted if option.kind == "minimal_upgrade")
    assert chosen.vetting == "passed"
    evidence = {e for option in vetted for e in option.evidence_ids} | {"EV-CODE-001", "EV-RUN"}
    ledger = [{"id": e, "facts": []} for e in sorted(evidence)]
    for row in ledger:
        if row["id"] == "EV-FINDING":
            row["facts"] = [
                {"type": "package", "value": "safe"},
                {"type": "version", "value": "1.0.0"},
                {"type": "purl", "value": "pkg:cargo/safe@1.0.0"},
            ]
        if row["id"] == "EV-FIX":
            row["facts"] = [{"type": "fixed_version", "value": "1.0.1"}]
        if row["id"] == "EV-RUN":
            row["facts"] = [{"type": "count", "value": 1}, {"type": "status", "value": "complete"}]
    pf = {
        "finding_id": "F-001",
        "type": "capability_added",
        "component": "pkg:cargo/safe@1.0.0",
        "severity": "critical",
        "priority": "P0",
        "score_breakdown": [],
        "paths": [],
        "decision": "needs_human",
        "evidence_ids": ["EV-FINDING"],
    }
    index = build(ledger, [pf], vetted)
    calls = []
    adversarial = [False]

    def transport(provider, message):
        schema = message["response_format"]["json_schema"]["name"]
        calls.append(schema)
        if schema == "JudgeBatch":
            flags = dict.fromkeys(JudgeFlags.model_fields, False)
            flags.update(runs_network=True, reads_env_or_secrets=True)
            value = {
                "items": [
                    {
                        "finding_id": "F-001",
                        "flags": flags,
                        "verdict": "suspicious",
                        "rationale": "Build-time network and environment access needs human review.",
                        "facts_used": [],
                        "cited_evidence_ids": ["EV-CODE-001"],
                    }
                ]
            }
        elif schema == "PlanResponse":
            value = {
                "chosen_option_id": chosen.option_id,
                "rationale": f"Choose {chosen.option_id} for human review.",
                "trade_offs": [],
                "rollback_steps": ["Request human review before reverting."],
                "facts_used": [
                    {
                        "type": "option_id",
                        "value": chosen.option_id,
                        "evidence_id": chosen.evidence_ids[0],
                    }
                ],
                "cited_evidence_ids": [chosen.evidence_ids[0]],
            }
            if adversarial[0]:
                value["rationale"] = "Use `9.9.9`."
        elif schema == "ExplainResponse":
            value = {
                "summary": "Run is `complete` with 1 finding.",
                "key_points": [],
                "facts_used": [
                    {"type": "status", "value": "complete", "evidence_id": "EV-RUN"},
                    {"type": "count", "value": 1, "evidence_id": "EV-RUN"},
                ],
                "cited_evidence_ids": ["EV-RUN"],
            }
        elif schema == "BriefResponse":
            value = {
                "summary": "Review `safe` before changing dependencies.",
                "open_questions": [],
                "facts_used": [{"type": "package", "value": "safe", "evidence_id": "EV-FINDING"}],
                "cited_evidence_ids": ["EV-FINDING"],
            }
        else:
            value = {"risk_opinion": "high", "facts_used": [], "cited_evidence_ids": ["EV-FINDING"]}
        return {
            "choices": [{"message": {"content": json.dumps(value)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }

    client = CompletionClient(
        tmp_path / "cache.sqlite",
        [Provider("recorded", "https://example.invalid", "fixture", "fixture-only")],
        ClientConfig(run_budget=Budget(max_calls=8)),
        transport=transport,
    )
    judge, planner, narrator, opinion = (
        VerifiedJudge(client, index, budget_key="golden"),
        Planner(client, index, budget_key="golden"),
        Narrator(client, index, budget_key="golden"),
        SecondOpinion(client, index, budget_key="golden"),
    )
    judge_finding = {
        **pf,
        "severity_rule": "capability_added",
        "needs_judgement": True,
        "evidence_ids": ["EV-CODE-001"],
    }
    original = deepcopy(judge_finding)
    summary_input = {
        "run_id": "golden",
        "status": "complete",
        "counts": [{"name": "findings", "value": 1, "evidence_ids": ["EV-RUN"]}],
        "top_findings": [pf],
        "plans": [
            {
                "finding_id": "F-001",
                "chosen_option_id": chosen.option_id,
                "verified": True,
                "evidence_ids": chosen.evidence_ids,
            }
        ],
        "validations": [],
        "evidence_ids": ["EV-RUN"],
    }
    brief_input = {"finding": pf, "observations": [], "evidence_ids": ["EV-FINDING"]}

    def flow():
        return [
            *judge.judge(
                [judge_finding], snippets={"F-001": {"text": planted, "evidence_id": "EV-CODE-001"}}
            ),
            planner.plan(pf, vetted),
            narrator.explain(summary_input),
            narrator.explain_brief(brief_input),
            opinion.second_opinion(pf),
        ]

    claims = flow()
    assert len(claims) == 5 and all(c is not None and c.verified for c in claims)
    assert {c.kind for c in claims} == {"judge", "plan", "explain", "brief", "second_opinion"}
    assert len(calls) == 5 and judge_finding == original
    assert all(c.verified for c in flow()) and len(calls) == 5  # all caches cost zero
    adversarial[0] = True
    bad = planner.plan(pf, vetted, previous_errors=["Adversarial recorded output case"])
    assert not bad.verified and "Unlisted fact 9.9.9" in bad.errors
    assert hallucination_count([*claims, bad], index=index) == 0
    spoof = bad.model_copy(update={"verified": True, "errors": []})
    assert hallucination_count([spoof], index=index) == 1
    report = {
        "mode": "offline_recorded_golden",
        "roles_verified": 5,
        "unsupported_claims_rejected": 1,
        "accepted_hallucinations": 0,
        "provider_calls_mocked": len(calls),
        "cache_rerun_calls": 0,
        "verifier": verify_catch_rate(root / "tests/fixtures/verifier"),
        "injection": injection_resistance(root / "tests/fixtures/inject"),
        "live_provider_tested": False,
        "target_code_executed": False,
    }
    if os.environ.get("GUARDIAN_MODULE2_EVAL_OUTPUT"):
        target = Path(os.environ["GUARDIAN_MODULE2_EVAL_OUTPUT"]).resolve()
        assert target.is_relative_to(root / "out")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
