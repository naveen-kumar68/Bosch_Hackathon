"""Runnable offline demo of the whole Module 2 flow on the inert planted-demo source.

No network, no live LLM and no target code is executed. A recorded-shape mock provider answers
every role; plain code verifies every claim. Run with: guardian llm demo
"""

import ast
import hashlib
import io
import json
import tarfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import metadata_changes, new_dependencies
from guardian.detect.typosquat import candidates as typosquat_candidates
from guardian.detect.vulns import parse_osv
from guardian.llm.completion import Budget, ClientConfig, CompletionClient, Provider
from guardian.llm.derived import findings_from_judge
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

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 24, 12, tzinfo=UTC)


def _archive(text):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        data = text.encode()
        member = tarfile.TarInfo("pkg/build.rs")
        member.size = len(data)
        output.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def _capture(version, source):
    data = _archive(source)
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


def planted_source(root=ROOT):
    tree = ast.parse((root / "demo/prepare.py").read_text("utf-8"))
    return next(
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and "fn look_alike_only_never_called" in n.value
    )


def run_demo(root: Path = ROOT, scratch: Path | None = None) -> dict:
    planted = planted_source(root)
    with TemporaryDirectory(prefix="guardian-demo-") as tmp:
        work = Path(scratch or tmp)
        before, after = _capture("1.0.0", planted), _capture("1.0.1", "fn main() {}")
        history = [
            {
                "name": "safe",
                "vers": v.version,
                "deps": [],
                "yanked": False,
                "cksum": v.registry_sha256,
            }
            for v in (before, after)
        ]
        before, after = replace(before, history=history), replace(after, history=history)
        request = {
            "finding_id": "F-001",
            "component": "pkg:cargo/safe@1.0.0",
            "evidence_ids": ["EV-FINDING"],
            "fixed_versions": [{"version": "1.0.1", "evidence_ids": ["EV-FIX"]}],
            "location": {"file": "Cargo.lock"},
        }
        options = CandidateGenerator(
            RegistrySnapshot([cargo_index("safe", history, "EV-INDEX")])
        ).candidates(request)
        known = {"EV-FINDING", "EV-POLICY", "EV-INDEX", "EV-OSV", "EV-SG", "EV-FIX"}
        for v in (before, after):
            known.update([*v.metadata_evidence_ids, *v.artifact_evidence_ids])
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
        vetter = Vetter(
            CapturedDetectors([before, after], bindings, scratch=work / "inspection"),
            VetPolicy(evidence_ids=["EV-POLICY"]),
            now=NOW,
        )
        vetted = vetter.vet(options)
        chosen = next(o for o in vetted if o.kind == "minimal_upgrade")

        evidence = {e for o in vetted for e in o.evidence_ids} | {"EV-CODE-001", "EV-RUN"}
        facts = {
            "EV-FINDING": [
                {"type": "package", "value": "safe"},
                {"type": "version", "value": "1.0.0"},
                {"type": "purl", "value": "pkg:cargo/safe@1.0.0"},
            ],
            "EV-FIX": [{"type": "fixed_version", "value": "1.0.1"}],
            "EV-RUN": [{"type": "count", "value": 1}, {"type": "status", "value": "complete"}],
        }
        ledger = [{"id": e, "facts": facts.get(e, [])} for e in sorted(evidence)]
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

        def transport(provider, message):  # recorded-shape mock: never leaves the machine
            schema = message["response_format"]["json_schema"]["name"]
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
                    "facts_used": [
                        {"type": "package", "value": "safe", "evidence_id": "EV-FINDING"}
                    ],
                    "cited_evidence_ids": ["EV-FINDING"],
                }
            else:
                value = {
                    "risk_opinion": "high",
                    "facts_used": [],
                    "cited_evidence_ids": ["EV-FINDING"],
                }
            return {
                "choices": [{"message": {"content": json.dumps(value)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            }

        client = CompletionClient(
            work / "cache.sqlite",
            [Provider("recorded", "https://example.invalid", "fixture", "fixture-only")],
            ClientConfig(run_budget=Budget(max_calls=8)),
            transport=transport,
        )
        key = "demo"
        judge = VerifiedJudge(client, index, budget_key=key)
        judge_finding = {
            **pf,
            "severity_rule": "capability_added",
            "needs_judgement": True,
            "evidence_ids": ["EV-CODE-001"],
        }
        summary = {
            "run_id": "demo",
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
        claims = {
            "judge": judge.judge(
                [judge_finding], snippets={"F-001": {"text": planted, "evidence_id": "EV-CODE-001"}}
            ),
            "plan": Planner(client, index, budget_key=key).plan(pf, vetted),
            "explain": Narrator(client, index, budget_key=key).explain(summary),
            "brief": Narrator(client, index, budget_key=key).explain_brief(
                {"finding": pf, "observations": [], "evidence_ids": ["EV-FINDING"]}
            ),
            "second_opinion": SecondOpinion(client, index, budget_key=key).second_opinion(pf),
        }
        flat = [*claims["judge"], *(c for k, c in claims.items() if k != "judge" and c is not None)]
        return {
            "options": [
                {
                    "option_id": o.option_id,
                    "kind": o.kind,
                    "target": o.target_version,
                    "vetting": o.vetting,
                    "reasons": o.vetting_reasons,
                }
                for o in vetted
            ],
            "claims": [
                {
                    "kind": c.kind,
                    "verified": c.verified,
                    "errors": c.errors,
                    "text": (getattr(c, "rationale", "") or getattr(c, "summary", "") or "")[:120],
                }
                for c in flat
            ],
            "judge_flags": {k: v for k, v in claims["judge"][0].flags.items() if v},
            "derived_findings": [f.type for f in findings_from_judge(claims["judge"])],
            "accepted_hallucinations": hallucination_count(flat, index=index),
            "verifier": verify_catch_rate(root / "tests/fixtures/verifier"),
            "injection": injection_resistance(root / "tests/fixtures/inject"),
            "live_provider_tested": False,
            "target_code_executed": False,
        }
