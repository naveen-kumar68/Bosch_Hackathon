"""Load verifier fixtures (scenario + labelled claims) and measure the catch rate."""

import json
from pathlib import Path

from guardian.verify.check import check
from guardian.verify.facts import FactsIndex
from guardian.verify.models import AIClaim


def load_scenario(fixtures_dir: Path) -> FactsIndex:
    s = json.loads((Path(fixtures_dir) / "scenario.json").read_text("utf-8"))
    return FactsIndex.build(
        components=s.get("components", []),
        findings=s.get("findings", []),
        vulnerabilities=s.get("vulnerabilities", []),
        options=s.get("options", []),
        evidence_ids=s.get("evidence_ids", []),
    )


def load_cases(fixtures_dir: Path) -> list[dict]:
    return json.loads((Path(fixtures_dir) / "cases.json").read_text("utf-8"))


def run_cases(fixtures_dir: Path) -> list[tuple[dict, AIClaim]]:
    index = load_scenario(fixtures_dir)
    return [(c, check(AIClaim.model_validate(c["claim"]), index)) for c in load_cases(fixtures_dir)]
