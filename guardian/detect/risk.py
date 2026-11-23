from pathlib import Path

import yaml

LEVELS = ["info", "low", "medium", "high", "critical"]


def load_rules(path: Path) -> dict:
    rules = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
    for name, rule in rules.items():
        if rule["severity"] not in LEVELS or not rule.get("rationale"):
            raise ValueError(f"Invalid severity rule {name}")
    return rules


def vulnerability_severity(score, kev, epss, scopes):
    if kev is True:
        return "critical", "kev"
    base = (
        "medium"
        if score is None
        else (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
            if score > 0
            else "info"
        )
    )
    index = LEVELS.index(base)
    rule = "cvss" if score is not None else "vulnerability"
    if epss is not None and epss >= 0.1:
        index = min(4, index + 1)
        rule += "+epss"
    if set(scopes) == {"dev"}:
        index = max(0, index - 1)
        rule += "+dev_only"
    return LEVELS[index], rule
