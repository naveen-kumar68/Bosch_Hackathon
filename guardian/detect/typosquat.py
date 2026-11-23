import json
import re

from rapidfuzz.distance import DamerauLevenshtein


def popular_names(http, ecosystem, minimum=5000):
    evidence, names = [], set()
    if ecosystem == "cargo":
        for page in range(1, 51):
            raw, identifier = http.get(
                f"https://crates.io/api/v1/crates?page={page}&per_page=100&sort=downloads"
            )
            evidence.append(identifier)
            names.update(crate["id"] for crate in json.loads(raw)["crates"])
    elif ecosystem == "pypi":
        raw, identifier = http.get(
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
        )
        evidence.append(identifier)
        names = {item["project"] for item in json.loads(raw)["rows"]}
    else:
        raise ValueError("Unsupported popularity registry")
    if len(names) < minimum:
        raise ValueError(f"Popularity dataset only contains {len(names)} unique names")
    return sorted(names), evidence


def candidates(name, popular, allowlist=()):
    if name in popular:
        return []
    allowed = {frozenset(pair) for pair in allowlist}
    hits = []
    for other in popular:
        if frozenset((name, other)) in allowed:
            continue
        distance = DamerauLevenshtein.distance(name, other, score_cutoff=2)
        digit_swap = re.sub(r"\d+$", "", name) == re.sub(r"\d+$", "", other) and name != other
        separator_swap = name.replace("_", "-") == other.replace("_", "-")
        if distance <= 2 or digit_swap or separator_swap:
            hits.append(
                {
                    "popular_name": other,
                    "distance": distance,
                    "digit_suffix": digit_swap,
                    "separator_swap": separator_swap,
                }
            )
    return sorted(hits, key=lambda hit: (hit["distance"], hit["popular_name"]))
