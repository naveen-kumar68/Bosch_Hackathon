"""Static image recipe checks and inventory drift; no container execution."""

import re
from collections import defaultdict


def inspect_dockerfile(text: str) -> list[dict]:
    hits, stages = [], set()
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(
            r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE
        )
        if not match:
            continue
        image = match[1]
        if image.lower() != "scratch" and image.lower() not in stages:
            if not re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
                hits.append({"type": "mutable_base_image", "line": number, "image": image})
            tag = image.rsplit(":", 1)[-1].split("@", 1)[0]
            if tag in {"latest", "sid", "sid-slim", "unstable", "unstable-slim"}:
                hits.append({"type": "unstable_base_image", "line": number, "image": image})
        if match[2]:
            stages.add(match[2].lower())
    return hits


def inventory_drift(shipped: dict, observed: dict) -> dict:
    def versions(document):
        result = defaultdict(set)

        def visit(items):
            for item in items:
                # Keep PURL ecosystem/name/qualifiers; compare version separately.
                from packageurl import PackageURL

                if item.get("purl"):
                    purl = PackageURL.from_string(item["purl"])
                    key = PackageURL(
                        type=purl.type,
                        namespace=purl.namespace,
                        name=purl.name,
                        qualifiers=purl.qualifiers,
                        subpath=purl.subpath,
                    ).to_string()
                else:
                    key = item.get("group", "") + "/" + item["name"]
                result[key].add(item.get("version", "unknown"))
                visit(item.get("components", []))

        visit(document.get("components", []))
        return result

    a, b = versions(shipped), versions(observed)
    return {
        "missing_from_observed": {k: sorted(a[k]) for k in sorted(a.keys() - b.keys())},
        "extra_in_observed": {k: sorted(b[k]) for k in sorted(b.keys() - a.keys())},
        "version_mismatched": {
            k: {"shipped": sorted(a[k]), "observed": sorted(b[k])}
            for k in sorted(a.keys() & b.keys())
            if a[k] != b[k]
        },
    }
