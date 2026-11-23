"""Cross-observation critical rule: new build dependency plus gained capabilities."""

from packageurl import PackageURL


def new_build_capability(previous_edges, current_edges, components, capability_hits):
    names = {c.purl: c.name for c in components}

    def name(purl):
        return names.get(purl) or PackageURL.from_string(purl).name

    prior = {(name(e.from_purl), name(e.to_purl)) for e in previous_edges if e.kind == "build"}
    results = []
    for edge in current_edges:
        identity = (name(edge.from_purl), name(edge.to_purl))
        if edge.kind != "build" or identity in prior:
            continue
        hits = [
            hit
            for hit in capability_hits.get(edge.to_purl, [])
            if hit["capability"] in {"network", "process"}
        ]
        if hits:
            results.append(
                {
                    "type": "new_build_dep_network",
                    "parent": edge.from_purl,
                    "component": edge.to_purl,
                    "hits": hits,
                    "evidence_ids": sorted(
                        set(edge.evidence_ids) | {h["evidence_id"] for h in hits}
                    ),
                }
            )
    return results
