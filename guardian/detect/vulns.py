"""Alias-connected advisory union. Scanners remain independent evidence sources."""

from collections import defaultdict

from guardian.detect.models import Vulnerability


def deduplicate(observations: list[Vulnerability]) -> list[Vulnerability]:
    parent = {}

    def root(alias):
        parent.setdefault(alias, alias)
        while parent[alias] != alias:
            parent[alias] = parent[parent[alias]]
            alias = parent[alias]
        return alias

    for item in observations:
        for alias in item.aliases:
            parent[root(alias)] = root(item.id)
    groups = defaultdict(list)
    for item in observations:
        groups[(item.component, root(item.id))].append(item)
    result = []
    for (component, _), items in sorted(groups.items()):
        aliases = sorted({alias for item in items for alias in [item.id, *item.aliases]})
        identifier = next((a for a in aliases if a.startswith("CVE-")), aliases[0])
        result.append(
            Vulnerability(
                id=identifier,
                aliases=aliases,
                component=component,
                evidence_ids=sorted({e for item in items for e in item.evidence_ids}),
                sources=sorted({s for item in items for s in item.sources}),
                vectors=sorted({v for item in items for v in item.vectors}),
                fixed_versions=sorted({v for item in items for v in item.fixed_versions}),
                flags=sorted({v for item in items for v in item.flags}),
            )
        )
    return result


def parse_osv(document: dict, components, evidence_id: str) -> list[Vulnerability]:
    index = defaultdict(list)
    for component in components:
        index[(component.name.lower().replace("_", "-"), component.version)].append(component)
    result = []
    for group in document.get("results", []):
        for package in group.get("packages", []):
            identity = package["package"]
            matches = index.get(
                (identity["name"].lower().replace("_", "-"), identity["version"]), []
            )
            ecosystem = {"crates.io": "cargo", "PyPI": "pypi"}.get(identity.get("ecosystem"))
            for component in matches:
                if component.ecosystem != ecosystem:
                    continue
                for advisory in package.get("vulnerabilities", []):
                    fixed = {
                        event["fixed"]
                        for affected in advisory.get("affected", [])
                        for span in affected.get("ranges", [])
                        for event in span.get("events", [])
                        if "fixed" in event
                    }
                    result.append(
                        Vulnerability(
                            id=advisory["id"],
                            aliases=advisory.get("aliases", []),
                            component=component.purl,
                            evidence_ids=[evidence_id],
                            sources=["osv"],
                            vectors=[
                                s["score"]
                                for s in advisory.get("severity", [])
                                if s.get("type", "").startswith("CVSS")
                            ],
                            fixed_versions=sorted(fixed),
                        )
                    )
    return result
