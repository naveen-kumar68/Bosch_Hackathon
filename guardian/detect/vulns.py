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


def parse_audit(document: dict, components, evidence_id: str) -> list[Vulnerability]:
    records = [(item, None) for item in document.get("vulnerabilities", {}).get("list", [])]
    for flag, items in document.get("warnings", {}).items():
        records.extend((item, flag) for item in items)
    result = []
    for item, flag in records:
        advisory = item.get("advisory")
        if not advisory:
            continue
        package = item["package"]
        for component in components:
            if component.ecosystem != "cargo" or (component.name, component.version) != (
                package["name"],
                package["version"],
            ):
                continue
            result.append(
                Vulnerability(
                    id=advisory["id"],
                    aliases=advisory.get("aliases", []),
                    component=component.purl,
                    evidence_ids=[evidence_id],
                    sources=["cargo-audit"],
                    vectors=[advisory["cvss"]] if advisory.get("cvss") else [],
                    fixed_versions=item.get("versions", {}).get("patched", []),
                    flags=[flag] if flag else [],
                )
            )
    return result


def parse_pip(document, components, evidence_id):
    result = []
    for item in document.get("dependencies", []):
        matches = [
            c
            for c in components
            if c.ecosystem == "pypi"
            and c.name.replace("_", "-").lower() == item["name"].replace("_", "-").lower()
            and c.version == item["version"]
        ]
        for component in matches:
            for vulnerability in item.get("vulns", []):
                result.append(
                    Vulnerability(
                        id=vulnerability["id"],
                        aliases=vulnerability.get("aliases", []),
                        component=component.purl,
                        evidence_ids=[evidence_id],
                        sources=["pip-audit"],
                        fixed_versions=vulnerability.get("fix_versions", []),
                    )
                )
    return result


def parse_grype(document, components, evidence_id):
    result = []
    for match in document.get("matches", []):
        artifact, advisory = match["artifact"], match["vulnerability"]
        for component in components:
            if (component.name, component.version) != (artifact["name"], artifact["version"]):
                continue
            vectors = [c["vector"] for c in advisory.get("cvss", []) if c.get("vector")]
            result.append(
                Vulnerability(
                    id=advisory["id"],
                    aliases=[],
                    component=component.purl,
                    evidence_ids=[evidence_id],
                    sources=["grype"],
                    vectors=vectors,
                    fixed_versions=advisory.get("fix", {}).get("versions", []),
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
