from collections import defaultdict

from packaging.version import InvalidVersion, Version

from guardian.models import Component


def inventory_diff(before: list[Component], after: list[Component]) -> dict:
    """Group by ecosystem/name; preserve multiple versions without guessing pairings."""
    old, new = defaultdict(list), defaultdict(list)
    for component in before:
        old[(component.ecosystem, component.name)].append(component)
    for component in after:
        new[(component.ecosystem, component.name)].append(component)
    result = {key: [] for key in ("added", "removed", "changed", "integrity", "new_direct")}
    for key in sorted(old.keys() | new.keys()):
        previous, current = old[key], new[key]
        if not previous:
            result["added"].extend(c.model_dump() for c in current)
        elif not current:
            result["removed"].extend(c.model_dump() for c in previous)
        else:
            previous_versions = {c.version for c in previous}
            current_versions = {c.version for c in current}
            if previous_versions != current_versions:
                direction = "changed"
                try:
                    a, b = max(map(Version, previous_versions)), max(map(Version, current_versions))
                    direction = "upgraded" if b > a else "downgraded" if b < a else "changed"
                except InvalidVersion:
                    pass
                result["changed"].append(
                    {
                        "ecosystem": key[0],
                        "name": key[1],
                        "before": sorted(previous_versions),
                        "after": sorted(current_versions),
                        "direction": direction,
                        "components": [c.purl for c in current],
                    }
                )
            for component in current:
                candidates = [c for c in previous if c.version == component.version]
                # Prefer exact source to avoid false checksum conflicts across registries.
                exact = [c for c in candidates if c.source == component.source]
                for prior in exact or candidates:
                    if prior.source != component.source:
                        result["integrity"].append(
                            {
                                "type": "source_changed",
                                "component": component.purl,
                                "before": prior.source,
                                "after": component.source,
                            }
                        )
                    if (
                        prior.checksum
                        and component.checksum
                        and prior.checksum != component.checksum
                    ):
                        result["integrity"].append(
                            {
                                "type": "checksum_changed",
                                "component": component.purl,
                                "before": prior.checksum,
                                "after": component.checksum,
                            }
                        )
        for component in current:
            if component.is_direct and not any(c.is_direct for c in previous):
                result["new_direct"].append(component.purl)
            if component.source in {"crates.io", "registry"} and not component.checksum:
                result["integrity"].append(
                    {"type": "registry_checksum_missing", "component": component.purl}
                )
    result["counts"] = {key: len(value) for key, value in result.items()}
    return result
