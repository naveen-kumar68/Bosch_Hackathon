"""Public registry facts. Missing provenance/publisher fields remain unknown."""

import json
from datetime import UTC, datetime
from urllib.parse import quote


def index_path(name):
    name = name.lower()
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        raise ValueError("Unsafe crate name")
    return (
        "1/" + name
        if len(name) == 1
        else "2/" + name
        if len(name) == 2
        else (
            "3/" + name[0] + "/" + name
            if len(name) == 3
            else name[:2] + "/" + name[2:4] + "/" + name
        )
        if len(name) > 1
        else "1/" + name
    )


class Registry:
    def __init__(self, http):
        self.http = http

    def crate_history(self, name):
        raw, evidence = self.http.get("https://index.crates.io/" + index_path(name))
        return [json.loads(line) for line in raw.splitlines() if line.strip()], evidence

    def metadata(self, component):
        if component.ecosystem == "cargo":
            raw, evidence = self.http.get(
                "https://crates.io/api/v1/crates/"
                + quote(component.name)
                + "/"
                + quote(component.version)
            )
            version = json.loads(raw)["version"]
            return {
                "published": version.get("created_at"),
                "publisher": (version.get("published_by") or {}).get("id"),
                "yanked": version["yanked"],
                "trusted_publishing": bool(version["trustpub_data"])
                if "trustpub_data" in version
                else None,
                "checksum": version.get("checksum"),
                "evidence_ids": [evidence],
            }, []
        raw, evidence = self.http.get(
            "https://pypi.org/pypi/"
            + quote(component.name)
            + "/"
            + quote(component.version)
            + "/json"
        )
        document = json.loads(raw)
        files = document["urls"]
        dates = sorted(f["upload_time_iso_8601"] for f in files)
        return {
            "published": dates[0] if dates else None,
            "publisher": None,
            "trusted_publishing": None,
            "yanked": all(f["yanked"] for f in files) if files else None,
            "evidence_ids": [evidence],
            "files": files,
            "dependencies": document["info"].get("requires_dist") or [],
            "dependencies_known": document["info"].get("requires_dist") is not None,
        }, []


def new_dependencies(history, before, after):
    by_version = {item["vers"]: item for item in history}
    old, new = by_version[before], by_version[after]

    def identity(dep):
        return (dep.get("package") or dep["name"], dep.get("kind", "normal"), dep.get("target"))

    previous = {identity(d) for d in old["deps"]}
    added = [d for d in new["deps"] if identity(d) not in previous]
    position = next(i for i, item in enumerate(history) if item["vers"] == after)
    for dep in added:
        count = 0
        for prior in reversed(history[:position]):
            if any(identity(d) == identity(dep) for d in prior["deps"]):
                break
            count += 1
        dep = dict(dep)
        dep["absent_in_previous_versions"] = count
        yield dep


def metadata_changes(before, after, now=None):
    now = now or datetime.now(UTC)
    types = []
    if after.get("published"):
        age = (now - datetime.fromisoformat(after["published"])).total_seconds()
        if 0 <= age < 7 * 86400:
            types.append("recent_release")
    if after.get("yanked") is True:
        types.append("yanked")
    if before:
        if (
            before.get("publisher") is not None
            and after.get("publisher") is not None
            and (before["publisher"] != after["publisher"])
        ):
            types.append("publisher_changed")
        if before.get("trusted_publishing") is True and after.get("trusted_publishing") is False:
            types.append("provenance_regression")
    return types
