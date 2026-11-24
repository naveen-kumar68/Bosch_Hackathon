"""Registry metadata sources for candidate generation: crates.io sparse index and PyPI JSON."""

import json
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Dep:
    name: str
    req: str
    kind: str = "normal"


@dataclass
class VersionInfo:
    version: str
    yanked: bool = False
    deps: list[Dep] | None = field(default_factory=list)  # None = not loaded yet
    cksum: str | None = None


@dataclass
class IndexResult:
    versions: list[VersionInfo]
    evidence_id: str | None = None


class StaticIndex:
    """Hand-made index for tests and offline runs: {name: [VersionInfo, ...]}."""

    def __init__(self, data: dict[str, list[VersionInfo]], evidence_id: str = "EV-IDX"):
        self.data, self.evidence_id = data, evidence_id

    def lookup(self, name: str) -> IndexResult:
        return IndexResult(list(self.data.get(name, [])), self.evidence_id)

    def deps(self, name: str, version: str) -> list[Dep]:
        for info in self.data.get(name, []):
            if info.version == version:
                return info.deps or []
        return []


def sparse_path(name: str) -> str:
    n = name.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


class SparseIndex:
    """crates.io sparse index. `get(url) -> (bytes, evidence_id)` is CachedHTTP.get."""

    BASE = "https://index.crates.io/"

    def __init__(self, get: Callable[[str], tuple[bytes, str]]):
        self.get = get

    def lookup(self, name: str) -> IndexResult:
        data, evidence_id = self.get(self.BASE + sparse_path(name))
        versions = []
        for line in data.decode("utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            deps = [
                Dep(d.get("package") or d["name"], d["req"], d.get("kind") or "normal")
                for d in row.get("deps", [])
            ]
            versions.append(
                VersionInfo(row["vers"], bool(row.get("yanked")), deps, row.get("cksum"))
            )
        return IndexResult(versions, evidence_id)

    def deps(self, name: str, version: str) -> list[Dep]:
        for info in self.lookup(name).versions:
            if info.version == version:
                return info.deps or []
        return []


class PyPIIndex:
    """PyPI JSON API; requires_dist is fetched per version, only for versions considered."""

    BASE = "https://pypi.org/pypi/"

    def __init__(self, get: Callable[[str], tuple[bytes, str]]):
        self.get = get

    def lookup(self, name: str) -> IndexResult:
        data, evidence_id = self.get(f"{self.BASE}{name}/json")
        releases = json.loads(data)["releases"]
        versions = [
            VersionInfo(v, bool(files) and all(f.get("yanked") for f in files), None)
            for v, files in releases.items()
            if files
        ]
        return IndexResult(versions, evidence_id)

    def deps(self, name: str, version: str) -> list[Dep]:
        from packaging.requirements import Requirement

        data, _ = self.get(f"{self.BASE}{name}/{version}/json")
        out = []
        for line in json.loads(data)["info"].get("requires_dist") or []:
            if "extra ==" in line:
                continue
            req = Requirement(line)
            out.append(Dep(req.name, str(req.specifier)))
        return out
