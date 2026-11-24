"""Captured registry adapters only: no HTTP, downloads, file reads or execution."""

from collections.abc import Iterable, Mapping
from typing import Literal

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from pydantic import Field

from guardian.remediate.models import EvidenceId, Model


class Dependency(Model):
    package: str
    requirement: str
    conditional: bool = False


class Release(Model):
    version: str
    yanked: bool | None
    evidence_ids: list[EvidenceId] = Field(min_length=1)
    dependencies: list[Dependency] | None = None
    requires_python: str | None = None


class PackageIndex(Model):
    ecosystem: Literal["cargo", "pypi"]
    package: str
    releases: list[Release]
    evidence_ids: list[EvidenceId] = Field(min_length=1)


def identity(ecosystem, name):
    return canonicalize_name(name) if ecosystem == "pypi" else name


class RegistrySnapshot:
    def __init__(self, packages: Iterable[PackageIndex] = ()):
        self.packages = {}
        for package in packages:
            key = package.ecosystem, identity(package.ecosystem, package.package)
            if key in self.packages:
                raise ValueError("Duplicate registry package snapshot")
            if len({r.version for r in package.releases}) != len(package.releases):
                raise ValueError("Duplicate registry release snapshot")
            self.packages[key] = package.model_copy(deep=True)

    def lookup(self, ecosystem: str, package: str) -> PackageIndex | None:
        return self.packages.get((ecosystem, identity(ecosystem, package)))


def cargo_index(package: str, rows: Iterable[Mapping], evidence_id: str) -> PackageIndex:
    releases = []
    for row in rows:
        if row.get("name") != package:
            raise ValueError("Cargo index package identity mismatch")
        deps = row.get("deps")
        dependencies = (
            None
            if not isinstance(deps, list)
            else [
                Dependency(
                    package=d.get("package") or d["name"],
                    requirement=d["req"],
                    conditional=bool(d.get("target") or d.get("optional") or d.get("registry")),
                )
                for d in deps
            ]
        )
        releases.append(
            Release(
                version=row["vers"],
                yanked=row.get("yanked"),
                dependencies=dependencies,
                evidence_ids=[evidence_id],
            )
        )
    return PackageIndex(
        ecosystem="cargo", package=package, releases=releases, evidence_ids=[evidence_id]
    )


def pypi_index(
    package: str,
    document: Mapping,
    evidence_id: str,
    *,
    version_documents: Mapping[str, tuple[Mapping, str]] | None = None,
) -> PackageIndex:
    """Per-version metadata/evidence is required to prove a parent's requires_dist."""
    if identity("pypi", document["info"]["name"]) != identity("pypi", package):
        raise ValueError("PyPI index package identity mismatch")
    releases = []
    for version, files in document["releases"].items():
        metadata = (version_documents or {}).get(version)
        evidence = [evidence_id]
        dependencies, requires_python = None, None
        if metadata:
            data, metadata_id = metadata
            info = data["info"]
            if (
                identity("pypi", info["name"]) != identity("pypi", package)
                or info["version"] != version
            ):
                raise ValueError("PyPI release metadata identity mismatch")
            evidence.append(metadata_id)
            requires_python = info.get("requires_python")
            if isinstance(info.get("requires_dist"), list):
                dependencies = []
                for item in info["requires_dist"]:
                    try:
                        req = Requirement(item)
                    except InvalidRequirement:
                        dependencies = None
                        break
                    dependencies.append(
                        Dependency(
                            package=canonicalize_name(req.name),
                            requirement=str(req.specifier),
                            conditional=bool(req.marker or req.url or req.extras),
                        )
                    )
        flags = [f.get("yanked") for f in files]
        yanked = (
            False
            if any(f is False for f in flags)
            else (True if flags and all(f is True for f in flags) else None)
        )
        # Without release metadata, use only unanimous artifact requires_python.
        if not metadata:
            requirements = {f.get("requires_python") for f in files}
            if len(requirements) == 1:
                requires_python = next(iter(requirements))
            elif len(requirements) > 1:
                continue  # artifact-specific interpreter compatibility is unknown
        releases.append(
            Release(
                version=version,
                yanked=yanked,
                dependencies=dependencies,
                requires_python=requires_python,
                evidence_ids=sorted(set(evidence)),
            )
        )
    return PackageIndex(
        ecosystem="pypi", package=package, releases=releases, evidence_ids=[evidence_id]
    )
