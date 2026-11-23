import configparser
import re
import tomllib
from pathlib import Path

from packageurl import PackageURL

from guardian.evidence import Recorder
from guardian.models import Component, Edge, Resolution, Target


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(
    text: str, root_name: str, root_version: str, evidence_ids: list[str]
) -> Resolution:
    root_name = normalize(root_name)
    root_purl = PackageURL(
        type="pypi", name=root_name, version=root_version, qualifiers={"repository_url": "local"}
    ).to_string()
    entries: dict[str, dict] = {}
    current = None
    in_via = False
    for line in text.splitlines():
        stripped = line.strip()
        pin = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s;\\]+)", stripped)
        if pin:
            name = normalize(pin[1])
            if name in entries:
                raise ValueError(f"Multiple pins for {name}; marker-specific resolution required")
            current = entries[name] = {
                "name": name,
                "version": pin[2],
                "via": [],
                "hashes": [],
                "marker": stripped.partition(";")[2].strip(),
            }
            in_via = False
        elif stripped and not stripped.startswith(("#", "--hash", "\\")):
            raise ValueError(f"Unsupported or unpinned requirement: {stripped}")
        if current is None:
            continue
        current["hashes"].extend(re.findall(r"--hash=sha256:([0-9a-fA-F]{64})", line))
        if stripped.startswith("# via"):
            in_via = True
            via = stripped.removeprefix("# via").strip()
            if via:
                current["via"].append(via)
        elif in_via and re.match(r"^\s+#\s{3,}\S", line):
            current["via"].append(stripped.lstrip("#").strip())
        elif stripped.startswith("#"):
            in_via = False
    components = [
        Component(
            purl=root_purl,
            name=root_name,
            version=root_version,
            ecosystem="pypi",
            source="path",
            is_root=True,
            evidence_ids=evidence_ids,
        )
    ]
    ids = {}
    for name, item in entries.items():
        purl = PackageURL(type="pypi", name=name, version=item["version"]).to_string()
        ids[name] = purl
        components.append(
            Component(
                purl=purl,
                name=name,
                version=item["version"],
                ecosystem="pypi",
                source="pypi",
                has_hash=bool(item["hashes"]),
                checksum=",".join(item["hashes"]) or None,
                evidence_ids=evidence_ids,
            )
        )
    edges = []
    warnings = []
    for name, item in entries.items():
        if not item["via"]:
            raise ValueError(f"Missing # via provenance for {name}")
        for via in item["via"]:
            parent_name = normalize(via.split("[", 1)[0].split(" ", 1)[0])
            is_root = via.startswith(("-r ", "-c ", ".", "setup.", "pyproject.toml")) or (
                parent_name == root_name
            )
            parent = root_purl if is_root else ids.get(parent_name)
            if parent is None:
                raise ValueError(f"Unknown # via parent {via!r} for {name}")
            edges.append(
                Edge(
                    from_purl=parent,
                    to_purl=ids[name],
                    kind="normal",
                    version_req="==" + item["version"],
                    target=item["marker"] or None,
                    evidence_ids=evidence_ids,
                )
            )
        if item["marker"]:
            warnings.append(f"Inventory retains conditional pin {name}: {item['marker']}")
    return Resolution(components=components, edges=edges, warnings=warnings)


class PypiAdapter:
    def detect(self, path: Path, target: Target) -> bool:
        return target.kind == "repository" and any(
            (path / p).is_file() for p in ("requirements.txt", "pyproject.toml", "setup.cfg")
        )

    def resolve(self, path: Path, target: Target, revision: str, recorder: Recorder) -> Resolution:
        name, version = target.name, target.ref
        manifest_evidence = []
        for manifest in ("setup.cfg", "pyproject.toml"):
            if (path / manifest).is_file():
                manifest_evidence.append(recorder.file(path / manifest, "Static Python manifest"))
        if (path / "setup.cfg").is_file():
            config = configparser.ConfigParser(interpolation=None)
            config.read(path / "setup.cfg", encoding="utf-8")
            name = config.get("metadata", "name", fallback=name)
        elif (path / "pyproject.toml").is_file():
            project = tomllib.loads((path / "pyproject.toml").read_text(encoding="utf-8"))
            name = project.get("project", {}).get("name", name)
            version = project.get("project", {}).get("version", version)
        self.requirements = path / "requirements.txt"
        if not self.requirements.is_file() or "# via" not in self.requirements.read_text(
            encoding="utf-8"
        ):
            source = self.requirements if self.requirements.is_file() else path / "pyproject.toml"
            if not source.is_file():
                raise ValueError(
                    "No static requirements/pyproject input; refusing to execute setup.py"
                )
            recorder.file(source, "Static Python resolver input")
            self.requirements = recorder.output / "resolved-requirements.txt"
            recorder.run(
                [
                    "uv",
                    "pip",
                    "compile",
                    "--no-build",
                    "--generate-hashes",
                    "--no-config",
                    str(source),
                    "--output-file",
                    str(self.requirements),
                ]
            )
        evidence = recorder.file(
            self.requirements, "Pinned Python requirements and via annotations"
        )
        return parse_requirements(
            self.requirements.read_text(encoding="utf-8"),
            name,
            version,
            [evidence, *manifest_evidence],
        )

    def sbom(self, path: Path, target: Target, revision: str, recorder: Recorder) -> None:
        recorder.run(
            [
                "cyclonedx-py",
                "requirements",
                str(self.requirements),
                "--output-format",
                "JSON",
                "--spec-version",
                "1.6",
                "--output-file",
                str(recorder.output / "sbom.cdx.json"),
            ]
        )
        recorder.file(recorder.output / "sbom.cdx.json", "Python CycloneDX SBOM")
        recorder.run(
            [
                "syft",
                "convert",
                str(recorder.output / "sbom.cdx.json"),
                "-o",
                f"spdx-json@2.3={recorder.output / 'sbom.spdx.json'}",
            ]
        )
