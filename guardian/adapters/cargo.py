import hashlib
import json
import os
import re
import tomllib
from pathlib import Path

from packageurl import PackageURL

from guardian.evidence import Recorder, tool_path
from guardian.models import Component, Edge, Resolution, Target


def cargo_purl(name: str, version: str, source: str | None) -> str:
    qualifiers = {}
    if source and source.startswith("git+"):
        qualifiers["vcs_url"] = source
    elif source and not source.startswith(
        (
            "registry+https://github.com/rust-lang/crates.io-index",
            "registry+https://index.crates.io",
        )
    ):
        qualifiers["repository_url"] = source
    if not source:
        qualifiers["repository_url"] = "local"
    return PackageURL(type="cargo", name=name, version=version, qualifiers=qualifiers).to_string()


def parse_metadata(metadata: dict, lock: dict, evidence_ids: list[str]) -> Resolution:
    checksums = {
        (p["name"], p["version"], p.get("source")): p.get("checksum") for p in lock["package"]
    }
    packages = {p["id"]: p for p in metadata["packages"]}
    purls = {
        key: cargo_purl(p["name"], p["version"], p.get("source")) for key, p in packages.items()
    }
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = set(metadata["workspace_members"])
    components = []
    for identifier, package in packages.items():
        source = package.get("source")
        kinds = {kind for target in package["targets"] for kind in target["kind"]}
        components.append(
            Component(
                purl=purls[identifier],
                name=package["name"],
                version=package["version"],
                ecosystem="cargo",
                source="path"
                if source is None
                else ("crates.io" if "crates.io" in source else source),
                checksum=checksums.get((package["name"], package["version"], source)),
                is_root=identifier in roots,
                has_build_script="custom-build" in kinds,
                is_proc_macro="proc-macro" in kinds,
                features=nodes.get(identifier, {}).get("features", []),
                evidence_ids=evidence_ids,
            )
        )
    edges = []
    for identifier, node in nodes.items():
        for dependency in node["deps"]:
            destination = packages[dependency["pkg"]]
            for kind in dependency["dep_kinds"]:
                requirements = [
                    d["req"]
                    for d in packages[identifier]["dependencies"]
                    if d["name"] == destination["name"]
                    and d.get("kind") == kind["kind"]
                    and d.get("target") == kind.get("target")
                ]
                if not requirements:
                    raise ValueError(f"Cannot associate resolved edge with manifest: {dependency}")
                edges.append(
                    Edge(
                        from_purl=purls[identifier],
                        to_purl=purls[dependency["pkg"]],
                        kind=kind["kind"] or "normal",
                        version_req=" || ".join(sorted(set(requirements))),
                        target=kind.get("target"),
                        evidence_ids=evidence_ids,
                    )
                )
    existing = {component.purl for component in components}
    warnings = []
    for package in lock["package"]:
        purl = cargo_purl(package["name"], package["version"], package.get("source"))
        if purl not in existing:
            source = package.get("source", "path")
            components.append(
                Component(
                    purl=purl,
                    name=package["name"],
                    version=package["version"],
                    ecosystem="cargo",
                    source="crates.io" if "crates.io" in source else source,
                    checksum=package.get("checksum"),
                    evidence_ids=evidence_ids,
                )
            )
            warnings.append(
                f"Lock-only component has no active resolved edges or target flags: {purl}"
            )
            existing.add(purl)
    if len(components) != len(lock["package"]):
        raise ValueError("Resolved component inventory differs from Cargo.lock package count")
    return Resolution(components=components, edges=edges, warnings=warnings)


def check_configuration(path: Path) -> None:
    # Reject executable Cargo overrides, not just build scripts. Avoid target-local
    # cargo wrappers, credential providers, custom rustc and toolchain installation.
    for directory in [path, *path.parents]:
        for name in (
            ".cargo/config",
            ".cargo/config.toml",
            "rust-toolchain",
            "rust-toolchain.toml",
        ):
            candidate = directory / name
            if candidate.exists():
                raise ValueError(f"Review required before using Cargo configuration: {candidate}")


def parse_context_tree(text: str, components: list[Component], evidence_id: str) -> dict:
    """Hash identical expanded subtrees, preserving context even for equal feature sets."""
    identities = {}
    for component in components:
        key = (component.name, component.version)
        if key in identities and identities[key] != component.purl:
            raise ValueError("Ambiguous Cargo tree identity: same name/version in multiple sources")
        identities[key] = component.purl
    occurrences, stack, roots = [], [], []
    for line in text.splitlines():
        match = re.match(r"^(\d+)(\S+) v([^ |]+).*?\|(.*)$", line)
        if not match:
            if line.strip():
                raise ValueError(f"Unrecognized Cargo tree line: {line[:160]}")
            continue
        depth = int(match[1])
        if depth > len(stack):
            raise ValueError("Cargo tree depth jumps unexpectedly")
        purl = identities[(match[2], match[3])]
        features = match[4].removesuffix(" (*)").strip()
        index = len(occurrences)
        occurrences.append({"purl": purl, "features": features, "children": []})
        if depth:
            occurrences[stack[depth - 1]]["children"].append(index)
        else:
            roots.append(index)
        stack = stack[:depth] + [index]
    identifiers, nodes, edges = {}, {}, set()
    for index in reversed(range(len(occurrences))):
        occurrence = occurrences[index]
        children = sorted({identifiers[child] for child in occurrence["children"]})
        key = json.dumps([occurrence["purl"], occurrence["features"], children])
        identifier = hashlib.sha256(key.encode()).hexdigest()
        identifiers[index] = identifier
        nodes[identifier] = {
            "purl": occurrence["purl"],
            "features": occurrence["features"],
            "evidence_ids": [evidence_id],
        }
        edges.update((identifier, child) for child in children)
    if not roots:
        raise ValueError("Cargo tree has no roots")
    return {
        "nodes": nodes,
        "edges": sorted(edges),
        "roots": sorted({identifiers[index] for index in roots}),
        "evidence_ids": [evidence_id],
    }


class CargoAdapter:
    def detect(self, path: Path, target: Target) -> bool:
        return target.kind == "repository" and (path / "Cargo.toml").is_file()

    def resolve(self, path: Path, target: Target, revision: str, recorder: Recorder) -> Resolution:
        check_configuration(path)
        lock_path = path / "Cargo.lock"
        lock_id = recorder.file(lock_path, "Pinned Cargo.lock, including checksums")
        for manifest in path.rglob("Cargo.toml"):
            recorder.file(manifest, "Target Cargo manifest")
        recorder.run(["cargo", "fetch", "--locked", "--manifest-path", str(path / "Cargo.toml")])
        raw, metadata_id, _ = recorder.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--all-features",
                "--manifest-path",
                str(path / "Cargo.toml"),
            ]
        )
        self.metadata = json.loads(raw)
        resolution = parse_metadata(
            self.metadata,
            tomllib.loads(lock_path.read_text(encoding="utf-8")),
            [metadata_id, lock_id],
        )
        tree, tree_id, _ = recorder.run(
            [
                "cargo",
                "tree",
                "--manifest-path",
                str(path / "Cargo.toml"),
                "--workspace",
                "--locked",
                "--all-features",
                "--target",
                "all",
                "-e",
                "normal,build,dev",
                "--prefix",
                "depth",
                "--no-dedupe",
                "--format",
                "{p}|{f}",
            ]
        )
        resolution.path_context = parse_context_tree(tree, resolution.components, tree_id)
        return resolution

    def sbom(self, path: Path, target: Target, revision: str, recorder: Recorder) -> None:
        lock_before = (path / "Cargo.lock").read_bytes()
        recorder.run(
            [
                "cargo-cyclonedx",
                "cyclonedx",
                "--manifest-path",
                str(path / "Cargo.toml"),
                "--format",
                "json",
                "--all",
                "--all-features",
                "--target",
                "all",
                "--spec-version",
                "1.6",
                "--override-filename",
                "guardian-sbom",
            ],
            env={
                "CARGO_NET_OFFLINE": "true",
                "PATH": str(Path(tool_path("cargo")).parent) + os.pathsep + os.environ["PATH"],
            },
        )
        if (path / "Cargo.lock").read_bytes() != lock_before:
            raise ValueError("Cargo CycloneDX modified the target lockfile")
        files = []
        for package in self.metadata["packages"]:
            if package["id"] in self.metadata["workspace_members"]:
                generated = Path(package["manifest_path"]).parent / "guardian-sbom.json"
                recorder.file(generated, "Cargo CycloneDX workspace member SBOM")
                files.append(str(generated))
        recorder.run(
            [
                "cyclonedx",
                "merge",
                "--input-files",
                *files,
                "--output-file",
                str(recorder.output / "sbom.cdx.json"),
                "--output-format",
                "json",
                "--output-version",
                "v1_6",
            ]
        )
        recorder.file(recorder.output / "sbom.cdx.json", "Merged Cargo CycloneDX SBOM")
        recorder.run(
            [
                "syft",
                "convert",
                str(recorder.output / "sbom.cdx.json"),
                "-o",
                f"spdx-json@2.3={recorder.output / 'sbom.spdx.json'}",
            ]
        )
