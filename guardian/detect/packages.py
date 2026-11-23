"""Registry and artifact observations for added or version-changed packages."""

import json
from pathlib import Path

import yaml
from packaging.requirements import Requirement
from packaging.version import Version

from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import Registry, metadata_changes, new_dependencies
from guardian.detect.static_tools import guarddog, semgrep
from guardian.detect.typosquat import candidates, popular_names


def inspect_packages(scan, previous, http, recorder, root: Path, add):
    registry = Registry(http)
    allowlist_file = root / "rules/typosquat.yaml"
    allowlists = yaml.safe_load(allowlist_file.read_text(encoding="utf-8"))["allowlist"]
    allowlist_evidence = recorder.file(allowlist_file, "Reviewed legitimate name pairs")
    old = {}
    for component in previous.components if previous else []:
        old.setdefault((component.ecosystem, component.name), []).append(component)
    current = {}
    for component in scan.components:
        current.setdefault((component.ecosystem, component.name), set()).add(component.version)
    popularity = {}
    observations = {}
    capabilities = {}
    for component in scan.components:
        if component.is_root or component.source not in {"crates.io", "registry", "pypi"}:
            continue
        prior = old.get((component.ecosystem, component.name), [])
        changed = (
            bool(previous)
            and {c.version for c in prior} != current[(component.ecosystem, component.name)]
        )
        added = bool(previous) and not prior
        needs_name = added or component.has_build_script or component.is_proc_macro
        if needs_name:
            if component.ecosystem not in popularity:
                popularity[component.ecosystem] = popular_names(http, component.ecosystem)
            names, ids = popularity[component.ecosystem]
            hits = candidates(component.name, names, allowlists.get(component.ecosystem, []))
            if hits:
                add(
                    "typosquat_added" if added else "typosquat_candidate",
                    component.purl,
                    "Package name resembles popular registry names",
                    [*ids, allowlist_evidence],
                    {"matches": hits, "newly_added": added},
                    heuristic=True,
                    needs_judgement=any(hit["distance"] == 2 for hit in hits),
                )
        if not changed:
            continue
        metadata, _ = registry.metadata(component)
        older = max(prior, key=lambda c: Version(c.version)) if prior else None
        before = registry.metadata(older)[0] if older else None
        evidence = [*metadata["evidence_ids"], *(before["evidence_ids"] if before else [])]
        observations[component.purl] = {"before": before, "after": metadata}
        for kind in metadata_changes(before, metadata):
            add(
                kind,
                component.purl,
                "Registry observation: " + kind,
                evidence,
                {"before": before, "after": metadata},
            )
        if (
            component.checksum
            and metadata.get("checksum")
            and component.checksum != metadata["checksum"]
        ):
            add(
                "checksum_changed",
                component.purl,
                "Lockfile checksum differs from registry checksum",
                [*component.evidence_ids, *metadata["evidence_ids"]],
                {"lockfile": component.checksum, "registry": metadata["checksum"]},
            )
        if component.ecosystem != "cargo":

            def python_artifact(package, info):
                files = sorted(
                    info["files"],
                    key=lambda file: (file["packagetype"] != "sdist", file["filename"]),
                )
                if not files:
                    raise ValueError("PyPI release has no artifacts")
                artifact = files[0]
                checksum = artifact["digests"]["sha256"]
                if package.has_hash and checksum not in (package.checksum or "").split(","):
                    raise ValueError("Selected PyPI artifact is not covered by locked hashes")
                data, download = http.get(artifact["url"])
                directory = root / "workspace/artifacts/pypi" / f"{package.name}-{package.version}"
                verified_extract(data, checksum, directory)
                archive = directory.parent / artifact["filename"]
                archive.write_bytes(data)
                recorder.note(
                    "PyPI artifact verified against captured registry SHA256; "
                    "lockfile hash unavailable"
                    if not package.has_hash
                    else "PyPI artifact verified against registry and locked hash",
                    [download, *info["evidence_ids"]],
                )
                hits = inspect_sources(directory)
                for hit in hits:
                    hit["evidence_id"] = recorder.file(
                        directory / hit["file"], "Python static capability source"
                    )
                if any(directory.rglob("setup.py")):
                    semgrep(directory, root / "rules/semgrep", recorder)
                    result, guard_evidence = guarddog(archive, recorder)
                    if result.get("issues", 0):
                        add(
                            "guarddog",
                            package.purl,
                            "GuardDog reported static package heuristics",
                            [guard_evidence],
                            {"result": result},
                            heuristic=True,
                            needs_judgement=True,
                        )
                return hits

            previous_deps = (
                {Requirement(value).name for value in before.get("dependencies", [])}
                if before
                else set()
            )
            for value in metadata.get("dependencies", []):
                dependency = Requirement(value)
                if dependency.name not in previous_deps:
                    add(
                        "new_dependency",
                        component.purl,
                        "New package-internal dependency: " + dependency.name,
                        evidence,
                        {"requirement": value},
                    )
            new_hits = python_artifact(component, metadata)
            old_hits = python_artifact(older, before) if older else []
            diff = capability_diff(old_hits, new_hits)
            capabilities[component.purl] = diff
            for hit in diff:
                add(
                    "capability_added",
                    component.purl,
                    "New static capability: " + hit["capability"],
                    [hit["evidence_id"], *metadata["evidence_ids"]],
                    {"hit": hit},
                    heuristic=True,
                    needs_judgement=True,
                )
            continue
        new_build = []
        if older and older.version != component.version:
            history, index_evidence = registry.crate_history(component.name)
            for dependency in new_dependencies(history, older.version, component.version):
                is_build = dependency.get("kind") == "build"
                add(
                    "new_build_dependency" if is_build else "new_dependency",
                    component.purl,
                    "New package-internal dependency: " + dependency["name"],
                    [index_evidence],
                    dependency,
                )
                if is_build:
                    new_build.append(dependency["name"])
        if not (component.has_build_script or component.is_proc_macro):
            continue

        def inspect_version(package):
            url = f"https://static.crates.io/crates/{package.name}/{package.name}-{package.version}.crate"
            data, download = http.get(url)
            destination = (
                root
                / "workspace/artifacts"
                / package.ecosystem
                / f"{package.name}-{package.version}"
            )
            verified_extract(data, package.checksum, destination)
            recorder.note("Artifact SHA256 verified against lockfile before extraction", [download])
            hits = inspect_sources(destination, proc_macro=bool(package.is_proc_macro))
            for hit in hits:
                hit["evidence_id"] = recorder.file(
                    destination / hit["file"], "Static capability source"
                )
            document, semgrep_evidence = semgrep(
                destination,
                root / "rules/semgrep",
                recorder,
                proc_macro=bool(package.is_proc_macro),
            )
            for match in document.get("results", []):
                # Retained as independent source; regex set controls the same capability diff.
                recorder.note("Semgrep capability hit " + match["check_id"], [semgrep_evidence])
            return hits

        new_hits = inspect_version(component)
        old_hits = inspect_version(older) if older and older.checksum else []
        diff = capability_diff(old_hits, new_hits)
        capabilities[component.purl] = diff
        for hit in diff:
            kind = "capability_added"
            if new_build and hit["capability"] in {"network", "process"}:
                # The cross-package critical correlation is performed separately; do not
                # assume the parent script's capability belongs to the new dependency.
                hit["parent_added_build_dependencies"] = new_build
            add(
                kind,
                component.purl,
                "New static capability: " + hit["capability"],
                [hit["evidence_id"], *metadata["evidence_ids"]],
                {"hit": hit, "previous_version": older.version if older else None},
                heuristic=True,
                needs_judgement=True,
            )
    (recorder.output / "registry-observations.json").write_text(
        json.dumps(observations, indent=2), encoding="utf-8", newline="\n"
    )
    return capabilities
