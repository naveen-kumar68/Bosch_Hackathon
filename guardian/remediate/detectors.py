"""Read captured facts and invoke bound existing detectors; no detector rule copies."""

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from packageurl import PackageURL

from guardian.remediate.registry import identity
from guardian.remediate.vet_contracts import CapturedVersion, DetectorBindings


def require_evidence(values):
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise ValueError("Captured detector evidence is missing")
    return list(values)


class CapturedDetectors:
    def __init__(
        self,
        versions: list[CapturedVersion],
        bindings: DetectorBindings,
        *,
        scratch: Path,
        popular_names: dict[str, list[str]] | None = None,
        popularity_evidence: dict[str, list[str]] | None = None,
    ):
        self.versions = {}
        for capture in versions:
            key = capture.ecosystem, identity(capture.ecosystem, capture.package), capture.version
            if key in self.versions:
                raise ValueError("Duplicate captured version")
            self.versions[key] = deepcopy(capture)
        self.bindings, self.scratch = bindings, scratch.resolve()
        self.popular_names, self.popularity_evidence = (
            popular_names or {},
            popularity_evidence or {},
        )

    def lookup(self, ecosystem, package, version):
        result = self.versions.get((ecosystem, identity(ecosystem, package), version))
        if result is None:
            raise ValueError("Version capture unavailable")
        require_evidence(result.metadata_evidence_ids)
        return result

    def vulnerability(self, capture):
        evidence = require_evidence(capture.osv_evidence_ids)
        document = capture.osv_document
        if not isinstance(document, dict):
            raise TypeError("OSV result unavailable")
        ecosystem = {"cargo": "crates.io", "pypi": "PyPI"}[capture.ecosystem]
        covered, expected = False, set()
        for group in document.get("results", []):
            for package in group.get("packages", []):
                target = package.get("package", {})
                if (
                    identity(capture.ecosystem, target.get("name", ""))
                    == identity(capture.ecosystem, capture.package)
                    and target.get("version") == capture.version
                    and target.get("ecosystem") == ecosystem
                    and isinstance(package.get("vulnerabilities"), list)
                ):
                    covered = True
                    for advisory in package["vulnerabilities"]:
                        if not isinstance(advisory.get("id"), str) or not advisory["id"]:
                            raise ValueError("OSV advisory identity incomplete")
                        expected.add(advisory["id"])
        if not covered:
            raise ValueError("OSV result does not cover candidate identity")
        purl = PackageURL(
            type=capture.ecosystem, name=capture.package, version=capture.version
        ).to_string()
        component = SimpleNamespace(
            name=capture.package, version=capture.version, ecosystem=capture.ecosystem, purl=purl
        )
        records = self.bindings.parse_osv(document, [component], evidence[0])
        if {record.id for record in records} != expected:
            raise ValueError("OSV parser coverage does not match captured advisories")
        return [record.id for record in records], evidence

    def metadata_changes(self, before, after, now):
        return self.bindings.metadata_changes(before.metadata, after.metadata, now=now)

    def dependencies(self, before, after):
        evidence = require_evidence(after.history_evidence_ids)
        if not isinstance(after.history, list):
            raise TypeError("Dependency history unavailable")
        versions = [row["vers"] for row in after.history]
        if (
            len(set(versions)) != len(versions)
            or before.version not in versions
            or after.version not in versions
        ):
            raise ValueError("Dependency history identity incomplete")
        for row in after.history:
            if identity(after.ecosystem, row.get("name", "")) != identity(
                after.ecosystem, after.package
            ) or not isinstance(row.get("deps"), list):
                raise ValueError("Dependency history identity incomplete")
            if any(dependency.get("registry") for dependency in row["deps"]):
                raise ValueError("Foreign dependency registry requires explicit source vetting")
        # Both Cargo index and normalized captured PyPI requires_dist rows use
        # the existing detector's vers/deps/name/kind/target schema.
        return list(
            self.bindings.new_dependencies(after.history, before.version, after.version)
        ), evidence

    def typosquats(self, ecosystem, dependencies, minimum):
        names = self.popular_names.get(ecosystem)
        evidence = require_evidence(self.popularity_evidence.get(ecosystem))
        if not names or len(set(names)) < minimum:
            raise ValueError("Popularity corpus coverage insufficient")
        matches = []
        for dependency in dependencies:
            name = dependency.get("package") or dependency["name"]
            for match in self.bindings.typosquat_candidates(name, names):
                matches.append({"package": name, "kind": dependency.get("kind", "normal"), **match})
        return matches, evidence

    def static_diff(self, before, after):
        """Verify hashes before extraction/inspection. Temporary sources are never executed."""
        evidence, hits = [], []
        self.scratch.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="guardian-vet-", dir=self.scratch) as temporary:
            root = Path(temporary).resolve()
            if not root.is_relative_to(self.scratch):
                raise ValueError("Inspection workspace escaped scratch root")
            for index, capture in enumerate((before, after)):
                evidence.extend(require_evidence(capture.artifact_evidence_ids))
                evidence.extend(require_evidence(capture.checksum_evidence_ids))
                if not isinstance(capture.artifact, bytes):
                    raise TypeError("Captured artifact bytes unavailable")
                self._bind_checksum(capture)
                directory = root / str(index)
                self.bindings.verified_extract(capture.artifact, capture.registry_sha256, directory)
                # Conservative: inspect all Rust source, also covering proc-macros.
                # Python's existing detector selects setup.py. No target build occurs.
                proc_macro = capture.ecosystem == "cargo"
                found = self.bindings.inspect_sources(directory, proc_macro=proc_macro)
                document, scanner_evidence = self.bindings.semgrep(directory, proc_macro=proc_macro)
                evidence.extend(require_evidence([scanner_evidence]))
                if (
                    not isinstance(document, dict)
                    or not isinstance(document.get("errors"), list)
                    or document.get("errors")
                    or not isinstance(document.get("results"), list)
                ):
                    raise ValueError("Static scanner failed or incomplete")
                # Any newly reported Semgrep rule is retained for conservative rejection;
                # regex capability names come only from the existing detector.
                for result in document["results"]:
                    found.append({"capability": "semgrep:" + result["check_id"]})
                hits.append(found)
        return self.bindings.capability_diff(hits[0], hits[1]), sorted(set(evidence))

    @staticmethod
    def _bind_checksum(capture):
        expected = capture.registry_sha256
        if not isinstance(expected, str):
            raise TypeError("Registry checksum unavailable")
        if capture.ecosystem == "cargo":
            rows = [
                r
                for r in (capture.history or [])
                if r.get("vers") == capture.version and r.get("name") == capture.package
            ]
            if (
                len(rows) != 1
                or rows[0].get("cksum", "").lower() != expected.lower()
                or not set(capture.checksum_evidence_ids) & set(capture.history_evidence_ids)
            ):
                raise ValueError("Checksum is not bound to captured Cargo index version")
        elif capture.ecosystem == "pypi":
            hashes = [
                f.get("digests", {}).get("sha256", "").lower()
                for f in capture.metadata.get("files", [])
            ]
            if expected.lower() not in hashes or not set(capture.checksum_evidence_ids) & set(
                capture.metadata_evidence_ids
            ):
                raise ValueError("Checksum is not bound to captured PyPI artifact metadata")
        else:
            raise ValueError("Unsupported checksum source")
