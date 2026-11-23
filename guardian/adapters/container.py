import json
from pathlib import Path

from packageurl import PackageURL

from guardian.evidence import Recorder
from guardian.models import Component, Edge, Resolution, Target


class ContainerAdapter:
    def detect(self, path: Path, target: Target) -> bool:
        return target.kind == "image"

    def resolve(self, path: Path, target: Target, revision: str, recorder: Recorder) -> Resolution:
        image = f"{target.source}@{revision}"
        raw, evidence, _ = recorder.run(["syft", "scan", "docker:" + image, "-o", "syft-json"])
        document = json.loads(raw)
        (recorder.output / "syft.json").write_text(raw, encoding="utf-8", newline="\n")
        root = PackageURL(
            type="oci",
            name=target.source.rsplit("/", 1)[-1],
            version=revision,
            qualifiers={"repository_url": target.source},
        ).to_string()
        components = {
            root: Component(
                purl=root,
                name=target.name,
                version=revision,
                ecosystem="oci",
                source=target.source,
                is_root=True,
                evidence_ids=[evidence],
            )
        }
        warnings = []
        for item in document["artifacts"]:
            purl = item.get("purl")
            if not purl:
                raise ValueError(f"Syft artifact lacks purl: {item['name']}")
            purl = PackageURL.from_string(purl).to_string()
            if purl in components:
                continue
            checksums = item.get("checksums", [])
            components[purl] = Component(
                purl=purl,
                name=item["name"],
                version=item.get("version") or "unknown",
                ecosystem=PackageURL.from_string(purl).type,
                source="image",
                checksum=",".join(c["algorithm"] + ":" + c["value"] for c in checksums) or None,
                evidence_ids=[evidence],
            )
        # Syft inventories are containment observations, not invented package dependencies.
        edges = [
            Edge(from_purl=root, to_purl=purl, kind="contains", evidence_ids=[evidence])
            for purl in components
            if purl != root
        ]
        warnings.append(
            "Container edges represent image containment, not package dependency resolution."
        )
        container, _, _ = recorder.run(["docker", "create", image])
        container = container.strip()
        try:
            recorder.run(
                [
                    "docker",
                    "cp",
                    f"{container}:/app/sbom.json",
                    str(recorder.output / "shipped-sbom.json"),
                ]
            )
            recorder.file(recorder.output / "shipped-sbom.json", "SBOM shipped at /app/sbom.json")
        finally:
            recorder.run(["docker", "rm", container])
        return Resolution(components=list(components.values()), edges=edges, warnings=warnings)

    def sbom(self, path: Path, target: Target, revision: str, recorder: Recorder) -> None:
        recorder.run(
            [
                "syft",
                "convert",
                str(recorder.output / "syft.json"),
                "-o",
                f"cyclonedx-json@1.6={recorder.output / 'sbom.cdx.json'}",
                "-o",
                f"spdx-json@2.3={recorder.output / 'sbom.spdx.json'}",
            ]
        )
