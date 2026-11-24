"""Fail-closed, evidence-bearing policy decisions over existing detector results."""

from datetime import datetime

from packageurl import PackageURL

from guardian.remediate.detectors import CapturedDetectors
from guardian.remediate.models import FixOption, VettingCheck
from guardian.remediate.registry import identity
from guardian.remediate.vet_contracts import VetPolicy


class Vetter:
    def __init__(self, detectors: CapturedDetectors, policy: VetPolicy, *, now: datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Vetting requires an explicit timezone-aware evaluation time")
        if not all(detectors.bindings.evidence_exists(e) for e in policy.evidence_ids):
            raise ValueError("Vetting policy evidence must exist in the ledger")
        self.detectors, self.policy, self.now = detectors, policy, now

    def vet(self, options: list[FixOption]) -> list[FixOption]:
        return [self._option(option) for option in options]

    def _option(self, original):
        option = FixOption.model_validate(original.model_dump())
        if option.kind == "escalate":
            return option
        option.vetting_checks, option.vetting_reasons = [], []
        purl = PackageURL.from_string(option.component)
        primary = [
            change
            for change in option.changes
            if identity(purl.type, change.package) == identity(purl.type, purl.name)
            and change.from_version == purl.version
            and change.to_version == option.target_version
        ]
        if not primary or not option.changes:
            self._check(
                option,
                "identity",
                option.component,
                False,
                ["Option changes do not bind its component and target version"],
                option.evidence_ids,
            )
        else:
            for change in option.changes:
                self._change(option, purl.type, change)
        option.vetting = (
            "passed" if all(c.status == "passed" for c in option.vetting_checks) else "rejected"
        )
        option.vetting_reasons = [
            reason
            for check in option.vetting_checks
            if check.status == "rejected"
            for reason in check.reasons
        ]
        option.evidence_ids = sorted(
            {
                *option.evidence_ids,
                *(e for check in option.vetting_checks for e in check.evidence_ids),
            }
        )
        return option

    def _check(self, option, name, component, passed, reasons, evidence, flags=None):
        requested = {
            *option.evidence_ids,
            *self.policy.evidence_ids,
            *(e for e in evidence if isinstance(e, str) and e),
        }
        supported = {e for e in requested if self.detectors.bindings.evidence_exists(e)}
        if supported != requested:
            passed = False
            reasons = [*reasons, "Check references evidence not present in the ledger"]
        option.vetting_checks.append(
            VettingCheck(
                check=name,
                component=component,
                status="passed" if passed else "rejected",
                reasons=reasons,
                evidence_ids=sorted(supported),
                flags=flags or [],
            )
        )

    def _change(self, option, ecosystem, change):
        component = PackageURL(
            type=ecosystem, name=change.package, version=change.to_version
        ).to_string()
        try:
            before = self.detectors.lookup(ecosystem, change.package, change.from_version)
            after = self.detectors.lookup(ecosystem, change.package, change.to_version)
        except Exception:  # noqa: BLE001 -- external adapters must fail closed without logging secrets
            self._check(
                option,
                "availability",
                component,
                False,
                ["Version evidence unavailable; candidate rejected"],
                option.evidence_ids,
            )
            return
        evidence = [*before.metadata_evidence_ids, *after.metadata_evidence_ids]
        try:
            advisories, ids = self.detectors.vulnerability(after)
            self._check(
                option,
                "vulnerability",
                component,
                not advisories,
                ["Candidate has advisories: " + ", ".join(sorted(advisories))]
                if advisories
                else ["Captured advisory lookup reports no candidate vulnerabilities"],
                ids,
            )
        except Exception:  # noqa: BLE001
            self._check(
                option,
                "vulnerability",
                component,
                False,
                ["Candidate advisory lookup is missing, incomplete or failed"],
                evidence,
            )
        try:
            published = datetime.fromisoformat(after.metadata["published"])
            if published.tzinfo is None or published.utcoffset() is None:
                raise ValueError("Publication time has no timezone")
            age = (self.now - published).total_seconds() / 86400
            passed = (
                age >= self.policy.min_release_age_days and after.metadata.get("yanked") is False
            )
            reasons = (
                ["Candidate release is old enough and not yanked"]
                if passed
                else ["Candidate is too new, future-dated, yanked or has unknown yank status"]
            )
            self._check(option, "release", component, passed, reasons, evidence)
        except (ValueError, KeyError, TypeError):
            self._check(
                option,
                "release",
                component,
                False,
                ["Release timestamp/yank evidence incomplete"],
                evidence,
            )
        try:
            flags = self.detectors.metadata_changes(before, after, self.now)
            old, new = before.metadata.get("publisher"), after.metadata.get("publisher")
            trusted = self.policy.trusted_publishers.get(
                f"{ecosystem}:{identity(ecosystem, change.package)}", []
            )
            known = all(
                isinstance(value, (str, int)) and not isinstance(value, bool) and value != ""
                for value in (old, new)
            )
            publisher_ok = known and (old == new or new in trusted)
            provenance_ok = (
                isinstance(before.metadata.get("trusted_publishing"), bool)
                and isinstance(after.metadata.get("trusted_publishing"), bool)
                and "provenance_regression" not in flags
            )
            source_ok = (
                isinstance(before.metadata.get("source"), str)
                and bool(before.metadata["source"])
                and before.metadata["source"] == after.metadata.get("source")
            )
            passed = publisher_ok and provenance_ok and source_ok
            self._check(
                option,
                "publisher_provenance",
                component,
                passed,
                ["Publisher/source accepted and publishing provenance retained"]
                if passed
                else [
                    "Publisher/source changed or publisher/provenance evidence is unknown/regressed"
                ],
                evidence,
            )
        except Exception:  # noqa: BLE001
            self._check(
                option,
                "publisher_provenance",
                component,
                False,
                ["Publisher/provenance detector failed"],
                evidence,
            )
        additions = None
        try:
            additions, ids = self.detectors.dependencies(before, after)
            flags = sorted(
                {
                    ("new_build_dependency:" if d.get("kind") == "build" else "new_dependency:")
                    + (d.get("package") or d["name"])
                    for d in additions
                }
            )
            self._check(
                option,
                "dependency_diff",
                component,
                True,
                ["Captured per-version dependencies compared"],
                ids,
                flags,
            )
            if additions:
                matches, popularity_ids = self.detectors.typosquats(
                    ecosystem, additions, self.policy.min_popular_names
                )
                self._check(
                    option,
                    "typosquat",
                    component,
                    not matches,
                    [
                        "New dependency resembles a popular package: "
                        + ", ".join(sorted({m["package"] for m in matches}))
                    ]
                    if matches
                    else ["New dependency names passed the existing typosquat detector"],
                    [*ids, *popularity_ids],
                )
            else:
                self._check(
                    option, "typosquat", component, True, ["No new dependency names to screen"], ids
                )
        except Exception:  # noqa: BLE001
            self._check(
                option,
                "dependency_screening",
                component,
                False,
                ["Dependency diff or popularity screening incomplete/failed"],
                evidence,
            )
        try:
            new_hits, ids = self.detectors.static_diff(before, after)
            # A new or unknown static rule is not silently treated as harmless.
            dangerous = sorted({hit["capability"] for hit in new_hits})
            self._check(
                option,
                "integrity",
                component,
                True,
                [
                    "Both artifacts SHA256-verified against captured registry checksums before inspection"
                ],
                ids,
            )
            self._check(
                option,
                "capability_diff",
                component,
                not dangerous,
                ["New capabilities rejected: " + ", ".join(dangerous)]
                if dangerous
                else ["No new forbidden capability reported by existing static rules"],
                ids,
            )
        except Exception:  # noqa: BLE001
            self._check(
                option,
                "integrity_static",
                component,
                False,
                ["Checksum verification, safe extraction or static inspection incomplete/failed"],
                [
                    *evidence,
                    *before.artifact_evidence_ids,
                    *after.artifact_evidence_ids,
                    *before.checksum_evidence_ids,
                    *after.checksum_evidence_ids,
                ],
            )
