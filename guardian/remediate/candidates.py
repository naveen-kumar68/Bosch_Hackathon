"""Deterministic proposals, not vetted fixes. Never reads or edits target files."""

import hashlib

from packageurl import PackageURL
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from guardian.llm.completion import canonical
from guardian.remediate.models import Change, FixOption, RemediationRequest
from guardian.remediate.registry import RegistrySnapshot, identity
from guardian.remediate.versions import matches, parse, stable


def _record(value):
    return value.model_dump() if hasattr(value, "model_dump") else value


class CandidateGenerator:
    def __init__(self, registry: RegistrySnapshot):
        self.registry = registry

    def candidates(self, pf) -> list[FixOption]:
        request = RemediationRequest.model_validate(_record(pf))
        purl = PackageURL.from_string(request.component)
        ecosystem, name, current = purl.type, purl.name, purl.version
        options, reasons = [], []
        index = self.registry.lookup(ecosystem, name)
        try:
            parse(ecosystem, current)
            for boundary in request.fixed_versions:
                parse(ecosystem, boundary.version)
            if index is not None:
                targets = self._targets(request, index, current)
                for release, boundaries in targets:
                    if self._compatible(ecosystem, release.version, request.constraints) and all(
                        matches(ecosystem, release.version, parent.requirement)
                        for parent in request.parents
                    ):
                        evidence = [
                            *index.evidence_ids,
                            *release.evidence_ids,
                            *self._boundary_evidence(boundaries),
                            *self._constraint_evidence(request.constraints),
                            *(e for parent in request.parents for e in parent.evidence_ids),
                        ]
                        options.append(
                            self._option(
                                request,
                                "minimal_upgrade",
                                release.version,
                                [
                                    self._change(
                                        ecosystem,
                                        request.location.file,
                                        name,
                                        current,
                                        release.version,
                                    )
                                ],
                                evidence,
                                [
                                    "Smallest available stable upgrade within captured constraints; vetting pending."
                                ],
                            )
                        )
                        break
                if not any(option.kind == "minimal_upgrade" for option in options):
                    options.extend(
                        self._parent_bumps(request, index, targets, ecosystem, name, current)
                    )
                baseline = request.baseline
                if baseline and parse(ecosystem, baseline.version) < parse(ecosystem, current):
                    release = next(
                        (
                            r
                            for r in self._releases(request, index)
                            if r.version == baseline.version
                        ),
                        None,
                    )
                    if release is not None:
                        options.append(
                            self._option(
                                request,
                                "rollback",
                                baseline.version,
                                [
                                    self._change(
                                        ecosystem,
                                        request.location.file,
                                        name,
                                        current,
                                        baseline.version,
                                    )
                                ],
                                [
                                    *baseline.evidence_ids,
                                    *index.evidence_ids,
                                    *release.evidence_ids,
                                ],
                                [
                                    "Restore the captured baseline pin; compatibility and security vetting pending."
                                ],
                            )
                        )
            if not options:
                reasons.append(
                    "No proposal can be established from the captured versions and constraints."
                )
        except (ValueError, TypeError):
            # Unsupported ranges/metadata must not become guessed compatibility.
            options = []
            reasons.append(
                "Unsupported or inconsistent version/constraint metadata requires manual review."
            )
        if index is None:
            reasons.append("Captured registry index is unavailable.")
        options.append(
            self._option(
                request,
                "escalate",
                None,
                [],
                [],
                reasons or ["Human review is always available; no automatic change is applied."],
            )
        )
        unique = {}
        for option in options:
            if option.option_id in unique and unique[option.option_id] != option:
                raise ValueError("Remediation option ID collision")
            unique[option.option_id] = option
        order = {"minimal_upgrade": 0, "parent_bump": 1, "rollback": 2, "escalate": 3}
        return sorted(unique.values(), key=lambda o: (order[o.kind], o.option_id))

    def _releases(self, request, index):
        valid = []
        for release in index.releases:
            try:
                if release.yanked is not False or not stable(index.ecosystem, release.version):
                    continue
                if (
                    index.ecosystem == "pypi"
                    and release.requires_python
                    and (
                        request.python_version is None
                        or Version(request.python_version)
                        not in SpecifierSet(release.requires_python)
                    )
                ):
                    continue
                valid.append(release)
            except ValueError:
                continue  # malformed release records are never selected
        return sorted(valid, key=lambda r: (parse(index.ecosystem, r.version), r.version))

    def _targets(self, request, index, current):
        result = []
        for release in self._releases(request, index):
            parsed = parse(index.ecosystem, release.version)
            if parsed <= parse(index.ecosystem, current):
                continue
            boundaries = []
            for boundary in request.fixed_versions:
                fixed = parse(index.ecosystem, boundary.version)
                if index.ecosystem == "cargo":
                    same_line = parsed.major == fixed.major and (
                        fixed.major != 0 or parsed.minor == fixed.minor
                    )
                else:
                    same_line = (
                        parsed.epoch == fixed.epoch and parsed.release[0] == fixed.release[0]
                    )
                if parsed >= fixed and same_line:
                    boundaries.append(boundary)
            if boundaries:
                result.append((release, boundaries))
        return result

    @staticmethod
    def _compatible(ecosystem, version, constraints):
        return all(
            matches(ecosystem, version, constraint.requirement) for constraint in constraints
        )

    @staticmethod
    def _constraint_evidence(constraints):
        return [e for constraint in constraints for e in constraint.evidence_ids]

    @staticmethod
    def _boundary_evidence(boundaries):
        return [e for boundary in boundaries for e in boundary.evidence_ids]

    def _parent_bumps(self, request, child_index, targets, ecosystem, name, current):
        options = []
        for parent in sorted(request.parents, key=lambda p: (p.package, p.current_version)):
            parent_index = self.registry.lookup(ecosystem, parent.package)
            if parent_index is None:
                continue
            found = False
            for parent_release in self._releases(request, parent_index):
                if parse(ecosystem, parent_release.version) <= parse(
                    ecosystem, parent.current_version
                ):
                    continue
                if (
                    not self._compatible(ecosystem, parent_release.version, parent.constraints)
                    or parent_release.dependencies is None
                ):
                    continue
                dependencies = [
                    d
                    for d in parent_release.dependencies
                    if identity(ecosystem, d.package) == identity(ecosystem, name)
                ]
                if not dependencies or any(d.conditional for d in dependencies):
                    continue
                for release, boundaries in targets:
                    others = [p for p in request.parents if p is not parent]
                    if (
                        not self._compatible(ecosystem, release.version, request.constraints)
                        or not all(
                            matches(ecosystem, release.version, p.requirement) for p in others
                        )
                        or not all(
                            matches(ecosystem, release.version, d.requirement) for d in dependencies
                        )
                    ):
                        continue
                    evidence = [
                        *child_index.evidence_ids,
                        *release.evidence_ids,
                        *parent_index.evidence_ids,
                        *parent_release.evidence_ids,
                        *self._boundary_evidence(boundaries),
                        *parent.evidence_ids,
                        *self._constraint_evidence(parent.constraints),
                        *self._constraint_evidence(request.constraints),
                        *(e for p in others for e in p.evidence_ids),
                    ]
                    changes = [
                        self._change(
                            ecosystem,
                            parent.location.file,
                            parent.package,
                            parent.current_version,
                            parent_release.version,
                        ),
                        self._change(
                            ecosystem, request.location.file, name, current, release.version
                        ),
                    ]
                    options.append(
                        self._option(
                            request,
                            "parent_bump",
                            release.version,
                            changes,
                            evidence,
                            [
                                "Smallest captured parent bump admitting a fix-boundary candidate; vetting pending."
                            ],
                        )
                    )
                    found = True
                    break
                if found:
                    break
        return options

    @staticmethod
    def _change(ecosystem, file, name, before, after):
        return Change(
            file=file,
            package=name,
            from_version=before,
            to_version=after,
            operation="lock_update"
            if ecosystem == "cargo" and file.endswith("Cargo.lock")
            else "replace_pin",
        )

    @staticmethod
    def _option(request, kind, target, changes, evidence, reasons):
        changes = sorted(changes, key=lambda c: (c.file, c.package, c.from_version, c.to_version))
        action = {
            "finding_id": request.finding_id,
            "kind": kind,
            "component": request.component,
            "target_version": target,
            "changes": [c.model_dump() for c in changes],
        }
        identifier = "O-" + hashlib.sha256(canonical(action).encode("utf-8")).hexdigest()[:8]
        return FixOption(
            option_id=identifier,
            **action,
            evidence_ids=sorted({*request.evidence_ids, *evidence}),
            reasons=reasons,
        )
