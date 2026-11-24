"""Deterministic fix candidates. Proposes commands and manifest edits; never runs anything."""

from pathlib import Path

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion
from packaging.version import Version as PyVersion

from guardian.remediate.models import FixOption, PrioritisedFinding, make_option_id
from guardian.remediate.registry import VersionInfo
from guardian.remediate.semver_rs import Requirement, Version

MAX_DEPTH = 6


class CargoScheme:
    name = "cargo"
    parse = staticmethod(Version)

    @staticmethod
    def allows(req: str, version) -> bool:
        return Requirement(req).matches(version) if req.strip() else True

    @staticmethod
    def requirement_for(version) -> str:
        return f"^{version.text}"


class PyScheme:
    name = "pypi"
    parse = staticmethod(PyVersion)

    @staticmethod
    def allows(req: str, version) -> bool:
        try:
            return SpecifierSet(req).contains(version, prereleases=False) if req.strip() else True
        except InvalidSpecifier:
            return False

    @staticmethod
    def requirement_for(version) -> str:
        return f"=={version}"


def compat_key(scheme, version):
    if scheme.name == "cargo":
        return version.compat_key()
    major, minor = version.major, version.minor
    return (major,) if major else (0, minor)


def load_replacements(path: Path | None) -> dict:
    """rules/replacements.yaml (Module 4): {package: alternative | {alternative: name}}."""
    if path is None or not Path(path).is_file():
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    data = data.get("replacements", data)
    return {k: (v["alternative"] if isinstance(v, dict) else v) for k, v in data.items()}


class _Planner:
    def __init__(self, pf, index, scheme):
        self.pf, self.index, self.scheme = pf, index, scheme
        self.evidence = list(pf.evidence_ids)
        self._cache: dict[str, list[tuple]] = {}
        self.manifest = pf.manifest or (
            "Cargo.toml" if pf.ecosystem == "cargo" else "requirements.txt"
        )

    def usable(self, package: str) -> list[tuple]:
        """Non-yanked, non-prerelease versions, ascending."""
        if package not in self._cache:
            result = self.index.lookup(package)
            if result.evidence_id and result.evidence_id not in self.evidence:
                self.evidence.append(result.evidence_id)
            parsed = []
            for info in result.versions:
                try:
                    version = self.scheme.parse(info.version)
                except (ValueError, InvalidVersion):
                    continue
                if not info.yanked and not getattr(version, "is_prerelease", False):
                    parsed.append((version, info))
            self._cache[package] = sorted(parsed, key=lambda item: item[0])
        return self._cache[package]

    def dep_req(self, package: str, info: VersionInfo, child: str) -> str | None:
        deps = info.deps if info.deps is not None else self.index.deps(package, info.version)
        for dep in deps:
            if dep.name.lower() == child.lower() and dep.kind != "dev":
                return dep.req
        return None

    def edges_into(self, package: str):
        return [e for e in self.pf.edges if e.child == package]

    def is_fixed(self, version, fixed) -> bool:
        return any(
            version >= f and compat_key(self.scheme, version) == compat_key(self.scheme, f)
            for f in fixed
        ) or (bool(fixed) and version >= max(fixed))

    def _step(self, package, current, target):
        return {
            "package": package,
            "from_version": current,
            "target_version": str(target.text if hasattr(target, "text") else target),
        }

    def _update(self, package, current, target):
        if self.scheme.name == "cargo":
            return [["cargo", "update", "-p", f"{package}@{current}", "--precise", self._v(target)]]
        return []

    @staticmethod
    def _v(version) -> str:
        return version.text if hasattr(version, "text") else str(version)

    def resolve(self, package, current, target, depth):
        """Plan so that `package` can sit at `target`: fix each blocking requirer."""
        if depth > MAX_DEPTH:
            return None
        commands, changes, steps = [], [], []
        for edge in self.edges_into(package):
            if self.scheme.allows(edge.req, target):
                continue
            if edge.is_root:
                changes.append(
                    {
                        "file": self.manifest,
                        "action": "set_requirement",
                        "dependency": package,
                        "from_req": edge.req,
                        "to_req": self.scheme.requirement_for(target),
                    }
                )
                continue
            if edge.parent_version is None:
                return None
            sub = self.raise_to(
                edge.parent,
                edge.parent_version,
                lambda info, e=edge: (
                    (r := self.dep_req(e.parent, info, package)) is not None
                    and self.scheme.allows(r, target)
                ),
                depth + 1,
            )
            if sub is None:
                return None
            commands += sub[0]
            changes += sub[1]
            steps += sub[2]
        commands += self._update(package, current, target)
        steps.append(self._step(package, current, target))
        return commands, changes, steps

    def raise_to(self, package, current, ok, depth):
        """Smallest newer version of `package` accepted by `ok`, with its requirers resolved."""
        try:
            current_v = self.scheme.parse(current)
        except (ValueError, InvalidVersion):
            return None
        for version, info in self.usable(package):
            if version > current_v and ok(info):
                plan = self.resolve(package, current, version, depth)
                if plan:
                    return plan
        return None


def _upgrade(pf, planner, scheme) -> FixOption | None:
    fixed = []
    for text in pf.fixed_versions:
        try:
            fixed.append(scheme.parse(text))
        except (ValueError, InvalidVersion):
            continue
    if not fixed:
        return None
    current = scheme.parse(pf.version)
    edges = planner.edges_into(pf.package)
    candidates = [
        (v, i) for v, i in planner.usable(pf.package) if v > current and planner.is_fixed(v, fixed)
    ]
    plan, lock_only = None, False
    for version, _info in candidates:  # 1) lockfile-only: inside every existing requirement
        if all(scheme.allows(e.req, version) for e in edges):
            commands = planner._update(pf.package, pf.version, version)
            changes = (
                []
                if commands
                else [
                    {
                        "file": planner.manifest,
                        "action": "add_constraint",
                        "package": pf.package,
                        "spec": scheme.requirement_for(version),
                    }
                ]
            )
            plan, lock_only = (
                (commands, changes, [planner._step(pf.package, pf.version, version)]),
                True,
            )
            break
    if plan is None:  # 2) bump requirers (manifest edit when the requirer is the project)
        for version, _info in candidates:
            plan = planner.resolve(pf.package, pf.version, version, 0)
            if plan:
                break
    if plan is None:
        return None
    commands, changes, steps = plan
    target = steps[-1]["target_version"]
    major = any(
        compat_key(scheme, scheme.parse(s["from_version"]))
        != compat_key(scheme, scheme.parse(s["target_version"]))
        for s in steps
    )
    notes = [] if lock_only else ["Requirement blocks the fixed version: requirer bump needed."]
    if major:
        notes.append("Major (breaking-range) jump: review before applying.")
    return _option(
        pf,
        planner,
        "upgrade",
        pf.package,
        pf.version,
        target,
        commands,
        changes,
        steps,
        major,
        notes,
    )


def _option(
    pf,
    planner,
    kind,
    package,
    from_v,
    target,
    commands,
    changes,
    steps,
    major,
    notes,
    extra_evidence=(),
):
    evidence = list(dict.fromkeys([*planner.evidence, *extra_evidence]))
    return FixOption(
        option_id=make_option_id(
            kind=kind,
            package=package,
            from_version=from_v,
            target=target,
            commands=commands,
            changes=changes,
            finding=pf.finding_id,
        ),
        kind=kind,
        ecosystem=pf.ecosystem,
        package=package,
        from_version=from_v,
        target_version=target,
        fixes_package=pf.package if kind == "upgrade" else None,
        fixes_version=target if kind == "upgrade" else None,
        commands=commands,
        changes=changes,
        steps=steps,
        major_jump=major,
        notes=notes,
        evidence_ids=evidence,
    )


def candidates(pf: PrioritisedFinding, index, replacements: dict | None = None) -> list[FixOption]:
    """upgrade | pin | remove | replace | escalate, in that order. Escalate is always present."""
    scheme = CargoScheme if pf.ecosystem == "cargo" else PyScheme
    planner = _Planner(pf, index, scheme)
    options: list[FixOption] = []
    lookup_failed = False

    if pf.type == "vulnerability":
        try:
            option = _upgrade(pf, planner, scheme)
        except Exception:  # noqa: BLE001 -- registry outage must degrade to escalate, not crash
            option, lookup_failed = None, True
        if option:
            options.append(option)

    if pf.type != "vulnerability" and pf.baseline_version and pf.baseline_version != pf.version:
        notes = ["Pin to the last known-good version; watch for a clean upstream release."]
        try:
            for version, _info in planner.usable(pf.package):
                if version == scheme.parse(pf.baseline_version):
                    break
            else:
                notes.append("Baseline version is yanked or absent from the index.")
        except Exception:  # noqa: BLE001
            lookup_failed = True
        step = {
            "package": pf.package,
            "from_version": pf.version,
            "target_version": pf.baseline_version,
        }
        options.append(
            _option(
                pf,
                planner,
                "pin",
                pf.package,
                pf.version,
                pf.baseline_version,
                planner._update(pf.package, pf.version, pf.baseline_version) or [],
                []
                if scheme.name == "cargo"
                else [
                    {
                        "file": planner.manifest,
                        "action": "set_requirement",
                        "dependency": pf.package,
                        "to_req": scheme.requirement_for(pf.baseline_version),
                    }
                ],
                [step],
                False,
                notes,
                pf.baseline_evidence_ids,
            )
        )

    if pf.dev_only and not pf.imported:
        options.append(
            _option(
                pf,
                planner,
                "remove",
                pf.package,
                pf.version,
                None,
                [],
                [
                    {
                        "file": planner.manifest,
                        "action": "remove_dependency",
                        "dependency": pf.package,
                        "section": "dev-dependencies",
                    }
                ],
                [{"package": pf.package, "from_version": pf.version, "target_version": None}],
                False,
                ["Dev-only and never imported."],
            )
        )

    alternative = (replacements or {}).get(pf.package)
    if alternative:
        options.append(
            _option(
                pf,
                planner,
                "replace",
                alternative,
                None,
                None,
                [],
                [
                    {
                        "file": planner.manifest,
                        "action": "replace_dependency",
                        "dependency": pf.package,
                        "with": alternative,
                    }
                ],
                [{"package": alternative, "from_version": None, "target_version": None}],
                False,
                ["Replacement listed in rules/replacements.yaml."],
            )
        )

    notes = ["Human decides."]
    if lookup_failed:
        notes.append("Registry lookup failed; no automatic option could be computed.")
    escalate = _option(
        pf, planner, "escalate", pf.package, pf.version, None, [], [], [], False, notes
    )
    options.append(escalate.model_copy(update={"vetting": "passed"}))
    return options
