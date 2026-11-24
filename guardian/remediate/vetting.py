"""Candidate vetting: a proposed fix version must pass the same checks as any new package.

Calls the existing detectors (registry metadata, dependency diff, typosquat, capability diff);
nothing here builds or runs target code. A rejected option stays in the list with its reasons.
"""

import tempfile
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from packageurl import PackageURL

from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import metadata_changes, new_dependencies
from guardian.detect.typosquat import candidates as typosquat_candidates
from guardian.models import Component
from guardian.remediate.models import FixOption

REJECTED_CAPABILITIES = {"network", "process", "environment", "decode", "high_entropy"}
PURL_TYPE = {"cargo": "cargo", "pypi": "pypi"}


@dataclass
class VettingContext:
    http: object  # .get(url) -> (bytes, evidence_id)  (CachedHTTP)
    registry: object  # detect.registry.Registry: .metadata(component), .crate_history(name)
    vuln_lookup: Callable[[Component], tuple[list, str | None]]  # OSV/advisory for one version
    popular: dict[str, Collection[str]] = field(default_factory=dict)  # ecosystem -> names
    popular_evidence: list[str] = field(default_factory=list)
    allowlist: dict[str, list] = field(default_factory=dict)
    known: dict[str, Component] = field(default_factory=dict)  # current components by name
    trusted_publishers: set = field(default_factory=set)
    min_release_age_days: int = 7
    workdir: Path | None = None
    now: datetime | None = None

    @classmethod
    def from_config(cls, settings: dict, **kwargs):
        return cls(min_release_age_days=settings.get("min_release_age_days", 7), **kwargs)


class _Result:
    def __init__(self):
        self.checks: list[dict] = []
        self.reasons: list[str] = []
        self.evidence: list[str] = []

    def record(self, check, status, detail, evidence=()):
        evidence = [e for e in evidence if e]
        self.checks.append(
            {"check": check, "status": status, "detail": detail, "evidence_ids": evidence}
        )
        self.evidence += [e for e in evidence if e not in self.evidence]
        if status in {"fail", "note"}:
            self.reasons.append(("" if status == "fail" else "note: ") + detail)

    @property
    def failed(self):
        return any(c["status"] == "fail" for c in self.checks)


def _component(ecosystem, name, version, base: Component | None = None) -> Component:
    purl = PackageURL(type=PURL_TYPE[ecosystem], name=name, version=version).to_string()
    flags = {}
    if base is not None:
        flags = {
            "has_build_script": base.has_build_script,
            "is_proc_macro": base.is_proc_macro,
            "checksum": None,
        }
    return Component(
        purl=purl,
        name=name,
        version=version,
        ecosystem=ecosystem,
        source="crates.io" if ecosystem == "cargo" else "pypi",
        evidence_ids=["vetting"],
        **flags,
    )


def _vulnerable(ctx, target, result):
    try:
        vulns, evidence = ctx.vuln_lookup(target)
    except Exception:  # noqa: BLE001 -- an unanswerable lookup is not a clean bill of health
        result.record(
            "not_vulnerable", "fail", f"advisory lookup failed for {target.name} {target.version}"
        )
        return
    if vulns:
        ids = ", ".join(sorted(v.id for v in vulns))
        result.record(
            "not_vulnerable",
            "fail",
            f"{target.name} {target.version} is itself affected by {ids}",
            [evidence],
        )
    else:
        result.record("not_vulnerable", "pass", "no advisories for target version", [evidence])


def _metadata(ctx, target, current, result):
    try:
        after, _ = ctx.registry.metadata(target)
    except Exception:  # noqa: BLE001
        result.record(
            "registry_metadata",
            "fail",
            f"registry metadata unavailable for {target.name} {target.version}",
        )
        return None
    evidence = list(after.get("evidence_ids", []))
    before = None
    try:
        before = ctx.registry.metadata(current)[0] if current.version else None
        evidence += before.get("evidence_ids", []) if before else []
    except Exception:  # noqa: BLE001
        result.record(
            "registry_metadata",
            "note",
            f"registry metadata unavailable for current {current.name} {current.version}",
        )
    now = ctx.now or datetime.now(UTC)
    published = after.get("published")
    if not published:
        result.record(
            "release_age",
            "fail",
            f"release date of {target.name} {target.version} is unknown",
            evidence,
        )
    else:
        age = (now - datetime.fromisoformat(published)).total_seconds() / 86400
        if age < ctx.min_release_age_days:
            result.record(
                "release_age",
                "fail",
                f"{target.name} {target.version} was released {int(age)} days ago (minimum {ctx.min_release_age_days})",
                evidence,
            )
        else:
            result.record("release_age", "pass", f"released {int(age)} days ago", evidence)
    changes = [c for c in metadata_changes(before, after, now) if c != "recent_release"]
    if after.get("publisher") in ctx.trusted_publishers:
        changes = [c for c in changes if c != "publisher_changed"]
    for change in changes:
        text = {
            "yanked": f"{target.name} {target.version} is yanked",
            "publisher_changed": f"publisher of {target.name} changed versus {current.version}",
            "provenance_regression": f"trusted publishing regressed for {target.name} {target.version}",
        }[change]
        result.record(change, "fail", text, evidence)
    if not changes:
        result.record("publisher", "pass", "publisher and provenance unchanged", evidence)
    return after


def _dependency_diff(ctx, target, current, after_meta, result) -> tuple[list[str], bool]:
    """Returns (new dependency names, any new build dependency)."""
    added, build = [], False
    try:
        if target.ecosystem == "cargo":
            history, evidence = ctx.registry.crate_history(target.name)
            new = list(new_dependencies(history, current.version, target.version))
            added = [d.get("package") or d["name"] for d in new]
            build = any(d.get("kind") == "build" for d in new)
        else:
            before = ctx.registry.metadata(current)[0].get("dependencies", [])
            after = (after_meta or {}).get("dependencies", [])
            evidence = (after_meta or {}).get("evidence_ids", [])
            names = lambda reqs: {r.split(";")[0].split()[0].split("[")[0].lower() for r in reqs}
            added = sorted(names(after) - names(before))
    except Exception:  # noqa: BLE001
        result.record(
            "dependency_diff",
            "fail",
            f"dependency diff unavailable for {target.name} {current.version} -> {target.version}",
        )
        return [], False
    if not added:
        result.record("dependency_diff", "pass", "no new dependencies", [evidence])
        return [], False
    kind = "build-dependency" if build else "dependency"
    result.record(
        "dependency_diff",
        "note",
        f"{target.name} {target.version} adds new {kind}: {', '.join(added)}",
        [evidence],
    )
    names = ctx.popular.get(target.ecosystem)
    for name in added:
        hits = (
            typosquat_candidates(name, names or [], ctx.allowlist.get(target.ecosystem, []))
            if names
            else []
        )
        if hits:
            result.record(
                "typosquat",
                "fail",
                f"new dependency {name} resembles popular package {hits[0]['popular_name']}",
                ctx.popular_evidence,
            )
    return added, build


def _download(ctx, component: Component, after_meta=None):
    """Return (bytes, checksum, evidence ids) for one version's source artifact."""
    if component.ecosystem == "cargo":
        history, index_evidence = ctx.registry.crate_history(component.name)
        entry = next(i for i in history if i["vers"] == component.version)
        url = f"https://static.crates.io/crates/{component.name}/{component.name}-{component.version}.crate"
        data, evidence = ctx.http.get(url)
        return data, entry["cksum"], [evidence, index_evidence]
    info = after_meta if after_meta is not None else ctx.registry.metadata(component)[0]
    files = sorted(info["files"], key=lambda f: (f["packagetype"] != "sdist", f["filename"]))
    artifact = files[0]
    data, evidence = ctx.http.get(artifact["url"])
    return data, artifact["digests"]["sha256"], [evidence, *info["evidence_ids"]]


def _capabilities(ctx, component: Component, label, after_meta=None):
    data, checksum, evidence = _download(ctx, component, after_meta)
    base = ctx.workdir or Path(tempfile.mkdtemp(prefix="guardian-vetting-"))
    destination = base / f"{label}-{component.name}-{component.version}"
    verified_extract(data, checksum, destination)  # SHA256 against the index before extraction
    return inspect_sources(destination, proc_macro=bool(component.is_proc_macro)), evidence


def _capability_diff(ctx, target, current, after_meta, new_build, result):
    needs = new_build or target.has_build_script is not False or target.is_proc_macro is not False
    if not needs:
        result.record("capability_diff", "pass", "no build script or proc-macro", [])
        return
    try:
        new_hits, evidence = _capabilities(ctx, target, "target", after_meta)
    except Exception:  # noqa: BLE001
        result.record(
            "capability_diff",
            "fail",
            f"target artifact of {target.name} {target.version} could not be verified",
        )
        return
    old_hits = []
    try:
        old_hits, old_evidence = _capabilities(ctx, current, "current")
        evidence += old_evidence
    except Exception:  # noqa: BLE001
        result.record(
            "capability_diff",
            "note",
            f"current {current.name} {current.version} baseline unavailable; every capability counts as new",
            evidence,
        )
    added = {h["capability"] for h in capability_diff(old_hits, new_hits)}
    bad = sorted(added & REJECTED_CAPABILITIES)
    if bad:
        result.record(
            "capability_diff",
            "fail",
            f"{target.name} {target.version} adds capabilities: {', '.join(bad)}",
            evidence,
        )
    else:
        result.record(
            "capability_diff",
            "pass",
            "no new network, exec, env or obfuscation capability",
            evidence,
        )


def vet_option(option: FixOption, ctx: VettingContext) -> FixOption:
    if option.kind == "escalate":
        return option
    result = _Result()
    steps = [s for s in option.steps if s.get("target_version")]
    if option.kind == "remove":
        result.record("no_new_code", "pass", "removal adds no code")
    elif option.kind == "replace" or not steps:
        result.record(
            "target_version", "fail", "no concrete target version to vet; needs human review"
        )
    for step in steps:
        name, target_v, current_v = (
            step["package"],
            step["target_version"],
            step.get("from_version"),
        )
        base = ctx.known.get(name)
        current = _component(option.ecosystem, name, current_v or "0", base)
        target = _component(option.ecosystem, name, target_v, base)
        _vulnerable(ctx, target, result)
        meta = _metadata(ctx, target, current, result)
        _added, new_build = _dependency_diff(ctx, target, current, meta, result)
        _capability_diff(ctx, target, current, meta, new_build, result)
    status = "rejected" if result.failed else "passed"
    return option.model_copy(
        update={
            "vetting": status,
            "vetting_reasons": result.reasons,
            "vetting_checks": result.checks,
            "vetting_evidence_ids": result.evidence,
        }
    )


def vet_all(options: list[FixOption], ctx: VettingContext) -> list[FixOption]:
    """Every option stays in the list; rejected ones carry their reasons for the UI."""
    return [vet_option(o, ctx) for o in options]
