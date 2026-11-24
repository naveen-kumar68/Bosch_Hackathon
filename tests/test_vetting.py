import hashlib
import io
import tarfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from guardian.models import Component
from guardian.remediate import (
    Edge,
    PrioritisedFinding,
    VettingContext,
    candidates,
    vet_all,
    vet_option,
)
from guardian.remediate.registry import StaticIndex, VersionInfo
from guardian.verify import FactsIndex

NOW = datetime(2026, 11, 24, tzinfo=UTC)


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def crate(build_rs=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in {
            "leaf/Cargo.toml": "[package]\n",
            "leaf/build.rs": build_rs or "fn main() {}\n",
        }.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeRegistry:
    def __init__(self, meta, history):
        self.meta, self.history = meta, history

    def metadata(self, component):
        return {
            "evidence_ids": [f"EV-META-{component.version}"],
            **self.meta[component.version],
        }, []

    def crate_history(self, name):
        return self.history, "EV-INDEX"


class FakeHTTP:
    def __init__(self, crates):
        self.crates = crates

    def get(self, url):
        version = url.rsplit("-", 1)[1].removesuffix(".crate")
        return self.crates[version], f"EV-DL-{version}"


def build(published_days_ago=60, deps=(), target_build_rs=None, vulnerable=False, meta=None, **ctx):
    target_crate, old_crate = crate(target_build_rs), crate()
    history = [
        {"vers": "1.2.3", "deps": [], "cksum": hashlib.sha256(old_crate).hexdigest()},
        {"vers": "1.2.5", "deps": list(deps), "cksum": hashlib.sha256(target_crate).hexdigest()},
    ]
    base = {"published": iso(400), "publisher": 7, "yanked": False, "trusted_publishing": True}
    target_meta = {**base, "published": iso(published_days_ago), **(meta or {})}
    registry = FakeRegistry({"1.2.3": base, "1.2.5": target_meta}, history)
    known = {
        "leaf": Component(
            purl="pkg:cargo/leaf@1.2.3",
            name="leaf",
            version="1.2.3",
            ecosystem="cargo",
            source="crates.io",
            has_build_script=False,
            is_proc_macro=False,
            evidence_ids=["EV-C"],
        )
    }
    if target_build_rs is not None or deps:
        known["leaf"] = known["leaf"].model_copy(update={"has_build_script": True})
    advisory = [SimpleNamespace(id="RUSTSEC-2025-9999")] if vulnerable else []
    return VettingContext(
        http=FakeHTTP({"1.2.3": old_crate, "1.2.5": target_crate}),
        registry=registry,
        vuln_lookup=lambda component: (advisory, "EV-OSV"),
        popular={"cargo": ["serde_derive", "serde", "tokio"]},
        popular_evidence=["EV-POP"],
        known=known,
        now=NOW,
        **ctx,
    )


def options():
    pf = PrioritisedFinding(
        finding_id="F-1",
        type="vulnerability",
        package="leaf",
        version="1.2.3",
        fixed_versions=["1.2.4"],
        evidence_ids=["EV-ADV"],
        edges=[Edge(parent="mid", parent_version="0.4.0", child="leaf", req="^1.2")],
    )
    index = StaticIndex({"leaf": [VersionInfo("1.2.3"), VersionInfo("1.2.5")]})
    return candidates(pf, index)


def test_clean_candidate_passes_with_evidence():
    upgrade, escalate = vet_all(options(), build())
    assert upgrade.vetting == "passed" and upgrade.vetting_reasons == []
    assert {c["check"] for c in upgrade.vetting_checks} >= {
        "not_vulnerable",
        "release_age",
        "publisher",
        "dependency_diff",
        "capability_diff",
    }
    assert {"EV-OSV", "EV-META-1.2.5", "EV-INDEX"} <= set(upgrade.vetting_evidence_ids)
    assert all(c["evidence_ids"] or c["check"] == "capability_diff" for c in upgrade.vetting_checks)
    assert escalate.kind == "escalate" and escalate.vetting == "passed"


def test_candidate_younger_than_seven_days_is_rejected():
    upgrade = vet_all(options(), build(published_days_ago=2))[0]
    assert upgrade.vetting == "rejected"
    assert upgrade.vetting_reasons == ["leaf 1.2.5 was released 2 days ago (minimum 7)"]
    assert "EV-META-1.2.5" in upgrade.vetting_evidence_ids


def test_release_age_threshold_is_configurable():
    assert (
        vet_all(options(), build(published_days_ago=2, min_release_age_days=1))[0].vetting
        == "passed"
    )
    assert (
        vet_all(options(), build(published_days_ago=20, min_release_age_days=30))[0].vetting
        == "rejected"
    )


def test_typosquatted_new_build_dependency_is_rejected():
    deps = [{"name": "serde_derve", "kind": "build", "req": "1.0.0"}]
    upgrade = vet_all(options(), build(deps=deps))[0]
    assert upgrade.vetting == "rejected"
    assert (
        "new dependency serde_derve resembles popular package serde_derive"
        in upgrade.vetting_reasons
    )
    assert any("adds new build-dependency: serde_derve" in r for r in upgrade.vetting_reasons)
    assert "EV-POP" in upgrade.vetting_evidence_ids


def test_new_clean_dependency_is_flagged_but_not_rejected():
    deps = [{"name": "tokio", "kind": "normal", "req": "1"}]
    upgrade = vet_all(options(), build(deps=deps))[0]
    assert upgrade.vetting == "passed"
    assert any(r.startswith("note:") and "tokio" in r for r in upgrade.vetting_reasons)


def test_itself_vulnerable_yanked_and_publisher_change_are_rejected():
    assert any(
        "itself affected by RUSTSEC-2025-9999" in r
        for r in vet_all(options(), build(vulnerable=True))[0].vetting_reasons
    )
    assert (
        "leaf 1.2.5 is yanked"
        in vet_all(options(), build(meta={"yanked": True}))[0].vetting_reasons
    )
    changed = vet_all(options(), build(meta={"publisher": 99}))[0]
    assert "publisher of leaf changed versus 1.2.3" in changed.vetting_reasons
    trusted = vet_all(options(), build(meta={"publisher": 99}, trusted_publishers={99}))[0]
    assert trusted.vetting == "passed"
    regressed = vet_all(options(), build(meta={"trusted_publishing": False}))[0]
    assert "trusted publishing regressed for leaf 1.2.5" in regressed.vetting_reasons


def test_new_network_capability_in_build_script_is_rejected():
    evil = 'fn main() { std::net::TcpStream::connect("203.0.113.9:80").ok(); }\n'
    upgrade = vet_all(options(), build(target_build_rs=evil))[0]
    assert upgrade.vetting == "rejected"
    assert "leaf 1.2.5 adds capabilities: network" in upgrade.vetting_reasons
    assert "EV-DL-1.2.5" in upgrade.vetting_evidence_ids


def test_checksum_mismatch_rejects_before_extraction():
    ctx = build(target_build_rs="fn main() {}\n")
    ctx.registry.history[1]["cksum"] = "0" * 64
    upgrade = vet_all(options(), ctx)[0]
    assert upgrade.vetting == "rejected"
    assert "leaf 1.2.5 could not be verified" in upgrade.vetting_reasons[-1]


def test_lookup_failure_never_passes():
    ctx = build()
    ctx.vuln_lookup = lambda component: (_ for _ in ()).throw(OSError("offline"))
    assert vet_all(options(), ctx)[0].vetting == "rejected"


def test_remove_passes_and_replace_without_version_is_rejected():
    pf = PrioritisedFinding(
        finding_id="F-2",
        type="vulnerability",
        package="leaf",
        version="1.2.3",
        evidence_ids=["EV-ADV"],
        dev_only=True,
        imported=False,
    )
    ctx = build()
    remove = vet_option(candidates(pf, StaticIndex({}))[0], ctx)
    assert remove.kind == "remove" and remove.vetting == "passed"
    replace = vet_option(candidates(pf, StaticIndex({}), {"leaf": "leaf-ng"})[1], ctx)
    assert replace.kind == "replace" and replace.vetting == "rejected"


def test_rejected_option_stays_listed_and_input_not_mutated():
    original = options()
    vetted = vet_all(original, build(published_days_ago=1))
    assert [o.option_id for o in vetted] == [o.option_id for o in original]
    assert original[0].vetting == "pending" and vetted[0].vetting == "rejected"


def test_verifier_only_accepts_vetted_options():
    vetted = vet_all(options(), build(published_days_ago=1))
    facts = FactsIndex.build(options=vetted, evidence_ids=["EV-ADV"])
    assert facts.options[vetted[0].option_id]["vetting"] == "rejected"
    assert "EV-META-1.2.5" in facts.evidence
