import subprocess

import pytest

from guardian.remediate import Edge, PrioritisedFinding, candidates, load_replacements
from guardian.remediate.registry import Dep, StaticIndex, VersionInfo, sparse_path
from guardian.remediate.semver_rs import Requirement, Version
from guardian.verify import FactsIndex


@pytest.fixture(autouse=True)
def nothing_is_executed(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Module 2 must never execute commands")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)


def vi(version, yanked=False, **deps):
    return VersionInfo(version, yanked, [Dep(n, r) for n, r in deps.items()])


def pf(**kw):
    base = dict(  # noqa: C408
        finding_id="F-1",
        type="vulnerability",
        package="leaf",
        version="1.2.3",
        fixed_versions=["1.2.4"],
        evidence_ids=["EV-ADV"],
        edges=[
            Edge(parent="app", child="middle", req="^0.4", is_root=True),
            Edge(parent="middle", parent_version="0.4.0", child="leaf", req="^1.2"),
        ],
    )
    base.update(kw)
    return PrioritisedFinding(**base)


def kinds(options):
    return [o.kind for o in options]


def test_semver_requirements():
    ok = lambda r, v: Requirement(r).matches(Version(v))
    assert ok("^1.2", "1.9.0") and not ok("^1.2", "2.0.0")
    assert ok("^0.2.3", "0.2.9") and not ok("^0.2.3", "0.3.0")
    assert ok("^0.0.3", "0.0.3") and not ok("^0.0.3", "0.0.4")
    assert ok("~1.2.3", "1.2.9") and not ok("~1.2.3", "1.3.0")
    assert ok(">=1.2, <1.5", "1.4.9") and not ok(">=1.2, <1.5", "1.5.0")
    assert ok("1.*", "1.9.9") and not ok("1.*", "2.0.0")
    assert ok("=1.2.3", "1.2.3") and not ok("=1.2.3", "1.2.4")
    assert not ok("^1.2", "1.3.0-beta.1")
    assert Version("1.0.0-rc.1") < Version("1.0.0") < Version("1.0.1")


def test_sparse_index_paths():
    assert sparse_path("a") == "1/a" and sparse_path("ab") == "2/ab"
    assert sparse_path("abc") == "3/a/abc" and sparse_path("serde") == "se/rd/serde"


def test_lockfile_only_picks_smallest_compatible_and_skips_yanked():
    index = StaticIndex(
        {
            "leaf": [
                vi("1.2.3"),
                vi("1.2.4", yanked=True),
                vi("1.2.5"),
                vi("1.3.0"),
                vi("2.0.0"),
                vi("1.2.6-beta.1"),
            ]
        }
    )
    options = candidates(pf(), index)
    upgrade = options[0]
    assert upgrade.kind == "upgrade" and upgrade.target_version == "1.2.5"
    assert upgrade.commands == [["cargo", "update", "-p", "leaf@1.2.3", "--precise", "1.2.5"]]
    assert upgrade.changes == [] and not upgrade.major_jump
    assert set(upgrade.evidence_ids) == {"EV-ADV", "EV-IDX"}


def test_parent_bump_manifest_change_for_direct_parent_and_major_flag():
    index = StaticIndex(
        {
            "leaf": [vi("1.2.3"), vi("2.0.1")],
            "middle": [
                vi("0.4.0", leaf="^1.2"),
                vi("0.4.1", leaf="^1.2"),
                vi("0.5.0", leaf="^2.0"),
                vi("0.6.0", leaf="^2.0"),
            ],
        }
    )
    (upgrade, *_rest) = candidates(pf(fixed_versions=["2.0.1"]), index)
    assert upgrade.kind == "upgrade" and upgrade.target_version == "2.0.1"
    assert upgrade.changes == [
        {
            "file": "Cargo.toml",
            "action": "set_requirement",
            "dependency": "middle",
            "from_req": "^0.4",
            "to_req": "^0.5.0",
        }
    ]
    assert upgrade.commands == [
        ["cargo", "update", "-p", "middle@0.4.0", "--precise", "0.5.0"],
        ["cargo", "update", "-p", "leaf@1.2.3", "--precise", "2.0.1"],
    ]
    assert upgrade.major_jump
    assert {s["package"] for s in upgrade.steps} == {"middle", "leaf"}


def test_parent_bump_is_lockfile_only_when_root_requirement_allows_it():
    index = StaticIndex(
        {
            "leaf": [vi("1.2.3"), vi("2.0.1")],
            "middle": [vi("0.4.0", leaf="^1.2"), vi("0.4.2", leaf="^2.0")],
        }
    )
    edges = [
        Edge(parent="app", child="middle", req="^0.4", is_root=True),
        Edge(parent="middle", parent_version="0.4.0", child="leaf", req="^1.2"),
    ]
    (upgrade, *_rest) = candidates(pf(fixed_versions=["2.0.1"], edges=edges), index)
    assert upgrade.changes == []
    assert upgrade.commands[0] == ["cargo", "update", "-p", "middle@0.4.0", "--precise", "0.4.2"]
    assert upgrade.major_jump  # leaf itself moves 1.x -> 2.x
    middle = next(s for s in upgrade.steps if s["package"] == "middle")
    assert middle["target_version"] == "0.4.2"  # smallest parent allowing the fixed child


def test_no_fixed_version_available_gives_only_escalate():
    index = StaticIndex({"leaf": [vi("1.2.3")]})
    assert kinds(candidates(pf(), index)) == ["escalate"]


def test_rollback_pin_to_baseline_version():
    index = StaticIndex({"leaf": [vi("1.0.0"), vi("1.0.1")]})
    suspicious = pf(
        type="suspicious_change",
        version="1.0.1",
        fixed_versions=[],
        baseline_version="1.0.0",
        baseline_evidence_ids=["EV-BASE"],
    )
    options = candidates(suspicious, index)
    assert kinds(options) == ["pin", "escalate"]
    pin = options[0]
    assert pin.commands == [["cargo", "update", "-p", "leaf@1.0.1", "--precise", "1.0.0"]]
    assert "EV-BASE" in pin.evidence_ids and "watch for a clean" in pin.notes[0]


def test_remove_only_when_dev_only_and_not_imported():
    index = StaticIndex({})
    assert "remove" in kinds(
        candidates(pf(dev_only=True, imported=False, fixed_versions=[]), index)
    )
    assert "remove" not in kinds(
        candidates(pf(dev_only=True, imported=True, fixed_versions=[]), index)
    )
    assert "remove" not in kinds(
        candidates(pf(dev_only=False, imported=False, fixed_versions=[]), index)
    )


def test_replace_only_when_listed(tmp_path):
    index = StaticIndex({})
    rules = tmp_path / "replacements.yaml"
    rules.write_text("replacements:\n  leaf: leaf-ng\n", encoding="utf-8")
    listed = candidates(pf(fixed_versions=[]), index, load_replacements(rules))
    assert kinds(listed) == ["replace", "escalate"] and listed[0].package == "leaf-ng"
    assert "replace" not in kinds(candidates(pf(fixed_versions=[]), index, load_replacements(None)))
    assert load_replacements(tmp_path / "missing.yaml") == {}


def test_escalate_always_present_and_vetted_by_definition():
    index = StaticIndex({"leaf": [vi("1.2.3"), vi("1.2.5")]})
    for finding in (pf(), pf(type="suspicious_change"), pf(fixed_versions=[])):
        options = candidates(finding, index)
        assert options[-1].kind == "escalate" and options[-1].vetting == "passed"
        assert all(o.vetting == "pending" for o in options[:-1])


def test_registry_outage_degrades_to_escalate():
    class Down:
        def lookup(self, name):
            raise OSError("offline")

    options = candidates(pf(), Down())
    assert kinds(options) == ["escalate"]
    assert any("lookup failed" in n for n in options[0].notes)


def test_option_ids_are_stable_and_distinct():
    index = StaticIndex({"leaf": [vi("1.2.3"), vi("1.2.5")]})
    first, second = candidates(pf(), index), candidates(pf(), index)
    assert [o.option_id for o in first] == [o.option_id for o in second]
    assert all(o.option_id.startswith("O-") and len(o.option_id) == 10 for o in first)
    assert len({o.option_id for o in first}) == len(first)


def test_python_pin_bump_and_transitive_constraint():
    index = StaticIndex(
        {"requests": [VersionInfo("2.30.0"), VersionInfo("2.31.0"), VersionInfo("2.32.0")]}
    )
    finding = pf(
        ecosystem="pypi",
        package="requests",
        version="2.30.0",
        fixed_versions=["2.31.0"],
        edges=[Edge(parent="kuksa-python-sdk", child="requests", req="==2.30.0", is_root=True)],
    )
    (upgrade, *_rest) = candidates(finding, index)
    assert upgrade.commands == []
    assert upgrade.changes == [
        {
            "file": "requirements.txt",
            "action": "set_requirement",
            "dependency": "requests",
            "from_req": "==2.30.0",
            "to_req": "==2.31.0",
        }
    ]
    transitive = finding.model_copy(
        update={
            "edges": [
                Edge(parent="urllib-wrapper", parent_version="1.0", child="requests", req=">=2.0")
            ]
        }
    )
    (upgrade, *_rest) = candidates(transitive, index)
    assert (
        upgrade.changes[0]["action"] == "add_constraint"
        and upgrade.changes[0]["spec"] == "==2.31.0"
    )


def test_options_feed_the_verifier_facts():
    index = StaticIndex(
        {
            "leaf": [vi("1.2.3"), vi("2.0.1")],
            "middle": [vi("0.4.0", leaf="^1.2"), vi("0.5.0", leaf="^2.0")],
        }
    )
    options = candidates(pf(fixed_versions=["2.0.1"]), index)
    facts = FactsIndex.build(options=options)
    assert {"leaf", "middle"} <= facts.packages
    assert {"0.5.0", "2.0.1"} <= facts.versions
    assert options[0].option_id in facts.options
