import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.llm.claims import AIClaim, FactReference
from guardian.remediate import api
from guardian.remediate.candidates import CandidateGenerator
from guardian.remediate.models import RemediationRequest
from guardian.remediate.registry import RegistrySnapshot, cargo_index, pypi_index
from guardian.remediate.versions import SemVer, cargo_matches
from guardian.verify.api import check
from guardian.verify.facts import build

DATA = json.loads((Path(__file__).parent / "fixtures/remediate/cargo.json").read_text("utf-8"))


def cargo_snapshot(child=None, parent=None):
    return RegistrySnapshot(
        [
            cargo_index("child", child or DATA["child"], "EV-INDEX"),
            cargo_index("parent", parent or DATA["parent"], "EV-PARENT-INDEX"),
        ]
    )


def parent_link(**changes):
    parent = {
        "package": "parent",
        "current_version": "1.0.0",
        "requirement": "=0.4.0",
        "location": {"file": "Cargo.lock"},
        "evidence_ids": ["EV-PARENT-LOCK"],
        "constraints": [{"requirement": "^1.0.0", "evidence_ids": ["EV-PARENT-MANIFEST"]}],
    }
    parent.update(changes)
    return parent


def option(options, kind):
    return next(o for o in options if o.kind == kind)


def test_cargo_minimum_skip_yanked_and_keep_baseline_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("never execute target code"))
    request = deepcopy(DATA["request"])
    before = deepcopy(request)
    registry = cargo_snapshot()
    registry_before = {key: value.model_dump() for key, value in registry.packages.items()}
    options = CandidateGenerator(registry).candidates(request)
    upgrade = option(options, "minimal_upgrade")
    assert upgrade.target_version == "0.4.3"
    assert upgrade.evidence_ids == ["EV-ADVISORY", "EV-INDEX", "EV-MANIFEST"]
    assert upgrade.changes[0].file == "Cargo.lock" and upgrade.changes[0].operation == "lock_update"
    assert option(options, "rollback").target_version == "0.3.9"
    assert option(options, "escalate").changes == []
    assert all(
        o.vetting == "pending" and re.fullmatch(r"O-[0-9a-f]{8}", o.option_id) for o in options
    )
    assert request == before and registry_before == {
        k: v.model_dump() for k, v in registry.packages.items()
    }
    assert not list(tmp_path.iterdir())  # no target files, shell scripts or outputs written


def test_cargo_parent_bump_finds_minimum_parent_and_child():
    request = {**deepcopy(DATA["request"]), "parents": [parent_link()]}
    options = CandidateGenerator(cargo_snapshot()).candidates(request)
    assert not any(o.kind == "minimal_upgrade" for o in options)
    bump = option(options, "parent_bump")
    assert [(c.package, c.to_version) for c in bump.changes] == [
        ("child", "0.4.3"),
        ("parent", "1.0.1"),
    ]
    assert {
        "EV-PARENT-LOCK",
        "EV-PARENT-INDEX",
        "EV-PARENT-MANIFEST",
        "EV-INDEX",
        "EV-ADVISORY",
    } <= set(bump.evidence_ids)


def test_other_parent_constraints_are_not_ignored():
    request = {
        **deepcopy(DATA["request"]),
        "parents": [parent_link(), parent_link(package="other", evidence_ids=["EV-OTHER"])],
    }
    options = CandidateGenerator(cargo_snapshot()).candidates(request)
    assert not any(o.kind in {"minimal_upgrade", "parent_bump"} for o in options)


def test_parent_root_constraint_and_unknown_or_conditional_metadata_block_bump():
    request = {
        **deepcopy(DATA["request"]),
        "parents": [
            parent_link(constraints=[{"requirement": "=1.0.0", "evidence_ids": ["EV-PARENT-PIN"]}])
        ],
    }
    assert not any(
        o.kind == "parent_bump" for o in CandidateGenerator(cargo_snapshot()).candidates(request)
    )
    request["parents"] = [parent_link()]
    for dependencies in [None, [{"name": "child", "req": "^0.4.2", "optional": True}], []]:
        rows = [{"name": "parent", "vers": "1.0.1", "yanked": False, "deps": dependencies}]
        assert not any(
            o.kind == "parent_bump"
            for o in CandidateGenerator(cargo_snapshot(parent=rows)).candidates(request)
        )


def test_missing_registry_no_fixes_and_bad_ranges_always_escalate():
    request = deepcopy(DATA["request"])
    assert [o.kind for o in CandidateGenerator(RegistrySnapshot()).candidates(request)] == [
        "escalate"
    ]
    request["fixed_versions"] = []
    options = CandidateGenerator(cargo_snapshot()).candidates(request)
    assert {o.kind for o in options} == {"rollback", "escalate"}
    request = deepcopy(DATA["request"])
    request["constraints"][0]["requirement"] = "^0.4 || ^0.5"
    options = CandidateGenerator(cargo_snapshot()).candidates(request)
    assert [o.kind for o in options] == ["escalate"]
    assert "manual review" in options[0].reasons[0]


def test_rollback_does_not_guess_a_version_or_select_yanked_baseline():
    for baseline in ["0.4.0", "9.9.9", "0.4.2", "0.5.2-beta.1"]:
        request = deepcopy(DATA["request"])
        request["baseline"]["version"] = baseline
        options = CandidateGenerator(cargo_snapshot()).candidates(request)
        assert not any(o.kind == "rollback" for o in options)


def test_stable_ids_and_order_ignore_registry_order_and_evidence_capture_ids():
    registry = cargo_snapshot(
        child=list(reversed(DATA["child"])), parent=list(reversed(DATA["parent"]))
    )
    original = CandidateGenerator(cargo_snapshot()).candidates(DATA["request"])
    reordered = CandidateGenerator(registry).candidates(DATA["request"])
    assert original == reordered
    request = deepcopy(DATA["request"])
    request["evidence_ids"] = ["EV-NEW-CAPTURE"]
    assert [o.option_id for o in original] == [
        o.option_id for o in CandidateGenerator(registry).candidates(request)
    ]


def python_snapshot(parent_requires="urllib3>=1.26.5,<2"):
    document = {
        "info": {"name": "urllib3"},
        "releases": {
            "1.26.0": [{"yanked": False, "requires_python": ">=3.8"}],
            "1.26.5": [{"yanked": True, "requires_python": ">=3.8"}],
            "1.26.6": [{"yanked": False, "requires_python": ">=3.8"}],
            "1.26.7": [{"yanked": False, "requires_python": ">=3.13"}],
            "1.27.0rc1": [{"yanked": False}],
            "2.0.0": [{"yanked": False}],
        },
    }
    parent = {
        "info": {"name": "requests"},
        "releases": {
            "1.0": [{"yanked": False}],
            "1.1": [{"yanked": False}],
            "1.2": [{"yanked": False}],
        },
    }
    versions = {
        version: (
            {"info": {"name": "requests", "version": version, "requires_dist": [parent_requires]}},
            f"EV-PY-PARENT-{version}",
        )
        for version in ["1.1", "1.2"]
    }
    return RegistrySnapshot(
        [
            pypi_index("urllib3", document, "EV-PY-INDEX"),
            pypi_index("requests", parent, "EV-PY-PARENT-INDEX", version_documents=versions),
        ]
    )


def python_request():
    return {
        "finding_id": "F-PY",
        "component": "pkg:pypi/urllib3@1.26.0",
        "evidence_ids": ["EV-PY-ADVISORY"],
        "fixed_versions": [{"version": "1.26.5", "evidence_ids": ["EV-PY-ADVISORY"]}],
        "constraints": [{"requirement": "<2", "evidence_ids": ["EV-PY-CONSTRAINT"]}],
        "location": {"file": "sdk/requirements.txt"},
        "python_version": "3.12",
    }


@pytest.mark.parametrize("file", ["sdk/requirements.txt", "sdk/setup.cfg"])
def test_python_minimum_pin_and_requires_python(file):
    request = python_request()
    request["location"]["file"] = file
    upgrade = option(CandidateGenerator(python_snapshot()).candidates(request), "minimal_upgrade")
    assert upgrade.target_version == "1.26.6"
    assert upgrade.changes[0].file == file and upgrade.changes[0].operation == "replace_pin"
    request["python_version"] = "3.7"
    assert [o.kind for o in CandidateGenerator(python_snapshot()).candidates(request)] == [
        "escalate"
    ]
    request["python_version"] = None
    assert [o.kind for o in CandidateGenerator(python_snapshot()).candidates(request)] == [
        "escalate"
    ]


def test_python_parent_requires_dist_minimum_bump():
    request = python_request()
    request["parents"] = [
        {
            "package": "Requests",
            "current_version": "1.0",
            "requirement": "==1.26.0",
            "location": {"file": "sdk/requirements.txt"},
            "evidence_ids": ["EV-PY-PARENT-PIN"],
            "constraints": [{"requirement": "<2", "evidence_ids": ["EV-PY-ROOT"]}],
        }
    ]
    bump = option(CandidateGenerator(python_snapshot()).candidates(request), "parent_bump")
    assert [(c.package, c.to_version) for c in bump.changes] == [
        ("Requests", "1.1"),
        ("urllib3", "1.26.6"),
    ]
    assert "EV-PY-PARENT-1.1" in bump.evidence_ids
    for requirement in [
        'urllib3>=1.26.5; python_version >= "3.8"',
        "urllib3 @ https://example.invalid/not-downloaded.whl",
        "not a requirement !!",
    ]:
        options = CandidateGenerator(python_snapshot(requirement)).candidates(request)
        assert not any(o.kind == "parent_bump" for o in options)


def test_pypi_unknown_yanked_or_empty_artifacts_are_not_used():
    document = {
        "info": {"name": "urllib3"},
        "releases": {
            "1.26.6": [],
            "1.26.7": [{}],
            "1.26.8": [{"yanked": True}],
        },
    }
    registry = RegistrySnapshot([pypi_index("urllib3", document, "EV-PY-INDEX")])
    assert [o.kind for o in CandidateGenerator(registry).candidates(python_request())] == [
        "escalate"
    ]


def test_registry_identity_and_duplicate_records_are_rejected():
    with pytest.raises(ValueError, match="identity mismatch"):
        cargo_index("other", DATA["child"], "EV-INDEX")
    with pytest.raises(ValueError, match="identity mismatch"):
        pypi_index("other", {"info": {"name": "urllib3"}, "releases": {}}, "EV-PY")
    with pytest.raises(ValueError, match="Duplicate registry release"):
        RegistrySnapshot([cargo_index("child", [DATA["child"][0]] * 2, "EV-INDEX")])


@pytest.mark.parametrize(
    "path",
    ["../Cargo.toml", "C:/Cargo.toml", "/Cargo.toml", r"sdk\requirements.txt", "a/../Cargo.lock"],
)
def test_locations_stay_repo_relative(path):
    request = deepcopy(DATA["request"])
    request["location"]["file"] = path
    with pytest.raises(ValidationError, match="repository-relative"):
        RemediationRequest.model_validate(request)


def test_api_requires_no_llm_and_pending_options_cannot_be_chosen(monkeypatch):
    monkeypatch.setattr(api, "_generator", None)
    assert [o.kind for o in api.candidates(DATA["request"])] == ["escalate"]
    api.configure(cargo_snapshot())
    options = api.candidates(DATA["request"])
    ids = sorted({e for o in options for e in o.evidence_ids})
    index = build([{"id": e} for e in ids], [], options)
    upgrade = option(options, "minimal_upgrade")
    claim = AIClaim(
        kind="plan",
        chosen_option_id=upgrade.option_id,
        facts_used=[
            FactReference(
                type="option_id", value=upgrade.option_id, evidence_id=upgrade.evidence_ids[0]
            )
        ],
        cited_evidence_ids=[upgrade.evidence_ids[0]],
    )
    assert f"Option {upgrade.option_id} is not vetted: pending" in check(claim, index=index).errors
    escalate = option(options, "escalate")
    claim.chosen_option_id = escalate.option_id
    claim.facts_used = [
        FactReference(
            type="option_id", value=escalate.option_id, evidence_id=escalate.evidence_ids[0]
        )
    ]
    claim.cited_evidence_ids = [escalate.evidence_ids[0]]
    assert check(claim, index=index).verified


@pytest.mark.parametrize(
    "requirement, version, expected",
    [
        ("1.2.3", "1.9.0", True),
        ("1.2.3", "2.0.0", False),
        ("0.2.3", "0.3.0", False),
        ("0.0.3", "0.0.4", False),
        ("0.0", "0.0.9", True),
        ("0", "0.9.0", True),
        ("~1.2.3", "1.2.9", True),
        ("~1.2", "1.3.0", False),
        ("~1", "1.9.0", True),
        ("1.*", "1.9.0", True),
        ("1.2.*", "1.3.0", False),
        (">=1.2, <1.5", "1.4.9", True),
        (">=1.2, <1.5", "1.5.0", False),
        ("=1.2", "1.2.9", True),
        (">1", "1.9.9", False),
        (">1", "2.0.0", True),
        ("<=1.2", "1.3.0", False),
        ("*", "1.0.0-beta", False),
        ("1.0.0-alpha", "1.0.0-beta", True),
        ("1.0.0-alpha", "1.0.1-beta", False),
    ],
)
def test_cargo_reference_ranges(requirement, version, expected):
    assert cargo_matches(version, requirement) is expected


def test_semver_prerelease_precedence_and_build_metadata():
    versions = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    assert sorted(versions, key=SemVer.parse) == versions
    assert SemVer.parse("1.0.0+first") == SemVer.parse("1.0.0+second")
    with pytest.raises(ValueError):
        SemVer.parse("1.0.0-01")


def test_cargo_manifest_pin_uses_declarative_pin_change():
    request = deepcopy(DATA["request"])
    request["location"]["file"] = "Cargo.toml"
    upgrade = option(CandidateGenerator(cargo_snapshot()).candidates(request), "minimal_upgrade")
    assert upgrade.changes[0].operation == "replace_pin"
    assert upgrade.changes[0].file == "Cargo.toml"


def test_fix_boundaries_do_not_cross_unfixed_release_lines():
    request = deepcopy(DATA["request"])
    request["constraints"] = [{"requirement": "*", "evidence_ids": ["EV-ANY"]}]
    request["fixed_versions"] = [{"version": "0.4.2", "evidence_ids": ["EV-ADVISORY"]}]
    rows = [r for r in DATA["child"] if r["vers"] in {"0.4.0", "0.5.0", "1.0.0"}]
    options = CandidateGenerator(cargo_snapshot(child=rows)).candidates(request)
    assert not any(o.kind in {"minimal_upgrade", "parent_bump"} for o in options)


def test_pypi_version_metadata_identity_is_bound_to_index_version():
    document = {"info": {"name": "requests"}, "releases": {"1.1": [{"yanked": False}]}}
    wrong = {
        "1.1": ({"info": {"name": "requests", "version": "9.9", "requires_dist": []}}, "EV-WRONG")
    }
    with pytest.raises(ValueError, match="release metadata identity mismatch"):
        pypi_index("requests", document, "EV-PY-INDEX", version_documents=wrong)


def test_blank_evidence_and_foreign_registry_do_not_become_trusted_candidates():
    request = deepcopy(DATA["request"])
    request["evidence_ids"] = [""]
    with pytest.raises(ValidationError):
        RemediationRequest.model_validate(request)
    request = {**deepcopy(DATA["request"]), "parents": [parent_link()]}
    parent = [
        {
            "name": "parent",
            "vers": "1.0.1",
            "yanked": False,
            "deps": [
                {"name": "child", "req": "^0.4.2", "registry": "https://example.invalid/index"}
            ],
        }
    ]
    assert not any(
        o.kind == "parent_bump"
        for o in CandidateGenerator(cargo_snapshot(parent=parent)).candidates(request)
    )
