from guardian.detect.cicd import inspect_workflow
from guardian.detect.container import inspect_dockerfile, inventory_drift


def test_workflow_rules_and_safe_pins():
    text = """permissions: write-all
on: pull_request_target
jobs:
  check:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: cargo install tool
      - run: pip install git+https://example.test/pkg@v1
      - run: curl https://example.test/a | sh
"""
    assert {h["type"] for h in inspect_workflow(text, "ci.yml")} == {
        "workflow_permissions",
        "action_unpinned",
        "untrusted_checkout",
        "cargo_install_unlocked",
        "pip_git_mutable",
        "curl_pipe_shell",
    }
    assert (
        inspect_workflow("permissions: {}\nsteps:\n - uses: org/action@" + "a" * 40, "safe.yml")
        == []
    )


def test_scratch_stages_and_digest_pins():
    hits = inspect_dockerfile(
        "FROM --platform=linux/riscv64 debian:sid-slim AS build\n"
        "FROM build AS next\nFROM scratch\nFROM base@sha256:" + "a" * 64
    )
    assert {h["type"] for h in hits} == {"mutable_base_image", "unstable_base_image"}
    assert len(hits) == 2


def test_drift_compares_versions_without_losing_identity():
    a = {
        "components": [
            {"name": "x", "version": "1", "purl": "pkg:cargo/x@1"},
            {"name": "y", "version": "1", "purl": "pkg:cargo/y@1"},
        ]
    }
    b = {"components": [{"name": "x", "version": "2", "purl": "pkg:cargo/x@2"}]}
    drift = inventory_drift(a, b)
    assert drift["missing_from_observed"] == {"pkg:cargo/y": ["1"]}
    assert drift["version_mismatched"] == {"pkg:cargo/x": {"shipped": ["1"], "observed": ["2"]}}
