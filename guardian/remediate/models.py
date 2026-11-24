"""Remediation inputs and outputs. Adapt to guardian/contracts when they land."""

import hashlib
import json
from typing import Literal

from pydantic import Field

from guardian.models import Model


class Edge(Model):
    """parent (at parent_version) requires child with `req`. is_root: parent is the scanned project."""

    parent: str
    parent_version: str | None = None
    child: str
    req: str = ""
    is_root: bool = False


class PrioritisedFinding(Model):
    finding_id: str
    type: str
    ecosystem: Literal["cargo", "pypi"] = "cargo"
    package: str
    version: str
    fixed_versions: list[str] = Field(default_factory=list)
    advisory_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)
    edges: list[Edge] = Field(default_factory=list)
    baseline_version: str | None = None
    baseline_evidence_ids: list[str] = Field(default_factory=list)
    dev_only: bool = False
    imported: bool = True
    manifest: str | None = None
    severity: str | None = None
    priority: str | None = None


class FixOption(Model):
    option_id: str
    kind: Literal["upgrade", "pin", "remove", "replace", "escalate"]
    ecosystem: str
    package: str
    from_version: str | None = None
    target_version: str | None = None
    fixes_package: str | None = None
    fixes_version: str | None = None
    commands: list[list[str]] = Field(default_factory=list)  # proposed only, never executed here
    changes: list[dict] = Field(default_factory=list)  # manifest edits, applied by Module 3
    steps: list[dict] = Field(default_factory=list)  # every package/version this option touches
    major_jump: bool = False
    notes: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)
    vetting: Literal["pending", "passed", "rejected"] = "pending"
    vetting_reasons: list[str] = Field(default_factory=list)
    vetting_checks: list[dict] = Field(default_factory=list)
    vetting_evidence_ids: list[str] = Field(default_factory=list)


def make_option_id(**identity) -> str:
    blob = json.dumps(identity, sort_keys=True, default=str)
    return "O-" + hashlib.sha256(blob.encode()).hexdigest()[:8]
