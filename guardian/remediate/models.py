"""Provisional Module 2 contracts; no shared contracts have landed yet."""

from pathlib import PurePosixPath
from typing import Annotated, Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, field_validator

EvidenceId = Annotated[str, Field(min_length=1)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Constraint(Model):
    requirement: str
    evidence_ids: list[EvidenceId] = Field(min_length=1)


class Boundary(Model):
    version: str
    evidence_ids: list[EvidenceId] = Field(min_length=1)


class Location(Model):
    file: str

    @field_validator("file")
    @classmethod
    def relative_posix(cls, value):
        path = PurePosixPath(value)
        if (
            not value
            or "\\" in value
            or ":" in value
            or path.is_absolute()
            or ".." in path.parts
            or value != path.as_posix()
            or value == "."
        ):
            raise ValueError("Location must be a repository-relative POSIX file path")
        return value


class Parent(Model):
    package: str
    current_version: str
    requirement: str
    constraints: list[Constraint] = Field(default_factory=list)
    location: Location
    evidence_ids: list[EvidenceId] = Field(min_length=1)


class RemediationRequest(Model):
    finding_id: str = Field(min_length=1)
    component: str
    evidence_ids: list[EvidenceId] = Field(min_length=1)
    fixed_versions: list[Boundary] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    parents: list[Parent] = Field(default_factory=list)
    location: Location
    baseline: Boundary | None = None
    python_version: str | None = None

    @field_validator("component")
    @classmethod
    def supported_purl(cls, value):
        parsed = PackageURL.from_string(value)
        if parsed.type not in {"cargo", "pypi"} or not parsed.version or parsed.namespace:
            raise ValueError("A versioned Cargo or PyPI package PURL is required")
        return parsed.to_string()


class Change(Model):
    file: str
    package: str
    from_version: str
    to_version: str
    operation: Literal["lock_update", "replace_pin"]


class FixOption(Model):
    option_id: str = Field(pattern=r"^O-[0-9a-f]{8}$")
    finding_id: str
    kind: Literal["minimal_upgrade", "parent_bump", "rollback", "escalate"]
    component: str
    target_version: str | None = None
    changes: list[Change] = Field(default_factory=list)
    evidence_ids: list[EvidenceId] = Field(min_length=1)
    reasons: list[str] = Field(default_factory=list)
    vetting: Literal["pending", "passed", "rejected"] = "pending"
    vetting_reasons: list[str] = Field(default_factory=list)
