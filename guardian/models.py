"""Ecosystem-neutral contracts shared by adapters, storage and future agents."""

from datetime import datetime
from typing import Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(Model):
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    source: str
    ref: str
    revision: str | None = None
    kind: Literal["repository", "image"] = "repository"
    subdirectory: str = "."
    baseline: str | None = None


class Evidence(Model):
    id: str
    tool: str
    version: str
    command: list[str]
    timestamp: datetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_path: str
    path_base: str = "output"
    cwd: str
    returncode: int = 0
    description: str = ""


class Component(Model):
    purl: str
    name: str
    version: str
    ecosystem: str
    source: str
    checksum: str | None = None
    is_root: bool = False
    is_direct: bool = False
    scopes: list[str] = Field(default_factory=list)
    depth: int | None = None
    has_build_script: bool | None = None
    is_proc_macro: bool | None = None
    has_hash: bool | None = None
    features: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(min_length=1)

    @field_validator("purl")
    @classmethod
    def valid_purl(cls, value: str) -> str:
        return PackageURL.from_string(value).to_string()


class Edge(Model):
    from_purl: str
    to_purl: str
    kind: str
    version_req: str = ""
    target: str | None = None
    evidence_ids: list[str] = Field(min_length=1)


class Resolution(Model):
    components: list[Component]
    edges: list[Edge]
    path_context: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class ScanResult(Model):
    target: Target
    revision: str
    components: list[Component]
    edges: list[Edge]
    evidence: list[Evidence]
    path_context: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
