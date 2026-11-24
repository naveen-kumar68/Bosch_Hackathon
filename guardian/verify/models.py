"""Claim contract for AI output. Adapt to guardian/contracts AIClaim when it lands."""

from typing import Literal

from pydantic import Field

from guardian.models import Model

FACT_TYPES = (
    "package",
    "version",
    "purl",
    "advisory_id",
    "fixed_version",
    "path",
    "score",
    "option_id",
    "flag",
)
ALLOWED_FLAGS = (
    "runs_network",
    "downloads_and_executes",
    "reads_env_or_secrets",
    "writes_outside_build_dir",
    "obfuscated",
    "mentions_instructions_to_ai",
    "benign_build_step",
)
ClaimKind = Literal["judge", "plan", "explain", "brief", "second_opinion"]


class FactUsed(Model):
    type: str
    value: str
    evidence_id: str | None = None


class AIClaim(Model):
    kind: ClaimKind
    subject_id: str | None = None
    text: str = ""  # every free-text field of the AI output, joined; this is what gets scanned
    facts_used: list[FactUsed] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    chosen_option_id: str | None = None
    flags: dict[str, bool] = Field(default_factory=dict)
    payload: dict = Field(default_factory=dict)  # role-specific validated output
    verified: bool = False
    errors: list[str] = Field(default_factory=list)
    needs_human_review: bool = True
    label: Literal["AI inference"] = "AI inference"
