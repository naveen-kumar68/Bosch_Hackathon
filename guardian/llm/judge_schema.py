"""Judge provider schemas: classification only, no deterministic decision fields."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian.llm.claims import FactReference


class JudgeFlags(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    runs_network: bool
    downloads_and_executes: bool
    reads_env_or_secrets: bool
    writes_outside_build_dir: bool
    obfuscated: bool
    mentions_instructions_to_ai: bool
    benign_build_step: bool


class JudgeItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str = Field(min_length=1, max_length=128)
    flags: JudgeFlags
    verdict: Literal["benign", "suspicious", "malicious", "unknown"]
    rationale: str
    facts_used: list[FactReference]
    cited_evidence_ids: list[str] = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def limit_words(cls, value):
        if len(value.split()) > 60:
            raise ValueError("Judge rationale exceeds 60 words")
        return value


class JudgeBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    items: list[JudgeItem] = Field(min_length=1, max_length=5)
