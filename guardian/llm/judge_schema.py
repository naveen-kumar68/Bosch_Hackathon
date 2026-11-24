"""Judge output schema. Flags are a closed set; severity is not representable."""

from pydantic import Field, field_validator

from guardian.models import Model
from guardian.verify.models import FactUsed


class JudgeFlags(Model):
    runs_network: bool = False
    downloads_and_executes: bool = False
    reads_env_or_secrets: bool = False
    writes_outside_build_dir: bool = False
    obfuscated: bool = False
    mentions_instructions_to_ai: bool = False
    benign_build_step: bool = False


class JudgeItem(Model):
    finding_id: str
    flags: JudgeFlags
    verdict: str = Field(pattern=r"^(benign|suspicious|malicious|unknown)$")
    rationale: str
    facts_used: list[FactUsed] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("rationale")
    @classmethod
    def limit_words(cls, value):
        if len(value.split()) > 60:
            raise ValueError("Rationale exceeds 60 words")
        return value


class JudgeBatch(Model):
    items: list[JudgeItem] = Field(max_length=5)
