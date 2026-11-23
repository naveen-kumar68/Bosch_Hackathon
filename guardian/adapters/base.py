from pathlib import Path
from typing import Protocol

from guardian.evidence import Recorder
from guardian.models import Resolution, Target


class EcosystemAdapter(Protocol):
    def detect(self, path: Path, target: Target) -> bool: ...

    def resolve(
        self,
        path: Path,
        target: Target,
        revision: str,
        recorder: Recorder,
    ) -> Resolution: ...

    def sbom(
        self,
        path: Path,
        target: Target,
        revision: str,
        recorder: Recorder,
    ) -> None: ...
