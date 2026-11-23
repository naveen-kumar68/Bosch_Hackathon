"""Rate-limited HTTP cache whose raw responses are retained as scan evidence."""

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from guardian.evidence import Recorder


class CachedHTTP:
    def __init__(self, directory: Path, recorder: Recorder, *, offline=False, client=None):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.recorder = recorder
        self.offline = offline
        self.client = client or httpx.Client(
            timeout=180,
            follow_redirects=True,
            headers={
                "User-Agent": "SupplyChainGuardian/0.1 (https://github.com/naveen-kumar68/Bosch_Hackathon)"
            },
        )
        self.last_request = 0.0

    def get(self, url: str) -> tuple[bytes, str]:
        if not url.startswith("https://"):
            raise ValueError("Metadata requests require HTTPS")
        key = hashlib.sha256(url.encode()).hexdigest()
        path = self.directory / (key + ".json")
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            data = bytes.fromhex(cached["body_hex"])
            if hashlib.sha256(data).hexdigest() != cached["sha256"] or cached["url"] != url:
                raise ValueError("Metadata cache integrity mismatch")
        else:
            if self.offline:
                raise FileNotFoundError(f"No cached response for {url}")
            time.sleep(max(0, 1.05 - (time.monotonic() - self.last_request)))
            self.last_request = time.monotonic()
            try:
                response = self.client.get(url)
            except httpx.HTTPError as error:
                self.recorder.capture(
                    json.dumps(
                        {"status": "request_failed", "error_type": type(error).__name__}
                    ).encode(),
                    tool="httpx",
                    version=httpx.__version__,
                    command=["GET", url],
                    cwd=self.directory,
                    description="Metadata request failed; no registry fact inferred",
                    returncode=1,
                )
                raise
            response.raise_for_status()
            data = response.content
            cached = {
                "url": url,
                "fetched_at": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "body_hex": data.hex(),
            }
            path.write_text(json.dumps(cached), encoding="utf-8", newline="\n")
        evidence = self.recorder.capture(
            data,
            tool="httpx",
            version=httpx.__version__,
            command=["GET", url],
            cwd=self.directory,
            description=f"Public metadata; cache snapshot {cached['fetched_at']}",
        )
        return data, evidence
