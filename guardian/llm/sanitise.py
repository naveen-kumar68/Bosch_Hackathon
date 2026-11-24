"""Bound untrusted prompt data before it reaches a provider or the cache."""

import re

from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.high_entropy_strings import (
    Base64HighEntropyString,
    HexHighEntropyString,
)
from detect_secrets.settings import default_settings

PACKAGE_NAME = re.compile(r"^[A-Za-z0-9@/._:+-]{1,214}$")
SECRET = re.compile(r"\b(?:gsk_|sk-|ghp_|gho_)[A-Za-z0-9_-]{12,}")
ENTROPY = {p.secret_type: p for p in (Base64HighEntropyString(), HexHighEntropyString())}


def package_name(value: str) -> str:
    return value if PACKAGE_NAME.fullmatch(value) else "<invalid-name>"


def redact(value: str) -> str:
    lines = []
    with default_settings() as settings:
        # Offline detection only; never verify a suspected credential over the network.
        settings.disable_filters(
            "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
        )
        for line in value.splitlines():
            for secret in scan_line(line):
                if secret.secret_value:
                    plugin = ENTROPY.get(secret.type)
                    # scan_line's eager entropy search deliberately returns below-threshold
                    # candidates. Apply the installed plugins' thresholds before masking.
                    if (
                        plugin
                        and plugin.calculate_shannon_entropy(secret.secret_value)
                        <= plugin.entropy_limit
                    ):
                        continue
                    line = line.replace(secret.secret_value, "[REDACTED]")
            lines.append(SECRET.sub("[REDACTED]", line))
    return "\n".join(lines)


def snippet(value: str, max_chars: int = 4096) -> str:
    return redact("\n".join(value.splitlines()[:60]))[:max_chars]


def sanitise(value, max_snippet_chars: int = 4096):
    """Structured names are explicit; all text is redacted, including free text."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Prompt object keys must be strings")
            if (
                key in {"name", "package", "package_name"}
                or (key == "value" and value.get("type") == "package")
            ) and isinstance(item, str):
                result[key] = package_name(item)
            elif key in {"snippet", "code"} and isinstance(item, str):
                result[key] = snippet(item, max_snippet_chars)
            else:
                result[key] = sanitise(item, max_snippet_chars)
        return result
    if isinstance(value, list):
        return [sanitise(item, max_snippet_chars) for item in value]
    if isinstance(value, str):
        return redact(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError("Prompt data must be JSON compatible")
