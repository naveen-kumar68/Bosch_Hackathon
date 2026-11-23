"""Hash-first artifact inspection, safe extraction and static capability sets."""

import hashlib
import io
import math
import re
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

PATTERNS = {
    "network": r"\b(?:std::net|TcpStream::connect|reqwest|ureq|hyper::Client|requests\.(?:get|post)|urllib\.request|curl)\b",
    "process": r"std::process::Command|\bCommand::new|subprocess\.|os\.system\s*\(",
    "environment": r"env::vars|os\.environ|\.ssh|\.cargo[/\\]credentials|\bHOME\b|wallet",
    "decode": r"base64|fromhex|hex::decode",
    "write": r"fs::write|File::create|write_all|open\([^\n]*['\"]w",
    "embedded_binary": r"include_bytes!\s*\([^)]*\.(?:exe|bin|dll|so)",
}


def verified_extract(data: bytes, checksum: str, destination: Path, *, max_bytes=100_000_000):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum or ""):
        raise ValueError("A registry SHA256 is required before artifact inspection")
    if hashlib.sha256(data).hexdigest() != checksum.lower():
        raise ValueError("Artifact SHA256 mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
    seen, size = set(), 0

    def write(name, content):
        nonlocal size
        if "\\" in name or ":" in name:
            raise ValueError("Unsafe archive member")
        path = (destination / name).resolve()
        if not path.is_relative_to(destination) or path in seen:
            raise ValueError("Archive path traversal or duplicate member")
        seen.add(path)
        size += len(content)
        if size > max_bytes:
            raise ValueError("Extracted artifact exceeds size limit")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(m.file_size for m in archive.infolist()) > max_bytes:
                raise ValueError("Archive exceeds size limit")
            for member in archive.infolist():
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Archive symlink prohibited")
                if not member.is_dir():
                    write(member.filename, archive.read(member))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile() or member.size + size > max_bytes:
                    raise ValueError("Archive link, device or excessive member prohibited")
                write(member.name, archive.extractfile(member).read())
    return destination


def inspect_sources(directory: Path, *, proc_macro=False):
    hits = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or not (
            path.name in {"build.rs", "setup.py"} or proc_macro and path.suffix == ".rs"
        ):
            continue
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            for capability, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    hits.append(
                        {
                            "capability": capability,
                            "file": path.relative_to(directory).as_posix(),
                            "line": number,
                            "snippet": line[:500],
                            "method": "regex heuristic",
                        }
                    )
            for blob in re.findall(r"[A-Za-z0-9+/=]{60,}", line):
                entropy = -sum(
                    (count / len(blob)) * math.log2(count / len(blob))
                    for count in Counter(blob).values()
                )
                if entropy > 4.5:
                    hits.append(
                        {
                            "capability": "high_entropy",
                            "file": path.relative_to(directory).as_posix(),
                            "line": number,
                            "snippet": "[high entropy string redacted]",
                            "method": "Shannon entropy >4.5",
                        }
                    )
    return hits


def capability_diff(before, after):
    previous = {hit["capability"] for hit in before}
    return [hit for hit in after if hit["capability"] not in previous]
