import json

import httpx
import pytest

from guardian.detect.http import CachedHTTP
from guardian.detect.models import Vulnerability
from guardian.detect.vulns import deduplicate
from guardian.evidence import Recorder


def observation(identifier, aliases, source, component="pkg:cargo/test@1"):
    return Vulnerability(
        id=identifier, aliases=aliases, component=component, evidence_ids=[source], sources=[source]
    )


def test_alias_union_is_transitive_and_preserves_sources():
    items = [
        observation("RUSTSEC-1", ["GHSA-1"], "audit"),
        observation("GHSA-1", ["CVE-1"], "osv"),
        observation("CVE-1", [], "grype"),
    ]
    merged = deduplicate(items)
    assert len(merged) == 1
    assert merged[0].id == "CVE-1"
    assert set(merged[0].aliases) == {"RUSTSEC-1", "GHSA-1", "CVE-1"}
    assert merged[0].sources == ["audit", "grype", "osv"]


def test_same_advisory_on_two_components_is_not_lost():
    assert (
        len(
            deduplicate(
                [
                    observation("CVE-1", [], "osv"),
                    observation("CVE-1", [], "osv", "pkg:cargo/test@2"),
                ]
            )
        )
        == 2
    )


def test_http_cache_offline_and_tampering(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, content=b'{"observed":true}')

    recorder = Recorder(tmp_path / "out")
    cache = CachedHTTP(
        tmp_path / "cache", recorder, client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    cache.get("https://example.test/metadata")
    cache.offline = True
    assert cache.get("https://example.test/metadata")[0] == b'{"observed":true}'
    assert len(calls) == 1
    path = next((tmp_path / "cache").glob("*.json"))
    document = json.loads(path.read_text())
    document["body_hex"] = b"tampered".hex()
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="integrity"):
        cache.get("https://example.test/metadata")
