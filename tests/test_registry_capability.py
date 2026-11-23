import hashlib
import io
import tarfile

import pytest

from guardian.detect.capability import capability_diff, inspect_sources, verified_extract
from guardian.detect.registry import index_path, metadata_changes, new_dependencies
from guardian.detect.typosquat import candidates


@pytest.mark.parametrize(
    "name,path", [("a", "1/a"), ("ab", "2/ab"), ("abc", "3/a/abc"), ("serde", "se/rd/serde")]
)
def test_sparse_index_paths(name, path):
    assert index_path(name) == path


def test_provenance_unknown_is_not_regression():
    assert "provenance_regression" not in metadata_changes({"trusted_publishing": True}, {})
    assert "provenance_regression" in metadata_changes(
        {"trusted_publishing": True}, {"trusted_publishing": False}
    )


def test_new_build_dependency_history():
    history = [
        {"vers": "1", "deps": []},
        {"vers": "2", "deps": []},
        {"vers": "3", "deps": [{"name": "new", "kind": "build"}]},
    ]
    added = list(new_dependencies(history, "2", "3"))
    assert added[0]["kind"] == "build" and added[0]["absent_in_previous_versions"] == 2


def archive(name, content=b"data", link=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        member = tarfile.TarInfo(name)
        if link:
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(member)
        else:
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


@pytest.mark.parametrize("name,link", [("../outside", False), ("/outside", False), ("link", True)])
def test_safe_extract_rejects_traversal_and_links(tmp_path, name, link):
    data = archive(name, link=link)
    with pytest.raises(ValueError):
        verified_extract(data, hashlib.sha256(data).hexdigest(), tmp_path)


def test_hash_verified_before_parsing(tmp_path):
    with pytest.raises(ValueError, match="mismatch"):
        verified_extract(b"not an archive", "0" * 64, tmp_path)


def test_static_capability_diff_never_executes(tmp_path):
    data = archive(
        "crate/build.rs",
        b'// hackathon test fixture\nTcpStream::connect("127.0.0.1:9");\nstd::env::vars();\nbase64::decode("test");',
    )
    verified_extract(data, hashlib.sha256(data).hexdigest(), tmp_path)
    hits = capability_diff([], inspect_sources(tmp_path))
    assert {h["capability"] for h in hits} >= {"network", "environment", "decode"}


def test_typosquat_exact_allowlist_and_digit_suffix():
    assert candidates("serde", ["serde"]) == []
    assert candidates("serde_derve", ["serde_derive"])[0]["distance"] == 1
    assert candidates("proc-macro1", ["proc-macro2"])[0]["digit_suffix"]
    assert candidates("serde_derve", ["serde_derive"], [("serde_derve", "serde_derive")]) == []
