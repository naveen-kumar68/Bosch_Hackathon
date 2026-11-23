import pytest

from guardian.adapters.pypi import parse_requirements


def test_via_edges_hashes_and_markers(fixture_dir):
    result = parse_requirements(
        (fixture_dir / "requirements.txt").read_text(), "fixture_root", "1", ["observed"]
    )
    assert len(result.components) == 5
    assert len(result.edges) == 5
    components = {c.name: c for c in result.components}
    assert components["alpha"].has_hash
    assert not components["beta"].has_hash
    assert len([e for e in result.edges if e.to_purl == "pkg:pypi/shared@3.0.0"]) == 2
    assert any(e.target == 'sys_platform == "darwin"' for e in result.edges)


@pytest.mark.parametrize("text", ["a>=1", "a==1\n # via nonexistent", "a==1"])
def test_rejects_guessed_dependencies(text):
    with pytest.raises(ValueError):
        parse_requirements(text, "root", "1", ["observed"])
