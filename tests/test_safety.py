from pathlib import Path

import pytest

from guardian.adapters.cargo import check_configuration
from guardian.config import contained_path
from guardian.llm.client import create_client


def test_cargo_execution_overrides_are_rejected(tmp_path):
    (tmp_path / ".cargo").mkdir()
    (tmp_path / ".cargo/config.toml").write_text('[build]\nrustc="malicious.exe"\n')
    with pytest.raises(ValueError, match="Review required"):
        check_configuration(tmp_path)


def test_workspace_escape_rejected(tmp_path):
    with pytest.raises(ValueError, match="escapes"):
        contained_path(tmp_path, "../outside")


def test_llm_requires_explicit_provider_configuration(tmp_path):
    with pytest.raises(ValueError, match="settings missing"):
        create_client(tmp_path / "absent.env")


def test_no_ecosystem_branches_downstream():
    for directory in ("guardian/graph",):
        for path in Path(directory).glob("*.py"):
            code = path.read_text()
            assert "from guardian.adapters" not in code
            assert '== "cargo"' not in code
            assert '== "pypi"' not in code
