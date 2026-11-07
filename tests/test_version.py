"""The version in pyproject.toml (what PyPI shows) and promptwall.__version__ must agree."""
import tomllib
from pathlib import Path

import promptwall


def test_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as f:
        version = tomllib.load(f)["project"]["version"]
    assert promptwall.__version__ == version