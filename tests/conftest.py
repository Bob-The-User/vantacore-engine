"""Shared pytest fixtures for VantaCore Engine testing."""

from pathlib import Path
from typing import Callable
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Return a temporary output directory.

    Args:
        tmp_path: The default pytest temporary path fixture.

    Returns:
        Path to a newly created 'output' subdirectory.
    """
    out = tmp_path / "output"
    out.mkdir()
    return out


@pytest.fixture
def dump_path() -> Callable[[str], Path]:
    """Return a factory function that resolves absolute Path to a fixture file.

    Returns:
        A factory function taking a string filename and returning a Path object.
    """

    def _factory(name: str) -> Path:
        """Resolve a fixture name to its absolute Path.

        Args:
            name: Name of the fixture file (e.g. 'mock_raw_dram.bin').

        Returns:
            Absolute Path to the fixture.
        """
        return FIXTURES_DIR / name

    return _factory
