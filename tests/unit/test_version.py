"""Unit tests for package version and CLI entry points."""

import subprocess
from pathlib import Path
import vantacore_engine

REPO_ROOT = Path(__file__).parent.parent.parent


def test_version_constant() -> None:
    """Verify that the package version constant is set correctly."""
    assert vantacore_engine.__version__ == "0.1.0"


def test_cli_version_exits_zero() -> None:
    """Verify that the CLI version subcommand exits with code 0."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0


def test_cli_version_output_contains_version() -> None:
    """Verify that the CLI version output contains the correct version string."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "0.1.0" in result.stdout


def test_cli_version_output_contains_package_name() -> None:
    """Verify that the CLI version output contains the package name."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "vantacore-engine" in result.stdout


def test_cli_stub_scan_exits_zero() -> None:
    """Verify that the stub 'scan' command exits with code 0."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "scan", "nosuchfile.bin"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0
    assert "not available yet" in result.stdout


def test_cli_help_exits_zero() -> None:
    """Verify that the CLI --help command exits with code 0."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0
    assert "version" in result.stdout
    assert "scan" in result.stdout
    assert "detect" in result.stdout
    assert "verify" in result.stdout
