"""Unit tests for vantacore CLI subcommands and error handling."""

import json
from pathlib import Path
import subprocess
from typing import Callable
from unittest.mock import patch
import pytest

import vantacore_engine.cli as cli

REPO_ROOT = Path(__file__).parent.parent.parent


def test_cli_detect_text_output(dump_path: Callable[[str], Path]) -> None:
    """Verify CLI detect command outputs human-readable text for Cisco ASA dump."""
    lina_path = str(dump_path("mock_cisco_asa_lina.bin"))
    result = subprocess.run(
        ["pixi", "run", "vantacore", "detect", lina_path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "cisco_asa" in result.stdout.lower()


def test_cli_detect_json_output(dump_path: Callable[[str], Path]) -> None:
    """Verify CLI detect command with --json outputs valid JSON payload."""
    lina_path = str(dump_path("mock_cisco_asa_lina.bin"))
    result = subprocess.run(
        ["pixi", "run", "vantacore", "detect", "--json", lina_path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "platform_name" in data
    assert "confidence" in data
    assert "translation_backend" in data
    assert "extractor_paths" in data
    assert "encrypted" in data
    assert data["platform_name"] == "cisco_asa"


def test_cli_detect_nonexistent_file_exits_nonzero() -> None:
    """Verify CLI detect command exits with non-zero error for missing file."""
    result = subprocess.run(
        ["pixi", "run", "vantacore", "detect", "/tmp/does_not_exist_vantacore_test.bin"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "error" in result.stderr.lower() or "error" in result.stdout.lower()


def test_cli_direct_main_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify direct invocation of cli.main with version subcommand."""
    with patch("sys.argv", ["vantacore", "version"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "vantacore-engine" in captured.out


def test_cli_direct_main_scan(
    dump_path: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify direct invocation of cli.main with scan subcommand."""
    lina_path = str(dump_path("mock_cisco_asa_lina.bin"))
    with patch("sys.argv", ["vantacore", "scan", "--json", lina_path]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "scan_status" in data


def test_cli_direct_main_verify(
    dump_path: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify direct invocation of cli.main with verify subcommand."""
    lina_path = str(dump_path("mock_cisco_asa_lina.bin"))
    with patch("sys.argv", ["vantacore", "verify", "--json", lina_path]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "sha256" in data
    assert "platform" in data


def test_cli_direct_main_no_args(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify direct invocation of cli.main without subcommand prints help."""
    with patch("sys.argv", ["vantacore"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0


def test_cli_direct_main_detect_json(
    dump_path: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify direct invocation of cli.main detect --json."""
    lina_path = str(dump_path("mock_cisco_asa_lina.bin"))
    with patch("sys.argv", ["vantacore", "detect", "--json", lina_path]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["platform_name"] == "cisco_asa"


def test_cli_direct_main_detect_text(
    dump_path: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify direct invocation of cli.main detect text output."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))
    with patch("sys.argv", ["vantacore", "detect", ios_path]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0


def test_cli_direct_main_detect_missing_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify direct invocation of cli.main detect with missing file exits code 1."""
    with patch("sys.argv", ["vantacore", "detect", "/tmp/nonexistent_file_123.bin"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Error opening dump file" in captured.err
