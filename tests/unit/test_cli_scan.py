"""Unit tests for CLI scan and verify commands."""

import argparse
import json
from pathlib import Path
from typing import Callable
import pytest

import vantacore_engine.cli as cli


def test_cli_scan_missing_file_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify scan command exits code 1 when dump file does not exist."""
    args = argparse.Namespace(
        dump="/tmp/nonexistent_dump_file_404.bin",
        output_dir=None,
        json_output=True,
        include_secrets=False,
    )
    with pytest.raises(SystemExit) as exc:
        cli._cmd_scan(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Error opening dump file" in captured.err


def test_cli_scan_json_output_schema(
    dump_path: Callable[[str], Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify scan command output schema contains scan_status and extractors metadata."""
    dump_file = str(dump_path("mock_cisco_asa_lina.bin"))
    out_dir = tmp_path / "scan_out"
    args = argparse.Namespace(
        dump=dump_file,
        output_dir=str(out_dir),
        json_output=True,
        include_secrets=False,
    )
    with pytest.raises(SystemExit) as exc:
        cli._cmd_scan(args)
    assert exc.value.code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "scan_status" in data
    assert "overall" in data["scan_status"]
    assert "extractors_succeeded" in data["scan_status"]


def test_cli_scan_produces_output_files(
    dump_path: Callable[[str], Path], tmp_path: Path
) -> None:
    """Verify scan creates vantacore_output.json and audit log in output_dir."""
    dump_file = str(dump_path("mock_cisco_asa_lina.bin"))
    out_dir = tmp_path / "scan_artifacts"
    args = argparse.Namespace(
        dump=dump_file,
        output_dir=str(out_dir),
        json_output=False,
        include_secrets=False,
    )
    with pytest.raises(SystemExit) as exc:
        cli._cmd_scan(args)
    assert exc.value.code == 0

    output_json = out_dir / "vantacore_output.json"
    assert output_json.exists()
    with open(output_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "scan_status" in data


def test_cli_verify_json_output(
    dump_path: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify verify command returns all 7 required integrity fields."""
    dump_file = str(dump_path("mock_elf_core_x86_64.bin"))
    args = argparse.Namespace(
        dump=dump_file,
        json_output=True,
    )
    with pytest.raises(SystemExit) as exc:
        cli._cmd_verify(args)
    assert exc.value.code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    required_keys = {
        "sha256",
        "file_size",
        "elf_valid",
        "platform",
        "confidence",
        "architecture",
        "encrypted",
    }
    assert required_keys.issubset(set(data.keys()))


def test_cli_verify_missing_file_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify verify command exits code 1 for nonexistent file."""
    args = argparse.Namespace(
        dump="/tmp/nonexistent_verify_file_404.bin",
        json_output=True,
    )
    with pytest.raises(SystemExit) as exc:
        cli._cmd_verify(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Error opening dump file" in captured.err
