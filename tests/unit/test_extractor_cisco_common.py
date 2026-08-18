"""Unit tests for shared Cisco extractors (CLI history and SNMP config)."""

import io
import logging
from pathlib import Path
from unittest.mock import MagicMock

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.cisco.common.cli_history import CLIHistoryExtractor
from vantacore_engine.extractors.cisco.common.snmp_config import SNMPConfigExtractor


def test_cli_history_no_patterns(tmp_path: Path) -> None:
    """Verify CLIHistoryExtractor returns NOT_FOUND when no sentinels are present."""
    ext = CLIHistoryExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)

    res = ext.run(backend, fh, tmp_path)
    assert res["cli_history"] == []
    assert res["cli_history_confidence"] == "NOT_FOUND"


def test_cli_history_basic_pattern(tmp_path: Path) -> None:
    """Verify CLIHistoryExtractor detects and clusters CLI commands."""
    ext = CLIHistoryExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 100 + b"show conn\x00" + b"\x00" * 50 + b"enable\x00" + b"\x00" * 500
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert res["cli_history_confidence"] == "FOUND"
    assert len(res["cli_history"]) >= 1
    commands = res["cli_history"][0]["commands"]
    assert "show conn" in commands
    assert "enable" in commands


def test_cli_history_hop_cap(tmp_path: Path, caplog) -> None:
    """Verify CLIHistoryExtractor enforces 500k hop cap and logs warning."""
    caplog.set_level(logging.WARNING)
    ext = CLIHistoryExtractor()
    backend = FlatImageBackend()

    mock_fh = MagicMock()
    call_count = 0

    def mock_tell():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return 100_000_000_000
        return 0

    mock_fh.tell.side_effect = mock_tell
    mock_fh.read.return_value = b"\x00" * 64

    from unittest.mock import patch
    with patch("vantacore_engine.extractors.cisco.common.cli_history._MAX_HOPS", 10):
        res = ext.run(backend, mock_fh, tmp_path)
    assert "hop cap reached" in caplog.text
    assert isinstance(res["cli_history"], list)


def test_snmp_config_no_patterns(tmp_path: Path) -> None:
    """Verify SNMPConfigExtractor returns empty list when no SNMP strings present."""
    ext = SNMPConfigExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)

    res = ext.run(backend, fh, tmp_path)
    assert res["snmp_community_strings"] == []


def test_snmp_config_public_found_no_secrets(tmp_path: Path) -> None:
    """Verify SNMPConfigExtractor redacts community strings by default."""
    ext = SNMPConfigExtractor(include_secrets=False)
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"snmp-server community public RO\x00" + b"\x00" * 128
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["snmp_community_strings"]) >= 1
    entry = res["snmp_community_strings"][0]
    assert entry["redacted"] is True
    assert entry["value"] is None
    assert entry["physical_offset"] > 0


def test_snmp_config_public_found_include_secrets(tmp_path: Path) -> None:
    """Verify SNMPConfigExtractor reveals plaintext when include_secrets is True."""
    ext = SNMPConfigExtractor(include_secrets=True)
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"snmp-server community public RO\x00" + b"\x00" * 128
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["snmp_community_strings"]) >= 1
    entry = res["snmp_community_strings"][0]
    assert entry["redacted"] is False
    assert entry["value"] == "public"
