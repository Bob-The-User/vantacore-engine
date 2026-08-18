"""Unit tests for Cisco ASA extractors (lina process, conn table, ACL rules, VPN sessions)."""

import io
import logging
from pathlib import Path
from typing import Callable

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.cisco.asa.acl_rules import ASAACLRulesExtractor
from vantacore_engine.extractors.cisco.asa.conn_table import ASAConnTableExtractor
from vantacore_engine.extractors.cisco.asa.lina_process import LinaProcessExtractor
from vantacore_engine.extractors.cisco.asa.vpn_sessions import ASAVPNSessionsExtractor


def test_lina_process_from_elf_note(dump_path: Callable[[str], Path], tmp_path: Path) -> None:
    """Verify LinaProcessExtractor extracts process info from real mock ELF note."""
    dump_file = dump_path("mock_cisco_asa_lina.bin")
    ext = LinaProcessExtractor()
    backend = FlatImageBackend()

    with open(dump_file, "rb") as fh:
        res = ext.run(backend, fh, tmp_path)

    assert isinstance(res["lina_threads"], list)
    assert len(res["lina_threads"]) >= 1
    assert res["lina_threads"][0]["name"] == "lina"


def test_lina_process_fallback_on_corrupt_elf(tmp_path: Path, caplog) -> None:
    """Verify LinaProcessExtractor logs warning and falls back to pattern scan on corrupt ELF."""
    caplog.set_level(logging.WARNING)
    ext = LinaProcessExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 64 + b"lina\x00" + b"\x00" * 128
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert "ELF note parse failed" in caplog.text
    assert isinstance(res["lina_threads"], list)
    assert any(t["name"] == "lina" for t in res["lina_threads"])


def test_conn_table_basic_pattern(tmp_path: Path) -> None:
    """Verify ASAConnTableExtractor parses TCP connection entries."""
    ext = ASAConnTableExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"   TCP 10.0.0.1:1234 10.0.1.2:443, idle 0:00:01, bytes 1024, flags UIO\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["connections"]) == 1
    conn = res["connections"][0]
    assert conn["protocol"] == "TCP"
    assert conn["src_ip"] == "10.0.0.1"
    assert conn["src_port"] == 1234
    assert conn["dst_ip"] == "10.0.1.2"
    assert conn["dst_port"] == 443
    assert conn["bytes_in"] == 1024


def test_conn_table_empty(tmp_path: Path) -> None:
    """Verify ASAConnTableExtractor returns empty list when no connections found."""
    ext = ASAConnTableExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)

    res = ext.run(backend, fh, tmp_path)
    assert res["connections"] == []


def test_conn_table_invalid_ip_rejected(tmp_path: Path) -> None:
    """Verify ASAConnTableExtractor filters out invalid IPs (such as 0.0.0.0)."""
    ext = ASAConnTableExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"   TCP 0.0.0.0:1234 10.0.0.1:80\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert res["connections"] == []


def test_acl_rules_permit_extracted(tmp_path: Path) -> None:
    """Verify ASAACLRulesExtractor extracts permit rule."""
    ext = ASAACLRulesExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["acl_rules"]) == 1
    rule = res["acl_rules"][0]
    assert rule["acl_name"] == "OUTSIDE_IN"
    assert rule["action"] == "permit"
    assert rule["protocol"] == "tcp"


def test_acl_rules_deny_extracted(tmp_path: Path) -> None:
    """Verify ASAACLRulesExtractor extracts deny rule."""
    ext = ASAACLRulesExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"access-list INSIDE_OUT extended deny ip any any\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["acl_rules"]) == 1
    rule = res["acl_rules"][0]
    assert rule["acl_name"] == "INSIDE_OUT"
    assert rule["action"] == "deny"


def test_vpn_sessions_psk_redacted_by_default(tmp_path: Path) -> None:
    """Verify ASAVPNSessionsExtractor redacts PSK by default."""
    ext = ASAVPNSessionsExtractor(include_secrets=False)
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"pre-shared-key mysecretpsk123\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["vpn_psks"]) == 1
    psk = res["vpn_psks"][0]
    assert psk["redacted"] is True
    assert psk["value"] is None


def test_vpn_sessions_psk_visible_with_flag(tmp_path: Path) -> None:
    """Verify ASAVPNSessionsExtractor includes PSK plaintext when configured."""
    ext = ASAVPNSessionsExtractor(include_secrets=True)
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"pre-shared-key mysecretpsk123\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["vpn_psks"]) == 1
    psk = res["vpn_psks"][0]
    assert psk["redacted"] is False
    assert psk["value"] == "mysecretpsk123"


def test_vpn_sessions_psk_triggers_warning(tmp_path: Path, caplog) -> None:
    """Verify ASAVPNSessionsExtractor logs warning when PSK is found."""
    caplog.set_level(logging.WARNING)
    ext = ASAVPNSessionsExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"pre-shared-key mysecretpsk123\x00"
    fh = io.BytesIO(data)

    ext.run(backend, fh, tmp_path)
    assert "pre-shared key" in caplog.text.lower()
