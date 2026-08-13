"""Unit tests for LinuxNetworkExtractor."""

import io
from pathlib import Path
import struct

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.linux.network import (
    LinuxNetworkExtractor,
    _INET_SOCK_DPORT,
    _INET_SOCK_DST_IP,
    _INET_SOCK_SPORT,
    _INET_SOCK_SRC_IP,
)


def test_linux_network_all_zeros_returns_empty() -> None:
    """Verify zero-filled binary dump returns empty connections list."""
    ext = LinuxNetworkExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 65536)

    res = ext.run(backend, fh, Path("/tmp"))

    assert res["connections"] == []


def test_linux_network_mock_valid_inet_sock() -> None:
    """Verify candidate inet_sock IPv4 structure is extracted."""
    ext = LinuxNetworkExtractor()
    backend = FlatImageBackend()

    buf = bytearray(65536)
    offset = 0x1000

    # Local IP: 192.168.1.10 (0xC0, 0xA8, 0x01, 0x0A)
    buf[offset + _INET_SOCK_SRC_IP : offset + _INET_SOCK_SRC_IP + 4] = b"\xc0\xa8\x01\x0a"
    # Remote IP: 10.0.0.1 (0x0A, 0x00, 0x00, 0x01)
    buf[offset + _INET_SOCK_DST_IP : offset + _INET_SOCK_DST_IP + 4] = b"\x0a\x00\x00\x01"
    # Ports: 443 -> 80
    struct.pack_into(">H", buf, offset + _INET_SOCK_SPORT, 443)
    struct.pack_into(">H", buf, offset + _INET_SOCK_DPORT, 80)

    fh = io.BytesIO(bytes(buf))
    res = ext.run(backend, fh, Path("/tmp"))

    assert len(res["connections"]) >= 1
    conn = res["connections"][0]
    assert conn["local_addr"] == "192.168.1.10"
    assert conn["local_port"] == 443
    assert conn["remote_addr"] == "10.0.0.1"
    assert conn["remote_port"] == 80


def test_is_valid_ipv4_bytes() -> None:
    """Verify _is_valid_ipv4_bytes filters invalid IP byte sequences."""
    from vantacore_engine.extractors.linux.network import _is_valid_ipv4_bytes

    assert _is_valid_ipv4_bytes(b"\xc0\xa8\x01\x01") is True
    assert _is_valid_ipv4_bytes(b"\x00\x00\x00\x00") is False
    assert _is_valid_ipv4_bytes(b"\xff\xff\xff\xff") is False
    assert _is_valid_ipv4_bytes(b"\x00\x01\x02\x03") is False
    assert _is_valid_ipv4_bytes(b"\xff\x01\x02\x03") is False
    assert _is_valid_ipv4_bytes(b"\x01\x02") is False


def test_format_ipv4() -> None:
    """Verify _format_ipv4 formats IP address bytes into dotted decimal."""
    from vantacore_engine.extractors.linux.network import _format_ipv4

    assert _format_ipv4(b"\x0a\x00\x00\x01") == "10.0.0.1"

