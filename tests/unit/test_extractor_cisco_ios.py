"""Unit tests for Cisco IOS/IOS-XE extractors (routing table, processes, running config)."""

import io
from pathlib import Path

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.cisco.ios.ios_processes import IOSProcessesExtractor
from vantacore_engine.extractors.cisco.ios.routing_table import IOSRoutingTableExtractor
from vantacore_engine.extractors.cisco.ios.running_config import RunningConfigExtractor


def test_routing_table_ospf_route(tmp_path: Path) -> None:
    """Verify IOSRoutingTableExtractor parses OSPF route line."""
    ext = IOSRoutingTableExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 64 + b"O     192.168.1.0/24 [110/20] via 10.0.0.1\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["routing_table"]) == 1
    route = res["routing_table"][0]
    assert route["protocol"] == "OSPF"
    assert "192.168.1.0/24" in route["prefix"]
    assert route["next_hop"] == "10.0.0.1"


def test_routing_table_static_route(tmp_path: Path) -> None:
    """Verify IOSRoutingTableExtractor parses static ip route config line."""
    ext = IOSRoutingTableExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 64 + b"ip route 10.10.10.0 255.255.255.0 192.168.1.1\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["routing_table"]) == 1
    route = res["routing_table"][0]
    assert route["protocol"] == "STATIC"
    assert "10.10.10.0" in route["prefix"]
    assert route["next_hop"] == "192.168.1.1"


def test_routing_table_invalid_prefix_rejected(tmp_path: Path) -> None:
    """Verify IOSRoutingTableExtractor rejects invalid prefix tokens."""
    ext = IOSRoutingTableExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 64 + b"O     not.an.ip.address\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert res["routing_table"] == []


def test_ios_processes_basic(tmp_path: Path) -> None:
    """Verify IOSProcessesExtractor extracts process ID and name."""
    ext = IOSProcessesExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 64 + b"PID 42 Exec\x00"
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["ios_processes"]) == 1
    proc = res["ios_processes"][0]
    assert proc["pid"] == 42
    assert proc["name"] == "Exec"


def test_ios_processes_mempool_regions(tmp_path: Path) -> None:
    """Verify IOSProcessesExtractor identifies mempool magic blocks."""
    ext = IOSProcessesExtractor()
    backend = FlatImageBackend()
    data = b"\x00" * 128 + b"\xAB\x12\x34\xCD" + b"\x00" * 128
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    assert len(res["mempool_regions"]) == 1
    assert res["mempool_regions"][0]["physical_offset"] == 128


def test_running_config_high_confidence(tmp_path: Path) -> None:
    """Verify RunningConfigExtractor rates high confidence when all anchors present."""
    ext = RunningConfigExtractor()
    backend = FlatImageBackend()
    data = (
        b"hostname Router01\n"
        b"interface GigabitEthernet0/0\n"
        b"router ospf 1\n"
        b"ip route 0.0.0.0 0.0.0.0 1.1.1.1\n"
        b"line vty 0 4\n"
        b"crypto isakmp enable\n"
        b"aaa new-model\n\x00"
    )
    fh = io.BytesIO(data)

    res = ext.run(backend, fh, tmp_path)
    rc = res["running_config"]
    assert rc["confidence"] == "HIGH"
    assert rc["sections_found"] == 7
    assert "Router01" in rc["text"]


def test_running_config_not_found(tmp_path: Path) -> None:
    """Verify RunningConfigExtractor returns NOT_FOUND when zero anchors are matched."""
    ext = RunningConfigExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1000)

    res = ext.run(backend, fh, tmp_path)
    rc = res["running_config"]
    assert rc["confidence"] == "NOT_FOUND"
    assert rc["sections_found"] == 0
    assert rc["text"] == ""
