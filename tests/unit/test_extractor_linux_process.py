"""Unit tests for LinuxProcessExtractor."""

import io
from pathlib import Path
import struct
from unittest.mock import MagicMock

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.linux.process import (
    LinuxProcessExtractor,
    _TASK_COMM_OFFSET,
    _TASK_PID_OFFSET,
    _TASK_STATE_OFFSET,
    _TASK_TASKS_NEXT,
    _TASK_TGID_OFFSET,
)


def test_linux_process_all_zeros_returns_empty() -> None:
    """Verify zero-filled backend and dump return empty processes without exception."""
    ext = LinuxProcessExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 4096)

    res = ext.run(backend, fh, Path("/tmp"))

    assert res["processes"] == []
    assert res["dkom_anomalies"] == []


def test_linux_process_mock_valid_task_struct() -> None:
    """Verify valid task_struct is extracted by list walking."""
    ext = LinuxProcessExtractor()
    mock_backend = MagicMock()
    mock_backend.get_kernel_base.return_value = 0xFFFF800000000000

    # Prepare task_struct buffer for PID 1 (init) at 0xFFFF800000000000
    task_buf = bytearray(0x700)
    struct.pack_into("<i", task_buf, _TASK_PID_OFFSET, 1)
    struct.pack_into("<i", task_buf, _TASK_TGID_OFFSET, 1)
    struct.pack_into("<q", task_buf, _TASK_STATE_OFFSET, 0)
    task_buf[_TASK_COMM_OFFSET : _TASK_COMM_OFFSET + 7] = b"systemd"
    # tasks.next points to 0 (end of list)
    struct.pack_into("<Q", task_buf, _TASK_TASKS_NEXT, 0)

    def mock_read_virtual(ns, va, size):
        if va == 0xFFFF800000000000:
            return bytes(task_buf[:size])
        return b"\x00" * size

    mock_backend.read_virtual.side_effect = mock_read_virtual

    fh = io.BytesIO(b"\x00" * 4096)
    res = ext.run(mock_backend, fh, Path("/tmp"))

    assert len(res["processes"]) >= 1
    assert res["processes"][0]["pid"] == 1
    assert res["processes"][0]["comm"] == "systemd"


def test_linux_process_circular_list_walk_terminates() -> None:
    """Verify circular list (A.tasks.next -> A) terminates via visited check without infinite loop."""
    ext = LinuxProcessExtractor()
    mock_backend = MagicMock()
    mock_backend.get_kernel_base.return_value = 0xFFFF800000000000

    init_va = 0xFFFF800000000000
    task_buf = bytearray(0x700)
    struct.pack_into("<i", task_buf, _TASK_PID_OFFSET, 1)
    struct.pack_into("<i", task_buf, _TASK_TGID_OFFSET, 1)
    struct.pack_into("<q", task_buf, _TASK_STATE_OFFSET, 0)
    task_buf[_TASK_COMM_OFFSET : _TASK_COMM_OFFSET + 7] = b"systemd"
    # Point tasks.next to self (init_va + _TASK_TASKS_NEXT)
    struct.pack_into("<Q", task_buf, _TASK_TASKS_NEXT, init_va + _TASK_TASKS_NEXT)

    mock_backend.read_virtual.return_value = bytes(task_buf)

    fh = io.BytesIO(b"\x00" * 4096)
    res = ext.run(mock_backend, fh, Path("/tmp"))

    assert len(res["processes"]) == 1
    assert res["processes"][0]["pid"] == 1


def test_linux_process_dkom_anomaly_detection() -> None:
    """Verify process found in slab carving but absent from list walk is reported as DKOM anomaly."""
    ext = LinuxProcessExtractor()
    mock_backend = MagicMock()
    mock_backend.get_kernel_base.return_value = 0xFFFF800000000000
    mock_backend.read_virtual.return_value = b"\x00" * 0x700  # Primary path finds nothing

    # Create physical dump containing carved task_struct for PID 999
    dump_buf = bytearray(65536)
    offset = 0x1000
    struct.pack_into("<i", dump_buf, offset + _TASK_PID_OFFSET, 999)
    struct.pack_into("<i", dump_buf, offset + _TASK_TGID_OFFSET, 999)
    struct.pack_into("<q", dump_buf, offset + _TASK_STATE_OFFSET, 0)
    dump_buf[offset + _TASK_COMM_OFFSET : offset + _TASK_COMM_OFFSET + 6] = b"rootkit"

    fh = io.BytesIO(bytes(dump_buf))
    res = ext.run(mock_backend, fh, Path("/tmp"))

    assert any(proc["pid"] == 999 for proc in res["processes"])
    assert any(anom["pid"] == 999 and anom["severity"] == "HIGH" for anom in res["dkom_anomalies"])


def test_clean_comm_helpers() -> None:
    """Verify _clean_comm behavior with valid and invalid byte strings."""
    from vantacore_engine.extractors.linux.process import _clean_comm

    assert _clean_comm(b"systemd\x00\x00\x00") == "systemd"
    assert _clean_comm(b"\x00\x00") is None
    assert _clean_comm(b"\x80\xff\xfe") is None


def test_is_valid_kernel_va() -> None:
    """Verify _is_valid_kernel_va bounds check."""
    from vantacore_engine.extractors.linux.process import _is_valid_kernel_va

    assert _is_valid_kernel_va(0xFFFF800000000000) is True
    assert _is_valid_kernel_va(0x00007FFFFFFFFFFF) is False

