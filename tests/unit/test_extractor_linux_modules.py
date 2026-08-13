"""Unit tests for LinuxModulesExtractor."""

import io
from pathlib import Path
import struct
from unittest.mock import MagicMock

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.linux.modules import (
    LinuxModulesExtractor,
    _MODULE_CORE_LAYOUT_BASE,
    _MODULE_CORE_LAYOUT_SIZE,
    _MODULE_LIST_NEXT,
    _MODULE_NAME_OFFSET,
)


def test_linux_modules_all_zeros_returns_empty() -> None:
    """Verify zero-filled backend returns empty modules list."""
    ext = LinuxModulesExtractor()
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 65536)

    res = ext.run(backend, fh, Path("/tmp"))

    assert res["modules"] == []
    assert res["dkom_anomalies"] == []


def test_linux_modules_mock_valid_module_struct() -> None:
    """Verify kernel module is extracted by list walking."""
    ext = LinuxModulesExtractor()
    mock_backend = MagicMock()
    mock_backend.get_kernel_base.return_value = 0xFFFF800000000000

    mod_buf = bytearray(0x200)
    mod_buf[_MODULE_NAME_OFFSET : _MODULE_NAME_OFFSET + 5] = b"ext4\x00"
    struct.pack_into("<Q", mod_buf, _MODULE_CORE_LAYOUT_BASE, 0xFFFF800000900000)
    struct.pack_into("<I", mod_buf, _MODULE_CORE_LAYOUT_SIZE, 65536)
    struct.pack_into("<Q", mod_buf, _MODULE_LIST_NEXT, 0)

    mock_backend.read_virtual.return_value = bytes(mod_buf)

    fh = io.BytesIO(b"\x00" * 65536)
    res = ext.run(mock_backend, fh, Path("/tmp"))

    assert len(res["modules"]) >= 1
    assert res["modules"][0]["name"] == "ext4"
    assert res["modules"][0]["base"] == 0xFFFF800000900000
    assert res["modules"][0]["size"] == 65536


def test_linux_modules_dkom_anomaly_detection() -> None:
    """Verify module carved physically but missing from list walk is reported as DKOM anomaly."""
    ext = LinuxModulesExtractor()
    mock_backend = MagicMock()
    mock_backend.get_kernel_base.return_value = 0xFFFF800000000000
    mock_backend.read_virtual.return_value = b"\x00" * 0x200

    buf = bytearray(65536)
    offset = 0x1000
    buf[offset + _MODULE_NAME_OFFSET : offset + _MODULE_NAME_OFFSET + 10] = b"hidden_rk\x00"
    struct.pack_into("<Q", buf, offset + _MODULE_CORE_LAYOUT_BASE, 0xFFFF800000A00000)
    struct.pack_into("<I", buf, offset + _MODULE_CORE_LAYOUT_SIZE, 32768)

    fh = io.BytesIO(bytes(buf))
    res = ext.run(mock_backend, fh, Path("/tmp"))

    assert any(mod["name"] == "hidden_rk" for mod in res["modules"])
    assert any(anom["name"] == "hidden_rk" and anom["severity"] == "HIGH" for anom in res["dkom_anomalies"])


def test_clean_module_name() -> None:
    """Verify _clean_module_name validation for Linux module names."""
    from vantacore_engine.extractors.linux.modules import _clean_module_name

    assert _clean_module_name(b"ext4\x00\x00") == "ext4"
    assert _clean_module_name(b"\x00") is None
    assert _clean_module_name(b"123invalid\x00") is None
    assert _clean_module_name(b"a" * 60) is None

