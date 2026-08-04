"""Unit tests for FlatImageBackend memory translation backend."""

import os
from pathlib import Path
from typing import Callable
import pytest

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.translation_base import PageFaultError


def test_flat_image_detect(dump_path: Callable[[str], Path]) -> None:
    """Verify detect returns False for ELF headers and True for flat binaries."""
    backend = FlatImageBackend()

    with open(dump_path("mock_elf_core_x86_64.bin"), "rb") as elf_fh:
        assert backend.detect(elf_fh) is False

    with open(dump_path("mock_cisco_ios.bin"), "rb") as ios_fh:
        assert backend.detect(ios_fh) is True


def test_flat_image_contract(dump_path: Callable[[str], Path]) -> None:
    """Verify full contract of FlatImageBackend on mock_cisco_ios.bin."""
    backend = FlatImageBackend()
    ios_path = dump_path("mock_cisco_ios.bin")
    file_size = os.path.getsize(ios_path)

    with open(ios_path, "rb") as ios_fh:
        backend.initialize(ios_fh)
        assert backend._file_size == file_size

        # Read first 8 bytes
        first_8 = backend.read_virtual("FLAT_PHYSICAL", 0, 8)
        assert len(first_8) == 8
        ios_fh.seek(0)
        assert first_8 == ios_fh.read(8)

        # Read boundary at end of file (partial read zero-padded)
        partial = backend.read_virtual("FLAT_PHYSICAL", file_size - 4, 8)
        assert len(partial) == 8
        ios_fh.seek(file_size - 4)
        expected_partial = ios_fh.read(4) + b"\x00\x00\x00\x00"
        assert partial == expected_partial

        # Read at or beyond file size raises PageFaultError
        with pytest.raises(PageFaultError):
            backend.read_virtual("FLAT_PHYSICAL", file_size, 1)

        with pytest.raises(PageFaultError):
            backend.read_virtual("FLAT_PHYSICAL", file_size + 100, 8)

        # Basic metadata methods
        assert backend.enumerate_processes() == [("FLAT_PHYSICAL", "unknown", 0)]
        assert backend.get_kernel_base() == 0
        assert backend.get_architecture_name() == "flat"


def test_uninitialized_read_virtual_raises_page_fault() -> None:
    """Verify read_virtual on uninitialized backend raises PageFaultError."""
    backend = FlatImageBackend()
    with pytest.raises(PageFaultError):
        backend.read_virtual("FLAT_PHYSICAL", 0, 8)
