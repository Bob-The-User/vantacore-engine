"""Unit tests for X86_64TranslationBackend memory translation backend."""

import io
from pathlib import Path
import struct
from typing import Callable
import pytest

from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import PageFaultError


def test_x86_64_detect(dump_path: Callable[[str], Path]) -> None:
    """Verify x86_64 detect for ELF core dumps and invalid headers."""
    backend = X86_64TranslationBackend()

    # Valid ELF64 x86_64 core dump
    with open(dump_path("mock_elf_core_x86_64.bin"), "rb") as elf_fh:
        assert backend.detect(elf_fh) is True

    # ELFCLASS32 (byte 4 = 0x01)
    elf32_buf = io.BytesIO(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 10 + struct.pack("<H", 62))
    assert backend.detect(elf32_buf) is False

    # ARM64 ELF (e_machine = 183)
    arm64_buf = io.BytesIO(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10 + struct.pack("<H", 183))
    assert backend.detect(arm64_buf) is False


def test_x86_64_defaults_and_metadata() -> None:
    """Verify default attributes and metadata getters."""
    backend = X86_64TranslationBackend()
    assert backend.get_architecture_name() == "x86_64"
    assert backend.get_kernel_base() == 0xFFFF800000000000
    assert backend.enumerate_processes() == [("GLOBAL_KERNEL", "unknown", 0)]


def test_x86_64_read_phys_u64_out_of_bounds() -> None:
    """Verify _read_phys_u64 returns 0 for out-of-bounds offsets."""
    backend = X86_64TranslationBackend()
    dump_buf = io.BytesIO(b"\x00" * 100)
    backend.initialize(dump_buf)

    assert backend._read_phys_u64(95) == 0
    assert backend._read_phys_u64(-10) == 0
    assert backend._read_phys_u64(1000) == 0


def test_x86_64_walk_pml4_pcid_stripping() -> None:
    """Verify CR3 PCID lower 12 bits are masked in PML4 walk."""
    backend = X86_64TranslationBackend()
    # Create 4KB buffer with valid PML4 present entry at offset 0
    buf = bytearray(0x4000)
    # Entry at index 0 of PML4 points to PDPT at 0x1000
    struct.pack_into("<Q", buf, 0, 0x1000 | 1)
    dump_io = io.BytesIO(buf)
    backend.initialize(dump_io)

    # CR3 = 0x00000000 with PCID flags 0x001
    phys = backend._walk_pml4(0x0000001, 0x0)
    # Level 2 PDPT entry at 0x1000 is 0 (not present), so returns None
    assert phys is None


def test_x86_64_all_zero_dump_raises_page_fault() -> None:
    """Verify all-zero dump read_virtual raises PageFaultError."""
    backend = X86_64TranslationBackend()
    dump_io = io.BytesIO(b"\x00" * 0x10000)
    backend.initialize(dump_io)

    with pytest.raises(PageFaultError):
        backend.read_virtual("GLOBAL_KERNEL", 0xFFFF888000001000, 8)


def test_x86_64_uninitialized_read_virtual_raises_page_fault() -> None:
    """Verify read_virtual on uninitialized backend raises PageFaultError."""
    backend = X86_64TranslationBackend()
    with pytest.raises(PageFaultError):
        backend.read_virtual("GLOBAL_KERNEL", 0xFFFF888000001000, 8)
