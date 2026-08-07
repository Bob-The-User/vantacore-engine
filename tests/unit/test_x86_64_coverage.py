"""Unit tests for x86_64 PML4 page walking and KASLR IDT scan paths."""

from pathlib import Path
import struct
from typing import Callable
import pytest

from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import PageFaultError


def test_x86_64_pml4_page_walk_and_kaslr(dump_path: Callable[[str], Path]) -> None:
    """Verify x86_64 KASLR scan, _walk_pml4, and read_virtual page translation."""
    pml4_dump = dump_path("mock_pml4_dram.bin")
    backend = X86_64TranslationBackend()

    with open(pml4_dump, "rb") as fh:
        backend.initialize(fh)

        # KASLR scan detects synthetic IDT descriptor at 0x8000
        assert backend.get_kernel_base() == 0xFFFF800000000000

        # Direct _walk_pml4 resolution
        phys_addr = backend._walk_pml4(cr3=0x1000, vaddr=0xFFFF888000005000)
        assert phys_addr == 0x5000

        # read_virtual with unmapped cr3=0 raises PageFaultError
        with pytest.raises(PageFaultError):
            backend.read_virtual("GLOBAL_KERNEL", 0xFFFF888000005000, 8)

        # read_virtual with cr3=0x1000 ("0x1000") resolves page and reads payload
        data = backend.read_virtual("0x1000", 0xFFFF888000005000, 8)
        assert len(data) == 8
        expected = struct.pack("<Q", 0xDEADBEEFCAFEBABE)
        assert data == expected


def test_x86_64_detect(dump_path: Callable[[str], Path]) -> None:
    """Verify detect on ELF 64-bit x86_64 vs small non-ELF image."""
    backend = X86_64TranslationBackend()

    with open(dump_path("mock_elf_core_x86_64.bin"), "rb") as fh:
        assert backend.detect(fh) is True

    with open(dump_path("mock_cisco_ios.bin"), "rb") as fh:
        assert backend.detect(fh) is False
