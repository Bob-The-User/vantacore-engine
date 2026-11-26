"""Unit tests for x86_64 PML5 paging, KPTI dual-PGD, and direct-map fast-path."""

import io
import logging
from pathlib import Path
import struct
from typing import Callable
import pytest

from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend


def test_pml4_mode_default(dump_path: Callable[[str], Path]) -> None:
    """Verify that a PML4 memory image defaults to PML4 paging mode."""
    pml4_dump = dump_path("mock_pml4_dram.bin")
    backend = X86_64TranslationBackend()
    with open(pml4_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._pml5_enabled is False


def test_pml5_detected_from_fixture(dump_path: Callable[[str], Path]) -> None:
    """Verify that a PML5 memory image triggers heuristic 5-level paging detection."""
    pml5_dump = dump_path("mock_pml5_dram.bin")
    backend = X86_64TranslationBackend()
    with open(pml5_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._pml5_enabled is True


def test_phys_base_from_nt_file_note(dump_path: Callable[[str], Path]) -> None:
    """Verify phys_base is resolved from ELF NT_FILE note kernel mapping."""
    nt_dump = dump_path("mock_elf_nt_file.bin")
    backend = X86_64TranslationBackend()
    with open(nt_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._phys_base != 0


def test_phys_base_unknown_logs_warning(
    dump_path: Callable[[str], Path],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify warning is logged when phys_base cannot be determined."""
    raw_dump = dump_path("mock_raw_dram.bin")
    backend = X86_64TranslationBackend()
    with open(raw_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._phys_base == 0
        assert "phys_base unknown" in caplog.text


def test_kpti_detected_from_fixture(dump_path: Callable[[str], Path]) -> None:
    """Verify KPTI dual-PGD configuration is detected from dump layout."""
    kpti_dump = dump_path("mock_kpti_dram.bin")
    backend = X86_64TranslationBackend()
    with open(kpti_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._kpti_enabled is True


def test_huge_page_still_resolves() -> None:
    """Verify 2MB huge-page PD entry (bit 7 set) resolves virtual address correctly."""
    backend = X86_64TranslationBackend()
    size = 4 * 1024 * 1024
    buf = bytearray(size)

    # CR3 at 0x1000
    # PML4 index 0 points to PDPT at 0x2000
    buf[0x1000 : 0x1008] = struct.pack("<Q", 0x2000 | 1)

    # PDPT at 0x2000: index 0 points to PD at 0x3000
    buf[0x2000 : 0x2008] = struct.pack("<Q", 0x3000 | 1)

    # PD at 0x3000: index 0 is a 2MB huge page (bit 7 set) pointing to 0x200000
    buf[0x3000 : 0x3008] = struct.pack("<Q", 0x200000 | 0x81)

    backend.initialize(io.BytesIO(buf))

    # vaddr offset 0x40 inside the 2MB huge page (0x0000000000000040)
    resolved = backend._walk_pml4(0x1000, 0x40)
    assert resolved == 0x200040


def test_direct_map_fast_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify GLOBAL_KERNEL direct-map reads bypass page walking."""
    backend = X86_64TranslationBackend()
    size = 64 * 1024
    buf = bytearray(size)

    # Write test payload at physical offset 0x2000
    buf[0x2000 : 0x2008] = b"FASTPATH"

    backend.initialize(io.BytesIO(buf))
    backend._phys_base = 0x1000
    backend._page_offset_base = 0xFFFF888000000000

    def mock_walk(*args: object, **kwargs: object) -> None:
        raise RuntimeError("page walk must not be called on direct map")

    monkeypatch.setattr(backend, "_walk_pml4", mock_walk)
    monkeypatch.setattr(backend, "_walk_pml5", mock_walk)

    # Virtual address 0xFFFF888000001000:
    # phys = 0xFFFF888000001000 - 0xFFFF888000000000 + 0x1000 = 0x2000
    data = backend.read_virtual("GLOBAL_KERNEL", 0xFFFF888000001000, 8)
    assert data == b"FASTPATH"


def test_kpti_kernel_cr3_promotion(dump_path: Callable[[str], Path]) -> None:
    """Verify GLOBAL_KERNEL namespace promotes CR3 to kernel CR3 when KPTI enabled."""
    kpti_dump = dump_path("mock_kpti_dram.bin")
    backend = X86_64TranslationBackend()
    with open(kpti_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._kpti_enabled is True
        assert backend._kernel_cr3 == 0x3000

        # Read with GLOBAL_KERNEL namespace (cr3 default is 0, should promote to 0x3000)
        data = backend.read_virtual("GLOBAL_KERNEL", 0xFFFF800000005000, 15)
        assert data == b"KPTI_KERNEL_OK!"


def test_walk_pml5_positive_and_read_virtual(dump_path: Callable[[str], Path]) -> None:
    """Verify _walk_pml5 and read_virtual resolve 5-level virtual addresses."""
    pml5_dump = dump_path("mock_pml5_dram.bin")
    backend = X86_64TranslationBackend()
    with open(pml5_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._pml5_enabled is True
        resolved = backend._walk_pml5(0x0, 0xFFFF800000000000)
        assert resolved == 0x600000
        data = backend.read_virtual("0x0", 0xFFFF800000000000, 8)
        assert data == b"\x00" * 8


def test_walk_pml5_rejects_non_canonical_and_oob() -> None:
    """Verify _walk_pml5 rejects non-canonical 57-bit VAs, unmapped entries, and OOB targets."""
    buf = bytearray(0x10000)
    struct.pack_into("<Q", buf, 0x1000 + 0 * 8, 0x2000 | 1)
    struct.pack_into("<Q", buf, 0x1000 + 256 * 8, 0x2000 | 1)
    struct.pack_into("<Q", buf, 0x2000, 0x3000 | 1)
    struct.pack_into("<Q", buf, 0x3000, 0x4000 | 1)
    struct.pack_into("<Q", buf, 0x4000, 0x5000 | 1)
    struct.pack_into("<Q", buf, 0x5000, 0x6000 | 1)

    backend = X86_64TranslationBackend()
    backend.initialize(io.BytesIO(buf), force_pml5=True)
    assert backend._pml5_enabled is True

    # Non-canonical bit 56 vs bits 57..63 mismatches and mid-range bits
    assert backend._walk_pml5(0x1000, 0x0100000000000000) is None
    assert backend._walk_pml5(0x1000, 0xFE00000000000000) is None
    assert backend._walk_pml5(0x1000, 0x1234000000000000) is None
    assert backend._walk_pml5(0x1000, -1) is None

    # Unmapped PML5 entry
    assert backend._walk_pml5(0x1000, 0x0001000000000000) is None

    # Out-of-bounds pml4_phys target
    struct.pack_into("<Q", buf, 0x1000 + 1 * 8, 0x90000000 | 1)
    backend.initialize(io.BytesIO(buf), force_pml5=True)
    assert backend._walk_pml5(0x1000, 0x0001000000000000) is None


def test_detect_pml5_inconclusive_logs_warning(
    dump_path: Callable[[str], Path],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify inconclusive PML5 heuristic fails open to PML4 with WARNING log."""
    caplog.set_level(logging.WARNING)
    pml4_dump = dump_path("mock_pml4_dram.bin")
    backend = X86_64TranslationBackend()
    with open(pml4_dump, "rb") as fh:
        backend.initialize(fh)
        assert backend._pml5_enabled is False
        assert "PML5 heuristic inconclusive" in caplog.text


def test_scan_phys_base_nt_file_dos_guard_and_pe_fallback() -> None:
    """Verify NT_FILE count bounds check prevents DoS and MZ/PE fallback resolves phys_base."""
    # Adversarial NT_FILE count = 0xFFFFFFFFFFFFFFFF must exit cleanly without hanging
    dos_buf = bytearray(0x4000)
    desc = struct.pack("<QQ", 0xFFFFFFFFFFFFFFFF, 0x1000)
    note = struct.pack("<III", 5, len(desc), 0x46494C45) + b"CORE\x00\x00\x00\x00" + desc
    dos_buf[0x100 : 0x100 + len(note)] = note

    backend = X86_64TranslationBackend()
    backend.initialize(io.BytesIO(dos_buf))
    assert backend._phys_base == 0

    # MZ/PE fallback at 2MB alignment (0x200000)
    pe_buf = bytearray(3 * 1024 * 1024)
    offset = 2 * 1024 * 1024
    pe_buf[offset : offset + 4] = b"MZ\x00\x00"
    struct.pack_into("<I", pe_buf, offset + 0x3C, 0x80)
    pe_buf[offset + 0x80 : offset + 0x84] = b"PE\x00\x00"

    backend_pe = X86_64TranslationBackend()
    backend_pe.initialize(io.BytesIO(pe_buf))
    assert backend_pe._phys_base == offset
