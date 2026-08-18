"""Unit tests for encrypted memory detector MSR note branch coverage."""

import os
from pathlib import Path
from typing import Callable

from vantacore_engine.core.entropy import EncryptedMemoryDetector


def test_entropy_msr_note_parsing(dump_path: Callable[[str], Path]) -> None:
    """Verify EncryptedMemoryDetector parses ELF NT_X86_MSR notes without error."""
    msr_dump = dump_path("mock_elf_msr_note.bin")
    assert os.path.exists(msr_dump) is True

    file_size = os.path.getsize(msr_dump)
    detector = EncryptedMemoryDetector()

    with open(msr_dump, "rb") as fh:
        magic = fh.read(4)
        assert magic == b"\x7fELF"

        result = detector.detect(fh, file_size)
        assert isinstance(result, dict)
        assert "likely_encrypted" in result
        assert "confidence" in result
        assert "evidence" in result


def test_malformed_note_triggers_except() -> None:
    """Verify malformed ELF note section triggers except branch and is handled gracefully."""
    import io
    import struct

    # Construct minimal 64-bit ELF with a note section that raises error on parsing
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 4)      # ET_CORE
    e_machine = struct.pack("<H", 62)  # EM_X86_64
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0)
    e_phoff = struct.pack("<Q", 64)
    e_shoff = struct.pack("<Q", 120)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 0)
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 2)     # NULL + NOTE section
    e_shstrndx = struct.pack("<H", 0)

    elf_header = (
        e_ident + e_type + e_machine + e_version + e_entry + e_phoff + e_shoff
        + e_flags + e_ehsize + e_phentsize + e_phnum + e_shentsize + e_shnum + e_shstrndx
    )

    # Section 0: NULL
    shdr0 = b"\x00" * 64
    # Section 1: SHT_NOTE (sh_type=7, sh_offset=248, sh_size=8, corrupted note header)
    shdr1 = struct.pack("<IIQQQQIIQQ", 0, 7, 0, 0, 248, 8, 0, 0, 4, 0)
    # Note payload: only 8 bytes (incomplete note header since header is 12 bytes)
    corrupted_payload = b"\x05\x00\x00\x00\x02\x00\x00\x00"

    buf = elf_header + shdr0 + shdr1 + corrupted_payload
    fh = io.BytesIO(buf)

    detector = EncryptedMemoryDetector()
    result = detector.detect(fh, len(buf))
    assert isinstance(result, dict)
    assert "likely_encrypted" in result

