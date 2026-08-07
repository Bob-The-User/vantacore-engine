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
