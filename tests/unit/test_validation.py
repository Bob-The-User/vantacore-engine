"""Unit tests for InputValidator and decompression utilities."""

import hashlib
from pathlib import Path
import struct
import pytest
from vantacore_engine.utils.decompression import (
    decompress_lzo,
    decompress_lz4,
    decompress_zstd,
)
from vantacore_engine.utils.validation import InputValidator


def test_validate_elf_header_valid() -> None:
    """Verify valid ELF64 core header bytes pass validation."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    struct.pack_into("<H", header, 16, 4)  # ET_CORE = 4
    InputValidator.validate_elf_header(bytes(header))


def test_validate_elf_header_short_data() -> None:
    """Verify ValueError is raised if header data is too short."""
    with pytest.raises(ValueError, match="too short"):
        InputValidator.validate_elf_header(b"\x7fELF")


def test_validate_elf_header_invalid_magic() -> None:
    """Verify ValueError is raised if magic bytes are not ELF."""
    header = bytearray(32)
    header[0:4] = b"JFIF"
    with pytest.raises(ValueError, match="Not an ELF file"):
        InputValidator.validate_elf_header(bytes(header))


def test_validate_elf_header_invalid_etype() -> None:
    """Verify ValueError is raised if e_type is ET_EXEC (2) instead of ET_CORE (4)."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    struct.pack_into("<H", header, 16, 2)  # ET_EXEC
    with pytest.raises(ValueError, match="Not an ELF core file"):
        InputValidator.validate_elf_header(bytes(header))


def test_validate_phdr_bounds() -> None:
    """Verify phdr bounds checking logic."""
    InputValidator.validate_phdr_bounds(100, 50, 200)

    with pytest.raises(ValueError, match="PHDR extends past EOF"):
        InputValidator.validate_phdr_bounds(100, 150, 200)


def test_validate_pointer() -> None:
    """Verify pointer range checking logic."""
    assert InputValidator.validate_pointer(0, 1024)
    assert InputValidator.validate_pointer(1023, 1024)
    assert not InputValidator.validate_pointer(1024, 1024)
    assert not InputValidator.validate_pointer(-1, 1024)
    assert not InputValidator.validate_pointer(0, 0)


def test_compute_sha256(tmp_output_dir: Path) -> None:
    """Verify SHA-256 calculation accuracy and idempotency."""
    test_file = tmp_output_dir / "sample.bin"
    content = b"\x01" * 16
    test_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()

    digest1 = InputValidator.compute_sha256(test_file)
    digest2 = InputValidator.compute_sha256(test_file)

    assert digest1 == expected_hash
    assert digest2 == expected_hash


def test_decompression_utilities() -> None:
    """Verify LZ4, ZSTD decompression and LZO stub error handling."""
    raw = b"Hello VantaCore Forensics Memory Analysis"
    import lz4.frame
    import zstandard as zstd

    lz4_comp = lz4.frame.compress(raw)
    assert decompress_lz4(lz4_comp) == raw

    cctx = zstd.ZstdCompressor()
    zstd_comp = cctx.compress(raw)
    assert decompress_zstd(zstd_comp) == raw

    with pytest.raises(NotImplementedError, match="LZO decompression requires a ctypes binding"):
        decompress_lzo(b"\x00" * 8)
