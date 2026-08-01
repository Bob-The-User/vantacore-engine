"""Input validation utilities for memory dumps and pointers."""

import hashlib
from pathlib import Path
import struct
from typing import Union


class InputValidator:
    """Static validation methods for ELF headers, program headers, pointers, and file hashing."""

    @staticmethod
    def validate_elf_header(data: bytes) -> None:
        """Validate ELF magic and header fields.

        Args:
            data: Binary bytes containing ELF header (at least 20 bytes).

        Raises:
            ValueError: If data is too short, lacks ELF magic, or is not ET_CORE (type 4).

        """
        if len(data) < 20:
            raise ValueError(f"Data too short for ELF header: {len(data)} bytes")
        if data[0:4] != b"\x7fELF":
            raise ValueError(f"Not an ELF file: magic={data[0:4].hex()}")
        e_type = struct.unpack_from("<H", data, 16)[0]
        if e_type != 4:
            raise ValueError(f"Not an ELF core file: e_type={e_type} (expected 4/ET_CORE)")

    @staticmethod
    def validate_phdr_bounds(phdr_offset: int, phdr_size: int, file_size: int) -> None:
        """Validate program header boundary against total file size.

        Args:
            phdr_offset: Byte offset where program header starts.
            phdr_size: Byte size of program header entry or table.
            file_size: Total file size in bytes.

        Raises:
            ValueError: If PHDR offset and size extend beyond EOF.

        """
        if phdr_offset + phdr_size > file_size:
            raise ValueError(
                f"PHDR extends past EOF: offset={phdr_offset} size={phdr_size} file_size={file_size}"
            )

    @staticmethod
    def validate_pointer(ptr_value: int, file_size: int) -> bool:
        """Check if pointer value resolves within physical file bounds.

        Args:
            ptr_value: Integer pointer value to validate.
            file_size: Total file size in bytes.

        Returns:
            True if 0 <= ptr_value < file_size, False otherwise.

        """
        return 0 <= ptr_value < file_size

    @staticmethod
    def compute_sha256(file_path: Union[str, Path]) -> str:
        """Compute SHA-256 hex digest of a file in 1MB chunks.

        Args:
            file_path: Target file path to digest.

        Returns:
            SHA-256 hex string digest of file contents.

        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()
