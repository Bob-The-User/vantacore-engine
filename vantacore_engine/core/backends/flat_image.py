"""Flat binary memory translation backend for non-paged memory images."""

import logging
from typing import BinaryIO, Optional


from vantacore_engine.core.translation_base import (
    PageFaultError,
    TranslationBackend,
)

logger = logging.getLogger(__name__)


class FlatImageBackend(TranslationBackend):
    """Translation backend for raw, identity-mapped, or flat memory dumps."""

    def __init__(self) -> None:
        """Initialize unitialized flat image backend instance."""
        self._dump_handle: Optional[BinaryIO] = None
        self._file_size: int = 0

    def detect(self, dump_handle: BinaryIO) -> bool:
        """Detect if the memory dump is a flat image (non-ELF).

        Args:
            dump_handle: Open file-like handle to the binary memory dump.

        Returns:
            True if the dump does not start with ELF magic, False otherwise.

        """
        dump_handle.seek(0)
        magic = dump_handle.read(4)
        dump_handle.seek(0)
        return magic != b"\x7fELF"

    def initialize(self, dump_handle: BinaryIO, swap_path: Optional[str] = None) -> None:
        """Initialize the flat image backend with an open dump handle.

        Args:
            dump_handle: Open file-like handle to the binary memory dump.
            swap_path: Optional swap file path (unused for flat image).

        """
        self._dump_handle = dump_handle
        dump_handle.seek(0, 2)
        self._file_size = dump_handle.tell()
        dump_handle.seek(0)
        logger.info("Initialized FlatImageBackend with file size %d bytes", self._file_size)

    def read_virtual(self, namespace_id: str, virtual_address: int, length: int) -> bytes:
        """Read virtual (identity-mapped) memory bytes from flat image.

        Args:
            namespace_id: Identifier for address space (ignored for flat images).
            virtual_address: Byte offset in flat image.
            length: Number of bytes to read.

        Returns:
            Bytes object of length bytes. Unresolvable trailing regions are zero-filled.

        Raises:
            PageFaultError: If virtual_address is at or beyond the file size limit.

        """
        if self._dump_handle is None:
            raise PageFaultError("FlatImageBackend is not initialized")

        if virtual_address >= self._file_size:
            raise PageFaultError(
                f"Virtual address 0x{virtual_address:x} is beyond flat image size"
            )

        if virtual_address + length <= self._file_size:
            self._dump_handle.seek(virtual_address)
            return self._dump_handle.read(length)

        available = self._file_size - virtual_address
        self._dump_handle.seek(virtual_address)
        data = self._dump_handle.read(available)
        return data + b"\x00" * (length - available)

    def enumerate_processes(self) -> list[tuple[str, str, int]]:
        """Enumerate processes in flat image context.

        Returns:
            List containing a single placeholder tuple for flat physical memory.

        """
        return [("FLAT_PHYSICAL", "unknown", 0)]

    def get_kernel_base(self) -> int:
        """Get the kernel base address.

        Returns:
            Always 0 for flat physical memory images.

        """
        return 0

    def get_architecture_name(self) -> str:
        """Get target architecture name string.

        Returns:
            Architecture string identifier 'flat'.

        """
        return "flat"
