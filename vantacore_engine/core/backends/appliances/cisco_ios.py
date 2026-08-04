"""Cisco IOS Classic platform detector."""

import logging
from typing import BinaryIO, Type

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector
from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.translation_base import TranslationBackend

logger = logging.getLogger(__name__)


class CiscoIOSDetector(BaseApplianceDetector):
    """Detector for Cisco IOS Classic memory images."""

    def platform_name(self) -> str:
        """Get unique platform identifier string for Cisco IOS.

        Returns:
            String 'cisco_ios'.

        """
        return "cisco_ios"

    def _scan_bytes(
        self, dump_handle: BinaryIO, pattern: bytes, max_bytes: int, chunk_size: int = 4 * 1024 * 1024
    ) -> bool:
        """Scan binary dump in chunks up to max_bytes for pattern using bytes.find().

        Args:
            dump_handle: Open file-like handle to binary dump.
            pattern: Byte pattern to search for.
            max_bytes: Maximum number of bytes to read.
            chunk_size: Size of chunk buffer.

        Returns:
            True if pattern is found, False otherwise.

        """
        dump_handle.seek(0)
        read_total = 0
        overlap = len(pattern) - 1

        while read_total < max_bytes:
            to_read = min(chunk_size, max_bytes - read_total)
            chunk = dump_handle.read(to_read)
            if not chunk:
                break
            if chunk.find(pattern) != -1:
                dump_handle.seek(0)
                return True
            read_total += len(chunk)
            if len(chunk) == chunk_size and overlap > 0:
                dump_handle.seek(dump_handle.tell() - overlap)
                read_total -= overlap

        dump_handle.seek(0)
        return False

    def detect(self, dump_handle: BinaryIO, file_size: int) -> float:
        """Calculate confidence score for Cisco IOS Classic platform.

        Args:
            dump_handle: Open file-like handle to binary dump.
            file_size: Size of memory dump in bytes.

        Returns:
            Confidence score float between 0.0 and 1.0.

        """
        dump_handle.seek(0)
        magic = dump_handle.read(4)
        dump_handle.seek(0)

        score = 0.0
        scan_limit = min(file_size, 32 * 1024 * 1024)

        if self._scan_bytes(dump_handle, b"Cisco IOS Software", scan_limit):
            score += 0.80

        if self._scan_bytes(dump_handle, b"IOS (tm)", scan_limit):
            score += 0.60

        if magic != b"\x7fELF" and score > 0.0:
            score += 0.10

        dump_handle.seek(0)
        return min(score, 1.0)

    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Get translation backend class for Cisco IOS.

        Returns:
            FlatImageBackend class.

        """
        return FlatImageBackend

    def get_compatible_extractor_paths(self) -> list[str]:
        """Get compatible extractor paths for Cisco IOS.

        Returns:
            List of extractor path strings.

        """
        return ["generic", "cisco/common", "cisco/ios"]
