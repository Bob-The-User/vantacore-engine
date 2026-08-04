"""Cisco IOS XE platform detector."""

import logging
from typing import BinaryIO, Type

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector
from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import TranslationBackend

logger = logging.getLogger(__name__)


class CiscoIOSXEDetector(BaseApplianceDetector):
    """Detector for Cisco IOS XE Linux-based memory dumps."""

    def platform_name(self) -> str:
        """Get unique platform identifier string for Cisco IOS XE.

        Returns:
            String 'cisco_iosxe'.

        """
        return "cisco_iosxe"

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
        """Calculate confidence score for Cisco IOS XE platform.

        Args:
            dump_handle: Open file-like handle to binary dump.
            file_size: Size of memory dump in bytes.

        Returns:
            Confidence score float between 0.0 and 1.0.

        """
        dump_handle.seek(0)
        magic = dump_handle.read(4)
        dump_handle.seek(0)

        if magic != b"\x7fELF":
            return 0.0

        score = 0.0
        scan_limit = min(file_size, 64 * 1024 * 1024)

        if self._scan_bytes(dump_handle, b"Cisco IOS XE Software", scan_limit):
            score += 0.80

        if self._scan_bytes(dump_handle, b"IOSd", scan_limit):
            score += 0.50

        if self._scan_bytes(dump_handle, b"Linux version", scan_limit):
            score += 0.20

        dump_handle.seek(0)
        return min(score, 1.0)

    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Get translation backend class for Cisco IOS XE.

        Returns:
            X86_64TranslationBackend class.

        """
        return X86_64TranslationBackend

    def get_compatible_extractor_paths(self) -> list[str]:
        """Get compatible extractor paths for Cisco IOS XE.

        Returns:
            List of extractor path strings.

        """
        return ["generic", "linux", "cisco/common", "cisco/ios"]
