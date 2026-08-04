"""Cisco Adaptive Security Appliance (ASA) memory image detector."""

import logging
import struct
from typing import BinaryIO, Type

from elftools.elf.elffile import ELFFile

from vantacore_engine.core.backends.appliances.base_appliance import BaseApplianceDetector
from vantacore_engine.core.backends.x86_64 import X86_64TranslationBackend
from vantacore_engine.core.translation_base import TranslationBackend

logger = logging.getLogger(__name__)


class CiscoASADetector(BaseApplianceDetector):
    """Detector for Cisco ASA memory dumps (specifically lina process ELF64 coredumps)."""

    def platform_name(self) -> str:
        """Get the unique string identifier for Cisco ASA.

        Returns:
            String 'cisco_asa'.

        """
        return "cisco_asa"

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
        """Calculate confidence score for Cisco ASA platform.

        Args:
            dump_handle: Open file-like handle to binary dump.
            file_size: Size of memory dump in bytes.

        Returns:
            Confidence score float between 0.0 and 1.0.

        """
        dump_handle.seek(0)
        data = dump_handle.read(18)
        dump_handle.seek(0)

        if len(data) < 5 or data[0:4] != b"\x7fELF" or data[4] != 2:
            return 0.0

        score = 0.0

        e_type = struct.unpack_from("<H", data, 16)[0]
        if e_type == 4:  # ET_CORE
            score += 0.30

        try:
            dump_handle.seek(0)
            elf = ELFFile(dump_handle)
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_NOTE":
                    for note in segment.iter_notes():
                        n_type = note["n_type"]
                        if n_type == 3 or n_type == "NT_PRPSINFO":
                            desc = note["n_desc"]
                            pr_fname = b""
                            if isinstance(desc, (bytes, bytearray)):
                                if len(desc) >= 44:
                                    pr_fname = desc[40:56]
                            elif hasattr(desc, "get") or hasattr(desc, "__getitem__"):
                                try:
                                    pr_fname = desc["pr_fname"]
                                except Exception:
                                    pass

                            if isinstance(pr_fname, (bytes, bytearray)) and pr_fname.startswith(b"lina"):
                                score += 0.65
                                break
        except Exception as err:
            logger.debug("CiscoASADetector ELF note parsing exception: %s", err)


        scan_limit = min(file_size, 64 * 1024 * 1024)
        if self._scan_bytes(dump_handle, b"Cisco Adaptive Security Appliance", scan_limit):
            score += 0.50
        elif self._scan_bytes(dump_handle, b"Cisco ASA", scan_limit):
            score += 0.30

        dump_handle.seek(0)
        return min(score, 1.0)

    def get_translation_backend_class(self) -> Type[TranslationBackend]:
        """Get translation backend class for Cisco ASA.

        Returns:
            X86_64TranslationBackend class.

        """
        return X86_64TranslationBackend

    def get_compatible_extractor_paths(self) -> list[str]:
        """Get compatible extractor paths for Cisco ASA.

        Returns:
            List of extractor path strings.

        """
        return ["generic", "linux", "cisco/common", "cisco/asa"]

    def get_platform_metadata(self) -> dict:
        """Get metadata for Cisco ASA platform.

        Returns:
            Dictionary with dump_type indicator.

        """
        return {"dump_type": "lina_elf64_coredump"}
