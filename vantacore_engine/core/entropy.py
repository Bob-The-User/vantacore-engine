"""Encrypted memory detection using Shannon entropy and ELF MSR notes."""

import logging
import struct
from typing import BinaryIO, Any
import numpy as np

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

logger = logging.getLogger(__name__)


class EncryptedMemoryDetector:
    """Detects whole-image or region encryption in memory dumps."""

    def detect(self, dump_handle: BinaryIO, file_size: int) -> dict[str, Any]:
        """Detect whether memory dump is likely encrypted via entropy and MSR note analysis.

        Args:
            dump_handle: Open binary file handle to the memory dump.
            file_size: Size of the dump file in bytes.

        Returns:
            Dictionary with keys 'likely_encrypted' (bool), 'confidence' (float),
            and 'evidence' (list of strings).

        """
        evidence: list[str] = []
        if file_size < 4096:
            return {
                "likely_encrypted": False,
                "confidence": 0.0,
                "evidence": evidence,
            }

        step = max(file_size // 64, 4096)
        high_entropy_count = 0
        total_sampled_pages = 0

        for i in range(64):
            page_offset = (i * step) & ~0xFFF
            if page_offset + 4096 > file_size:
                continue

            dump_handle.seek(page_offset)
            page = dump_handle.read(4096)
            if len(page) < 4096:
                continue

            total_sampled_pages += 1
            arr = np.frombuffer(page, dtype=np.uint8)
            counts = np.bincount(arr, minlength=256)
            probs = counts[counts > 0] / 4096.0
            shannon_entropy = -float(np.sum(probs * np.log2(probs)))

            if shannon_entropy > 7.9:
                high_entropy_count += 1

        confidence = (
            float(high_entropy_count / total_sampled_pages)
            if total_sampled_pages > 0
            else 0.0
        )
        likely_encrypted = confidence >= 0.75

        # Check ELF MSR notes if applicable
        if file_size >= 4:
            dump_handle.seek(0)
            magic = dump_handle.read(4)
            if magic == b"\x7fELF" and HAS_ELFTOOLS:
                try:
                    dump_handle.seek(0)
                    elf = ELFFile(dump_handle)
                    for section in elf.iter_sections():
                        if hasattr(section, "iter_notes"):
                            for note in section.iter_notes():
                                name = note.n_name
                                if isinstance(name, bytes):
                                    name_str = name.decode("utf-8", errors="ignore")
                                else:
                                    name_str = str(name)

                                if name_str in ("LINUX", "CORE") and note.n_type == 0x202:
                                    note_data = note.n_desc
                                    offset = 0
                                    while offset + 12 <= len(note_data):
                                        msr_idx, msr_val = struct.unpack_from("<IQ", note_data, offset)
                                        offset += 12
                                        if msr_idx == 0xC0010131 and (msr_val & 1):
                                            evidence.append("AMD SEV active (MSR 0xC0010131 bit 0 set)")
                                        elif msr_idx == 0x982 and (msr_val & 1):
                                            evidence.append("Intel TME active (MSR 0x982 bit 0 set)")
                except Exception as e:
                    logger.debug("Failed parsing ELF MSR notes: %s", e)

        if likely_encrypted:
            logger.critical(
                "Memory dump appears to be encrypted (confidence %.2f). Diagnostic analysis may fail.",
                confidence,
            )

        return {
            "likely_encrypted": likely_encrypted,
            "confidence": confidence,
            "evidence": evidence,
        }
