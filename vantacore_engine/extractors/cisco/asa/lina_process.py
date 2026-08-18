"""Lina process and thread table extractor for Cisco ASA appliances."""

from collections import deque
import logging
from pathlib import Path
import struct
from typing import BinaryIO, Optional

from elftools.elf.elffile import ELFFile

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_VERSION_PREFIX = b"Cisco Adaptive Security Appliance Software Version "
_MAX_NOTES = 256
_CHUNK_SIZE = 65536
_MAX_HOPS = 500_000


def _extract_printable(b: bytes) -> str:
    """Extract clean printable ASCII string from byte buffer up to first null.

    Args:
        b: Byte sequence.

    Returns:
        Clean ASCII string or empty string.

    """
    raw = b.split(b"\x00")[0]
    try:
        decoded = raw.decode("ascii", errors="ignore")
        return "".join(c for c in decoded if 32 <= ord(c) <= 126).strip()
    except Exception:
        return ""


def _parse_prpsinfo_note(desc: bytes) -> Optional[dict]:
    """Parse an ELF NT_PRPSINFO note payload for process and thread metadata.

    Args:
        desc: Note description byte buffer.

    Returns:
        Dictionary with pid, ppid, fname, and args if valid, else None.

    """
    if len(desc) < 136:
        return None

    try:
        pr_pid = struct.unpack_from("<i", desc, 24)[0]
        pr_ppid = struct.unpack_from("<i", desc, 28)[0]
        pr_fname = _extract_printable(desc[40:56])
        pr_psargs = _extract_printable(desc[56:136])

        name = pr_fname if pr_fname else "lina"
        return {
            "pid": pr_pid,
            "ppid": pr_ppid,
            "name": name,
            "args": pr_psargs,
        }
    except Exception:
        return None


def _detect_firmware_version(dump_handle: BinaryIO) -> str:
    """Scan first 64KB of memory dump for ASA firmware version string.

    Args:
        dump_handle: Open binary dump file handle.

    Returns:
        Firmware version string or 'unknown'.

    """
    dump_handle.seek(0)
    header_chunk = dump_handle.read(65536)
    idx = header_chunk.find(_VERSION_PREFIX)
    if idx != -1:
        start = idx + len(_VERSION_PREFIX)
        ver_bytes = header_chunk[start : start + 16]
        ver_str = _extract_printable(ver_bytes)
        if ver_str:
            return ver_str
    return "unknown"


class LinaProcessExtractor(BaseExtractor):
    """Extractor recovering Cisco ASA lina process and thread tables."""

    name = "cisco/asa/lina_process"
    compatible_platforms = ["cisco_asa"]
    dependencies: list[str] = []

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Extract lina threads from ELF PT_NOTE segments with text-pattern fallback.

        Args:
            backend: TranslationBackend instance.
            dump_handle: Open binary memory dump file handle.
            output_dir: Output directory path.

        Returns:
            Dictionary containing lina_threads list.

        """
        fw_version = _detect_firmware_version(dump_handle)
        threads: list[dict] = []
        parsed_elf = False

        dump_handle.seek(0)
        try:
            elf = ELFFile(dump_handle)
            note_queue: deque = deque(maxlen=_MAX_NOTES)

            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_NOTE" or segment.header.get("p_type") == 4:
                    for note in segment.iter_notes():
                        if note.n_type in (1, 3):  # NT_PRSTATUS or NT_PRPSINFO
                            parsed = _parse_prpsinfo_note(note.n_desc)
                            if parsed:
                                note_queue.append(parsed)

            if not note_queue:
                # Also try sections if segment parsing did not produce notes
                for section in elf.iter_sections():
                    if hasattr(section, "iter_notes"):
                        for note in section.iter_notes():
                            if note.n_type in (1, 3):
                                parsed = _parse_prpsinfo_note(note.n_desc)
                                if parsed:
                                    note_queue.append(parsed)

            for item in note_queue:
                threads.append(
                    {
                        "pid": item["pid"],
                        "ppid": item["ppid"],
                        "name": item["name"],
                        "args": item["args"],
                        "source": "elf_note",
                        "firmware_version": fw_version,
                        "struct_layout_version": "N/A",
                    }
                )
            if threads:
                parsed_elf = True

        except Exception as exc:
            logger.warning(
                "LinaProcessExtractor: ELF note parse failed (%s). Using text-pattern fallback.",
                exc,
            )

        if not parsed_elf:
            # Physical text-pattern fallback
            dump_handle.seek(0, 2)
            total_size = dump_handle.tell()
            dump_handle.seek(0)
            hops = 0
            seen_offsets: set[int] = set()

            while True:
                offset = dump_handle.tell()
                if offset >= total_size or hops >= _MAX_HOPS:
                    break

                chunk = dump_handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                hops += 1

                pos = 0
                while pos < len(chunk):
                    idx = chunk.find(b"lina\x00", pos)
                    if idx == -1:
                        break
                    phys_off = offset + idx
                    if phys_off not in seen_offsets:
                        seen_offsets.add(phys_off)
                        threads.append(
                            {
                                "pid": 0,
                                "ppid": 0,
                                "name": "lina",
                                "args": "",
                                "source": "pattern_scan",
                                "firmware_version": fw_version,
                                "struct_layout_version": "N/A",
                            }
                        )
                        if len(threads) >= _MAX_NOTES:
                            break
                    pos = idx + 5
                if len(threads) >= _MAX_NOTES:
                    break

        return {"lina_threads": threads}
