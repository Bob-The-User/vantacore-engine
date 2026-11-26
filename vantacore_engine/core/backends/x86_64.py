"""x86_64 physical-to-virtual translation backend with 4-level paging support."""

import logging
import struct
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import (
    PageFaultError,
    TranslationBackend,
)


logger = logging.getLogger(__name__)


class X86_64TranslationBackend(TranslationBackend):
    """Translation backend for x86_64 architecture using PML4 4-level page walking."""

    def __init__(self) -> None:
        """Initialize uninitialized x86_64 translation backend instance."""
        self._dump_handle: Optional[BinaryIO] = None
        self._file_size: int = 0
        self._kernel_base: int = 0xFFFF800000000000
        self._page_offset_base: int = 0xFFFF888000000000
        self._pml5_enabled: bool = False
        self._phys_base: int = 0
        self._kpti_enabled: bool = False
        self._kernel_cr3: int = 0
        self._detected_cr3_phys: int = 0
        self._kaslr_detected: bool = False

    def detect(self, dump_handle: BinaryIO) -> bool:
        """Detect if the memory dump is an x86_64 image.

        Args:
            dump_handle: Open file-like handle to binary memory dump.

        Returns:
            True if dump has x86_64 ELF headers or fits raw DRAM size threshold.

        """
        dump_handle.seek(0, 2)
        file_size = dump_handle.tell()
        dump_handle.seek(0)

        data = dump_handle.read(20)
        dump_handle.seek(0)

        if len(data) >= 18 and data[0:4] == b"\x7fELF":
            is_64bit = data[4] == 2
            e_machine = struct.unpack_from("<H", data, 18)[0]
            return is_64bit and e_machine == 62

        return file_size >= 67108864

    def initialize(
        self,
        dump_handle: BinaryIO,
        swap_path: Optional[str] = None,
        force_pml5: bool = False,
    ) -> None:
        """Initialize backend state and execute KASLR/PML5/KPTI scans.

        Args:
            dump_handle: Open file-like handle to binary memory dump.
            swap_path: Optional path to a swap image.
            force_pml5: If True, force PML5 5-level paging.

        """
        self._dump_handle = dump_handle
        dump_handle.seek(0, 2)
        self._file_size = dump_handle.tell()
        dump_handle.seek(0)
        self._kaslr_detected = False

        self._scan_kaslr_base()
        self._scan_phys_base()
        self._scan_page_offset_base()
        self._detect_pml5(force_pml5)
        self._detect_kpti()

        logger.info(
            "Initialized X86_64TranslationBackend (kernel_base: 0x%x, size: %d)",
            self._kernel_base,
            self._file_size,
        )

    def _scan_kaslr_base(self) -> None:
        """Scan lower 2GB of physical memory for IDT descriptor to detect KASLR kernel base."""
        if self._dump_handle is None:
            return

        scan_limit = min(2 * 1024 * 1024 * 1024, self._file_size)
        offset = 0
        found = False

        while offset < scan_limit:
            self._dump_handle.seek(offset)
            data = self._dump_handle.read(10)
            if len(data) == 10:
                limit = struct.unpack_from("<H", data, 0)[0]
                if 0x0100 <= limit <= 0x0FFF:
                    base = struct.unpack_from("<Q", data, 2)[0]
                    if base >= 0xFFFF800000000000:
                        self._kernel_base = base & ~0xFFF
                        self._detected_cr3_phys = offset
                        self._kaslr_detected = True
                        logger.info("KASLR: kernel base detected at 0x%x", self._kernel_base)
                        found = True
                        break
            offset += 0x1000

        if not found:
            logger.warning(
                "KASLR: IDT/GDT scan failed. Falling back to default page_offset_base 0xffff888000000000."
            )

        self._dump_handle.seek(0)

    def _read_phys_u64(self, phys_offset: int) -> int:
        """Read 8-byte unsigned integer from physical offset.

        Args:
            phys_offset: Physical byte offset in memory dump.

        Returns:
            Unsigned 64-bit integer, or 0 if offset is out of bounds or read fails.

        """
        if self._dump_handle is None or phys_offset < 0 or phys_offset + 8 > self._file_size:
            return 0

        self._dump_handle.seek(phys_offset)
        buf = self._dump_handle.read(8)
        if len(buf) < 8:
            return 0
        return struct.unpack("<Q", buf)[0]

    def _detect_pml5(self, force_pml5: bool = False) -> None:
        """Detect whether 5-level paging (PML5) is active or force it via flag.

        Args:
            force_pml5: If True, override heuristic detection and force PML5 mode.

        """
        if force_pml5:
            self._pml5_enabled = True
            logger.info("PML5 forced by --force-pml5 flag")
            return

        if self._dump_handle is None:
            self._pml5_enabled = False
            return

        scan_limit = min(2 * 1024 * 1024 * 1024, self._file_size)
        candidates_found = 0
        pages_checked = 0
        offset = 0

        while offset < scan_limit and pages_checked < 256:
            entry = self._read_phys_u64(offset + 511 * 8)
            if entry & 1:
                target_phys = entry & 0x000FFFFFFFFFF000
                if 0 <= target_phys < self._file_size:
                    candidates_found += 1
            pages_checked += 1
            offset += 0x1000

        if candidates_found >= 3:
            self._pml5_enabled = True
            logger.info("PML5 5-level paging detected")
        else:
            self._pml5_enabled = False
            logger.warning("PML4 4-level paging assumed (PML5 heuristic inconclusive)")

    def _walk_pml5(self, cr3: int, vaddr: int) -> Optional[int]:
        """Perform 5-level PML5 page table walk.

        Args:
            cr3: Control Register 3 value (page directory base address).
            vaddr: Virtual address to translate.

        Returns:
            Resolved physical address, or None if translation fails or unmapped.

        """
        if vaddr < 0 or vaddr >= (1 << 64):
            return None

        top_byte = (vaddr >> 56) & 0xFF
        if top_byte not in (0x00, 0xFF):
            return None

        pml5i = (vaddr >> 48) & 0x1FF
        cr3_masked = cr3 & 0xFFFFFFFFFFFFF000
        entry = self._read_phys_u64(cr3_masked + pml5i * 8)
        if not (entry & 1):
            return None

        pml4_phys = entry & 0x000FFFFFFFFFF000
        if pml4_phys >= self._file_size:
            return None

        return self._walk_pml4(pml4_phys, vaddr)

    def _scan_phys_base(self) -> None:
        """Scan physical base address via ELF NT_FILE note or kernel image header."""
        if self._dump_handle is None:
            return

        # 1. ELF NT_FILE path: Read first 4MB of dump
        scan_limit = min(4 * 1024 * 1024, self._file_size)
        self._dump_handle.seek(0)
        header_buf = self._dump_handle.read(scan_limit)

        pos = 0
        while pos < len(header_buf) - 16:
            idx = header_buf.find(b"CORE", pos)
            if idx == -1:
                break
            if idx % 4 == 0 and idx >= 12:
                note_type = struct.unpack_from("<I", header_buf, idx - 4)[0]
                if note_type == 0x46494C45:  # NT_FILE
                    desc_offset = idx + 8
                    if desc_offset + 16 <= len(header_buf):
                        count = struct.unpack_from("<Q", header_buf, desc_offset)[0]
                        page_size = struct.unpack_from("<Q", header_buf, desc_offset + 8)[0]
                        triplets_offset = desc_offset + 16
                        strings_offset = triplets_offset + count * 24

                        if (
                            0 < count <= 4096
                            and 0 < page_size <= 0x40000000
                            and strings_offset <= len(header_buf)
                        ):
                            for _ in range(count):
                                if (
                                    triplets_offset + 24 > len(header_buf)
                                    or strings_offset >= len(header_buf)
                                ):
                                    break
                                start_va, _, file_offset = struct.unpack_from(
                                    "<QQQ", header_buf, triplets_offset
                                )
                                end_null = header_buf.find(b"\x00", strings_offset)
                                if end_null == -1:
                                    break
                                filename = header_buf[strings_offset:end_null].decode(
                                    "latin-1", errors="ignore"
                                )
                                strings_offset = end_null + 1
                                if (
                                    "kernel" in filename.lower()
                                    or "vmlinux" in filename.lower()
                                ) and start_va >= 0xFFFFFFFF80000000:
                                    candidate_phys = file_offset * page_size
                                    if 0 < candidate_phys <= 4 * 1024 * 1024 * 1024:
                                        self._phys_base = candidate_phys
                                        logger.info(
                                            "phys_base: 0x%x (from NT_FILE)", self._phys_base
                                        )
                                        return
                                triplets_offset += 24
            pos = idx + 4

        # 2. Kernel image header fallback: scan 2MB-aligned physical offsets up to min(4GB, _file_size)
        scan_cap = min(4 * 1024 * 1024 * 1024, self._file_size)
        offset = 0
        while offset < scan_cap:
            self._dump_handle.seek(offset)
            hdr = self._dump_handle.read(4)
            if len(hdr) == 4 and hdr[:2] == b"MZ" and hdr[2:4] == b"\x00\x00":
                if offset + 0x3C + 4 <= self._file_size:
                    self._dump_handle.seek(offset + 0x3C)
                    pe_raw = self._dump_handle.read(4)
                    if len(pe_raw) == 4:
                        pe_offset = struct.unpack("<I", pe_raw)[0]
                        if offset + pe_offset + 4 <= self._file_size:
                            self._dump_handle.seek(offset + pe_offset)
                            sig = self._dump_handle.read(4)
                            if sig == b"PE\x00\x00":
                                self._phys_base = offset
                                logger.info(
                                    "phys_base: 0x%x (from kernel image header)",
                                    self._phys_base,
                                )
                                return
            offset += 2 * 1024 * 1024

        self._phys_base = 0
        logger.warning(
            "phys_base unknown; physical KASLR slide not resolved. "
            "Virtual→physical translation for kernel text addresses may be incorrect."
        )

    def _scan_page_offset_base(self) -> None:
        """Scan candidate page_offset_base addresses for direct mapping."""
        if self._phys_base == 0:
            logger.warning("page_offset_base scan skipped: phys_base unknown")
            self._page_offset_base = 0xFFFF888000000000
            return

        for i in range(14):
            c = 0xFFFF880000000000 + (i * 0x40000000)
            phys_page = c - self._phys_base
            if phys_page < 0 or phys_page + 8 > self._file_size:
                continue
            val = self._read_phys_u64(phys_page)
            if (val & (1 << 63)) and val != 0:
                self._page_offset_base = c
                logger.info("page_offset_base: 0x%x", self._page_offset_base)
                return

        self._page_offset_base = 0xFFFF888000000000
        logger.warning(
            "page_offset_base could not be determined; using default 0xffff888000000000"
        )

    def _detect_kpti(self) -> None:
        """Detect KPTI dual-PGD configuration."""
        if not self._kaslr_detected:
            self._kpti_enabled = False
            logger.info("KPTI not detected")
            return

        user_cr3_phys = self._detected_cr3_phys
        candidate_kernel_cr3 = user_cr3_phys + 0x1000
        if candidate_kernel_cr3 + 8 > self._file_size:
            self._kpti_enabled = False
            logger.info("KPTI not detected")
            return

        entry = self._read_phys_u64(candidate_kernel_cr3 + 511 * 8)
        if entry & 1:
            addr = entry & 0x000FFFFFFFFFF000
            if 0 <= addr < self._file_size:
                self._kpti_enabled = True
                self._kernel_cr3 = candidate_kernel_cr3
                logger.info("KPTI dual-PGD detected (kernel CR3 phys = 0x%x)", self._kernel_cr3)
                return

        self._kpti_enabled = False
        logger.info("KPTI not detected")

    def _walk_pml4(self, cr3: int, vaddr: int) -> Optional[int]:
        """Perform iterative 4-level PML4 page table walk.

        Args:
            cr3: Control Register 3 value (page directory base address).
            vaddr: Virtual address to translate.

        Returns:
            Resolved physical address, or None if translation fails or unmapped.

        """
        cr3_masked = cr3 & 0xFFFFFFFFFFFFF000

        pml4i = (vaddr >> 39) & 0x1FF
        pdpti = (vaddr >> 30) & 0x1FF
        pdi = (vaddr >> 21) & 0x1FF
        pti = (vaddr >> 12) & 0x1FF
        page_off = vaddr & 0xFFF

        # Level 1: PML4
        entry = self._read_phys_u64(cr3_masked + pml4i * 8)
        if not (entry & 1):
            return None
        pdpt_phys = entry & 0x000FFFFFFFFFF000

        # Level 2: PDPT
        entry = self._read_phys_u64(pdpt_phys + pdpti * 8)
        if not (entry & 1):
            return None
        pd_phys = entry & 0x000FFFFFFFFFF000

        # Level 3: PD
        entry = self._read_phys_u64(pd_phys + pdi * 8)
        if not (entry & 1):
            return None
        if entry & (1 << 7):
            resolved = (entry & 0x000FFFFFFFE00000) + (vaddr & 0x1FFFFF)
            if resolved >= self._file_size:
                return None
            return resolved
        pt_phys = entry & 0x000FFFFFFFFFF000

        # Level 4: PT
        entry = self._read_phys_u64(pt_phys + pti * 8)
        if not (entry & 1):
            return None
        page_phys = entry & 0x000FFFFFFFFFF000

        resolved = page_phys + page_off
        if resolved >= self._file_size:
            return None
        return resolved

    def read_virtual(self, namespace_id: str, virtual_address: int, length: int) -> bytes:
        """Read virtual memory bytes across pages using PML4/PML5 page walking.

        Args:
            namespace_id: CR3 hex string or 'GLOBAL_KERNEL'.
            virtual_address: Starting virtual address.
            length: Number of bytes to read.

        Returns:
            Bytes object of length bytes. Unmapped regions are zero-filled.

        Raises:
            PageFaultError: If no pages could be resolved.

        """
        if self._dump_handle is None:
            raise PageFaultError("X86_64TranslationBackend is not initialized")

        # Check 1 — GLOBAL_KERNEL direct-map fast-path
        if (
            namespace_id == "GLOBAL_KERNEL"
            and virtual_address >= self._page_offset_base
            and self._phys_base != 0
        ):
            phys = virtual_address - self._page_offset_base + self._phys_base
            if 0 <= phys and phys + length <= self._file_size:
                self._dump_handle.seek(phys)
                read_bytes = self._dump_handle.read(length)
                if len(read_bytes) == length:
                    return read_bytes

        try:
            cr3 = int(namespace_id, 16) if namespace_id.startswith("0x") else 0
        except ValueError:
            cr3 = 0

        # Check 3 — KPTI kernel-CR3 promotion
        if self._kpti_enabled and namespace_id == "GLOBAL_KERNEL" and cr3 != self._kernel_cr3:
            cr3 = self._kernel_cr3

        result = bytearray()
        bytes_left = length
        curr_vaddr = virtual_address
        resolved_pages = 0
        total_pages = 0

        while bytes_left > 0:
            total_pages += 1
            page_off = curr_vaddr & 0xFFF
            chunk_len = min(bytes_left, 0x1000 - page_off)

            # Check 2 — PML5 dispatch
            if self._pml5_enabled:
                phys = self._walk_pml5(cr3, curr_vaddr)
            else:
                phys = self._walk_pml4(cr3, curr_vaddr)

            if phys is None:
                result.extend(b"\x00" * chunk_len)
            else:
                resolved_pages += 1
                self._dump_handle.seek(phys)
                read_bytes = self._dump_handle.read(chunk_len)
                result.extend(read_bytes)
                if len(read_bytes) < chunk_len:
                    result.extend(b"\x00" * (chunk_len - len(read_bytes)))

            curr_vaddr += chunk_len
            bytes_left -= chunk_len

        if resolved_pages == 0:
            raise PageFaultError(
                f"Page fault: 0 of {total_pages} pages resolved for vaddr 0x{virtual_address:x}"
            )

        return bytes(result)

    def enumerate_processes(self) -> list[tuple[str, str, int]]:
        """Enumerate active processes found in memory image.

        Returns:
            List containing placeholder tuple for global kernel context.

        """
        return [("GLOBAL_KERNEL", "unknown", 0)]

    def get_kernel_base(self) -> int:
        """Get calculated kernel virtual base address.

        Returns:
            Kernel base address integer.

        """
        return self._kernel_base

    def get_architecture_name(self) -> str:
        """Get architecture string identifier.

        Returns:
            String 'x86_64'.

        """
        return "x86_64"
