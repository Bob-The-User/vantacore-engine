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

    def initialize(self, dump_handle: BinaryIO, swap_path: Optional[str] = None) -> None:
        """Initialize backend state and execute KASLR IDT/GDT scan.

        Args:
            dump_handle: Open file-like handle to binary memory dump.
            swap_path: Optional path to a swap image.

        """
        self._dump_handle = dump_handle
        dump_handle.seek(0, 2)
        self._file_size = dump_handle.tell()
        dump_handle.seek(0)

        self._scan_kaslr_base()
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
                limit = struct.unpack_from("<H", data, 6)[0]
                if 0x0100 <= limit <= 0x0FFF:
                    base = struct.unpack_from("<Q", data, 2)[0]
                    if base >= 0xFFFF800000000000:
                        self._kernel_base = base & ~0xFFF
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
        """Read virtual memory bytes across pages using PML4 page walking.

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

        try:
            cr3 = int(namespace_id, 16) if namespace_id.startswith("0x") else 0
        except ValueError:
            cr3 = 0

        result = bytearray()
        bytes_left = length
        curr_vaddr = virtual_address
        resolved_pages = 0
        total_pages = 0

        while bytes_left > 0:
            total_pages += 1
            page_off = curr_vaddr & 0xFFF
            chunk_len = min(bytes_left, 0x1000 - page_off)

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
