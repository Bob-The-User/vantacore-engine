"""LinuxModulesExtractor for kernel module listing and DKOM anomaly detection."""

from collections import deque
import logging
from pathlib import Path
import struct
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_MODULE_NAME_OFFSET = 0x18
_MODULE_CORE_LAYOUT_BASE = 0x150
_MODULE_CORE_LAYOUT_SIZE = 0x158
_MODULE_LIST_NEXT = 0x08

_KERNEL_VA_MIN = 0xFFFF800000000000
_KERNEL_VA_MAX = 0xFFFFFFFFFFFF0000


def _is_valid_kernel_va(va: int) -> bool:
    return _KERNEL_VA_MIN <= va <= _KERNEL_VA_MAX


def _clean_module_name(name_bytes: bytes) -> Optional[str]:
    raw = name_bytes.split(b"\x00")[0]
    if not raw or len(raw) > 55:
        return None
    try:
        decoded = raw.decode("ascii")
        if all(32 <= ord(c) <= 126 for c in decoded) and decoded.isidentifier():
            return decoded
    except UnicodeDecodeError:
        return None
    return None


class LinuxModulesExtractor(BaseExtractor):
    """Extractor for Linux kernel modules via list walking and physical slab carving."""

    name = "linux/modules"
    compatible_platforms = ["linux", "cisco_iosxe"]
    dependencies: list[str] = []

    def _read_module_struct(
        self, backend: TranslationBackend, va: int
    ) -> Optional[dict]:
        """Read and decode module struct fields at virtual address.

        Args:
            backend: TranslationBackend instance.
            va: Module struct virtual address.

        Returns:
            Dictionary containing module metadata, or None if invalid.

        """
        try:
            buf = backend.read_virtual("GLOBAL_KERNEL", va, 0x200)
        except Exception:
            return None

        if len(buf) < _MODULE_CORE_LAYOUT_SIZE + 4:
            return None

        name = _clean_module_name(buf[_MODULE_NAME_OFFSET : _MODULE_NAME_OFFSET + 56])
        if not name:
            return None

        base_ptr = struct.unpack_from("<Q", buf, _MODULE_CORE_LAYOUT_BASE)[0]
        size = struct.unpack_from("<I", buf, _MODULE_CORE_LAYOUT_SIZE)[0]

        return {
            "name": name,
            "base": base_ptr,
            "size": size,
            "va": va,
        }

    def _find_head_module_va(self, backend: TranslationBackend) -> Optional[int]:
        """Search near kernel base for candidate module struct virtual address.

        Args:
            backend: TranslationBackend instance.

        Returns:
            Virtual address integer if found, else None.

        """
        try:
            kernel_base = backend.get_kernel_base()
        except Exception:
            return None

        if not kernel_base or not _is_valid_kernel_va(kernel_base):
            return None

        scan_start = kernel_base + 0x800000
        scan_range = 4 * 1024 * 1024
        stride = 256

        common_modules = {"ext4", "loop", "e1000", "e1000e", "overlay", "fuse"}

        for va in range(scan_start, scan_start + scan_range, stride):
            mod_info = self._read_module_struct(backend, va)
            if mod_info and mod_info["name"] in common_modules:
                return va

        return None

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Execute kernel module extraction via list walk and slab carving.

        Args:
            backend: TranslationBackend for virtual memory access.
            dump_handle: Open file handle for physical memory scanning.
            output_dir: Output directory path.

        Returns:
            Dictionary containing modules and dkom_anomalies lists.

        """
        modules = []
        list_walk_names = set()
        seen_names = set()

        head_va = self._find_head_module_va(backend)
        if head_va is not None:
            queue = deque([head_va])
            visited = set()
            hops = 0
            max_hops = 500_000

            while queue and hops < max_hops:
                va = queue.popleft()
                if va in visited or va == 0 or not _is_valid_kernel_va(va):
                    continue
                visited.add(va)
                hops += 1

                mod_info = self._read_module_struct(backend, va)
                if mod_info:
                    name = mod_info["name"]
                    if name not in seen_names:
                        seen_names.add(name)
                        list_walk_names.add(name)
                        modules.append(
                            {
                                "name": name,
                                "base": mod_info["base"],
                                "size": mod_info["size"],
                                "source": "list_walk",
                            }
                        )

                try:
                    next_ptr_bytes = backend.read_virtual("GLOBAL_KERNEL", va + _MODULE_LIST_NEXT, 8)
                    next_ptr = struct.unpack_from("<Q", next_ptr_bytes)[0]
                    if _is_valid_kernel_va(next_ptr):
                        next_mod_va = next_ptr - _MODULE_LIST_NEXT
                        if _is_valid_kernel_va(next_mod_va):
                            queue.append(next_mod_va)
                except Exception:
                    pass

        # Secondary path: Carve physical dump
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        carve_results = []
        chunk_size = 65536
        carve_hops = 0

        while True:
            offset = dump_handle.tell()
            if offset >= total_size or carve_hops >= 500_000:
                break

            chunk = dump_handle.read(chunk_size)
            if not chunk:
                break
            carve_hops += 1

            for align_off in range(0, len(chunk) - 0x200, 8):
                name_bytes = chunk[align_off + _MODULE_NAME_OFFSET : align_off + _MODULE_NAME_OFFSET + 56]
                name = _clean_module_name(name_bytes)
                if not name:
                    continue

                base_ptr = struct.unpack_from("<Q", chunk, align_off + _MODULE_CORE_LAYOUT_BASE)[0]
                size = struct.unpack_from("<I", chunk, align_off + _MODULE_CORE_LAYOUT_SIZE)[0]

                if _is_valid_kernel_va(base_ptr) and 4096 <= size <= 256 * 1024 * 1024:
                    phys_off = offset + align_off
                    carve_results.append(
                        {
                            "name": name,
                            "base": base_ptr,
                            "size": size,
                            "phys_offset": phys_off,
                        }
                    )
                    if name not in seen_names:
                        seen_names.add(name)
                        modules.append(
                            {
                                "name": name,
                                "base": base_ptr,
                                "size": size,
                                "source": "carve",
                            }
                        )

        dkom_anomalies = []
        for item in carve_results:
            if item["name"] not in list_walk_names:
                dkom_anomalies.append(
                    {
                        "name": item["name"],
                        "phys_offset": item["phys_offset"],
                        "severity": "HIGH",
                    }
                )

        return {"modules": modules, "dkom_anomalies": dkom_anomalies}
