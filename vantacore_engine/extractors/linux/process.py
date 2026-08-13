"""LinuxProcessExtractor for process listing and DKOM anomaly detection."""

from collections import deque
import logging
from pathlib import Path
import struct
from typing import BinaryIO, Optional

from vantacore_engine.core.translation_base import TranslationBackend
from vantacore_engine.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

_TASK_PID_OFFSET = 0x558
_TASK_TGID_OFFSET = 0x55C
_TASK_COMM_OFFSET = 0x678
_TASK_STATE_OFFSET = 0x000
_TASK_TASKS_NEXT = 0x4A8
_TASK_TASKS_PREV = 0x4B0
_TASK_PARENT_OFFSET = 0x4B8

_VALID_PID_MIN = 0
_VALID_PID_MAX = 4194304
_KERNEL_VA_MIN = 0xFFFF800000000000
_KERNEL_VA_MAX = 0xFFFFFFFFFFFF0000
_VALID_STATES = {0, 1, 2, 4, 8, 16, 32, 64, 128}


def _is_valid_kernel_va(va: int) -> bool:
    return _KERNEL_VA_MIN <= va <= _KERNEL_VA_MAX


def _clean_comm(comm_bytes: bytes) -> Optional[str]:
    raw_name = comm_bytes.split(b"\x00")[0]
    if not raw_name:
        return None
    try:
        decoded = raw_name.decode("ascii")
        if all(32 <= ord(c) <= 126 for c in decoded):
            return decoded
    except UnicodeDecodeError:
        return None
    return None


class LinuxProcessExtractor(BaseExtractor):
    """Extractor for Linux processes via list walking and slab carving."""

    name = "linux/process"
    compatible_platforms = ["linux", "cisco_iosxe"]
    dependencies: list[str] = []

    def _read_task_struct(
        self, backend: TranslationBackend, va: int
    ) -> Optional[dict]:
        """Read and decode task_struct fields at virtual address.

        Args:
            backend: TranslationBackend instance.
            va: Task struct virtual address.

        Returns:
            Dictionary with process details, or None if invalid.

        """
        try:
            buf = backend.read_virtual("GLOBAL_KERNEL", va, 0x700)
        except Exception:
            return None

        if len(buf) < 0x688:
            return None

        pid = struct.unpack_from("<i", buf, _TASK_PID_OFFSET)[0]
        if not (_VALID_PID_MIN <= pid < _VALID_PID_MAX):
            return None

        comm = _clean_comm(buf[_TASK_COMM_OFFSET : _TASK_COMM_OFFSET + 16])
        if comm is None:
            return None

        tgid = struct.unpack_from("<i", buf, _TASK_TGID_OFFSET)[0]
        state = struct.unpack_from("<q", buf, _TASK_STATE_OFFSET)[0]

        ppid = 0
        parent_va = struct.unpack_from("<Q", buf, _TASK_PARENT_OFFSET)[0]
        if _is_valid_kernel_va(parent_va) and parent_va != va:
            try:
                parent_buf = backend.read_virtual("GLOBAL_KERNEL", parent_va, 0x600)
                if len(parent_buf) >= _TASK_PID_OFFSET + 4:
                    parent_pid = struct.unpack_from("<i", parent_buf, _TASK_PID_OFFSET)[0]
                    if _VALID_PID_MIN <= parent_pid < _VALID_PID_MAX:
                        ppid = parent_pid
            except Exception:
                pass

        return {
            "pid": pid,
            "tgid": tgid,
            "comm": comm,
            "state": state,
            "ppid": ppid,
            "va": va,
        }

    def _find_init_task_va(self, backend: TranslationBackend) -> Optional[int]:
        """Find init_task virtual address using heuristic kernel scanning.

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

        stride = 256
        scan_range = 4 * 1024 * 1024
        for va in range(kernel_base, kernel_base + scan_range, stride):
            try:
                buf = backend.read_virtual("GLOBAL_KERNEL", va, 256)
            except Exception:
                continue

            if len(buf) < 256:
                continue

            # Check if PID == 1 at _TASK_PID_OFFSET
            # Since buf is only 256 bytes, read larger buffer if candidate match seen
            if _TASK_COMM_OFFSET + 16 <= len(buf):
                pid = struct.unpack_from("<i", buf, _TASK_PID_OFFSET)[0]
                if pid == 1:
                    comm = _clean_comm(buf[_TASK_COMM_OFFSET : _TASK_COMM_OFFSET + 16])
                    if comm and (comm.startswith("systemd") or comm.startswith("init") or comm == "swapper"):
                        return va

            # Also check if init_task is around va
            task_info = self._read_task_struct(backend, va)
            if task_info and task_info["pid"] == 1:
                comm = task_info["comm"]
                if comm.startswith("systemd") or comm.startswith("init") or comm == "swapper":
                    return va

        return None

    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Execute dual-path Linux process extraction (list walk + slab carving).

        Args:
            backend: TranslationBackend for virtual memory access.
            dump_handle: Open binary dump file handle for physical memory scanning.
            output_dir: Output directory path.

        Returns:
            Dictionary containing processes and dkom_anomalies lists.

        """
        processes = []
        list_walk_pids = set()
        seen_pids = set()

        # Primary path: List walking
        init_task_va = self._find_init_task_va(backend)
        if init_task_va is None:
            logger.warning(
                "LinuxProcessExtractor: init_task not found via heuristic. Primary path returning empty."
            )
        else:
            queue = deque([init_task_va])
            visited = set()
            hops = 0
            max_hops = 500_000

            while queue and hops < max_hops:
                va = queue.popleft()
                if va in visited or va == 0 or not _is_valid_kernel_va(va):
                    continue
                visited.add(va)
                hops += 1

                task_info = self._read_task_struct(backend, va)
                if task_info:
                    pid = task_info["pid"]
                    if pid not in seen_pids:
                        seen_pids.add(pid)
                        list_walk_pids.add(pid)
                        processes.append(
                            {
                                "pid": pid,
                                "tgid": task_info["tgid"],
                                "comm": task_info["comm"],
                                "state": task_info["state"],
                                "ppid": task_info["ppid"],
                                "source": "list_walk",
                            }
                        )

                # Read tasks.next pointer
                try:
                    next_ptr_bytes = backend.read_virtual("GLOBAL_KERNEL", va + _TASK_TASKS_NEXT, 8)
                    next_ptr = struct.unpack_from("<Q", next_ptr_bytes)[0]
                    if _is_valid_kernel_va(next_ptr):
                        next_task_va = next_ptr - _TASK_TASKS_NEXT
                        if _is_valid_kernel_va(next_task_va):
                            queue.append(next_task_va)
                except Exception:
                    pass

            if hops >= max_hops:
                logger.warning("LinuxProcessExtractor: traversal hop cap reached. List walk truncated.")

        # Secondary path: Slab carving
        dump_handle.seek(0, 2)
        total_size = dump_handle.tell()
        dump_handle.seek(0)

        carve_results = []
        carve_pids = set()
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

            for align_off in range(0, len(chunk) - 0x700, 8):
                if _TASK_COMM_OFFSET + 16 > len(chunk) - align_off:
                    continue

                pid = struct.unpack_from("<i", chunk, align_off + _TASK_PID_OFFSET)[0]
                if not (1 <= pid < _VALID_PID_MAX):
                    continue

                state = struct.unpack_from("<q", chunk, align_off + _TASK_STATE_OFFSET)[0]
                if state not in _VALID_STATES:
                    continue

                comm = _clean_comm(chunk[align_off + _TASK_COMM_OFFSET : align_off + _TASK_COMM_OFFSET + 16])
                if not comm:
                    continue

                tgid = struct.unpack_from("<i", chunk, align_off + _TASK_TGID_OFFSET)[0]
                carve_pids.add(pid)
                phys_off = offset + align_off

                if pid not in seen_pids:
                    seen_pids.add(pid)
                    processes.append(
                        {
                            "pid": pid,
                            "tgid": tgid,
                            "comm": comm,
                            "state": state,
                            "ppid": 0,
                            "source": "carve",
                        }
                    )

                carve_results.append(
                    {"pid": pid, "comm": comm, "phys_offset": phys_off}
                )

        dkom_anomalies = []
        for item in carve_results:
            if item["pid"] not in list_walk_pids:
                dkom_anomalies.append(
                    {
                        "pid": item["pid"],
                        "comm": item["comm"],
                        "phys_offset": item["phys_offset"],
                        "severity": "HIGH",
                    }
                )

        return {"processes": processes, "dkom_anomalies": dkom_anomalies}
