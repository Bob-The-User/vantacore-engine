"""Unit tests for scanner worker subprocess main entry point."""

import multiprocessing
import os
from pathlib import Path
from typing import Callable

from vantacore_engine.core.scanner.ring_buffer import SharedMemoryRingBuffer
from vantacore_engine.core.scanner.worker import _process_address, scanner_worker_main


def test_scanner_worker_basic(dump_path: Callable[[str], Path]) -> None:
    """Verify worker processes ring buffer addresses and pushes candidates to result queue."""
    dram_path = str(dump_path("mock_raw_dram.bin"))
    file_size = os.path.getsize(dram_path)

    ring = SharedMemoryRingBuffer(capacity=16, create=True)
    try:
        ring.put(0x1000)

        result_q: multiprocessing.Queue = multiprocessing.Queue()
        stop_evt = multiprocessing.Event()

        p = multiprocessing.Process(
            target=scanner_worker_main,
            args=(
                dram_path,
                file_size,
                ring.data_name,
                ring.meta_name,
                16,
                result_q,
                stop_evt,
                512,
            ),
            daemon=True,
        )
        p.start()

        # Stop worker after short delay
        stop_evt.set()
        p.join(timeout=5)

        assert p.exitcode == 0

        # Read results
        results = []
        while not result_q.empty():
            results.append(result_q.get_nowait())

        # In mock_raw_dram.bin, offset 0x1000 contains uint64 0x1000
        assert 0x1000 in results
    finally:
        ring.unlink()


def test_scanner_worker_oob_address(dump_path: Callable[[str], Path]) -> None:
    """Verify worker handles out-of-bounds addresses silently without crashing."""
    dram_path = str(dump_path("mock_raw_dram.bin"))
    file_size = os.path.getsize(dram_path)

    ring = SharedMemoryRingBuffer(capacity=16, create=True)
    try:
        # Enqueue an OOB address beyond dump_file_size
        ring.put(file_size + 0x1000)

        result_q: multiprocessing.Queue = multiprocessing.Queue()
        stop_evt = multiprocessing.Event()

        p = multiprocessing.Process(
            target=scanner_worker_main,
            args=(
                dram_path,
                file_size,
                ring.data_name,
                ring.meta_name,
                16,
                result_q,
                stop_evt,
                512,
            ),
            daemon=True,
        )
        p.start()

        stop_evt.set()
        p.join(timeout=5)

        assert p.exitcode == 0
    finally:
        ring.unlink()


def test_scanner_worker_large_window_size(dump_path: Callable[[str], Path]) -> None:
    """Verify worker handles window_size larger than dump file size."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))
    file_size = os.path.getsize(ios_path)

    ring = SharedMemoryRingBuffer(capacity=16, create=True)
    try:
        ring.put(0x0)  # Near 0

        result_q: multiprocessing.Queue = multiprocessing.Queue()
        stop_evt = multiprocessing.Event()

        p = multiprocessing.Process(
            target=scanner_worker_main,
            args=(
                ios_path,
                file_size,
                ring.data_name,
                ring.meta_name,
                16,
                result_q,
                stop_evt,
                file_size + 4096,  # Oversized window
            ),
            daemon=True,
        )
        p.start()

        stop_evt.set()
        p.join(timeout=5)

        assert p.exitcode == 0
    finally:
        ring.unlink()


def test_scanner_worker_immediate_stop(dump_path: Callable[[str], Path]) -> None:
    """Verify worker exits cleanly when stop_event is pre-set."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))
    file_size = os.path.getsize(ios_path)

    ring = SharedMemoryRingBuffer(capacity=16, create=True)
    try:
        result_q: multiprocessing.Queue = multiprocessing.Queue()
        stop_evt = multiprocessing.Event()
        stop_evt.set()  # Pre-set

        p = multiprocessing.Process(
            target=scanner_worker_main,
            args=(
                ios_path,
                file_size,
                ring.data_name,
                ring.meta_name,
                16,
                result_q,
                stop_evt,
                512,
            ),
            daemon=True,
        )
        p.start()
        p.join(timeout=5)

        assert p.exitcode == 0
    finally:
        ring.unlink()


def test_process_address_direct(dump_path: Callable[[str], Path]) -> None:
    """Verify direct invocation of _process_address with various bounds."""
    dram_path = dump_path("mock_raw_dram.bin")
    file_size = os.path.getsize(dram_path)
    result_q: multiprocessing.Queue = multiprocessing.Queue()

    with open(dram_path, "rb") as fh:
        # Negative address -> skipped
        _process_address(fh, -10, 512, file_size, result_q)
        assert result_q.empty()

        # OOB address -> skipped
        _process_address(fh, file_size + 1, 512, file_size, result_q)
        assert result_q.empty()

        # Near end of file with small read
        _process_address(fh, file_size - 4, 512, file_size, result_q)
        assert result_q.empty()

        # Valid address 0x1000
        _process_address(fh, 0x1000, 512, file_size, result_q)
        val = result_q.get(timeout=1)
        assert val == 0x1000


def test_scanner_worker_main_invalid_shm() -> None:
    """Verify scanner_worker_main handles invalid shared memory names gracefully."""
    result_q: multiprocessing.Queue = multiprocessing.Queue()
    stop_evt = multiprocessing.Event()

    # Invalid SHM name
    scanner_worker_main(
        "mock.bin",
        1000,
        "invalid_shm_data_9999",
        "invalid_shm_meta_9999",
        16,
        result_q,
        stop_evt,
        512,
    )


def test_scanner_worker_main_invalid_file(dump_path: Callable[[str], Path]) -> None:
    """Verify scanner_worker_main handles invalid file path gracefully."""
    ring = SharedMemoryRingBuffer(capacity=16, create=True)
    try:
        result_q: multiprocessing.Queue = multiprocessing.Queue()
        stop_evt = multiprocessing.Event()

        scanner_worker_main(
            "/tmp/nonexistent_file_99999.bin",
            1000,
            ring.data_name,
            ring.meta_name,
            16,
            result_q,
            stop_evt,
            512,
        )
    finally:
        ring.unlink()
