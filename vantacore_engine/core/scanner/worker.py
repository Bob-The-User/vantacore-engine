"""Subprocess entry point for lock-free parallel memory scanning workers."""

import logging
import multiprocessing
import time
from typing import Any
import numpy as np

from vantacore_engine.core.scanner.ring_buffer import SharedMemoryRingBuffer

logger = logging.getLogger(__name__)


def _process_address(
    fh: Any,
    addr: int,
    window_size: int,
    dump_file_size: int,
    result_queue: multiprocessing.Queue,
) -> None:
    """Process a single physical address by reading window and parsing pointer candidates.

    Args:
        fh: Open binary file handle.
        addr: Starting physical byte offset.
        window_size: Byte size of window to read.
        dump_file_size: Total file size in bytes for bounds checking.
        result_queue: Multiprocessing queue to push discovered pointer candidates.

    """
    if addr < 0 or addr + window_size > dump_file_size:
        return

    fh.seek(addr)
    window = fh.read(window_size)
    if len(window) < 8:
        return

    usable_len = len(window) - (len(window) % 8)
    candidates = np.frombuffer(window[:usable_len], dtype=np.uint64)
    mask = (candidates >= 0x1000) & (candidates <= dump_file_size - 8)
    for c in candidates[mask]:
        result_queue.put(int(c))


def scanner_worker_main(
    dump_path: str,
    dump_file_size: int,
    shm_data_name: str,
    shm_meta_name: str,
    ring_capacity: int,
    result_queue: multiprocessing.Queue,
    stop_event: multiprocessing.Event,
    window_size: int = 512,
) -> None:
    """Subprocess main entry point for a memory scanner worker process.

    Args:
        dump_path: Path string to the raw binary memory dump.
        dump_file_size: File size in bytes for fast bounds checking.
        shm_data_name: Name of data SharedMemory segment.
        shm_meta_name: Name of metadata SharedMemory segment.
        ring_capacity: SharedMemoryRingBuffer slot capacity.
        result_queue: Queue to push candidate physical addresses.
        stop_event: Process shutdown event.
        window_size: Scan window size in bytes.

    """
    try:
        ring_buf = SharedMemoryRingBuffer(
            capacity=ring_capacity,
            create=False,
            data_name=shm_data_name,
            meta_name=shm_meta_name,
        )
    except Exception as e:
        logger.error("Scanner worker failed to attach ring buffer: %s", e)
        return

    try:
        fh = open(dump_path, "rb")
    except Exception as e:
        logger.error("Scanner worker failed to open dump file %s: %s", dump_path, e)
        ring_buf.close()
        return

    try:
        logger.info("Scanner worker process initialized for %s", dump_path)
        while not stop_event.is_set():
            addr = ring_buf.get()
            if addr is None:
                time.sleep(0.001)
                continue

            _process_address(fh, addr, window_size, dump_file_size, result_queue)

        # Drain remaining ring buffer items upon receiving stop_event
        while True:
            addr = ring_buf.get()
            if addr is None:
                break
            _process_address(fh, addr, window_size, dump_file_size, result_queue)

    except Exception as e:
        logger.error("Scanner worker loop encountered error: %s", e)
    finally:
        try:
            ring_buf.close()
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass
        logger.info("Scanner worker process exiting")
