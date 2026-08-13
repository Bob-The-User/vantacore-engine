"""Coordinator orchestrator for multiprocess memory scanning."""

import logging
import multiprocessing
import os
import queue
from typing import Optional

from vantacore_engine.core.hooks import HookFramework
from vantacore_engine.core.scanner.ring_buffer import SharedMemoryRingBuffer
from vantacore_engine.core.scanner.worker import scanner_worker_main

logger = logging.getLogger(__name__)


class ScannerCoordinator:
    """Orchestrates worker subprocesses and SharedMemoryRingBuffer for parallel memory scanning."""

    def __init__(
        self,
        dump_path: str,
        num_workers: Optional[int] = None,
        ring_buffer_capacity: int = 256,
        window_size: int = 512,
        hook_framework: Optional[HookFramework] = None,
    ) -> None:
        """Initialize ScannerCoordinator settings.

        Args:
            dump_path: Path string to the target binary memory dump file.
            num_workers: Number of parallel worker subprocesses. Defaults to max(1, cpu_count-1).
            ring_buffer_capacity: Number of slots in the SharedMemoryRingBuffer.
            window_size: Byte size of scan window read by workers.
            hook_framework: Optional HookFramework instance for ON_NODE_DISCOVERED events.

        """
        self._dump_path = dump_path
        if num_workers is None:
            self._num_workers = max(1, (os.cpu_count() or 2) - 1)
        else:
            self._num_workers = num_workers

        self._ring_buffer_capacity = ring_buffer_capacity
        self._window_size = window_size
        self._hook_framework = hook_framework

        self._ring_buffer: Optional[SharedMemoryRingBuffer] = None
        self._result_queue: Optional[multiprocessing.Queue] = None
        self._stop_event: Optional[multiprocessing.Event] = None
        self._workers: list[multiprocessing.Process] = []
        self._respawn_counts: dict[int, int] = {}
        self._worker_args: tuple = ()
        self._started: bool = False

    def start(self) -> None:
        """Start SharedMemoryRingBuffer and worker subprocesses.

        Raises:
            RuntimeError: If coordinator is already started.
            FileNotFoundError: If dump_path does not exist.

        """
        if self._started:
            raise RuntimeError("ScannerCoordinator already started")

        dump_file_size = os.path.getsize(self._dump_path)

        self._ring_buffer = SharedMemoryRingBuffer(
            capacity=self._ring_buffer_capacity,
            create=True,
        )
        self._result_queue = multiprocessing.Queue()
        self._stop_event = multiprocessing.Event()
        self._workers = []

        self._worker_args = (
            self._dump_path,
            dump_file_size,
            self._ring_buffer.data_name,
            self._ring_buffer.meta_name,
            self._ring_buffer_capacity,
            self._result_queue,
            self._stop_event,
            self._window_size,
        )

        for _ in range(self._num_workers):
            p = multiprocessing.Process(
                target=scanner_worker_main,
                args=self._worker_args,
                daemon=True,
            )
            p.start()
            self._workers.append(p)

        self._respawn_counts = {i: 0 for i in range(len(self._workers))}
        self._started = True
        logger.info("ScannerCoordinator started %d workers", len(self._workers))

    def submit(self, physical_addr: int) -> bool:
        """Submit a physical address to the shared memory ring buffer for worker processing.

        Args:
            physical_addr: Physical byte offset address integer.

        Returns:
            True if address was enqueued, False if ring buffer was full.

        Raises:
            RuntimeError: If coordinator has not been started.

        """
        if not self._started or self._ring_buffer is None:
            raise RuntimeError("ScannerCoordinator not started")

        return self._ring_buffer.put(physical_addr)

    def drain_results(self) -> list[int]:
        """Drain all candidate physical addresses discovered by workers from result queue.

        Returns:
            List of physical address integers discovered by workers.

        """
        results: list[int] = []
        if self._result_queue is not None:
            while True:
                try:
                    results.append(self._result_queue.get_nowait())
                except queue.Empty:
                    break

        if self._hook_framework is not None:
            for addr in results:
                self._hook_framework.emit(
                    HookFramework.ON_NODE_DISCOVERED,
                    address=addr,
                    namespace="FLAT_PHYSICAL",
                )

        return results

    def _respawn_worker(self, worker_index: int) -> None:
        """Respawn a worker process if it has not exceeded the single-respawn cap.

        Args:
            worker_index: Index integer of the worker process in self._workers.

        """
        if self._respawn_counts.get(worker_index, 0) >= 1:
            pid = self._workers[worker_index].pid if worker_index < len(self._workers) else None
            logger.critical(
                "Worker at index %d (PID %s) crashed and has already been respawned once. Not respawning again.",
                worker_index,
                pid,
            )
            if self._stop_event is not None:
                self._stop_event.set()
            return

        crashed_pid = self._workers[worker_index].pid if worker_index < len(self._workers) else None
        p = multiprocessing.Process(
            target=scanner_worker_main,
            args=self._worker_args,
            daemon=True,
        )
        p.start()
        self._workers[worker_index] = p
        self._respawn_counts[worker_index] = self._respawn_counts.get(worker_index, 0) + 1
        logger.info(
            "Respawned worker at index %d (old PID %s, new PID %d).",
            worker_index,
            crashed_pid,
            p.pid,
        )

    def _check_workers(self) -> None:
        """Check worker exit codes and log critical errors for non-zero exits."""
        for i, worker in enumerate(self._workers):
            worker.join(timeout=0)
            if worker.exitcode is not None and worker.exitcode != 0:
                logger.critical("ScannerWorker PID %s exited with code %d", worker.pid, worker.exitcode)
                if self._started:
                    self._respawn_worker(i)

    def stop(self) -> None:
        """Stop worker subprocesses and clean up shared memory resources."""
        if not self._started:
            return

        if self._stop_event is not None:
            self._stop_event.set()

        for worker in self._workers:
            worker.join(timeout=5)

        self._check_workers()

        for worker in self._workers:
            if worker.is_alive():
                worker.terminate()

        self._workers = []

        if self._ring_buffer is not None:
            try:
                self._ring_buffer.close()
                self._ring_buffer.unlink()
            except Exception:
                pass
            self._ring_buffer = None

        self._started = False
        logger.info("ScannerCoordinator stopped")

    def __enter__(self) -> "ScannerCoordinator":
        """Enter context manager and start coordinator.

        Returns:
            Self instance.

        """
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exit context manager and stop coordinator."""
        self.stop()
