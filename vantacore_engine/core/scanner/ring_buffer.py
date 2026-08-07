"""SharedMemory-backed lock-free ring buffer for physical address queueing."""

import logging
import multiprocessing
import multiprocessing.synchronize
from multiprocessing.shared_memory import SharedMemory
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)


class SharedMemoryRingBuffer:
    """Ring buffer for IPC passing uint64 physical addresses via shared memory.

    Layout in metadata shared memory segment (24 bytes):
      - Offset 0: head index (uint64)
      - Offset 8: tail index (uint64)
      - Offset 16: capacity (uint64)

    Layout in data shared memory segment (capacity * 8 bytes):
      - uint64 array of address slots
    """

    HARD_CAPACITY_LIMIT = 65536

    def __init__(
        self,
        capacity: int = 256,
        lock: Optional[multiprocessing.synchronize.Lock] = None,
        *,
        create: bool = True,
        data_name: Optional[str] = None,
        meta_name: Optional[str] = None,
    ) -> None:
        """Initialize or attach to a shared memory ring buffer.

        Args:
            capacity: Number of slots for uint64 addresses.
            lock: Optional multiprocessing lock for concurrency synchronization.
            create: True to allocate new shared memory segments, False to attach.
            data_name: Shared memory segment name for data region (required if create=False).
            meta_name: Shared memory segment name for metadata region (required if create=False).

        Raises:
            ValueError: If capacity is non-positive or exceeds hard cap, or if required names are missing.

        """
        self._lock = lock if lock is not None else multiprocessing.Lock()
        self._closed = False

        if create:
            if capacity <= 0 or capacity > self.HARD_CAPACITY_LIMIT:
                raise ValueError(
                    f"ring buffer capacity must be between 1 and {self.HARD_CAPACITY_LIMIT} slots, got {capacity}"
                )
            self._shm_meta = SharedMemory(create=True, size=24)
            self._shm_data = SharedMemory(create=True, size=capacity * 8)

            self._meta_view = np.ndarray((3,), dtype=np.uint64, buffer=self._shm_meta.buf)
            self._meta_view[0] = 0  # head
            self._meta_view[1] = 0  # tail
            self._meta_view[2] = capacity

            self._data_view = np.ndarray((capacity,), dtype=np.uint64, buffer=self._shm_data.buf)
        else:
            if not data_name or not meta_name:
                raise ValueError("data_name and meta_name required when create=False")
            self._shm_data = SharedMemory(name=data_name, create=False)
            self._shm_meta = SharedMemory(name=meta_name, create=False)

            self._meta_view = np.ndarray((3,), dtype=np.uint64, buffer=self._shm_meta.buf)
            real_capacity = int(self._meta_view[2])
            self._data_view = np.ndarray((real_capacity,), dtype=np.uint64, buffer=self._shm_data.buf)

    @property
    def data_name(self) -> str:
        """Name of the underlying data SharedMemory segment.

        Returns:
            String name of shared memory segment.

        """
        return self._shm_data.name

    @property
    def meta_name(self) -> str:
        """Name of the underlying metadata SharedMemory segment.

        Returns:
            String name of shared memory segment.

        """
        return self._shm_meta.name

    @property
    def capacity(self) -> int:
        """Total capacity of the ring buffer.

        Returns:
            Integer slot capacity.

        """
        return int(self._meta_view[2])

    def put(self, addr: int) -> bool:
        """Put a uint64 physical address into the ring buffer.

        Args:
            addr: Physical byte address integer.

        Returns:
            True if address was successfully enqueued, False if buffer is full.

        Raises:
            RuntimeError: If ring buffer is closed.

        """
        if self._closed:
            raise RuntimeError("Ring buffer is closed")

        with self._lock:
            head = int(self._meta_view[0])
            tail = int(self._meta_view[1])
            cap = int(self._meta_view[2])

            next_tail = (tail + 1) % cap
            if next_tail == head:
                return False

            self._data_view[tail] = addr
            self._meta_view[1] = next_tail
            return True

    def get(self) -> Optional[int]:
        """Get the next uint64 physical address from the ring buffer.

        Returns:
            Physical address integer if available, or None if buffer is empty.

        Raises:
            RuntimeError: If ring buffer is closed.

        """
        if self._closed:
            raise RuntimeError("Ring buffer is closed")

        with self._lock:
            head = int(self._meta_view[0])
            tail = int(self._meta_view[1])
            cap = int(self._meta_view[2])

            if head == tail:
                return None

            addr = int(self._data_view[head])
            next_head = (head + 1) % cap
            self._meta_view[0] = next_head
            return addr

    def is_empty(self) -> bool:
        """Best-effort lock-free check if ring buffer is empty.

        Returns:
            True if head equals tail, False otherwise.

        """
        if self._closed:
            return True
        return int(self._meta_view[0]) == int(self._meta_view[1])

    def is_full(self) -> bool:
        """Best-effort check if ring buffer is full.

        Returns:
            True if next_tail equals head, False otherwise.

        """
        if self._closed:
            return False
        head = int(self._meta_view[0])
        tail = int(self._meta_view[1])
        cap = int(self._meta_view[2])
        return (tail + 1) % cap == head

    def close(self) -> None:
        """Close underlying shared memory attachments without unlinking them."""
        if not self._closed:
            self._closed = True
            try:
                self._shm_data.close()
            except Exception:
                pass
            try:
                self._shm_meta.close()
            except Exception:
                pass

    def unlink(self) -> None:
        """Unlink shared memory segments from system namespace."""
        self.close()
        try:
            self._shm_data.unlink()
        except Exception:
            pass
        try:
            self._shm_meta.unlink()
        except Exception:
            pass

    def __enter__(self) -> "SharedMemoryRingBuffer":
        """Enter context manager.

        Returns:
            Self instance.

        """
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exit context manager and close shared memory handles."""
        self.close()
