"""Unit tests for SharedMemoryRingBuffer."""

import pytest
from vantacore_engine.core.scanner.ring_buffer import SharedMemoryRingBuffer


def test_ring_buffer_lifecycle() -> None:
    """Verify basic put, get, empty, and full behavior of ring buffer."""
    rb = SharedMemoryRingBuffer(capacity=4, create=True)
    try:
        assert rb.is_empty() is True
        assert rb.is_full() is False

        assert rb.put(0x1000) is True
        assert rb.is_empty() is False

        addr = rb.get()
        assert addr == 0x1000
        assert rb.is_empty() is True

        # Capacity 4 holds 3 items max (tail+1 % cap == head)
        assert rb.put(0x100) is True
        assert rb.put(0x200) is True
        assert rb.put(0x300) is True
        assert rb.is_full() is True

        # Putting to a full buffer returns False
        assert rb.put(0x400) is False

        # Get items back in FIFO order
        assert rb.get() == 0x100
        assert rb.get() == 0x200
        assert rb.get() == 0x300
        assert rb.get() is None
    finally:
        rb.unlink()


def test_ring_buffer_invalid_capacity() -> None:
    """Verify ValueError is raised for invalid capacity bounds."""
    with pytest.raises(ValueError):
        SharedMemoryRingBuffer(capacity=0, create=True)

    with pytest.raises(ValueError):
        SharedMemoryRingBuffer(capacity=65537, create=True)


def test_ring_buffer_attach() -> None:
    """Verify attach (create=False) to existing shared memory segment."""
    creator = SharedMemoryRingBuffer(capacity=8, create=True)
    try:
        creator.put(0xDEADBEEF)

        attacher = SharedMemoryRingBuffer(
            capacity=8,
            create=False,
            data_name=creator.data_name,
            meta_name=creator.meta_name,
        )
        try:
            assert attacher.capacity == 8
            assert attacher.get() == 0xDEADBEEF
        finally:
            attacher.close()
    finally:
        creator.unlink()


def test_ring_buffer_missing_names_raises_value_error() -> None:
    """Verify ValueError when create=False without data_name or meta_name."""
    with pytest.raises(ValueError):
        SharedMemoryRingBuffer(create=False)


def test_ring_buffer_context_manager() -> None:
    """Verify context manager closes buffer automatically."""
    rb = SharedMemoryRingBuffer(capacity=8, create=True)
    try:
        with rb as b:
            assert b.put(0x1234) is True
        # Closed after context exit
        with pytest.raises(RuntimeError):
            rb.get()
    finally:
        rb.unlink()


def test_closed_buffer_put_raises_runtime_error() -> None:
    """Verify put on closed buffer raises RuntimeError."""
    rb = SharedMemoryRingBuffer(capacity=8, create=True)
    rb.close()
    try:
        with pytest.raises(RuntimeError):
            rb.put(0x100)
    finally:
        rb.unlink()
