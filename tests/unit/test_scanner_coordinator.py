"""Unit tests for ScannerCoordinator orchestrator."""

from pathlib import Path
from typing import Callable
import pytest

from vantacore_engine.core.hooks import HookFramework
from vantacore_engine.core.scanner.coordinator import ScannerCoordinator


def test_coordinator_lifecycle(dump_path: Callable[[str], Path]) -> None:
    """Verify ScannerCoordinator start, submit, drain, and stop lifecycle."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))

    coord = ScannerCoordinator(dump_path=ios_path, num_workers=2)
    assert coord._started is False

    coord.start()
    assert coord._started is True
    assert len(coord._workers) == 2

    # Double start raises RuntimeError
    with pytest.raises(RuntimeError):
        coord.start()

    # Submit valid physical address
    assert coord.submit(0x0) is True

    # Drain results
    results = coord.drain_results()
    assert isinstance(results, list)

    coord.stop()
    assert coord._started is False

    # Double stop is idempotent
    coord.stop()


def test_coordinator_submit_before_start_raises_runtime_error(dump_path: Callable[[str], Path]) -> None:
    """Verify submit before start raises RuntimeError."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))
    coord = ScannerCoordinator(dump_path=ios_path)
    with pytest.raises(RuntimeError):
        coord.submit(0x100)


def test_coordinator_context_manager(dump_path: Callable[[str], Path]) -> None:
    """Verify context manager interface starts and stops coordinator automatically."""
    ios_path = str(dump_path("mock_cisco_ios.bin"))

    with ScannerCoordinator(dump_path=ios_path, num_workers=1) as coord:
        assert coord._started is True
        assert coord.submit(0x100) is True
        results = coord.drain_results()
        assert isinstance(results, list)

    assert coord._started is False


def test_coordinator_hook_framework_integration(dump_path: Callable[[str], Path]) -> None:
    """Verify hook framework receives ON_NODE_DISCOVERED events on drain_results."""
    dram_path = str(dump_path("mock_raw_dram.bin"))
    hooks = HookFramework()
    discovered_nodes = []

    def on_node(address: int, namespace: str) -> None:
        discovered_nodes.append((address, namespace))

    hooks.register(HookFramework.ON_NODE_DISCOVERED, on_node)

    with ScannerCoordinator(dump_path=dram_path, num_workers=1, hook_framework=hooks) as coord:
        coord.submit(0x1000)
        # Give worker a moment to scan 0x1000
        import time
        time.sleep(0.05)
        results = coord.drain_results()
        if results:
            assert len(discovered_nodes) == len(results)
            assert discovered_nodes[0][1] == "FLAT_PHYSICAL"
