"""Unit tests for ScannerCoordinator worker respawn cap behavior."""

from unittest.mock import MagicMock, patch

from vantacore_engine.core.scanner.coordinator import ScannerCoordinator


def test_coordinator_worker_respawns_on_first_crash() -> None:
    """Verify coordinator respawns a crashed worker once."""
    coordinator = ScannerCoordinator("tests/fixtures/mock_raw_dram.bin", num_workers=1)

    mock_worker = MagicMock()
    mock_worker.exitcode = 1
    mock_worker.pid = 1234

    with patch("multiprocessing.Process") as mock_process_cls:
        new_process = MagicMock()
        new_process.pid = 5678
        mock_process_cls.return_value = new_process

        coordinator._workers = [mock_worker]
        coordinator._respawn_counts = {0: 0}
        coordinator._started = True

        coordinator._check_workers()

        assert coordinator._respawn_counts[0] == 1
        assert coordinator._workers[0] == new_process


def test_coordinator_worker_stops_on_second_crash() -> None:
    """Verify coordinator sets stop_event and does not respawn worker on second crash."""
    coordinator = ScannerCoordinator("tests/fixtures/mock_raw_dram.bin", num_workers=1)

    stop_event = MagicMock()
    coordinator._stop_event = stop_event

    mock_worker = MagicMock()
    mock_worker.exitcode = 1
    mock_worker.pid = 5678

    coordinator._workers = [mock_worker]
    coordinator._respawn_counts = {0: 1}
    coordinator._started = True

    coordinator._check_workers()

    assert coordinator._respawn_counts[0] == 1
    stop_event.set.assert_called_once()


def test_coordinator_clean_exit_does_not_trigger_respawn() -> None:
    """Verify clean exit (exitcode 0) does not increment respawn count."""
    coordinator = ScannerCoordinator("tests/fixtures/mock_raw_dram.bin", num_workers=1)

    mock_worker = MagicMock()
    mock_worker.exitcode = 0
    mock_worker.pid = 1234

    coordinator._workers = [mock_worker]
    coordinator._respawn_counts = {0: 0}
    coordinator._started = True

    coordinator._check_workers()

    assert coordinator._respawn_counts[0] == 0
