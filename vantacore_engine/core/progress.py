"""Rate-limited progress event bus for long-running forensics tasks."""

from datetime import datetime, timezone
import time
from typing import Any, Callable, Optional


class ProgressEventBus:
    """Rate-limited progress reporting event bus."""

    def __init__(self) -> None:
        """Initialize progress event bus with 10 events/sec rate limit."""
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._last_emit: float = 0.0
        self._min_interval: float = 0.1

    def add_listener(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Add a progress listener callback.

        Args:
            callback: Callable receiving a progress payload dictionary.

        """
        self._listeners.append(callback)

    def emit(
        self,
        phase: str,
        pct: float,
        rate: Optional[float] = None,
        eta_sec: Optional[float] = None,
    ) -> None:
        """Emit a rate-limited progress event to all listeners.

        Events arriving faster than 10Hz (min 0.1s interval) are dropped.

        Args:
            phase: Current execution phase description.
            pct: Overall completion percentage (0.0 - 100.0).
            rate: Processing rate in items/sec or MB/sec.
            eta_sec: Estimated time remaining in seconds.

        """
        now = time.monotonic()
        if now - self._last_emit < self._min_interval:
            return
        self._last_emit = now

        payload = {
            "phase": phase,
            "pct": pct,
            "rate": rate,
            "eta_sec": eta_sec,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        for listener in self._listeners:
            listener(payload)
