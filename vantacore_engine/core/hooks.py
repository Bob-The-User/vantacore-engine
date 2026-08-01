"""Event hook framework for extensible scan-time notifications."""

from collections import defaultdict
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


class HookFramework:
    """Publish-subscribe event hook framework for scan events."""

    ON_NODE_DISCOVERED = "on_node_discovered"
    ON_EDGE_DISCOVERED = "on_edge_discovered"
    ON_SCAN_COMPLETE = "on_scan_complete"
    ON_EXTRACTOR_COMPLETE = "on_extractor_complete"

    def __init__(self) -> None:
        """Initialize empty callback registries."""
        self._callbacks: dict[str, list[Callable[..., None]]] = defaultdict(list)

    def register(self, event_name: str, callback: Callable[..., None]) -> None:
        """Register a callback for a specific event name.

        Args:
            event_name: Event identifier string.
            callback: Callable to invoke when event is emitted.

        """
        self._callbacks[event_name].append(callback)

    def emit(self, event_name: str, **kwargs: Any) -> None:
        """Emit an event to all registered callbacks.

        Exceptions in individual callbacks are caught and logged, allowing other callbacks to run.

        Args:
            event_name: Event identifier string.
            **kwargs: Keyword arguments passed to registered callbacks.

        """
        callbacks = self._callbacks.get(event_name, [])
        for cb in callbacks:
            try:
                cb(**kwargs)
            except Exception as e:
                cb_name = getattr(cb, "__name__", str(cb))
                logger.error("Hook callback %s raised: %s", cb_name, e)
