"""Base abstract classes and DAG executor for extractor plugins."""

from abc import ABC, abstractmethod
from collections import deque
import logging
from pathlib import Path
from typing import BinaryIO

from vantacore_engine.core.translation_base import TranslationBackend

logger = logging.getLogger(__name__)


class BaseExtractor(ABC):
    """Abstract base class for all memory artifact extractors."""

    name: str = ""
    compatible_platforms: list[str] = []
    dependencies: list[str] = []

    @abstractmethod
    def run(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Run the extractor on the memory dump.

        Args:
            backend: TranslationBackend instance for virtual memory reading.
            dump_handle: Open file handle for physical memory access.
            output_dir: Output directory path for writing extracted artifacts.

        Returns:
            Dictionary containing extracted data artifacts.

        """


class CycleError(Exception):
    """Raised when a cyclic dependency is detected among extractors."""


class ExtractorDAGExecutor:
    """Executes extractor plugins in topological dependency order."""

    def __init__(
        self,
        extractors: list[BaseExtractor],
        platform_name: str,
    ) -> None:
        """Initialize and resolve topological order for compatible extractors.

        Args:
            extractors: List of BaseExtractor instances available.
            platform_name: Detected platform name string.

        """
        self._extractors = [
            e
            for e in extractors
            if platform_name in e.compatible_platforms or "*" in e.compatible_platforms
        ]
        self._disabled: list[str] = []
        self._execution_order: list[BaseExtractor] = self._resolve_dag()

    def _resolve_dag(self) -> list[BaseExtractor]:
        """Resolve topological execution order using Kahn's algorithm.

        Returns:
            List of BaseExtractor instances in execution order.

        """
        name_map = {e.name: e for e in self._extractors}
        in_degree = {e.name: 0 for e in self._extractors}
        dependents: dict[str, list[str]] = {e.name: [] for e in self._extractors}

        for e in self._extractors:
            for dep_name in e.dependencies:
                if dep_name in in_degree:
                    in_degree[e.name] += 1
                    dependents[dep_name].append(e.name)

        queue: deque[str] = deque(
            [name for name, deg in in_degree.items() if deg == 0]
        )
        sorted_names: list[str] = []

        while queue:
            node = queue.popleft()
            sorted_names.append(node)
            for dep in dependents.get(node, []):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    queue.append(dep)

        if len(sorted_names) < len(self._extractors):
            cycle_names = [e.name for e in self._extractors if e.name not in sorted_names]
            logger.critical(
                "Cyclic dependency detected among: %s. Disabling all extractors in the cycle.",
                cycle_names,
            )
            self._disabled.extend(cycle_names)

        return [name_map[name] for name in sorted_names]

    def execute(
        self,
        backend: TranslationBackend,
        dump_handle: BinaryIO,
        output_dir: Path,
    ) -> dict:
        """Execute all compatible extractors in topological order.

        Args:
            backend: TranslationBackend instance for memory resolution.
            dump_handle: Open file handle for physical memory read access.
            output_dir: Directory path for artifact writing.

        Returns:
            Dictionary containing merged extractor results and scan status block.

        """
        succeeded: list[str] = []
        failed: list[str] = []
        skipped: list[str] = []
        merged_results: dict = {}

        succeeded_set: set[str] = set()

        for extractor in self._execution_order:
            missing_dep = None
            for dep in extractor.dependencies:
                if dep not in succeeded_set:
                    missing_dep = dep
                    break

            if missing_dep is not None:
                skipped.append(extractor.name)
                logger.warning(
                    "Extractor '%s' skipped because dependency '%s' failed or was skipped.",
                    extractor.name,
                    missing_dep,
                )
                continue

            try:
                res = extractor.run(backend, dump_handle, output_dir)
                if isinstance(res, dict):
                    merged_results.update(res)
                succeeded.append(extractor.name)
                succeeded_set.add(extractor.name)
            except Exception as exc:
                failed.append(extractor.name)
                logger.critical(
                    "Extractor '%s' failed with: %s. Skipping. Other extractors will continue.",
                    extractor.name,
                    exc,
                )

        overall = "COMPLETE" if not failed and not skipped else "PARTIAL"

        return {
            "scan_status": {
                "overall": overall,
                "extractors_succeeded": succeeded,
                "extractors_failed": failed,
                "extractors_skipped": skipped,
            },
            **merged_results,
        }
