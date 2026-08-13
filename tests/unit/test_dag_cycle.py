"""Unit tests for ExtractorDAGExecutor cycle detection and isolation."""

import io
from pathlib import Path

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.base import BaseExtractor, ExtractorDAGExecutor


def test_dag_two_node_cycle_isolation() -> None:
    """Verify 2-node cycle (A->B->A) is disabled while standalone C succeeds."""

    class A(BaseExtractor):
        name = "cycle/a"
        compatible_platforms = ["*"]
        dependencies = ["cycle/b"]

        def run(self, b, fh, od):
            return {"a": 1}

    class B(BaseExtractor):
        name = "cycle/b"
        compatible_platforms = ["*"]
        dependencies = ["cycle/a"]

        def run(self, b, fh, od):
            return {"b": 1}

    class C(BaseExtractor):
        name = "standalone/c"
        compatible_platforms = ["*"]
        dependencies = []

        def run(self, b, fh, od):
            return {"c": 1}

    executor = ExtractorDAGExecutor([A(), B(), C()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert "standalone/c" in res["scan_status"]["extractors_succeeded"]
    assert "cycle/a" not in res["scan_status"]["extractors_succeeded"]
    assert "cycle/b" not in res["scan_status"]["extractors_succeeded"]
    assert res["c"] == 1


def test_dag_three_node_cycle() -> None:
    """Verify 3-node cycle (A->B->C->A) results in zero extractors running."""

    class A(BaseExtractor):
        name = "cycle3/a"
        compatible_platforms = ["*"]
        dependencies = ["cycle3/b"]

        def run(self, b, fh, od):
            return {}

    class B(BaseExtractor):
        name = "cycle3/b"
        compatible_platforms = ["*"]
        dependencies = ["cycle3/c"]

        def run(self, b, fh, od):
            return {}

    class C(BaseExtractor):
        name = "cycle3/c"
        compatible_platforms = ["*"]
        dependencies = ["cycle3/a"]

        def run(self, b, fh, od):
            return {}

    executor = ExtractorDAGExecutor([A(), B(), C()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert res["scan_status"]["extractors_succeeded"] == []


def test_dag_self_dependency_cycle() -> None:
    """Verify self-dependency (A->A) is detected as cycle and disabled."""

    class SelfDep(BaseExtractor):
        name = "cycle/self"
        compatible_platforms = ["*"]
        dependencies = ["cycle/self"]

        def run(self, b, fh, od):
            return {}

    executor = ExtractorDAGExecutor([SelfDep()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert res["scan_status"]["extractors_succeeded"] == []
