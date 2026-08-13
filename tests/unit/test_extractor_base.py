"""Unit tests for BaseExtractor and ExtractorDAGExecutor."""

import io
from pathlib import Path
import pytest

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.extractors.base import BaseExtractor, ExtractorDAGExecutor


def test_base_extractor_abstract_instantiation_raises_type_error() -> None:
    """Verify concrete class without run() raises TypeError on instantiation."""

    class IncompleteExtractor(BaseExtractor):
        name = "test/incomplete"

    with pytest.raises(TypeError):
        IncompleteExtractor()  # type: ignore


def test_dag_executor_empty_list() -> None:
    """Verify ExtractorDAGExecutor with empty extractor list returns COMPLETE."""
    executor = ExtractorDAGExecutor([], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert res["scan_status"]["overall"] == "COMPLETE"
    assert res["scan_status"]["extractors_succeeded"] == []
    assert res["scan_status"]["extractors_failed"] == []
    assert res["scan_status"]["extractors_skipped"] == []


def test_dag_executor_dependency_ordering() -> None:
    """Verify dependency B runs before dependent A."""
    execution_order = []

    class ExtractorB(BaseExtractor):
        name = "test/b"
        compatible_platforms = ["*"]
        dependencies = []

        def run(self, backend, dump_handle, output_dir):
            execution_order.append("b")
            return {"b_data": 1}

    class ExtractorA(BaseExtractor):
        name = "test/a"
        compatible_platforms = ["*"]
        dependencies = ["test/b"]

        def run(self, backend, dump_handle, output_dir):
            execution_order.append("a")
            return {"a_data": 2}

    executor = ExtractorDAGExecutor([ExtractorA(), ExtractorB()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert execution_order == ["b", "a"]
    assert res["scan_status"]["overall"] == "COMPLETE"
    assert res["scan_status"]["extractors_succeeded"] == ["test/b", "test/a"]
    assert res["b_data"] == 1
    assert res["a_data"] == 2


def test_dag_executor_dependency_failure_skips_dependent() -> None:
    """Verify failure of dependency B causes dependent A to be skipped."""

    class ExtractorB(BaseExtractor):
        name = "test/b"
        compatible_platforms = ["*"]
        dependencies = []

        def run(self, backend, dump_handle, output_dir):
            raise ValueError("Mock failure in B")

    class ExtractorA(BaseExtractor):
        name = "test/a"
        compatible_platforms = ["*"]
        dependencies = ["test/b"]

        def run(self, backend, dump_handle, output_dir):
            return {"a_data": 2}

    executor = ExtractorDAGExecutor([ExtractorA(), ExtractorB()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert res["scan_status"]["overall"] == "PARTIAL"
    assert "test/b" in res["scan_status"]["extractors_failed"]
    assert "test/a" in res["scan_status"]["extractors_skipped"]


def test_dag_executor_platform_filtering() -> None:
    """Verify extractors incompatible with platform_name are not executed."""

    class AsaExtractor(BaseExtractor):
        name = "cisco/asa_specific"
        compatible_platforms = ["cisco_asa"]
        dependencies = []

        def run(self, backend, dump_handle, output_dir):
            return {"asa": True}

    executor = ExtractorDAGExecutor([AsaExtractor()], "linux")
    backend = FlatImageBackend()
    fh = io.BytesIO(b"\x00" * 1024)
    res = executor.execute(backend, fh, Path("/tmp"))

    assert res["scan_status"]["overall"] == "COMPLETE"
    assert res["scan_status"]["extractors_succeeded"] == []
    assert "asa" not in res
