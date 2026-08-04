"""Unit tests for TranslationBackend ABC and translation exception classes."""

import pytest

from vantacore_engine.core.backends.flat_image import FlatImageBackend
from vantacore_engine.core.translation_base import (
    PageFaultError,
    TranslationBackend,
    TranslationError,
)


def test_translation_backend_abc_non_instantiable() -> None:
    """Verify TranslationBackend ABC cannot be instantiated directly."""
    with pytest.raises(TypeError):
        TranslationBackend()  # type: ignore[abstract]


def test_flat_image_backend_is_subclass() -> None:
    """Verify FlatImageBackend is a valid instantiable subclass of TranslationBackend."""
    backend = FlatImageBackend()
    assert isinstance(backend, TranslationBackend)


def test_translation_exceptions_inherit_runtime_error() -> None:
    """Verify TranslationError and PageFaultError inherit from RuntimeError."""
    err = TranslationError("Bootstrapping failed")
    pf = PageFaultError("Zero pages resolved")
    assert isinstance(err, RuntimeError)
    assert isinstance(pf, RuntimeError)
