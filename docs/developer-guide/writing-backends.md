# Writing Translation Backends

Translation backends bridge raw byte offsets in physical memory files to structured virtual address spaces.

## Implementing a Translation Backend

All translation backends inherit from `TranslationBackend` located in `vantacore_engine.core.translation_base`.

### Backend Interface

```python
from typing import BinaryIO, Optional
from vantacore_engine.core.translation_base import TranslationBackend, PageFaultError

class CustomTranslationBackend(TranslationBackend):
    """Custom translation backend for specialized CPU architectures."""

    def __init__(self) -> None:
        """Initialize translation backend state."""
        self._dump_handle: Optional[BinaryIO] = None
        self._file_size: int = 0

    def initialize(self, dump_handle: BinaryIO, file_size: int) -> None:
        """Bind dump handle and discover address translation roots.

        Args:
            dump_handle: Open binary file handle.
            file_size: Total file size in bytes.

        """
        self._dump_handle = dump_handle
        self._file_size = file_size

    def read_physical(self, paddr: int, size: int) -> bytes:
        """Read bytes from physical offset.

        Args:
            paddr: Physical byte offset.
            size: Number of bytes to read.

        Returns:
            Byte array read from memory.

        """
        if self._dump_handle is None:
            raise PageFaultError("Backend uninitialized")
        if paddr < 0 or paddr + size > self._file_size:
            return b"\x00" * size
        self._dump_handle.seek(paddr)
        return self._dump_handle.read(size)

    def read_virtual(self, namespace: str, vaddr: int, size: int) -> bytes:
        """Translate virtual address in namespace and read bytes.

        Args:
            namespace: Address space identifier (e.g., 'GLOBAL_KERNEL').
            vaddr: Virtual address integer.
            size: Number of bytes to read.

        Returns:
            Translated byte buffer.

        """
        # Implement page table walk or mapping resolution here
        paddr = self.translate_vaddr(namespace, vaddr)
        if paddr is None:
            raise PageFaultError(f"Address {hex(vaddr)} not mapped")
        return self.read_physical(paddr, size)

    def get_architecture_name(self) -> str:
        """Return standardized architecture identifier."""
        return "custom_arch"
```
