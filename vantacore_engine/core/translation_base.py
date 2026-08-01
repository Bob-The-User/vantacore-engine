"""Abstract base class and exceptions for memory translation backends."""

from abc import ABC, abstractmethod
from typing import BinaryIO, Optional


class TranslationError(RuntimeError):
    """Raised when critical translation bootstrapping fails."""


class PageFaultError(RuntimeError):
    """Raised when read_virtual() resolves zero pages."""


class TranslationBackend(ABC):
    """Abstract base class for physical-to-virtual address translation backends."""

    @abstractmethod
    def detect(self, dump_handle: BinaryIO) -> bool:
        """Detect if this translation backend supports the given memory dump.

        Args:
            dump_handle: Open file-like handle to the binary memory dump.

        Returns:
            True if the dump can be parsed by this backend, False otherwise.

        """

    @abstractmethod
    def initialize(self, dump_handle: BinaryIO, swap_path: Optional[str] = None) -> None:
        """Initialize page tables and backend state from the memory dump.

        Args:
            dump_handle: Open file-like handle to the binary memory dump.
            swap_path: Optional path to a Windows pagefile or swap image.

        Raises:
            TranslationError: If critical translation bootstrapping fails (e.g., cannot find valid PGD).

        """

    @abstractmethod
    def read_virtual(self, namespace_id: str, virtual_address: int, length: int) -> bytes:
        """Read a sequence of virtual memory bytes from the specified address space.

        Args:
            namespace_id: CR3 hex string for user-space process, or 'GLOBAL_KERNEL' for kernel context.
            virtual_address: Virtual memory address to start reading from.
            length: Number of bytes to read.

        Returns:
            Bytes object of exactly length bytes. Unresolvable regions within pages are zero-filled.

        Raises:
            PageFaultError: Only when zero pages could be resolved (total failure).

        """

    @abstractmethod
    def enumerate_processes(self) -> list[tuple[str, str, int]]:
        """Enumerate active processes found in the memory image.

        Returns:
            List of 3-tuples: (namespace_id, process_name, pid).
            namespace_id is a CR3 hex string for user-space processes, or 'GLOBAL_KERNEL' for kernel context.

        """

    @abstractmethod
    def get_kernel_base(self) -> int:
        """Get the calculated virtual base address of the kernel.

        Returns:
            Virtual base address of the kernel as an integer.

        """

    @abstractmethod
    def get_architecture_name(self) -> str:
        """Get the string identifier of the target architecture.

        Returns:
            Architecture name string (e.g., 'x86_64', 'arm64').

        """
