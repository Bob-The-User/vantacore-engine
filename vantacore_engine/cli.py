"""CLI entry point and command implementation for VantaCore Engine."""

import argparse
import json

import os
import sys
from rich.console import Console
from rich.table import Table

from vantacore_engine import __version__
from vantacore_engine.core.backends.appliances.generic_flat import GenericFlatDetector
from vantacore_engine.core.backends.appliances.registry import PlatformDetectorRegistry
from vantacore_engine.core.backends.detector import ArchitectureDetector
from vantacore_engine.core.entropy import EncryptedMemoryDetector


def _cmd_version(args: argparse.Namespace) -> None:
    """Print version information and exit.

    Args:
        args: Command-line arguments from argparse.

    """
    print(f"vantacore-engine {__version__}")
    print(f"Python {sys.version}")
    sys.exit(0)


def _cmd_scan(args: argparse.Namespace) -> None:
    """Scan a memory image (stub).

    Args:
        args: Command-line arguments from argparse.

    """
    print("'scan' is not available yet. It will be implemented in a later phase.")
    sys.exit(0)


def _cmd_detect(args: argparse.Namespace) -> None:
    """Detect network appliances and architecture of a memory dump.

    Args:
        args: Command-line arguments from argparse.

    """
    try:
        fh = open(args.dump, "rb")
    except (FileNotFoundError, PermissionError) as err:
        print(f"Error opening dump file: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        file_size = os.path.getsize(args.dump)
        enc = EncryptedMemoryDetector().detect(fh, file_size)
        if enc["likely_encrypted"]:
            print(
                f"WARNING: Dump shows high entropy ({enc['entropy']:.2f}). Memory may be encrypted.",
                file=sys.stderr,
            )

        registry = PlatformDetectorRegistry()
        detector = registry.detect(fh, file_size)

        if detector is None:
            detector = GenericFlatDetector()
            confidence = 0.1
        else:
            fh.seek(0)
            confidence = detector.detect(fh, file_size)

        arch_detector = ArchitectureDetector()
        fh.seek(0)
        backend = arch_detector.detect(fh, file_size)
    finally:
        fh.close()

    result = {
        "platform_name": detector.platform_name(),
        "confidence": round(confidence, 3),
        "translation_backend": backend.get_architecture_name(),
        "extractor_paths": detector.get_compatible_extractor_paths(),
        "encrypted": enc["likely_encrypted"],
    }

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        console = Console()
        table = Table(title="VantaCore Memory Dump Detection")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Platform Name", result["platform_name"])
        table.add_row("Confidence Score", str(result["confidence"]))
        table.add_row("Translation Backend", result["translation_backend"])
        table.add_row("Extractor Paths", ", ".join(result["extractor_paths"]))
        table.add_row("Likely Encrypted", str(result["encrypted"]))
        console.print(table)

    sys.exit(0)


def _cmd_verify(args: argparse.Namespace) -> None:
    """Verify memory dump integrity (stub).

    Args:
        args: Command-line arguments from argparse.

    """
    print("'verify' is not available yet. It will be implemented in a later phase.")
    sys.exit(0)


def main() -> None:
    """CLI entry point for VantaCore Engine."""
    parser = argparse.ArgumentParser(description="VantaCore Engine CLI")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    version_parser = subparsers.add_parser("version", help="Print version info")
    version_parser.set_defaults(func=_cmd_version)

    scan_parser = subparsers.add_parser("scan", help="Scan a memory image")
    scan_parser.add_argument("args", nargs="*", help="Arguments for scan")
    scan_parser.set_defaults(func=_cmd_scan)

    detect_parser = subparsers.add_parser("detect", help="Detect network appliances")
    detect_parser.add_argument("dump", help="Path to memory dump file")
    detect_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    detect_parser.set_defaults(func=_cmd_detect)

    verify_parser = subparsers.add_parser("verify", help="Verify memory dump integrity")
    verify_parser.add_argument("args", nargs="*", help="Arguments for verify")
    verify_parser.set_defaults(func=_cmd_verify)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(0)

