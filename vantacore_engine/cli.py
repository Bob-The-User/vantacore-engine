"""CLI entry point and command implementation for VantaCore Engine."""

import argparse
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import pkgutil
import sys
from rich.console import Console
from rich.table import Table

from vantacore_engine import __version__
from vantacore_engine.core.audit import ForensicAuditTrail
from vantacore_engine.core.backends.appliances.generic_flat import GenericFlatDetector
from vantacore_engine.core.backends.appliances.registry import PlatformDetectorRegistry
from vantacore_engine.core.backends.detector import ArchitectureDetector
from vantacore_engine.core.entropy import EncryptedMemoryDetector
from vantacore_engine.utils.validation import InputValidator
import vantacore_engine.extractors as _extractors_pkg
from vantacore_engine.extractors.base import BaseExtractor, ExtractorDAGExecutor


def _discover_extractors(include_secrets: bool = False) -> list[BaseExtractor]:
    """Walk vantacore_engine.extractors package and instantiate all BaseExtractor subclasses.

    Args:
        include_secrets: Whether to configure extractors with secrets extraction enabled.

    Returns:
        List of instantiated BaseExtractor instances.

    """
    extractors: list[BaseExtractor] = []
    prefix = _extractors_pkg.__name__ + "."
    for _, modname, ispkg in pkgutil.walk_packages(_extractors_pkg.__path__, prefix):
        if not ispkg:
            try:
                mod = importlib.import_module(modname)
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if (
                        issubclass(obj, BaseExtractor)
                        and obj is not BaseExtractor
                        and hasattr(obj, "name")
                        and obj.name
                    ):
                        sig = inspect.signature(obj.__init__)
                        if "include_secrets" in sig.parameters:
                            ext = obj(include_secrets=include_secrets)
                        else:
                            ext = obj()
                        extractors.append(ext)
            except Exception:
                continue
    return extractors


def _cmd_version(args: argparse.Namespace) -> None:
    """Print version information and exit.

    Args:
        args: Command-line arguments from argparse.

    """
    print(f"vantacore-engine {__version__}")
    print(f"Python {sys.version}")
    sys.exit(0)


def _cmd_scan(args: argparse.Namespace) -> None:
    """Execute end-to-end memory dump analysis and extraction workflow.

    Args:
        args: Command-line arguments from argparse.

    """
    if not hasattr(args, "dump") or not args.dump:
        print("Error: Path to memory dump file is required for scan.", file=sys.stderr)
        sys.exit(1)

    try:
        fh = open(args.dump, "rb")
    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"Error opening dump file: {err}", file=sys.stderr)
        sys.exit(1)

    audit: ForensicAuditTrail | None = None
    try:
        file_size = os.path.getsize(args.dump)

        # Compute SHA-256 in 4MB chunks
        h = hashlib.sha256()
        fh.seek(0)
        while chunk := fh.read(4 * 1024 * 1024):
            h.update(chunk)
        sha256 = h.hexdigest()
        fh.seek(0)

        enc = EncryptedMemoryDetector().detect(fh, file_size)
        if enc["likely_encrypted"]:
            print(
                f"WARNING: Dump shows high entropy ({enc['confidence']:.2f}). Memory may be encrypted.",
                file=sys.stderr,
            )

        registry = PlatformDetectorRegistry()
        fh.seek(0)
        detector = registry.detect(fh, file_size)

        if detector is None:
            detector = GenericFlatDetector()
            confidence = 0.1
        else:
            fh.seek(0)
            confidence = detector.detect(fh, file_size)

        platform_name = detector.platform_name()

        arch_detector = ArchitectureDetector()
        fh.seek(0)
        backend = arch_detector.detect(fh, file_size)
        arch_name = backend.get_architecture_name()

        output_dir = (
            Path(args.output_dir)
            if getattr(args, "output_dir", None)
            else Path(f"./vantacore_output_{sha256[:8]}")
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        audit_path = output_dir / "vantacore_audit.jsonl"
        audit = ForensicAuditTrail(audit_path, sha256)
        audit.record(
            ForensicAuditTrail.DUMP_INGESTED,
            file_path=args.dump,
            file_size=file_size,
            platform=platform_name,
            architecture=arch_name,
        )

        include_secrets = getattr(args, "include_secrets", False)
        all_extractors = _discover_extractors(include_secrets=include_secrets)
        dag_executor = ExtractorDAGExecutor(all_extractors, platform_name)

        fh.seek(0)
        result = dag_executor.execute(backend, fh, output_dir)

        audit.record(
            ForensicAuditTrail.SCAN_COMPLETED,
            scan_status=result.get("scan_status", {}),
        )

        output_json_path = output_dir / "vantacore_output.json"
        with open(output_json_path, "w", encoding="utf-8") as out_f:
            json.dump(result, out_f, indent=2)

    finally:
        if audit is not None:
            audit.close()
        fh.close()

    if getattr(args, "json_output", False):
        print(json.dumps(result, indent=2))
    else:
        console = Console()
        table = Table(title="VantaCore Scan Complete")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Dump file", args.dump)
        table.add_row("SHA-256", sha256)
        table.add_row("Platform", f"{platform_name} (confidence: {confidence:.2f})")
        table.add_row("Architecture", arch_name)
        scan_status = result.get("scan_status", {})
        table.add_row("Scan status", str(scan_status.get("overall", "UNKNOWN")))
        table.add_row(
            "Extractors succeeded", str(len(scan_status.get("extractors_succeeded", [])))
        )
        table.add_row("Extractors failed", str(len(scan_status.get("extractors_failed", []))))
        table.add_row("Output directory", str(output_dir))
        table.add_row("Audit trail", str(output_dir / "vantacore_audit.jsonl"))
        console.print(table)

    sys.exit(0)


def _cmd_detect(args: argparse.Namespace) -> None:
    """Detect network appliances and architecture of a memory dump.

    Args:
        args: Command-line arguments from argparse.

    """
    if not hasattr(args, "dump") or not args.dump:
        print("Error: Path to memory dump file is required for detect.", file=sys.stderr)
        sys.exit(1)

    try:
        fh = open(args.dump, "rb")
    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"Error opening dump file: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        file_size = os.path.getsize(args.dump)
        enc = EncryptedMemoryDetector().detect(fh, file_size)
        if enc["likely_encrypted"]:
            print(
                f"WARNING: Dump shows high entropy ({enc['confidence']:.2f}). Memory may be encrypted.",
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
    """Verify memory dump integrity, headers, platform, and architecture.

    Args:
        args: Command-line arguments from argparse.

    """
    if not hasattr(args, "dump") or not args.dump:
        print("Error: Path to memory dump file is required for verify.", file=sys.stderr)
        sys.exit(1)

    try:
        fh = open(args.dump, "rb")
    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"Error opening dump file: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        file_size = os.path.getsize(args.dump)

        # Compute SHA-256 in 4MB chunks
        h = hashlib.sha256()
        fh.seek(0)
        while chunk := fh.read(4 * 1024 * 1024):
            h.update(chunk)
        sha256 = h.hexdigest()

        elf_valid = False
        try:
            fh.seek(0)
            magic = fh.read(4)
            if magic == b"\x7fELF":
                fh.seek(0)
                InputValidator.validate_elf_header(fh)
                elf_valid = True
        except Exception:
            elf_valid = False

        fh.seek(0)
        enc = EncryptedMemoryDetector().detect(fh, file_size)

        fh.seek(0)
        registry = PlatformDetectorRegistry()
        detector = registry.detect(fh, file_size)
        if detector is None:
            detector = GenericFlatDetector()
            confidence = 0.1
        else:
            fh.seek(0)
            confidence = detector.detect(fh, file_size)
        platform_name = detector.platform_name()

        fh.seek(0)
        arch_detector = ArchitectureDetector()
        backend = arch_detector.detect(fh, file_size)
        arch_name = backend.get_architecture_name()

    finally:
        fh.close()

    result = {
        "sha256": sha256,
        "file_size": file_size,
        "elf_valid": elf_valid,
        "platform": platform_name,
        "confidence": round(confidence, 3),
        "architecture": arch_name,
        "encrypted": enc["likely_encrypted"],
    }

    if getattr(args, "json_output", False):
        print(json.dumps(result, indent=2))
    else:
        console = Console()
        table = Table(title="VantaCore Memory Dump Verification")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("SHA-256", sha256)
        table.add_row("File Size", f"{file_size} bytes")
        table.add_row("ELF Header Valid", str(elf_valid))
        table.add_row("Platform", f"{platform_name} (confidence: {confidence:.2f})")
        table.add_row("Architecture", arch_name)
        table.add_row("Likely Encrypted", str(enc["likely_encrypted"]))
        console.print(table)

    sys.exit(0)


def main() -> None:
    """CLI entry point for VantaCore Engine."""
    parser = argparse.ArgumentParser(description="VantaCore Engine CLI")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    version_parser = subparsers.add_parser("version", help="Print version info")
    version_parser.set_defaults(func=_cmd_version)

    scan_parser = subparsers.add_parser("scan", help="Scan a memory image")
    scan_parser.add_argument("dump", nargs="?", default=None, help="Path to memory dump file")
    scan_parser.add_argument(
        "--output-dir", default=None, dest="output_dir", help="Output directory for scan artifacts"
    )
    scan_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    scan_parser.add_argument(
        "--include-secrets",
        action="store_true",
        dest="include_secrets",
        help="Include extracted secrets in plaintext",
    )
    scan_parser.add_argument("--workers", type=int, default=None, help="Number of worker processes")
    scan_parser.add_argument("--timeout", type=int, default=3600, help="Scan timeout in seconds")
    scan_parser.set_defaults(func=_cmd_scan)

    detect_parser = subparsers.add_parser("detect", help="Detect network appliances")
    detect_parser.add_argument("dump", nargs="?", default=None, help="Path to memory dump file")
    detect_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    detect_parser.set_defaults(func=_cmd_detect)

    verify_parser = subparsers.add_parser("verify", help="Verify memory dump integrity")
    verify_parser.add_argument("dump", nargs="?", default=None, help="Path to memory dump file")
    verify_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    verify_parser.set_defaults(func=_cmd_verify)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(0)
