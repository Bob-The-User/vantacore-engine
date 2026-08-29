#!/usr/bin/env python3
"""Script to audit dependencies for GPL licenses.

Can be run in two ways:
  Standalone (default): pixi run python scripts/check_licenses.py
  Piped (explicit):     pixi run pip-licenses --format=json | pixi run python scripts/check_licenses.py --from-stdin

The script always self-invokes pip-licenses as a subprocess unless
--from-stdin is explicitly passed. This works correctly in both
interactive terminals and non-interactive CI environments.
"""

import json
import subprocess
import sys
from typing import Dict, List

# Allowlist for permitted GPL-like licenses (specifically LGPL)
LGPL_ALLOWLIST = [
    "LGPL",
    "GNU Lesser General Public License",
    "Lesser GPL",
]


# Packages to ignore in the audit (e.g. the package itself, dual-licensed dev deps)
IGNORED_PACKAGES = [
    "vantacore-engine",
    "docutils",
]


def audit_licenses(packages: List[Dict[str, str]]) -> int:
    """Audit the licenses of input packages.

    Args:
        packages: A list of dictionaries representing packages, where each
            dictionary has 'Name' and 'License' keys.

    Returns:
        0 if the audit passes (no non-allowed GPL licenses), 1 otherwise.
    """
    gpl_packages = []
    for pkg in packages:
        name = pkg.get("Name", "Unknown")
        if name in IGNORED_PACKAGES:
            continue

        license_str = pkg.get("License", "Unknown")

        # Check if the license string contains "GPL"
        if "GPL" in license_str:
            # Check if it matches any allowlisted LGPL variant
            is_allowlisted = any(
                allow in license_str for allow in LGPL_ALLOWLIST
            )
            if not is_allowlisted:
                gpl_packages.append(pkg)

    if gpl_packages:
        print(
            "License audit: FAILED. Found GPL-licensed dependencies:",
            file=sys.stderr,
        )
        for pkg in gpl_packages:
            print(
                f"  - {pkg.get('Name', 'Unknown')}: {pkg.get('License', 'Unknown')}",
                file=sys.stderr,
            )
        return 1

    print("License audit: PASS")
    return 0


def _fetch_licenses_via_subprocess() -> List[Dict[str, str]]:
    """Run pip-licenses and return parsed JSON output.

    Returns:
        A list of package license dictionaries.

    Raises:
        SystemExit: If pip-licenses is not available or returns non-zero.
    """
    # Resolve the pip-licenses binary relative to the current Python interpreter
    # so it always uses the same pixi environment, regardless of PATH.
    pip_licenses_bin = str(
        __import__("pathlib").Path(sys.executable).parent / "pip-licenses"
    )

    try:
        result = subprocess.run(
            [pip_licenses_bin, "--format=json"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            f"Error: pip-licenses not found at {pip_licenses_bin}. "
            "Install it with: pixi add pip-licenses",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode != 0:
        print(
            f"Error: pip-licenses exited with code {result.returncode}:\n{result.stderr}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Error parsing pip-licenses JSON output: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Main execution function.

    Reads license data from stdin when --from-stdin is passed explicitly,
    otherwise always self-invokes pip-licenses as a subprocess. This works
    correctly in both interactive terminals and non-interactive CI environments.
    """
    if "--from-stdin" in sys.argv:
        # Explicit pipe mode: caller piped pip-licenses JSON to us
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON from stdin: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Default mode: self-invoke pip-licenses (works in TTY and CI)
        data = _fetch_licenses_via_subprocess()

    if not isinstance(data, list):
        print("Expected JSON array from pip-licenses output", file=sys.stderr)
        sys.exit(1)

    sys.exit(audit_licenses(data))


if __name__ == "__main__":
    main()
