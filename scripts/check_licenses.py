#!/usr/bin/env python3
"""Script to audit dependencies for GPL licenses."""

import json
import sys
from typing import List, Dict

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


def main() -> None:
    """Main execution function to read JSON from stdin and audit."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from stdin: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("Expected JSON array from pip-licenses output", file=sys.stderr)
        sys.exit(1)

    sys.exit(audit_licenses(data))


if __name__ == "__main__":
    main()
