"""Post-parse format-string filter for ASA extractor output."""

import logging
import re2

logger = logging.getLogger(__name__)

_FORMAT_SPECIFIER_PATTERN = re2.compile(r"^%[a-zA-Z]$")

_EXACT_BLOCKLIST = {
    "%s",
    "%d",
    "%i",
    "%x",
    "%u",
    "%p",
    "%f",
    "<key>",
    "public",
    "private",
    "(null)",
    "NULL",
    "none",
    "None",
}


def filter_record(record: dict) -> dict:
    """Return new dict with format-string contaminated values replaced by None.

    Args:
        record: Flat dictionary of extracted values.

    Returns:
        New dict (original not mutated) with contaminated string values set to None.

    """
    filtered = {}
    for key, val in record.items():
        if isinstance(val, str):
            if val in _EXACT_BLOCKLIST or _FORMAT_SPECIFIER_PATTERN.match(val):
                logger.debug("Filtered contaminated value for key '%s' (len=%d)", key, len(val))
                filtered[key] = None
            else:
                filtered[key] = val
        else:
            filtered[key] = val
    return filtered
