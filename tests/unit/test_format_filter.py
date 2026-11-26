"""Unit tests for PostParseFormatFilter format-string sanitization."""

from vantacore_engine.utils.format_filter import filter_record


def test_printf_specifier_removed() -> None:
    """Verify printf specifier %s is filtered to None."""
    assert filter_record({"ip": "%s"}) == {"ip": None}


def test_lina_constant_public_removed() -> None:
    """Verify default SNMP string 'public' is filtered to None."""
    assert filter_record({"community": "public"}) == {"community": None}


def test_lina_constant_private_removed() -> None:
    """Verify default SNMP string 'private' is filtered to None."""
    assert filter_record({"community": "private"}) == {"community": None}


def test_valid_ip_preserved() -> None:
    """Verify valid IP address is preserved unchanged."""
    assert filter_record({"ip": "192.168.1.1"}) == {"ip": "192.168.1.1"}


def test_non_string_values_preserved() -> None:
    """Verify integers, booleans, and non-strings are preserved unchanged."""
    assert filter_record({"count": 42, "active": True}) == {"count": 42, "active": True}


def test_key_placeholder_removed() -> None:
    """Verify '<key>' placeholder is filtered to None."""
    assert filter_record({"key": "<key>"}) == {"key": None}


def test_empty_dict_handled() -> None:
    """Verify empty dictionary returns empty dictionary."""
    assert filter_record({}) == {}


def test_original_not_mutated() -> None:
    """Verify input dictionary is not mutated during filtering."""
    original = {"ip": "%s", "port": 80}
    result = filter_record(original)
    assert original["ip"] == "%s"
    assert result["ip"] is None
