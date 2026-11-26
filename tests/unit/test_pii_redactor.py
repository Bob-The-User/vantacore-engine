"""Unit tests for DualLayerPIIRedactor."""

import pytest
from vantacore_engine.utils.pii_redactor import DualLayerPIIRedactor


@pytest.fixture(scope="module")
def redactor() -> DualLayerPIIRedactor:
    """Fixture providing a standard DualLayerPIIRedactor instance."""
    return DualLayerPIIRedactor()


def test_redact_ipv4(redactor: DualLayerPIIRedactor) -> None:
    """Verify IPv4 addresses are redacted with [REDACTED_IP]."""
    text = "The server at 192.168.1.1 connected to 10.0.0.254 on port 80."
    redacted = redactor.redact(text)
    assert "192.168.1.1" not in redacted
    assert "10.0.0.254" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert redacted == "The server at [REDACTED_IP] connected to [REDACTED_IP] on port 80."


def test_redact_email(redactor: DualLayerPIIRedactor) -> None:
    """Verify email addresses are redacted with [REDACTED_EMAIL]."""
    text = "Contact support at support@example.com or admin.root@corp.internal for access."
    redacted = redactor.redact(text)
    assert "support@example.com" not in redacted
    assert "admin.root@corp.internal" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert redacted == "Contact support at [REDACTED_EMAIL] or [REDACTED_EMAIL] for access."


def test_redact_ssn(redactor: DualLayerPIIRedactor) -> None:
    """Verify Social Security Numbers are redacted with [REDACTED_SSN]."""
    text = "Employee SSN: 123-45-6789 on record."
    redacted = redactor.redact(text)
    assert "123-45-6789" not in redacted
    assert "[REDACTED_SSN]" in redacted
    assert redacted == "Employee SSN: [REDACTED_SSN] on record."


def test_redact_credit_card(redactor: DualLayerPIIRedactor) -> None:
    """Verify Credit Card numbers are redacted with [REDACTED_CC]."""
    text = "Card 4111-2222-3333-4444 and 5500 0000 0000 0004 charged."
    redacted = redactor.redact(text)
    assert "4111-2222-3333-4444" not in redacted
    assert "5500 0000 0000 0004" not in redacted
    assert "[REDACTED_CC]" in redacted
    assert redacted == "Card [REDACTED_CC] and [REDACTED_CC] charged."


def test_redact_phone(redactor: DualLayerPIIRedactor) -> None:
    """Verify phone numbers are redacted with [REDACTED_PHONE]."""
    text = "Call 555-123-4567 or +1-800-555-0199 for assistance."
    redacted = redactor.redact(text)
    assert "555-123-4567" not in redacted
    assert "+1-800-555-0199" not in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert redacted == "Call [REDACTED_PHONE] or [REDACTED_PHONE] for assistance."


def test_redact_ner_person_org(redactor: DualLayerPIIRedactor) -> None:
    """Verify named persons and organizations are redacted via spaCy NER."""
    text = "John Smith was hired by Microsoft Corporation in Seattle."
    redacted = redactor.redact(text)
    assert "John Smith" not in redacted
    assert "Microsoft Corporation" not in redacted
    assert "[REDACTED_PERSON]" in redacted
    assert "[REDACTED_ORG]" in redacted


def test_redact_spacy_unavailable_fallback() -> None:
    """Verify fallback to regex-only redaction when spaCy model fails to load."""
    fallback_redactor = DualLayerPIIRedactor(model_name="nonexistent_spacy_model_xyz")
    assert fallback_redactor._nlp is None

    text = "User at 10.1.2.3 sent email to test@domain.org regarding John Smith."
    redacted = fallback_redactor.redact(text)
    # Regex layer should succeed
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "10.1.2.3" not in redacted
    assert "test@domain.org" not in redacted
    # Person not redacted because NER is disabled
    assert "John Smith" in redacted


def test_redact_idempotent(redactor: DualLayerPIIRedactor) -> None:
    """Verify redacting already-redacted text is idempotent and does not corrupt markers."""
    text = "Alice Johnson at 172.16.0.1 emailed ops@corp.net from Google."
    pass1 = redactor.redact(text)
    pass2 = redactor.redact(pass1)
    pass3 = redactor.redact(pass2)
    assert pass1 == pass2 == pass3


def test_redact_dict(redactor: DualLayerPIIRedactor) -> None:
    """Verify recursive dictionary redaction without mutating original record."""
    original = {
        "user": "Alice Cooper",
        "ip": "10.0.0.1",
        "contact": {
            "email": "alice@corp.com",
            "phone": "555-987-6543",
        },
        "tags": ["192.168.1.50", "admin", 42],
        "count": 100,
        "active": True,
    }

    result = redactor.redact_dict(original)

    # Original unchanged
    assert original["user"] == "Alice Cooper"
    assert original["ip"] == "10.0.0.1"
    assert original["contact"]["email"] == "alice@corp.com"
    assert original["tags"][0] == "192.168.1.50"

    # Redacted correctly
    assert "[REDACTED_PERSON]" in result["user"] or "[REDACTED" in result["user"]
    assert result["ip"] == "[REDACTED_IP]"
    assert result["contact"]["email"] == "[REDACTED_EMAIL]"
    assert result["contact"]["phone"] == "[REDACTED_PHONE]"
    assert result["tags"][0] == "[REDACTED_IP]"
    assert result["tags"][1] == "admin"
    assert result["tags"][2] == 42
    assert result["count"] == 100
    assert result["active"] is True


def test_redact_ner_model_alias_and_oversized_blob_speed() -> None:
    """Verify ner_model parameter, marker integrity, and fast execution on 50KB non-prose blobs."""
    import time

    r = DualLayerPIIRedactor(ner_model="en_core_web_sm")
    evil = ("a" * 25000) + "@" + ("b" * 25000) + " " + ("123-" * 5000)
    t0 = time.perf_counter()
    _ = r.redact(evil)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert elapsed_ms < 250.0

    # Existing placeholder text must never be re-tagged into nested brackets
    sample = "Host 10.0.0.1 and REDACTED_IP and Alice Johnson at Microsoft Corporation"
    out = r.redact(sample)
    assert "[[" not in out and "]]" not in out
    assert r.redact(out) == out
