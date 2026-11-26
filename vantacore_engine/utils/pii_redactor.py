"""Dual-layer PII redactor combining re2 regex and spaCy NER."""

import logging
from typing import Any, Dict, Set
import re2

logger = logging.getLogger(__name__)


class DualLayerPIIRedactor:
    """Dual-layer PII redactor combining deterministic regexes and contextual NER.

    Layer 1 uses Google RE2 for ReDoS-safe deterministic redaction of common
    structured PII (IPv4 addresses, email addresses, SSNs, credit cards, phone numbers).
    Layer 2 uses spaCy NER for contextual entity redaction (PERSON, ORG, GPE, LOC, FAC).
    """

    _IPV4_PATTERN = re2.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _EMAIL_PATTERN = re2.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _SSN_PATTERN = re2.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    _CC_PATTERN = re2.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    _PHONE_PATTERN = re2.compile(
        r"(?:(?:\+1|\b1)[-.\s]*)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )

    _NER_ENTITY_LABELS: Set[str] = {"PERSON", "ORG", "GPE", "LOC", "FAC"}
    _PLACEHOLDER_PATTERN = re2.compile(r"\[REDACTED_[A-Z]+\]")
    _OVERSIZED_TOKEN_PATTERN = re2.compile(r"\S{500,}")

    def __init__(
        self,
        ner_model: str = "en_core_web_sm",
        *,
        model_name: str | None = None,
    ) -> None:
        """Initialize the PII redactor.

        Args:
            ner_model: spaCy language model name to load for Layer 2 NER.
                Defaults to 'en_core_web_sm'. If loading fails, Layer 1 regex
                redaction remains active and a warning is logged.
            model_name: Optional alias for ner_model kept for backward compatibility.

        """
        effective_model = model_name if model_name is not None else ner_model
        self._model_name = effective_model
        self._nlp = None

        try:
            import spacy

            self._nlp = spacy.load(effective_model)
        except Exception as exc:
            logger.warning(
                "spaCy model '%s' could not be loaded: %s. "
                "Contextual NER layer disabled; deterministic regex layer active.",
                effective_model,
                exc,
            )

    def redact(self, text: str) -> str:
        """Redact PII from the provided string using dual-layer pipeline.

        Args:
            text: Input string potentially containing PII.

        Returns:
            Sanitized string with PII replaced by redaction placeholders.

        """
        if not text:
            return text

        # Layer 1: Deterministic regex substitutions
        redacted = self._EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
        redacted = self._CC_PATTERN.sub("[REDACTED_CC]", redacted)
        redacted = self._SSN_PATTERN.sub("[REDACTED_SSN]", redacted)
        redacted = self._PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)
        redacted = self._IPV4_PATTERN.sub("[REDACTED_IP]", redacted)

        # Layer 2: spaCy NER contextual substitutions
        if self._nlp is not None:
            # Replace oversized non-whitespace tokens (>1024 chars) with equal-length
            # spaces in a temporary view for spaCy so NER stays linear-time without
            # shifting character offsets in `redacted`.
            ner_parts: list[str] = []
            last_idx = 0
            for match in self._OVERSIZED_TOKEN_PATTERN.finditer(redacted):
                start, end = match.span()
                ner_parts.append(redacted[last_idx:start])
                ner_parts.append(" " * (end - start))
                last_idx = end
            ner_input = "".join(ner_parts) + redacted[last_idx:] if ner_parts else redacted

            if ner_input.strip():
                doc = self._nlp(ner_input)
                placeholder_spans = [
                    (m.start(), m.end())
                    for m in self._PLACEHOLDER_PATTERN.finditer(redacted)
                ]
                # Filter entities and avoid re-redacting or overlapping existing placeholders
                ents = [
                    ent
                    for ent in doc.ents
                    if ent.label_ in self._NER_ENTITY_LABELS
                    and "REDACTED_" not in ent.text
                    and not any(
                        ent.start_char < pe and ent.end_char > ps
                        for ps, pe in placeholder_spans
                    )
                ]
                # Sort in reverse start char order to prevent offset drift
                ents.sort(key=lambda e: e.start_char, reverse=True)

                for ent in ents:
                    placeholder = f"[REDACTED_{ent.label_}]"
                    redacted = (
                        redacted[: ent.start_char]
                        + placeholder
                        + redacted[ent.end_char :]
                    )

        return redacted

    def redact_dict(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact all string values in a dictionary structure.

        Args:
            record: Mapping of keys to values (can be nested with dicts/lists).

        Returns:
            New dictionary with all string values redacted. Original is not mutated.

        """
        result: Dict[str, Any] = {}
        for key, val in record.items():
            if isinstance(val, str):
                result[key] = self.redact(val)
            elif isinstance(val, dict):
                result[key] = self.redact_dict(val)
            elif isinstance(val, list):
                result[key] = [
                    self.redact(item)
                    if isinstance(item, str)
                    else self.redact_dict(item)
                    if isinstance(item, dict)
                    else item
                    for item in val
                ]
            else:
                result[key] = val
        return result
