"""Data-minimization helpers for connector output and LLM prompts."""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEY_PARTS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "cookie",
    "session",
    "credential",
    "authorization",
    "private_key",
    "api_key",
    "private_message",
    "private_communication",
    "message_body",
    "raw_leak",
    "raw_record",
    "hash",
}

_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}")
_LONG_SECRET_PATTERN = re.compile(r"\b[a-zA-Z0-9_\-]{40,}\b")


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def redact_sensitive(value: Any, *, max_string_length: int = 4000) -> Any:
    """Recursively remove credentials while preserving evidentiary metadata."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                output[key_text] = "<redacted>"
            else:
                output[key_text] = redact_sensitive(
                    item, max_string_length=max_string_length
                )
        return output

    if isinstance(value, (list, tuple, set)):
        return [
            redact_sensitive(item, max_string_length=max_string_length)
            for item in value
        ]

    if isinstance(value, str):
        cleaned = _BEARER_PATTERN.sub("Bearer <redacted>", value)
        cleaned = _LONG_SECRET_PATTERN.sub("<redacted-long-value>", cleaned)
        if len(cleaned) > max_string_length:
            return cleaned[:max_string_length] + "…<truncated>"
        return cleaned

    return value
