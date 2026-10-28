"""Remove credentials from stored evidence. Synthetic canaries stay visible."""

from __future__ import annotations

import re

_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_MAX_CHARS = 1500


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    cleaned = text or ""
    for secret in secrets or []:
        if secret and secret in cleaned:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = _BEARER.sub("Bearer [REDACTED]", cleaned)
    if len(cleaned) > _MAX_CHARS:
        cleaned = cleaned[:_MAX_CHARS] + "\n...[truncated]"
    return cleaned
