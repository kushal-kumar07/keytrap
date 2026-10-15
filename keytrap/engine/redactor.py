"""Secret redaction utilities."""

from __future__ import annotations

import re

_MIN_REDACTABLE_LENGTH = 12
_MIN_SUFFIX_LENGTH = 20
_ALREADY_REDACTED = re.compile(r"[A-Za-z0-9_\-]{0,11}\*{4}[A-Za-z0-9_\-]{0,4}")


def redact(raw_secret: str, provider: str) -> str:
    """Return a redacted representation without exposing the full secret.

    Only well-known public provider prefixes are kept. Anything else shows at
    most the last four characters, and only when the value is long enough that
    four characters are a negligible share of it.
    """
    if _ALREADY_REDACTED.fullmatch(raw_secret):
        return raw_secret

    if len(raw_secret) < _MIN_REDACTABLE_LENGTH:
        return "****"

    for prefix in _prefixes_for(provider.lower()):
        if raw_secret.startswith(prefix):
            return f"{prefix}****{raw_secret[-4:]}"

    if len(raw_secret) >= _MIN_SUFFIX_LENGTH:
        return f"****{raw_secret[-4:]}"
    return "****"


def _prefixes_for(provider: str) -> tuple[str, ...]:
    if provider == "stripe":
        return ("sk_live_", "sk_test_", "rk_live_", "rk_test_")
    if provider in ("aws", "aws key"):
        return ("AKIA", "ASIA")
    if provider == "github":
        return ("github_pat_", "ghp_", "gho_", "ghs_", "ghu_")
    if provider == "slack":
        return ("xoxb-", "xoxp-", "xoxa-")
    return ()
