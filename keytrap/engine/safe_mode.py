"""Safe-mode policy for scans."""

from __future__ import annotations

import os
from typing import Any


def safe_mode_enabled(options: dict[str, Any] | None = None) -> bool:
    options = options or {}
    env_value = os.environ.get("SAFE_MODE", "").lower()
    return bool(options.get("safe_mode")) or env_value in {"1", "true", "yes", "on"}


def apply_safe_mode(options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return scan options with conservative safe-mode constraints applied."""
    merged = dict(options or {})
    if not safe_mode_enabled(merged):
        return merged

    merged.update(
        {
            "safe_mode": True,
            "max_workers": 1,
            "external_validation": False,
            "rate_limit": "conservative",
            "strict_scope": True,
        }
    )
    return merged
