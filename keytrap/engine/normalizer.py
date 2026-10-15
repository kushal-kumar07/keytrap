"""Normalize scanner agent output dictionaries into FindingSchema."""

from __future__ import annotations

from typing import Any

from keytrap.engine.schema import FindingSchema


class NormalizerError(ValueError):
    """Raised when scanner output cannot become a FindingSchema."""

    def __init__(self, field_name: str) -> None:
        self.field_name = field_name
        super().__init__(f"Invalid or missing normalized finding field: {field_name}")


REQUIRED_FIELDS: dict[str, type | tuple[type, ...]] = {
    "scan_id": str,
    "agent": str,
    "provider": str,
    "secret_type": str,
    "secret": str,
    "repo": str,
    "branch": str,
    "commit": str,
    "file_path": str,
    "line_start": int,
    "line_end": int,
    "context_before": str,
    "confidence": (float, int),
    "severity": str,
    "risk_score": int,
    "created_at": str,
}


def normalize(raw: dict[str, Any]) -> FindingSchema:
    """Convert a scanner output dictionary to FindingSchema."""
    for field_name, expected_type in REQUIRED_FIELDS.items():
        if field_name not in raw or not isinstance(raw[field_name], expected_type):
            raise NormalizerError(field_name)

    return FindingSchema(
        scan_id=raw["scan_id"],
        agent=raw["agent"],
        provider=raw["provider"],
        secret_type=raw["secret_type"],
        secret=raw["secret"],
        repo=raw["repo"],
        branch=raw["branch"],
        commit=raw["commit"],
        file_path=raw["file_path"],
        line_start=raw["line_start"],
        line_end=raw["line_end"],
        context_before=raw["context_before"],
        confidence=float(raw["confidence"]),
        severity=raw["severity"],
        risk_score=raw["risk_score"],
        created_at=raw["created_at"],
    )
