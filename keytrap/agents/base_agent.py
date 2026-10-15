"""Base class for KeyTrap scanner agents."""

from __future__ import annotations

from abc import ABC, abstractmethod

from keytrap.engine.normalizer import normalize
from keytrap.engine.schema import FindingSchema


class BaseScannerAgent(ABC):
    """Shared scanner agent interface and safety helpers."""

    @abstractmethod
    def scan(self) -> list[FindingSchema]:
        """Scan and return normalized findings."""
        raise NotImplementedError

    def check_allowlist(
        self,
        file_path: str,
        value: str,
        allowlist: dict,
    ) -> bool:
        """Return True when a path or placeholder value should be suppressed."""
        normalized_path = file_path.lower().replace("\\", "/")
        path_prefixes = tuple(
            prefix.lower().strip("/")
            for prefix in allowlist.get("paths", ("tests", "docs", "examples"))
        )
        if normalized_path.startswith(path_prefixes) or any(
            f"/{prefix}/" in normalized_path for prefix in path_prefixes
        ):
            return True

        normalized_value = value.lower()
        placeholders = allowlist.get(
            "placeholder_values",
            ("example", "placeholder", "notreal", "fake", "test"),
        )
        return any(marker.lower() in normalized_value for marker in placeholders)

    def normalize(self, raw_dict: dict) -> FindingSchema:
        return normalize(raw_dict)
