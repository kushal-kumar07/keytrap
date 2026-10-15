"""Rule loading and validation utilities."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import re
import threading
from typing import Any

import yaml


CONFIDENCE_MAP: dict[str, float] = {
    "low": 0.4,
    "medium": 0.7,
    "high": 0.9,
}

REQUIRED_FIELDS = (
    "id",
    "name",
    "provider",
    "category",
    "severity",
    "confidence",
    "regex",
    "secret_group",
    "redaction",
    "tags",
    "allowlist",
    "source",
)


@dataclass(frozen=True)
class Rule:
    """Validated rule definition loaded from YAML."""

    rule_id: str
    name: str
    provider: str
    category: str
    severity: str
    confidence: float
    regex: str
    pattern: re.Pattern[str]
    secret_group: int
    redaction: str
    tags: tuple[str, ...]
    allowlist: dict[str, tuple[str, ...]]
    source: dict[str, Any]


class RuleLoader:
    """Load and validate regex rules from YAML sources."""

    def __init__(self, production: bool | None = None) -> None:
        environment = os.environ.get("ENVIRONMENT", "development").lower()
        self.production = production if production is not None else environment == "production"
        self.rules: list[Rule] = []
        self._logger = logging.getLogger(__name__)

    def load(self, directory: Path) -> tuple[int, int]:
        """Load rules from a directory of YAML files."""
        if not directory.exists():
            raise FileNotFoundError(f"Rule directory not found: {directory}")

        self.rules = []
        loaded_count = 0
        failed_count = 0

        yaml_files = sorted(
            set(directory.rglob("*.yml")).union(directory.rglob("*.yaml"))
        )

        for yaml_file in yaml_files:
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                failed_count += 1
                self._log_failure(yaml_file.name, f"Invalid YAML: {exc}")
                continue

            rules = data.get("rules", [])
            if not isinstance(rules, list):
                failed_count += 1
                self._log_failure(yaml_file.name, "Rules list missing or invalid")
                continue

            for raw_rule in rules:
                if not isinstance(raw_rule, dict):
                    failed_count += 1
                    self._log_failure(yaml_file.name, "Rule entry is not a mapping")
                    continue

                rule_id = raw_rule.get("id", "unknown")
                missing = [field for field in REQUIRED_FIELDS if field not in raw_rule]
                if missing:
                    failed_count += 1
                    self._log_failure(rule_id, f"Missing fields: {', '.join(missing)}")
                    continue

                try:
                    pattern = re.compile(str(raw_rule["regex"]))
                except re.error as exc:
                    failed_count += 1
                    self._log_failure(rule_id, f"Regex compile failed: {exc}")
                    continue

                if not self._passes_redos_check(rule_id, pattern):
                    failed_count += 1
                    continue

                allowlist = self._normalize_allowlist(raw_rule.get("allowlist"), rule_id)
                if allowlist is None:
                    failed_count += 1
                    continue

                confidence = self._normalize_confidence(raw_rule.get("confidence"))
                if confidence is None:
                    failed_count += 1
                    self._log_failure(rule_id, "Invalid confidence value")
                    continue

                tags = raw_rule.get("tags", [])
                if not isinstance(tags, list):
                    failed_count += 1
                    self._log_failure(rule_id, "Tags must be a list")
                    continue

                source = raw_rule.get("source", {})
                if not isinstance(source, dict) or not {
                    "origin",
                    "license",
                    "reviewed",
                }.issubset(source.keys()):
                    failed_count += 1
                    self._log_failure(rule_id, "Source metadata missing required fields")
                    continue

                try:
                    secret_group = int(raw_rule.get("secret_group", 0))
                except (TypeError, ValueError):
                    failed_count += 1
                    self._log_failure(rule_id, "secret_group must be an integer")
                    continue

                rule = Rule(
                    rule_id=str(raw_rule["id"]),
                    name=str(raw_rule["name"]),
                    provider=str(raw_rule["provider"]),
                    category=str(raw_rule["category"]),
                    severity=str(raw_rule["severity"]),
                    confidence=confidence,
                    regex=str(raw_rule["regex"]),
                    pattern=pattern,
                    secret_group=secret_group,
                    redaction=str(raw_rule["redaction"]),
                    tags=tuple(str(tag) for tag in tags),
                    allowlist=allowlist,
                    source=source,
                )
                self.rules.append(rule)
                loaded_count += 1

        return loaded_count, failed_count

    def _normalize_confidence(self, value: Any) -> float | None:
        if isinstance(value, (int, float)):
            numeric = float(value)
            if 0.0 <= numeric <= 1.0:
                return numeric
            return None
        if isinstance(value, str):
            return CONFIDENCE_MAP.get(value.lower())
        return None

    def _normalize_allowlist(
        self,
        allowlist: Any,
        rule_id: str,
    ) -> dict[str, tuple[str, ...]] | None:
        if not isinstance(allowlist, dict):
            self._log_failure(rule_id, "Allowlist must be a mapping")
            return None

        paths = allowlist.get("paths", [])
        values = allowlist.get("values", [])
        if not isinstance(paths, list) or not isinstance(values, list):
            self._log_failure(rule_id, "Allowlist paths and values must be lists")
            return None

        return {
            "paths": tuple(str(path) for path in paths),
            "placeholder_values": tuple(str(value) for value in values),
        }

    def _passes_redos_check(self, rule_id: str, pattern: re.Pattern[str]) -> bool:
        if _looks_catastrophic(pattern.pattern):
            self._log_failure(rule_id, "Regex rejected by heuristic")
            return False

        adversarial = "a" * 10000 + "!"
        error_holder: list[Exception] = []

        def worker() -> None:
            try:
                pattern.search(adversarial)
            except Exception as exc:  # pragma: no cover - defensive
                error_holder.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        timer_triggered = threading.Event()

        def on_timeout() -> None:
            timer_triggered.set()

        timeout_seconds = _redos_timeout_seconds()
        timer = threading.Timer(timeout_seconds, on_timeout)
        timer.start()
        thread.start()
        thread.join(timeout_seconds)
        timer.cancel()

        if thread.is_alive() or timer_triggered.is_set():
            self._log_failure(rule_id, "Regex failed ReDoS timeout")
            return False
        if error_holder:
            self._log_failure(rule_id, "Regex execution failed")
            return False
        return True

    def _log_failure(self, rule_id: str, reason: str) -> None:
        self._logger.warning("Rule %s rejected: %s", rule_id, reason)


def _looks_catastrophic(pattern: str) -> bool:
    return bool(re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern))


def _redos_timeout_seconds() -> float:
    value = os.environ.get("KEYTRAP_REDOS_TIMEOUT_MS")
    if not value:
        return 0.1
    try:
        timeout_ms = float(value)
    except ValueError:
        return 0.1
    return max(0.01, timeout_ms / 1000.0)
