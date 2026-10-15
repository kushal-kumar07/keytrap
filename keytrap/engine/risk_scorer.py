"""Risk scoring for normalized findings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from keytrap.engine.schema import FindingSchema


SIGNALS = (
    "provider_specific_live_key",
    "public_repo_or_commit",
    "production_file_path",
    "multiple_scanner_agents",
    "old_deleted_commit",
    "multiple_branches",
    "file_modified_last_7_days",
    "repo_over_100_stars",
    "test_docs_examples_fixtures_path",
    "obvious_placeholder_value",
)


def score(
    finding: FindingSchema,
    metadata: dict[str, Any] | None = None,
) -> tuple[int, dict[str, int]]:
    """Score a finding from 0 to 100 and return signal contributions."""
    metadata = metadata or {}
    breakdown = {signal: 0 for signal in SIGNALS}

    if _provider_specific_live_key(finding):
        breakdown["provider_specific_live_key"] = 30
    if metadata.get("public_repo") or metadata.get("public_commit"):
        breakdown["public_repo_or_commit"] = 25
    if _production_path(finding.file_path):
        breakdown["production_file_path"] = 20
    if _multiple_agents(metadata):
        breakdown["multiple_scanner_agents"] = 15
    if metadata.get("old_deleted_commit"):
        breakdown["old_deleted_commit"] = 10
    if _multiple_branches(metadata):
        breakdown["multiple_branches"] = 10
    if _modified_last_7_days(metadata.get("file_modified_at")):
        breakdown["file_modified_last_7_days"] = 15
    if int(metadata.get("repo_stars", 0) or 0) > 100:
        breakdown["repo_over_100_stars"] = 10
    if _low_signal_path(finding.file_path):
        breakdown["test_docs_examples_fixtures_path"] = -25
    if metadata.get("placeholder_value") or _placeholder(finding.secret):
        breakdown["obvious_placeholder_value"] = -25

    raw_score = sum(breakdown.values())
    return max(0, min(100, raw_score)), breakdown


def _provider_specific_live_key(finding: FindingSchema) -> bool:
    value = finding.secret
    provider = finding.provider
    return (
        (provider == "stripe" and value.startswith("sk_live_"))
        or (provider == "aws" and (value.startswith("AKIA") or "****" in value))
        or (provider == "github" and value.startswith(("ghp_", "gho_")))
        or (provider == "slack" and value.startswith("xoxb-"))
    )


def _production_path(file_path: str) -> bool:
    path = file_path.lower()
    return any(part in path for part in (".env", "config", "deploy", "terraform"))


def _low_signal_path(file_path: str) -> bool:
    normalized = file_path.lower().replace("\\", "/")
    return normalized.startswith(("tests/", "docs/", "examples/", "fixtures/")) or any(
        part in normalized for part in ("/tests/", "/docs/", "/examples/", "/fixtures/")
    )


def _multiple_agents(metadata: dict[str, Any]) -> bool:
    count = metadata.get("agent_count")
    if count is not None:
        return int(count) > 1
    agents = metadata.get("agents")
    return isinstance(agents, (list, tuple, set)) and len(agents) > 1


def _multiple_branches(metadata: dict[str, Any]) -> bool:
    count = metadata.get("branch_count")
    if count is not None:
        return int(count) > 1
    branches = metadata.get("branches")
    return isinstance(branches, (list, tuple, set)) and len(branches) > 1


def _modified_last_7_days(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value >= datetime.now(timezone.utc) - timedelta(days=7)


def _placeholder(value: str) -> bool:
    normalized = value.lower()
    return any(marker in normalized for marker in ("example", "placeholder", "notreal"))
