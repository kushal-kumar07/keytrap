"""Shared pytest fixtures for KeyTrap."""

from __future__ import annotations

from pathlib import Path

import pytest

from keytrap.engine.schema import FindingSchema
from tests.seed_repo import DEFAULT_PATH, RAW_SEEDED_VALUES, build_seeded_repo

__all__ = ["RAW_SEEDED_VALUES"]


@pytest.fixture(scope="session", autouse=True)
def seeded_repo() -> Path:
    """Build the git fixture once per session; it is not committed."""
    if not (DEFAULT_PATH / ".git").exists():
        build_seeded_repo(DEFAULT_PATH)
    return DEFAULT_PATH




@pytest.fixture
def sample_finding() -> FindingSchema:
    return FindingSchema(
        scan_id="scan-1",
        agent="CustomRegexAgent",
        provider="stripe",
        secret_type="Stripe live key",
        secret="sk_live_****XXXX",
        repo="owner/name",
        branch="main",
        commit="abc123",
        file_path="backend/.env",
        line_start=3,
        line_end=3,
        context_before="STRIPE_KEY=sk_live_****XXXX",
        confidence=0.95,
        severity="high",
        risk_score=0,
        created_at="2026-05-10T00:00:00+00:00",
    )


@pytest.fixture
def outputs_dir(tmp_path: Path) -> Path:
    path = Path("tests/outputs")
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_file():
            child.unlink()
    return path
