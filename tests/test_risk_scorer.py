"""Tests for risk scoring signals."""

from __future__ import annotations

from datetime import datetime, timezone

import dataclasses

from keytrap.engine.risk_scorer import SIGNALS, score
from keytrap.engine.schema import FindingSchema


def test_each_signal_independently(sample_finding: FindingSchema) -> None:
    cases = [
        ({}, "provider_specific_live_key", 30),
        ({"public_repo": True}, "public_repo_or_commit", 25),
        ({"agent_count": 2}, "multiple_scanner_agents", 15),
        ({"old_deleted_commit": True}, "old_deleted_commit", 10),
        ({"branch_count": 2}, "multiple_branches", 10),
        (
            {"file_modified_at": datetime.now(timezone.utc).isoformat()},
            "file_modified_last_7_days",
            15,
        ),
        ({"repo_stars": 101}, "repo_over_100_stars", 10),
        ({"placeholder_value": True}, "obvious_placeholder_value", -25),
    ]

    neutral = dataclasses.replace(
        sample_finding,
        provider="unknown",
        secret="unknown****XXXX",
        file_path="src/app.py",
    )

    for metadata, signal, contribution in cases:
        finding = sample_finding if signal == "provider_specific_live_key" else neutral
        _, breakdown = score(finding, metadata)
        assert breakdown[signal] == contribution


def test_production_path_scores_higher_than_tests_path(
    sample_finding: FindingSchema,
) -> None:
    prod_finding = dataclasses.replace(sample_finding, file_path="backend/.env")
    test_finding = dataclasses.replace(sample_finding, file_path="tests/test_app.py")

    prod_score, _ = score(prod_finding)
    test_score, _ = score(test_finding)

    assert prod_score > test_score


def test_score_clamped_at_100(sample_finding: FindingSchema) -> None:
    scored, _ = score(
        sample_finding,
        {
            "public_repo": True,
            "agent_count": 3,
            "old_deleted_commit": True,
            "branch_count": 3,
            "file_modified_at": datetime.now(timezone.utc),
            "repo_stars": 200,
        },
    )

    assert scored == 100


def test_score_clamped_at_zero(sample_finding: FindingSchema) -> None:
    low_finding = dataclasses.replace(
        sample_finding,
        provider="unknown",
        secret="unknown****XXXX",
        file_path="tests/test_app.py",
    )

    scored, _ = score(low_finding, {"placeholder_value": True})

    assert scored == 0


def test_breakdown_has_entry_for_every_signal(
    sample_finding: FindingSchema,
) -> None:
    _, breakdown = score(sample_finding)

    assert set(breakdown) == set(SIGNALS)
