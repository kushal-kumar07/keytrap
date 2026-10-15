"""Tests for the normalized finding schema."""

from __future__ import annotations

import dataclasses

import pytest

from keytrap.engine.schema import EVIDENCE_POLICY, FindingSchema, make_finding_id


def test_finding_schema_creates_all_fields(sample_finding: FindingSchema) -> None:
    assert sample_finding.finding_id == make_finding_id(
        "owner/name",
        "abc123",
        "backend/.env",
        3,
        "sk_live_****XXXX",
    )
    assert sample_finding.evidence_policy == EVIDENCE_POLICY
    assert sample_finding.scan_id == "scan-1"
    assert sample_finding.agent == "CustomRegexAgent"
    assert sample_finding.provider == "stripe"
    assert sample_finding.context_before == "STRIPE_KEY=sk_live_****XXXX"


def test_finding_id_is_deterministic(sample_finding: FindingSchema) -> None:
    same = dataclasses.replace(sample_finding, risk_score=80)

    assert same.finding_id == sample_finding.finding_id


def test_evidence_policy_cannot_be_set_by_caller() -> None:
    with pytest.raises(TypeError):
        FindingSchema(
            scan_id="scan-1",
            agent="CustomRegexAgent",
            provider="unknown",
            secret_type="token",
            secret="secret****tail",
            repo="owner/name",
            branch="main",
            commit="abc123",
            file_path="app.py",
            line_start=1,
            line_end=1,
            context_before="",
            confidence=0.5,
            severity="low",
            risk_score=0,
            created_at="2026-05-10T00:00:00+00:00",
            evidence_policy="raw_allowed",
        )
