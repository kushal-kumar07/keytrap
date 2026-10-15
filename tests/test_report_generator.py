"""Tests for report generation."""

from __future__ import annotations

import dataclasses
import zipfile
from pathlib import Path

import pytest

from keytrap.engine.orchestrator import ScanResult
from keytrap.engine.schema import FindingSchema
from keytrap.reports.report_generator import generate
from tests.conftest import RAW_SEEDED_VALUES


def _scan_result(sample_finding: FindingSchema) -> ScanResult:
    first = dataclasses.replace(
        sample_finding,
        agent="CustomRegexAgent,TruffleHogAgent",
        provider="stripe",
        secret_type="Stripe live key",
        secret="sk_live_****XXXX",
        file_path="backend/.env",
        context_before="STRIPE_KEY=sk_live_****XXXX",
        risk_score=80,
        severity="high",
    )
    second = dataclasses.replace(
        sample_finding,
        agent="HistoryAgent",
        provider="github",
        secret_type="GitHub token",
        secret="ghp_****XXXX",
        file_path="tests/test_payments.py",
        context_before="TOKEN=ghp_****XXXX",
        risk_score=20,
        severity="low",
    )

    return ScanResult(
        scan_id="scan-1",
        findings=[first, second],
        stats={
            "raw_findings": 2,
            "deduped_findings": 2,
            "by_severity": {"high": 1, "low": 1},
            "by_agent": {"CustomRegexAgent": 1, "TruffleHogAgent": 1, "HistoryAgent": 1},
        },
        started_at="2026-05-16T00:00:00+00:00",
        completed_at="2026-05-16T00:00:10+00:00",
    )


@pytest.mark.parametrize("fmt", ["markdown", "pdf", "hackerone"])
def test_report_formats_generate(
    monkeypatch,
    tmp_path: Path,
    sample_finding: FindingSchema,
    fmt: str,
) -> None:
    monkeypatch.setenv("KEYTRAP_REPORTS_DIR", str(tmp_path))
    result = _scan_result(sample_finding)

    output_path = generate(result, fmt)
    assert output_path.exists()


def test_markdown_report_structure(monkeypatch, tmp_path: Path, sample_finding: FindingSchema) -> None:
    monkeypatch.setenv("KEYTRAP_REPORTS_DIR", str(tmp_path))
    result = _scan_result(sample_finding)

    output_path = generate(result, "markdown")
    content = output_path.read_text(encoding="utf-8")

    assert "Executive Summary" in content
    assert "Findings" in content
    assert "Methodology" in content


def test_pdf_report_signature(monkeypatch, tmp_path: Path, sample_finding: FindingSchema) -> None:
    monkeypatch.setenv("KEYTRAP_REPORTS_DIR", str(tmp_path))
    result = _scan_result(sample_finding)

    output_path = generate(result, "pdf")
    data = output_path.read_bytes()

    assert data.startswith(b"%PDF")


def test_hackerone_report_fields(monkeypatch, tmp_path: Path, sample_finding: FindingSchema) -> None:
    monkeypatch.setenv("KEYTRAP_REPORTS_DIR", str(tmp_path))
    result = _scan_result(sample_finding)

    output_path = generate(result, "hackerone")
    with zipfile.ZipFile(output_path, "r") as archive:
        names = archive.namelist()
        assert len(names) == 2
        content = archive.read(names[0]).decode("utf-8")

    assert "Title:" in content
    assert "Severity:" in content
    assert "Steps to Reproduce:" in content
    assert "Impact:" in content
    assert "Remediation:" in content
