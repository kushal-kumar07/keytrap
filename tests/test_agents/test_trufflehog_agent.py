"""Tests for the TruffleHogAgent."""

from __future__ import annotations

from pathlib import Path

from keytrap.agents.trufflehog_agent import TruffleHogAgent
from keytrap.engine.schema import FindingSchema
from tests.conftest import RAW_SEEDED_VALUES


def test_trufflehog_agent_finds_seeded_secret(
    monkeypatch,
    outputs_dir: Path,
) -> None:

    repo_root = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "seeded-repo"
    agent = TruffleHogAgent()

    findings = agent.scan(repo_path=str(repo_root), scan_id="scan-1", branch="main")

    assert findings
    assert all(isinstance(finding, FindingSchema) for finding in findings)

    output_file = outputs_dir / "trufflehog-output.txt"
    output_file.write_text(
        "\n".join(finding.secret for finding in findings),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)
