"""Tests for the CustomRegexAgent."""

from __future__ import annotations

from pathlib import Path

import pytest

from keytrap.agents.custom_regex_agent import CustomRegexAgent
from keytrap.engine.rule_loader import RuleLoader
from tests.conftest import RAW_SEEDED_VALUES


def _load_rules() -> list:
    loader = RuleLoader(production=False)
    root = Path(__file__).resolve().parents[2]
    loader.load(root / "rules")
    return list(loader.rules)


def test_custom_regex_agent_detects_and_allowlists(
    monkeypatch: pytest.MonkeyPatch,
    outputs_dir: Path,
) -> None:

    rules = _load_rules()
    agent = CustomRegexAgent(rules)

    repo_root = Path(__file__).resolve().parents[2]
    env_path = repo_root / "tests" / "fixtures" / "seeded-repo" / "backend" / ".env"
    tests_path = (
        repo_root
        / "tests"
        / "fixtures"
        / "seeded-repo"
        / "tests"
        / "test_payments.py"
    )
    docs_path = repo_root / "tests" / "fixtures" / "seeded-repo" / "docs" / "api.md"

    env_content = env_path.read_text(encoding="utf-8")
    tests_content = tests_path.read_text(encoding="utf-8")
    docs_content = docs_path.read_text(encoding="utf-8")

    findings = agent.scan(
        file_path="backend/.env",
        file_content=env_content,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )

    providers = {finding.provider for finding in findings}
    assert "stripe" in providers
    assert "aws" in providers

    allowlisted_tests = agent.scan(
        file_path="tests/test_payments.py",
        file_content=tests_content,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )
    assert allowlisted_tests == []

    allowlisted_docs = agent.scan(
        file_path="docs/api.md",
        file_content=docs_content,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )
    assert allowlisted_docs == []

    output_file = outputs_dir / "custom-regex-output.txt"
    output_file.write_text(
        "\n".join(finding.secret for finding in findings),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)
