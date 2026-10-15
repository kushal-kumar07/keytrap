"""Tests for the EntropyAgent."""

from __future__ import annotations

from keytrap.agents.entropy_agent import EntropyAgent


def test_entropy_agent_detects_high_entropy_token(monkeypatch) -> None:

    token = "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW"
    content = f"token={token} and the words should be ignored"

    agent = EntropyAgent()
    findings = agent.scan(
        file_path="app/config.py",
        file_content=content,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )

    assert findings
    assert all(finding.provider == "unknown" for finding in findings)
    assert all(finding.confidence >= 0.4 for finding in findings)
    assert all(finding.secret_type == "high_entropy_token" for finding in findings)
    assert any(token in finding.secret for finding in findings)


def test_entropy_agent_skips_common_words_and_paths(monkeypatch) -> None:

    agent = EntropyAgent()
    words = "the and for with this that"
    paths = "/var/log/app/config.yaml C:\\temp\\file.txt"

    findings_words = agent.scan(
        file_path="docs/readme.md",
        file_content=words,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )
    findings_paths = agent.scan(
        file_path="docs/readme.md",
        file_content=paths,
        scan_id="scan-1",
        repo="owner/name",
        branch="main",
        commit="abc123",
    )

    assert findings_words == []
    assert findings_paths == []
