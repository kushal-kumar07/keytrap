"""Tests for the HistoryAgent."""

from __future__ import annotations

from pathlib import Path

import git

from keytrap.agents.history_agent import HistoryAgent
from tests.conftest import RAW_SEEDED_VALUES


def test_history_agent_finds_removed_secret(monkeypatch, outputs_dir: Path) -> None:

    repo_root = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "seeded-repo"
    repo = git.Repo(repo_root)
    commits = list(repo.iter_commits())

    commit_with_secret = commits[1]

    agent = HistoryAgent()
    findings = agent.scan(repo_path=str(repo_root), scan_id="scan-1")

    assert any(finding.commit == commit_with_secret.hexsha for finding in findings)

    output_file = outputs_dir / "history-agent-output.txt"
    output_file.write_text(
        "\n".join(
            f"{finding.secret}\n{finding.context_before}" for finding in findings
        ),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)
