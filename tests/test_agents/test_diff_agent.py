"""Tests for the DiffAgent."""

from __future__ import annotations

from pathlib import Path

import git

from keytrap.agents.diff_agent import DiffAgent
from tests.conftest import RAW_SEEDED_VALUES


def test_diff_agent_scans_added_lines(monkeypatch, outputs_dir: Path) -> None:

    repo_root = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "seeded-repo"
    repo = git.Repo(repo_root)
    commits = list(repo.iter_commits())

    head_commit = commits[1].hexsha
    base_commit = commits[2].hexsha
    old_commit = commits[3].hexsha

    agent = DiffAgent()
    findings = agent.scan(
        repo_path=str(repo_root),
        base_commit=base_commit,
        head_commit=head_commit,
        scan_id="scan-1",
        branch="main",
    )

    assert findings
    assert all(finding.commit == head_commit for finding in findings)
    assert all(finding.commit != old_commit for finding in findings)

    output_file = outputs_dir / "diff-agent-output.txt"
    output_file.write_text(
        "\n".join(
            f"{finding.secret}\n{finding.context_before}" for finding in findings
        ),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)
