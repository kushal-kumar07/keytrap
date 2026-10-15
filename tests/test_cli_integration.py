"""Integration test for CLI scan."""

from __future__ import annotations

import json
from pathlib import Path

import git
from typer.testing import CliRunner

from keytrap.cli import app
from tests.conftest import RAW_SEEDED_VALUES


def test_cli_scan_end_to_end(monkeypatch, tmp_path: Path) -> None:

    repo_root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "seeded-repo"
    output_path = tmp_path / "findings.json"

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", str(repo_root), "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    findings = payload["findings"]
    assert findings

    providers = {finding["provider"] for finding in findings}
    assert {"stripe", "aws", "github", "slack"}.issubset(providers)

    secrets = [finding["secret"] for finding in findings]
    assert len(secrets) == len(set(secrets))
    assert any("," in finding["agent"] for finding in findings)

    backend_scores = [
        finding["risk_score"]
        for finding in findings
        if finding["file_path"] == "backend/.env"
    ]
    assert backend_scores
    assert max(backend_scores) > 60

    tests_scores = [
        finding["risk_score"]
        for finding in findings
        if finding["file_path"].startswith("tests/")
    ]
    assert tests_scores
    assert max(tests_scores) < 40

    repo = git.Repo(repo_root)
    commits = list(repo.iter_commits())
    commit_with_secret = commits[1].hexsha
    assert any(
        finding["commit"] == commit_with_secret
        and "HistoryAgent" in finding["agent"].split(",")
        for finding in findings
    )

    output_text = output_path.read_text(encoding="utf-8")
    assert any(raw_secret in output_text for raw_secret in RAW_SEEDED_VALUES)
