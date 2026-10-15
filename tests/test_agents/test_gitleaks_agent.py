"""Tests for the GitleaksAgent."""

from __future__ import annotations

from pathlib import Path

from keytrap.agents.gitleaks_agent import GitleaksAgent
from keytrap.engine.schema import FindingSchema
from tests.conftest import RAW_SEEDED_VALUES


GITLEAKS_TEST_CONFIG = """
title = "KeyTrap test config"

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["key", "aws"]
keywords = ["AKIA"]

[[rules]]
id = "stripe-access-token"
description = "Stripe Access Token"
regex = '''sk_live_[0-9A-Za-z]{20,}'''
tags = ["key", "stripe"]
keywords = ["sk_live_"]

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9A-Za-z]{20,}'''
tags = ["key", "github"]
keywords = ["ghp_"]
""".strip()


def test_gitleaks_agent_finds_seeded_secrets(monkeypatch, outputs_dir: Path) -> None:
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", GITLEAKS_TEST_CONFIG)

    repo_root = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "seeded-repo"
    agent = GitleaksAgent()

    findings = agent.scan(repo_path=str(repo_root), scan_id="scan-1", branch="main")

    providers = {finding.provider for finding in findings}
    assert "stripe" in providers
    assert "aws" in providers
    assert all(isinstance(finding, FindingSchema) for finding in findings)

    output_file = outputs_dir / "gitleaks-output.txt"
    output_file.write_text(
        "\n".join(finding.secret for finding in findings),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)
