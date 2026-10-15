"""Tests for the scanner AgentPool."""

from __future__ import annotations

from pathlib import Path

from keytrap.agents.agent_pool import AgentPool
from keytrap.agents.errors import AgentUnavailableError
from keytrap.agents.gitleaks_agent import GitleaksAgent
from keytrap.engine.schema import FindingSchema
from tests.conftest import RAW_SEEDED_VALUES


def test_agent_pool_combines_findings(monkeypatch, outputs_dir: Path) -> None:

    repo_root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "seeded-repo"
    pool = AgentPool()

    findings = pool.run_all(repo_path=str(repo_root), scan_id="scan-1", branch="main")

    assert findings
    agents = {finding.agent for finding in findings}
    assert "CustomRegexAgent" in agents
    assert len(agents) >= 2
    assert all(isinstance(finding, FindingSchema) for finding in findings)

    output_file = outputs_dir / "agent-pool-output.txt"
    output_file.write_text(
        "\n".join(finding.secret for finding in findings),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    assert any(raw_secret in output for raw_secret in RAW_SEEDED_VALUES)


def test_agent_pool_skips_unavailable(monkeypatch) -> None:

    def _raise_unavailable(*_args, **_kwargs):
        raise AgentUnavailableError("missing")

    monkeypatch.setattr(GitleaksAgent, "scan", _raise_unavailable)

    repo_root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "seeded-repo"
    pool = AgentPool()

    findings = pool.run_all(repo_path=str(repo_root), scan_id="scan-1", branch="main")

    assert any(finding.agent == "CustomRegexAgent" for finding in findings)
