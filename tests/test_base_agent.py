"""Tests for the scanner agent base class."""

from __future__ import annotations

import dataclasses

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.engine.schema import FindingSchema


class ExampleAgent(BaseScannerAgent):
    def scan(self) -> list[FindingSchema]:
        return []


def test_base_agent_helpers_delegate_safely(
    monkeypatch,
    sample_finding: FindingSchema,
) -> None:
    agent = ExampleAgent()
    raw = dataclasses.asdict(sample_finding)
    raw.pop("finding_id")
    raw.pop("evidence_policy")

    assert agent.check_allowlist("tests/test_app.py", "anything", {}) is True
    assert agent.check_allowlist("src/app.py", "NotRealPlaceholder", {}) is True
    assert agent.normalize(raw) == sample_finding
