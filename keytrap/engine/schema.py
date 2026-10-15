"""Normalized finding schema for KeyTrap scanner agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256


VALID_PROVIDERS = {"stripe", "aws", "github", "gcp", "slack", "unknown"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
EVIDENCE_POLICY = "raw"


def make_finding_id(
    repo: str,
    commit: str,
    file_path: str,
    line_start: int,
    secret: str,
) -> str:
    """Create the deterministic finding id mandated by the contract."""
    material = f"{repo}{commit}{file_path}{line_start}{secret}"
    return sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingSchema:
    """The exact normalized finding schema emitted by every scanner agent."""

    scan_id: str
    agent: str
    provider: str
    secret_type: str
    secret: str
    repo: str
    branch: str
    commit: str
    file_path: str
    line_start: int
    line_end: int
    context_before: str
    confidence: float
    severity: str
    risk_score: int
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finding_id: str = field(init=False)
    evidence_policy: str = field(init=False, default=EVIDENCE_POLICY)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "finding_id",
            make_finding_id(
                self.repo,
                self.commit,
                self.file_path,
                self.line_start,
                self.secret,
            ),
        )
        object.__setattr__(self, "evidence_policy", EVIDENCE_POLICY)
