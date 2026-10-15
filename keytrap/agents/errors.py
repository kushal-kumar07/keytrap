"""Agent-specific error types."""

from __future__ import annotations


class AgentUnavailableError(RuntimeError):
    """Raised when a scanner agent dependency is missing."""
