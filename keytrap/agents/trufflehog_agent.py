"""TruffleHog subprocess agent."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.errors import AgentUnavailableError
from keytrap.engine.schema import FindingSchema


_LOGGER = logging.getLogger(__name__)


class TruffleHogAgent(BaseScannerAgent):
    """Run TruffleHog and normalize findings."""

    def scan(self, repo_path: str, scan_id: str, branch: str) -> list[FindingSchema]:
        binary = _ensure_binary("trufflehog")
        repo_root = Path(repo_path).resolve()
        cmd = [
            binary,
            "git",
            f"file://{repo_root}",
            "--json",
            "--no-verification",
            "--no-update",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AgentUnavailableError("TruffleHog not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("TruffleHog scan timed out") from exc

        findings: list[FindingSchema] = []
        repo_name = repo_root.name

        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            raw_secret = entry.get("Raw")
            if not raw_secret:
                continue

            provider = _infer_provider(entry)
            metadata = _extract_git_metadata(entry)
            file_path = _relative_path(metadata.get("file"), repo_root)
            if not file_path:
                file_path = "unknown"

            line_num = _safe_int(metadata.get("line"), 1)
            commit = metadata.get("commit") or "unknown"
            secret_type = _secret_type(entry)

            raw_finding = {
                "scan_id": scan_id,
                "agent": "TruffleHogAgent",
                "provider": provider,
                "secret_type": secret_type,
                "secret": raw_secret,
                "repo": repo_name,
                "branch": branch,
                "commit": commit,
                "file_path": file_path,
                "line_start": line_num,
                "line_end": line_num,
                "context_before": raw_secret,
                "confidence": 0.9,
                "severity": _severity_for(provider),
                "risk_score": 0,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            findings.append(self.normalize(raw_finding))

        return findings


def _ensure_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        _LOGGER.warning("%s binary not found in PATH", name)
        raise AgentUnavailableError(f"{name} not installed")
    return path


def _extract_git_metadata(entry: dict) -> dict[str, object]:
    metadata = entry.get("SourceMetadata")
    if not isinstance(metadata, dict):
        return {}
    data = metadata.get("Data")
    if not isinstance(data, dict):
        return {}
    git_meta = data.get("Git")
    if not isinstance(git_meta, dict):
        return {}
    return {
        "file": git_meta.get("file") or git_meta.get("File"),
        "line": git_meta.get("line") or git_meta.get("Line"),
        "commit": git_meta.get("commit") or git_meta.get("Commit"),
    }


def _infer_provider(entry: dict) -> str:
    pieces = [
        str(entry.get("DetectorName") or ""),
        str(entry.get("DetectorType") or ""),
        str(entry.get("RuleID") or ""),
    ]
    haystack = " ".join(piece for piece in pieces if piece).lower()
    return _provider_from_text(haystack)


def _provider_from_text(text: str) -> str:
    if "stripe" in text:
        return "stripe"
    if "aws" in text or "access key" in text:
        return "aws"
    if "github" in text or "ghp" in text:
        return "github"
    if "gcp" in text or "google" in text:
        return "gcp"
    if "slack" in text or "xoxb" in text:
        return "slack"
    return "unknown"


def _secret_type(entry: dict) -> str:
    return (
        str(entry.get("DetectorName"))
        if entry.get("DetectorName")
        else str(entry.get("DetectorType") or "TruffleHog")
    )


def _severity_for(provider: str) -> str:
    if provider in {"stripe", "aws", "github", "gcp", "slack"}:
        return "high"
    return "medium"


def _safe_int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _relative_path(file_path: object, repo_root: Path) -> str:
    if not file_path:
        return ""
    path = Path(str(file_path))
    try:
        if path.is_absolute():
            return path.relative_to(repo_root).as_posix()
    except (ValueError, OSError):
        return path.as_posix()
    return path.as_posix()
