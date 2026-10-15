"""Gitleaks subprocess agent."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.errors import AgentUnavailableError
from keytrap.engine.schema import FindingSchema


_LOGGER = logging.getLogger(__name__)


class GitleaksAgent(BaseScannerAgent):
	"""Run Gitleaks and normalize findings."""

	def scan(self, repo_path: str, scan_id: str, branch: str) -> list[FindingSchema]:
		binary = _ensure_binary("gitleaks")
		report_path = Path(tempfile.gettempdir()) / f"gitleaks_{scan_id}.json"
		cmd = [
			binary,
			"detect",
			"--source",
			str(repo_path),
			"--report-format",
			"json",
			"--report-path",
			str(report_path),
		]

		try:
			result = subprocess.run(
				cmd,
				capture_output=True,
				text=True,
				timeout=60,
				check=False,
			)
		except FileNotFoundError as exc:
			raise AgentUnavailableError("Gitleaks not installed") from exc
		except subprocess.TimeoutExpired as exc:
			raise TimeoutError("Gitleaks scan timed out") from exc

		if result.returncode not in (0, 1):
			raise RuntimeError("Gitleaks scan failed")

		try:
			if not report_path.exists():
				return []

			payload = report_path.read_text(encoding="utf-8").strip()
			if not payload:
				return []

			parsed = json.loads(payload)
		finally:
			report_path.unlink(missing_ok=True)

		entries = _normalize_report(parsed)
		if not entries:
			return []

		repo_name = Path(repo_path).name
		findings: list[FindingSchema] = []

		for entry in entries:
			raw_secret = entry.get("Secret")
			if not raw_secret:
				continue

			provider = _infer_provider(entry)

			file_path = _relative_path(entry.get("File"), repo_path)
			if not file_path:
				file_path = "unknown"

			start_line = _safe_int(entry.get("StartLine"), 1)
			end_line = _safe_int(entry.get("EndLine"), start_line)
			context_before = str(entry.get("Match") or "")
			secret_type = entry.get("Description") or entry.get("RuleID") or "Gitleaks"

			raw_finding = {
				"scan_id": scan_id,
				"agent": "GitleaksAgent",
				"provider": provider,
				"secret_type": str(secret_type),
				"secret": raw_secret,
				"repo": repo_name,
				"branch": branch,
				"commit": entry.get("Commit") or "unknown",
				"file_path": file_path,
				"line_start": start_line,
				"line_end": end_line,
				"context_before": context_before,
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


def _normalize_report(parsed: object) -> list[dict]:
	if isinstance(parsed, list):
		return [entry for entry in parsed if isinstance(entry, dict)]
	if isinstance(parsed, dict):
		for key in ("findings", "Findings", "Leaks", "leaks"):
			value = parsed.get(key)
			if isinstance(value, list):
				return [entry for entry in value if isinstance(entry, dict)]
	return []


def _infer_provider(entry: dict) -> str:
	pieces: list[str] = []
	for key in ("RuleID", "Description"):
		value = entry.get(key)
		if value:
			pieces.append(str(value))

	tags = entry.get("Tags")
	if isinstance(tags, list):
		pieces.extend(str(tag) for tag in tags)
	elif tags:
		pieces.append(str(tags))

	haystack = " ".join(pieces).lower()
	return _provider_from_text(haystack)


def _provider_from_text(text: str) -> str:
	if "stripe" in text:
		return "stripe"
	if "aws" in text or "access key" in text:
		return "aws"
	if "github" in text or "ghp_" in text:
		return "github"
	if "gcp" in text or "google" in text:
		return "gcp"
	if "slack" in text or "xoxb" in text:
		return "slack"
	return "unknown"


def _severity_for(provider: str) -> str:
	if provider in {"stripe", "aws", "github", "gcp", "slack"}:
		return "high"
	return "medium"


def _safe_int(value: object, fallback: int) -> int:
	try:
		return int(value)
	except (TypeError, ValueError):
		return fallback


def _relative_path(file_path: object, repo_path: str) -> str:
	if not file_path:
		return ""
	path = Path(str(file_path))
	try:
		repo_root = Path(repo_path).resolve()
		if path.is_absolute():
			return path.relative_to(repo_root).as_posix()
	except (ValueError, OSError):
		return path.as_posix()
	return path.as_posix()
