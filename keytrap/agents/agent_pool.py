"""Parallel agent pool for KeyTrap scanner agents."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from keytrap.agents.custom_regex_agent import CustomRegexAgent
from keytrap.agents.diff_agent import DiffAgent
from keytrap.agents.entropy_agent import EntropyAgent
from keytrap.agents.filters import should_skip_file
from keytrap.agents.errors import AgentUnavailableError
from keytrap.agents.gitleaks_agent import GitleaksAgent
from keytrap.agents.history_agent import HistoryAgent
from keytrap.agents.trufflehog_agent import TruffleHogAgent
from keytrap.engine.schema import FindingSchema


_LOGGER = logging.getLogger(__name__)

# Progress callback: on_event(kind, **data). Kinds: agent_queued, agent_start,
# agent_done (count, seconds), agent_unavailable (reason), agent_failed (error).
EventCallback = Callable[..., None]


class AgentPool:
	"""Run scanner agents concurrently and combine findings."""

	def run_all(
		self,
		repo_path: str,
		scan_id: str,
		branch: str,
		on_event: EventCallback | None = None,
	) -> list[FindingSchema]:
		emit = on_event or (lambda *_a, **_k: None)
		repo_root = Path(repo_path)
		tasks = []

		tasks.append(("GitleaksAgent", GitleaksAgent().scan, (repo_path, scan_id, branch)))
		tasks.append(
			(
				"TruffleHogAgent",
				TruffleHogAgent().scan,
				(repo_path, scan_id, branch),
			)
		)
		tasks.append(
			(
				"CustomRegexAgent",
				_scan_with_custom_regex,
				(repo_root, scan_id, branch),
			)
		)
		tasks.append(("EntropyAgent", _scan_with_entropy, (repo_root, scan_id, branch)))
		tasks.append(("HistoryAgent", HistoryAgent().scan, (repo_path, scan_id)))
		tasks.append(("DiffAgent", _scan_with_diff, (repo_root, scan_id, branch)))

		findings: list[FindingSchema] = []

		def timed(name: str, func, args):
			emit("agent_start", agent=name)
			started = time.monotonic()
			try:
				result = func(*args)
			except AgentUnavailableError as exc:
				emit("agent_unavailable", agent=name, reason=str(exc))
				raise
			except Exception as exc:  # noqa: BLE001 - reported, then logged by caller
				emit("agent_failed", agent=name, error=str(exc))
				raise
			emit(
				"agent_done",
				agent=name,
				count=len(result),
				seconds=time.monotonic() - started,
			)
			return result

		for name, _func, _args in tasks:
			emit("agent_queued", agent=name)

		max_workers = int(os.environ.get("KEYTRAP_AGENT_MAX_WORKERS", "4"))
		with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
			future_map = {
				executor.submit(timed, name, func, args): name for name, func, args in tasks
			}
			for future in as_completed(future_map):
				name = future_map[future]
				try:
					findings.extend(future.result())
				except AgentUnavailableError as exc:
					_LOGGER.warning("%s unavailable: %s", name, exc)
				except Exception as exc:  # noqa: BLE001 - log and continue
					_LOGGER.error("%s failed: %s", name, exc)

		return findings


def _scan_with_custom_regex(
	repo_root: Path,
	scan_id: str,
	branch: str,
) -> list[FindingSchema]:
	agent = CustomRegexAgent()
	repo_name = repo_root.name
	commit = _git_head(repo_root)
	findings: list[FindingSchema] = []

	for file_path in repo_root.rglob("*"):
		if file_path.is_dir():
			continue
		if _skip_path(file_path) or should_skip_file(file_path.name):
			continue

		try:
			content = file_path.read_text(encoding="utf-8")
		except UnicodeDecodeError:
			continue

		relative_path = file_path.relative_to(repo_root).as_posix()
		findings.extend(
			agent.scan(
				file_path=relative_path,
				file_content=content,
				scan_id=scan_id,
				repo=repo_name,
				branch=branch,
				commit=commit,
			)
		)

	return findings


def _scan_with_entropy(
	repo_root: Path,
	scan_id: str,
	branch: str,
) -> list[FindingSchema]:
	agent = EntropyAgent()
	repo_name = repo_root.name
	commit = _git_head(repo_root)
	findings: list[FindingSchema] = []

	for file_path in repo_root.rglob("*"):
		if file_path.is_dir():
			continue
		if _skip_path(file_path) or should_skip_file(file_path.name):
			continue

		try:
			content = file_path.read_text(encoding="utf-8")
		except UnicodeDecodeError:
			continue

		relative_path = file_path.relative_to(repo_root).as_posix()
		findings.extend(
			agent.scan(
				file_path=relative_path,
				file_content=content,
				scan_id=scan_id,
				repo=repo_name,
				branch=branch,
				commit=commit,
			)
		)

	return findings


def _scan_with_diff(
	repo_root: Path,
	scan_id: str,
	branch: str,
) -> list[FindingSchema]:
	base_commit = os.environ.get("DIFF_BASE_COMMIT")
	head_commit = os.environ.get("DIFF_HEAD_COMMIT")
	if not base_commit or not head_commit:
		# Default: the latest commit against the one before it.
		head_commit = _rev_parse(repo_root, "HEAD")
		base_commit = _rev_parse(repo_root, "HEAD~1")
		if not head_commit or not base_commit:
			raise AgentUnavailableError("only one commit, nothing to diff")
	return DiffAgent().scan(
		repo_path=str(repo_root),
		base_commit=base_commit,
		head_commit=head_commit,
		scan_id=scan_id,
		branch=branch,
	)


def _rev_parse(repo_root: Path, ref: str) -> str | None:
	try:
		result = subprocess.run(
			["git", "-C", str(repo_root), "rev-parse", "--verify", "--quiet", ref],
			capture_output=True,
			text=True,
			timeout=5,
			check=False,
		)
	except (FileNotFoundError, subprocess.TimeoutExpired):
		return None
	return result.stdout.strip() or None


def _skip_path(path: Path) -> bool:
	return ".git" in path.parts


def _git_head(repo_root: Path) -> str:
	try:
		result = subprocess.run(
			["git", "-C", str(repo_root), "rev-parse", "HEAD"],
			capture_output=True,
			text=True,
			timeout=5,
			check=False,
		)
	except (FileNotFoundError, subprocess.TimeoutExpired):
		return "unknown"

	if result.returncode != 0:
		return "unknown"
	return result.stdout.strip() or "unknown"
