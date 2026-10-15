"""Scan orchestration for KeyTrap."""

from __future__ import annotations

import dataclasses
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from keytrap.agents.agent_pool import AgentPool
from keytrap.agents.context_judge_agent import ContextJudgeAgent
from keytrap.engine import redactor
from keytrap.engine.normalizer import normalize
from keytrap.engine.risk_scorer import score
from keytrap.engine.rule_loader import RuleLoader
from keytrap.engine.schema import FindingSchema


@dataclass(frozen=True)
class ScanJob:
	repo_path: str
	scan_id: str
	branch: str
	scope: dict[str, Any] | None = None
	options: dict[str, Any] | None = None
	base_commit: str | None = None
	head_commit: str | None = None


@dataclass(frozen=True)
class ScanResult:
	scan_id: str
	findings: list[FindingSchema]
	stats: dict[str, Any]
	started_at: str
	completed_at: str


def run_scan(scan_job: ScanJob, on_event=None) -> ScanResult:
	emit = on_event or (lambda *_a, **_k: None)
	started_at = datetime.now(timezone.utc).isoformat()
	rules = _load_rules()
	pool = AgentPool()

	with _env_overrides(
		{
			"DIFF_BASE_COMMIT": scan_job.base_commit,
			"DIFF_HEAD_COMMIT": scan_job.head_commit,
			"KEYTRAP_AGENT_MAX_WORKERS": _max_workers_override(scan_job),
		}
	):
		emit("stage", stage="scan")
		findings = pool.run_all(
			scan_job.repo_path,
			scan_job.scan_id,
			scan_job.branch,
			on_event=on_event,
		)

	normalized = [_normalize_finding(finding) for finding in findings]
	head_commit = _git_head(scan_job.repo_path)
	deduped, metadata = _dedupe_findings(
		normalized,
		scan_job.repo_path,
		head_commit,
	)
	_job_metadata = _metadata_from_job(scan_job)

	external_validation = _external_validation_enabled(scan_job)
	emit("stage", stage="judge", enabled=external_validation)
	judged: list[FindingSchema] = []
	judge = ContextJudgeAgent() if external_validation else None
	for finding in deduped:
		if external_validation and finding.confidence < 0.75:
			surrounding = _surrounding_lines(
				scan_job.repo_path,
				finding.file_path,
				finding.line_start,
				rules,
			)
			judged.append(judge.review(finding, surrounding))
		else:
			judged.append(finding)

	emit("stage", stage="score")
	scored: list[FindingSchema] = []
	for finding in judged:
		meta = {
			**_job_metadata,
			**metadata.get(finding.secret, {}),
			"file_modified_at": _file_modified_at(scan_job.repo_path, finding.file_path),
		}
		risk_score, _ = score(finding, meta)
		scored.append(dataclasses.replace(finding, risk_score=risk_score))

	scored.sort(key=lambda item: item.risk_score, reverse=True)
	completed_at = datetime.now(timezone.utc).isoformat()

	stats = _build_stats(findings, scored)
	emit("stage", stage="done")
	return ScanResult(
		scan_id=scan_job.scan_id,
		findings=scored,
		stats=stats,
		started_at=started_at,
		completed_at=completed_at,
	)


def _normalize_finding(finding: FindingSchema) -> FindingSchema:
	raw = dataclasses.asdict(finding)
	raw.pop("finding_id", None)
	raw.pop("evidence_policy", None)
	return normalize(raw)


def _dedupe_findings(
	findings: Iterable[FindingSchema],
	repo_path: str,
	head_commit: str,
) -> tuple[list[FindingSchema], dict[str, dict[str, Any]]]:
	grouped: dict[str, list[FindingSchema]] = {}
	for finding in findings:
		grouped.setdefault(finding.secret, []).append(finding)

	deduped: list[FindingSchema] = []
	metadata: dict[str, dict[str, Any]] = {}

	repo = _git_repo(repo_path)
	commit_cache: dict[str, int] = {}

	for secret, group in grouped.items():
		agents = _collect_agents(group)
		branches = {item.branch for item in group}
		primary = _pick_primary(group, head_commit, repo, commit_cache)
		agent_label = ",".join(sorted(agents))
		updated = dataclasses.replace(primary, agent=agent_label)
		deduped.append(updated)

		metadata[secret] = {
			"agent_count": len(agents),
			"agents": sorted(agents),
			"branch_count": len(branches),
			"branches": sorted(branches),
			"old_deleted_commit": _has_deleted_history_finding(
				group,
				repo_path,
				head_commit,
			),
		}

	return deduped, metadata


def _collect_agents(group: Iterable[FindingSchema]) -> set[str]:
	agents: set[str] = set()
	for finding in group:
		for part in finding.agent.split(","):
			part = part.strip()
			if part:
				agents.add(part)
	return agents


def _pick_primary(
	group: list[FindingSchema],
	head_commit: str,
	repo,
	commit_cache: dict[str, int],
) -> FindingSchema:
	def key(item: FindingSchema) -> tuple[float, int, int]:
		is_current_head = int(item.commit == head_commit)
		commit_time = _commit_timestamp(repo, item.commit, commit_cache)
		return (item.confidence, is_current_head, commit_time)

	return max(group, key=key)


def _has_deleted_history_finding(
	group: Iterable[FindingSchema],
	repo_path: str,
	head_commit: str,
) -> bool:
	for finding in group:
		if "HistoryAgent" not in _collect_agents([finding]):
			continue
		if finding.commit == head_commit:
			continue
		if not (Path(repo_path) / finding.file_path).exists():
			return True
	return False


def _commit_timestamp(repo, commit_hash: str, cache: dict[str, int]) -> int:
	if commit_hash in cache:
		return cache[commit_hash]
	if repo is None:
		cache[commit_hash] = 0
		return 0
	try:
		commit = repo.commit(commit_hash)
		cache[commit_hash] = int(commit.committed_date)
	except Exception:
		cache[commit_hash] = 0
	return cache[commit_hash]


def _surrounding_lines(
	repo_path: str,
	file_path: str,
	line_number: int,
	rules,
) -> list[str]:
	file_on_disk = Path(repo_path) / file_path
	if not file_on_disk.exists() or not file_on_disk.is_file():
		return []

	try:
		lines = file_on_disk.read_text(encoding="utf-8").splitlines()
	except UnicodeDecodeError:
		return []

	if not lines:
		return []

	start = max(1, line_number - 5)
	end = min(len(lines), line_number + 4)
	segment = lines[start - 1 : end]
	return [_sanitize_line(line, rules) for line in segment]


def _sanitize_line(line: str, rules) -> str:
	sanitized = line
	for rule in rules:
		for match in rule.pattern.finditer(line):
			try:
				raw_secret = match.group(rule.secret_group)
			except IndexError:
				continue
			redacted = redactor.redact(raw_secret, rule.provider)
			sanitized = sanitized.replace(raw_secret, redacted)

	sanitized = _redact_entropy_tokens(sanitized)
	return sanitized


def _redact_entropy_tokens(text: str) -> str:
	from keytrap.agents.entropy_agent import _TOKEN_PATTERN, _shannon_entropy

	redacted = text
	for match in _TOKEN_PATTERN.finditer(text):
		token = match.group(0).strip()
		if len(token) < 20:
			continue
		if _should_skip_entropy_token(token):
			continue
		if _shannon_entropy(token) < 4.5:
			continue
		replacement = redactor.redact(token, "unknown")
		redacted = redacted.replace(token, replacement)
	return redacted


def _should_skip_entropy_token(token: str) -> bool:
	lowered = token.lower()
	if lowered.isdigit():
		return True
	if "/" in token or "\\" in token:
		return True
	return False


def _load_rules():
	loader = RuleLoader()
	rules_dir = Path(
		os.environ.get(
			"KEYTRAP_RULES_DIR",
			str(Path(__file__).resolve().parents[2] / "rules"),
		)
	)
	loader.load(rules_dir)
	return loader.rules


def _metadata_from_job(scan_job: ScanJob) -> dict[str, Any]:
	scope = scan_job.scope or {}
	options = scan_job.options or {}
	return {
		"public_repo": bool(scope.get("public_repo") or options.get("public_repo")),
		"public_commit": bool(
			scope.get("public_commit") or options.get("public_commit")
		),
		"repo_stars": scope.get("repo_stars", options.get("repo_stars", 0)),
	}


def _file_modified_at(repo_path: str, file_path: str) -> str | None:
	path = Path(repo_path) / file_path
	if not path.exists() or not path.is_file():
		return None
	try:
		return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
	except OSError:
		return None


def _build_stats(
	raw_findings: Iterable[FindingSchema],
	final_findings: Iterable[FindingSchema],
) -> dict[str, Any]:
	raw_count = len(list(raw_findings))
	findings_list = list(final_findings)
	by_severity: dict[str, int] = {}
	by_agent: dict[str, int] = {}

	for finding in findings_list:
		by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
		for agent in finding.agent.split(","):
			name = agent.strip()
			if not name:
				continue
			by_agent[name] = by_agent.get(name, 0) + 1

	return {
		"raw_findings": raw_count,
		"deduped_findings": len(findings_list),
		"by_severity": by_severity,
		"by_agent": by_agent,
	}


def _git_head(repo_path: str) -> str:
	repo = _git_repo(repo_path)
	if repo is None:
		return "unknown"
	try:
		return repo.head.commit.hexsha
	except Exception:
		return "unknown"


def _git_repo(repo_path: str):
	try:
		import git

		return git.Repo(repo_path)
	except Exception:
		return None


@contextmanager
def _env_overrides(overrides: dict[str, str | None]) -> Iterable[None]:
	previous = {}
	for key, value in overrides.items():
		previous[key] = os.environ.get(key)
		if value is None:
			os.environ.pop(key, None)
		else:
			os.environ[key] = value

	try:
		yield
	finally:
		for key, value in previous.items():
			if value is None:
				os.environ.pop(key, None)
			else:
				os.environ[key] = value


def _max_workers_override(scan_job: ScanJob) -> str | None:
	options = scan_job.options or {}
	value = options.get("max_workers")
	if value is None:
		return None
	return str(value)


def _external_validation_enabled(scan_job: ScanJob) -> bool:
	options = scan_job.options or {}
	return options.get("external_validation", True) is not False
