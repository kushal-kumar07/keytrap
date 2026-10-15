"""Git history scanner agent."""

from __future__ import annotations

import dataclasses
import os
from itertools import islice
from pathlib import Path

import git

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.custom_regex_agent import CustomRegexAgent
from keytrap.agents.entropy_agent import EntropyAgent
from keytrap.agents.filters import looks_binary, should_skip_file
from keytrap.engine.schema import FindingSchema


class HistoryAgent(BaseScannerAgent):
	"""Scan git history for secrets across commits."""

	def scan(self, repo_path: str, scan_id: str) -> list[FindingSchema]:
		repo = git.Repo(repo_path)
		repo_name = Path(repo_path).name
		branch = _active_branch(repo)
		max_commits = int(os.environ.get("MAX_COMMITS_HISTORY", 1000))

		regex_agent = CustomRegexAgent()
		entropy_agent = EntropyAgent()
		findings: list[FindingSchema] = []

		for commit in islice(repo.iter_commits(), max_commits):
			for diff_item in _commit_diffs(commit):
				file_path = diff_item.b_path or diff_item.a_path
				if not file_path or should_skip_file(file_path):
					continue

				content = _read_file_at_commit(commit, file_path)
				if content is None:
					continue

				findings.extend(
					_relabel_findings(
						regex_agent.scan(
							file_path=file_path,
							file_content=content,
							scan_id=scan_id,
							repo=repo_name,
							branch=branch,
							commit=commit.hexsha,
						)
					)
				)
				findings.extend(
					_relabel_findings(
						entropy_agent.scan(
							file_path=file_path,
							file_content=content,
							scan_id=scan_id,
							repo=repo_name,
							branch=branch,
							commit=commit.hexsha,
						)
					)
				)

			message = commit.message or ""
			if message.strip():
				findings.extend(
					_relabel_findings(
						regex_agent.scan(
							file_path="commit_message",
							file_content=message,
							scan_id=scan_id,
							repo=repo_name,
							branch=branch,
							commit=commit.hexsha,
						)
					)
				)
				findings.extend(
					_relabel_findings(
						entropy_agent.scan(
							file_path="commit_message",
							file_content=message,
							scan_id=scan_id,
							repo=repo_name,
							branch=branch,
							commit=commit.hexsha,
						)
					)
				)

		return findings


def _relabel_findings(findings: list[FindingSchema]) -> list[FindingSchema]:
	return [dataclasses.replace(finding, agent="HistoryAgent") for finding in findings]


def _active_branch(repo: git.Repo) -> str:
	try:
		return repo.active_branch.name
	except (TypeError, ValueError):
		return "unknown"


def _commit_diffs(commit: git.Commit) -> git.DiffIndex:
	if commit.parents:
		return commit.parents[0].diff(commit)
	return commit.diff(git.NULL_TREE)


def _read_file_at_commit(commit: git.Commit, file_path: str) -> str | None:
	try:
		blob = commit.tree / file_path
	except KeyError:
		return None

	try:
		data = blob.data_stream.read()
	except OSError:
		return None

	if looks_binary(data):
		return None

	try:
		return data.decode("utf-8")
	except UnicodeDecodeError:
		return data.decode("utf-8", errors="ignore")
