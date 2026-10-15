"""Git diff scanner agent."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import git

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.custom_regex_agent import CustomRegexAgent
from keytrap.agents.entropy_agent import EntropyAgent
from keytrap.engine.schema import FindingSchema


class DiffAgent(BaseScannerAgent):
	"""Scan added lines between two commits."""

	def scan(
		self,
		repo_path: str,
		base_commit: str,
		head_commit: str,
		scan_id: str,
		branch: str,
	) -> list[FindingSchema]:
		repo = git.Repo(repo_path)
		repo_name = Path(repo_path).name
		regex_agent = CustomRegexAgent()
		entropy_agent = EntropyAgent()
		findings: list[FindingSchema] = []

		diff_index = repo.commit(base_commit).diff(head_commit, create_patch=True)
		for diff_item in diff_index:
			added_lines = _added_lines(diff_item.diff)
			if not added_lines:
				continue

			file_path = diff_item.b_path or diff_item.a_path or "unknown"
			content = "\n".join(added_lines)

			findings.extend(
				_relabel_findings(
					regex_agent.scan(
						file_path=file_path,
						file_content=content,
						scan_id=scan_id,
						repo=repo_name,
						branch=branch,
						commit=head_commit,
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
						commit=head_commit,
					)
				)
			)

		return findings


def _relabel_findings(findings: list[FindingSchema]) -> list[FindingSchema]:
	return [dataclasses.replace(finding, agent="DiffAgent") for finding in findings]


def _added_lines(patch: bytes | str) -> list[str]:
	if isinstance(patch, bytes):
		patch_text = patch.decode("utf-8", errors="ignore")
	else:
		patch_text = patch

	added: list[str] = []
	for line in patch_text.splitlines():
		if line.startswith("+++"):
			continue
		if line.startswith("+"):
			added.append(line[1:])
	return added
