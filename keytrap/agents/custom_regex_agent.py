"""Custom regex scanner agent."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Iterable

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.filters import looks_binary, should_skip_file
from keytrap.engine.rule_loader import Rule, RuleLoader
from keytrap.engine.schema import FindingSchema


class CustomRegexAgent(BaseScannerAgent):
	"""Scan file contents against configured regex rules."""

	def __init__(self, rules: Iterable[Rule] | None = None) -> None:
		if rules is None:
			loader = RuleLoader()
			rules_dir = _rules_dir_override() or _default_rules_dir()
			loader.load(rules_dir)
			self.rules = list(loader.rules)
		else:
			self.rules = list(rules)

	def scan(
		self,
		file_path: str,
		file_content: str,
		scan_id: str,
		repo: str,
		branch: str,
		commit: str,
	) -> list[FindingSchema]:
		candidates: list[tuple[int, int, FindingSchema]] = []

		if should_skip_file(file_path) or looks_binary(file_content):
			return []

		for rule in self.rules:
			for match in rule.pattern.finditer(file_content):
				try:
					raw_secret = match.group(rule.secret_group)
				except IndexError:
					continue

				if self.check_allowlist(file_path, raw_secret, rule.allowlist):
					continue

				line_start, line_end = _line_span(file_content, match.start(), match.end())
				context_before = _context_line(
					file_content,
					match.start(),
					match.end(),
				)

				raw_finding = {
					"scan_id": scan_id,
					"agent": "CustomRegexAgent",
					"provider": rule.provider,
					"secret_type": rule.name,
					"secret": raw_secret,
					"repo": repo,
					"branch": branch,
					"commit": commit,
					"file_path": file_path,
					"line_start": line_start,
					"line_end": line_end,
					"context_before": context_before,
					"confidence": rule.confidence,
					"severity": rule.severity,
					"risk_score": 0,
					"created_at": datetime.now(timezone.utc).isoformat(),
				}
				span_start, span_end = match.span(rule.secret_group)
				candidates.append((span_start, span_end, self.normalize(raw_finding)))

		return _drop_nested_matches(candidates)


def _drop_nested_matches(
	candidates: list[tuple[int, int, FindingSchema]],
) -> list[FindingSchema]:
	"""Drop matches fully inside a longer match, e.g. a shorter rule hitting
	the same token. They would hash differently and defeat deduplication."""
	return [
		finding
		for start, end, finding in candidates
		if not any(
			o_start <= start and end <= o_end and (o_start, o_end) != (start, end)
			for o_start, o_end, _ in candidates
		)
	]


def _default_rules_dir() -> Path:
	return Path(__file__).resolve().parents[2] / "rules"


def _rules_dir_override() -> Path | None:
	value = os.environ.get("KEYTRAP_RULES_DIR")
	if not value:
		return None
	return Path(value)


def _line_span(text: str, start: int, end: int) -> tuple[int, int]:
	line_start = text.count("\n", 0, start) + 1
	line_end = text.count("\n", 0, end) + 1
	return line_start, line_end


def _context_line(
	text: str,
	start: int,
	end: int,
) -> str:
	line_start = text.rfind("\n", 0, start)
	line_start = 0 if line_start == -1 else line_start + 1
	line_end = text.find("\n", end)
	line_end = len(text) if line_end == -1 else line_end
	return text[line_start:line_end]

