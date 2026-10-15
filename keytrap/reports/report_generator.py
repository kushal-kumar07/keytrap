"""Report generation for KeyTrap scans."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from keytrap.engine.orchestrator import ScanResult
from keytrap.engine.risk_scorer import score
from keytrap.engine.schema import FindingSchema


_LOGGER = logging.getLogger(__name__)


def generate(scan_result: ScanResult, fmt: str) -> Path:
	"""Generate a report and return the output path."""
	normalized = fmt.lower().strip()
	output_dir = _reports_dir()
	output_dir.mkdir(parents=True, exist_ok=True)

	if normalized == "markdown":
		path = output_dir / f"scan_{scan_result.scan_id}.md"
		path.write_text(_render_markdown(scan_result), encoding="utf-8")
		return path

	if normalized == "pdf":
		try:
			from weasyprint import HTML
		except ImportError as e:
			raise ImportError(
				"WeasyPrint is required for PDF generation. "
				"Install with: pip install weasyprint"
			) from e
		markdown = _render_markdown(scan_result)
		path = output_dir / f"scan_{scan_result.scan_id}.pdf"
		HTML(string=markdown).write_pdf(path)
		return path

	if normalized == "hackerone":
		folder = output_dir / f"scan_{scan_result.scan_id}_hackerone"
		if folder.exists():
			shutil.rmtree(folder)
		folder.mkdir(parents=True, exist_ok=True)
		_render_hackerone_files(folder, scan_result.findings)
		zip_path = output_dir / f"scan_{scan_result.scan_id}_hackerone.zip"
		if zip_path.exists():
			zip_path.unlink()
		_zip_folder(folder, zip_path)
		return zip_path

	raise ValueError(f"Unsupported report format: {fmt}")


def scan_result_from_file(path: Path) -> ScanResult:
	"""Build a ScanResult from a findings.json written by `keytrap scan`."""
	scan = json.loads(Path(path).read_text(encoding="utf-8"))

	findings = [
		FindingSchema(**{k: v for k, v in row.items() if k not in _DERIVED_FIELDS})
		for row in scan.get("findings", [])
	]
	stats = scan.get("stats") or {
		"raw_findings": len(findings),
		"deduped_findings": len(findings),
		"by_severity": _count_by(findings, "severity"),
		"by_agent": _count_agents(findings),
		"by_provider": _count_by(findings, "provider"),
	}
	now = datetime.now(timezone.utc).isoformat()

	return ScanResult(
		scan_id=scan.get("scan_id") or "unknown",
		findings=sorted(findings, key=lambda item: item.risk_score, reverse=True),
		stats=stats,
		started_at=scan.get("started_at") or now,
		completed_at=scan.get("completed_at") or now,
	)


_DERIVED_FIELDS = {"finding_id", "evidence_policy"}


def _render_markdown(scan_result: ScanResult) -> str:
	findings = sorted(scan_result.findings, key=lambda item: item.risk_score, reverse=True)
	stats = scan_result.stats or {}
	total = stats.get("deduped_findings", len(findings))
	by_severity = stats.get("by_severity", _count_by(findings, "severity"))

	lines = [
		"# KeyTrap Report",
		"",
		"## Executive Summary",
		f"Total findings: {total}",
		f"Severities: {_format_counts(by_severity)}",
		"",
		"## Findings",
		"| Risk | Severity | Provider | File | Line | Redacted Secret | Commit |",
		"| --- | --- | --- | --- | --- | --- | --- |",
	]

	for finding in findings:
		lines.append(
			"| "
			f"{finding.risk_score} | "
			f"{finding.severity} | "
			f"{finding.provider} | "
			f"{finding.file_path} | "
			f"{finding.line_start} | "
			f"{finding.secret} | "
			f"{finding.commit} |"
		)

	lines.append("")
	lines.append("## Finding Details")

	for index, finding in enumerate(findings, start=1):
		lines.extend(
			[
				f"### Finding {index}",
				f"- Provider: {finding.provider}",
				f"- Severity: {finding.severity}",
				f"- Risk score: {finding.risk_score}",
				f"- Agent(s): {finding.agent}",
				f"- File: {finding.file_path}:{finding.line_start}",
				f"- Commit: {finding.commit}",
				f"- Secret: {finding.secret}",
				"",
				"Context:",
				"```",
				finding.context_before,
				"```",
				"",
				"Risk score breakdown:",
			]
		)

		lines.extend(_format_breakdown(finding))
		lines.append("")
		lines.append("Remediation:")
		lines.append(_remediation_text(finding.provider))
		lines.append("")

	lines.extend(
		[
			"## Methodology",
			"- GitleaksAgent, TruffleHogAgent, CustomRegexAgent, EntropyAgent.",
			"- HistoryAgent for deleted or historical exposures.",
			"- DiffAgent for added-line scans when diff commits are supplied.",
			"- ContextJudgeAgent for low-confidence triage using surrounding context (secrets masked before sending).",
		]
	)

	return "\n".join(lines)


def _render_hackerone_files(output_dir: Path, findings: Iterable[FindingSchema]) -> None:
	for index, finding in enumerate(findings, start=1):
		file_path = output_dir / f"finding_{index}.md"
		content = _hackerone_markdown(finding)
		file_path.write_text(content, encoding="utf-8")


def _hackerone_markdown(finding: FindingSchema) -> str:
	remediation = _remediation_text(finding.provider)
	lines = [
		f"Title: {finding.provider} secret exposure in {finding.file_path}",
		f"Severity: {finding.severity}",
		"",
		"Steps to Reproduce:",
		f"1. Locate {finding.file_path} at line {finding.line_start}.",
		f"2. Review commit {finding.commit}.",
		f"3. Observe secret {finding.secret}.",
		"",
		"Impact:",
		"Exposed credentials can enable unauthorized access to linked services.",
		"",
		"Remediation:",
		remediation,
		"",
	]
	return "\n".join(lines)


def _format_breakdown(finding: FindingSchema) -> list[str]:
	_, breakdown = score(finding, {})
	lines = []
	for signal, value in breakdown.items():
		if value == 0:
			continue
		sign = "+" if value > 0 else ""
		lines.append(f"- {signal}: {sign}{value}")
	return lines or ["- none"]


def _remediation_text(provider: str) -> str:
	templates_dir = Path(__file__).resolve().parents[1] / "reports" / "templates" / "remediation"
	filename = f"{provider.lower()}.md"
	path = templates_dir / filename
	if not path.exists():
		path = templates_dir / "generic.md"
	return path.read_text(encoding="utf-8").strip()


def _reports_dir() -> Path:
	return Path(
		os.environ.get(
			"KEYTRAP_REPORTS_DIR",
			str(Path(tempfile.gettempdir()) / "keytrap_reports"),
		)
	)



def _zip_folder(source: Path, output_path: Path) -> None:
	with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		for file_path in source.rglob("*"):
			if file_path.is_file():
				archive.write(file_path, file_path.relative_to(source))


def _count_by(findings: Iterable[FindingSchema], field: str) -> dict[str, int]:
	counts: dict[str, int] = {}
	for finding in findings:
		value = str(getattr(finding, field))
		counts[value] = counts.get(value, 0) + 1
	return counts


def _format_counts(counts: dict[str, int]) -> str:
	if not counts:
		return "none"
	return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _count_agents(findings: Iterable[FindingSchema]) -> dict[str, int]:
	counts: dict[str, int] = {}
	for finding in findings:
		for part in finding.agent.split(","):
			name = part.strip()
			if not name:
				continue
			counts[name] = counts.get(name, 0) + 1
	return counts
