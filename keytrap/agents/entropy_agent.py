"""Entropy scanner agent."""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.agents.filters import looks_binary, should_skip_file
from keytrap.engine.schema import FindingSchema


_TOKEN_PATTERN = re.compile(r"[^\s\"':;,()\[\]=<>{}!?&`]+")
_UUID_PATTERN = re.compile(
	r"^[0-9a-fA-F]{8}-"
	r"[0-9a-fA-F]{4}-"
	r"[0-9a-fA-F]{4}-"
	r"[0-9a-fA-F]{4}-"
	r"[0-9a-fA-F]{12}$"
)
_COMMON_WORDS = {
	"the",
	"and",
	"for",
	"with",
	"this",
	"that",
	"from",
	"your",
	"you",
	"are",
	"not",
	"but",
	"have",
	"has",
	"had",
	"was",
	"were",
	"will",
	"would",
	"can",
	"could",
	"should",
	"a",
	"an",
	"in",
	"on",
	"of",
	"to",
	"as",
	"by",
	"be",
	"it",
	"is",
	"or",
	"if",
	"then",
	"else",
	"when",
	"where",
	"which",
	"what",
	"why",
	"how",
	"all",
	"any",
	"some",
	"more",
	"most",
	"less",
	"few",
	"many",
	"about",
	"into",
	"over",
	"under",
	"before",
	"after",
	"again",
	"once",
	"here",
	"there",
	"example",
	"placeholder",
}


class EntropyAgent(BaseScannerAgent):
	"""Scan file contents for high-entropy tokens."""

	def scan(
		self,
		file_path: str,
		file_content: str,
		scan_id: str,
		repo: str,
		branch: str,
		commit: str,
	) -> list[FindingSchema]:
		findings: list[FindingSchema] = []

		if should_skip_file(file_path) or looks_binary(file_content):
			return findings

		for match in _TOKEN_PATTERN.finditer(file_content):
			token = match.group(0).strip()
			if not token or _skip_token(token):
				continue

			context_before = _context_line(file_content, match.start(), match.end())
			confidence = _secret_confidence(token, context_before)
			if confidence is None:
				continue

			line_start, line_end = _line_span(file_content, match.start(), match.end())

			raw_finding = {
				"scan_id": scan_id,
				"agent": "EntropyAgent",
				"provider": "unknown",
				"secret_type": "high_entropy_token",
				"secret": token,
				"repo": repo,
				"branch": branch,
				"commit": commit,
				"file_path": file_path,
				"line_start": line_start,
				"line_end": line_end,
				"context_before": context_before,
				"confidence": confidence,
				"severity": "low",
				"risk_score": 0,
				"created_at": datetime.now(timezone.utc).isoformat(),
			}
			findings.append(self.normalize(raw_finding))

		return findings


def _skip_token(token: str) -> bool:
	"""Cheap rejects: words, numbers, paths, UUIDs."""
	if token.lower() in _COMMON_WORDS or token.isdigit():
		return True
	if "/" in token or "\\" in token:
		return True
	return "-" in token and bool(_UUID_PATTERN.match(token))


# Characters a generated key is made of: base64 / base64url / hex, plus dots for JWTs.
_KEY_CHARS = re.compile(r"[A-Za-z0-9+=_\-.~]+")
_HEX = re.compile(r"[0-9a-fA-F]+")
_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
# A name made only of readable chunks: Words, ACRONYMS, short numbers (displayName, API_KEY_2).
_NAME_CHUNK = re.compile(r"(?:[A-Z]?[a-z]{3,}|[A-Z]{2,}(?![a-z])|[A-Z][a-z]?|\d{1,3})")
_SECRET_HINT = re.compile(
	r"(?i)(secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey|auth|credential|"
	r"private[_-]?key|access[_-]?key|bearer|signature)"
)


def _looks_like_name(token: str) -> bool:
	"""True for identifiers and constants made of dictionary-style chunks."""
	for part in re.split(r"[_\-.]+", token):
		if not part:
			continue
		pos = 0
		while pos < len(part):
			m = _NAME_CHUNK.match(part, pos)
			if not m:
				return False
			pos = m.end()
		# a long run of one-letter chunks ("aB3dE5...") is random, not a name
		if len(part) > 8 and len(_NAME_CHUNK.findall(part)) > len(part) / 3:
			return False
	return True


def _secret_confidence(token: str, line: str) -> float | None:
	"""Return a confidence if the token looks like a generated secret, else None.

	Tokens must be built from key characters, must not read like a name or a
	dotted property access, and need more evidence when nothing on the line
	hints at a credential.
	"""
	if _JWT.fullmatch(token):
		return 0.7
	if not _KEY_CHARS.fullmatch(token) or "." in token:
		return None
	if re.match(r"(?i)(sha\d+|md5)-", token):  # subresource-integrity hashes
		return None
	if _looks_like_name(token):
		return None

	classes = sum(
		(any(c.islower() for c in token), any(c.isupper() for c in token), any(c.isdigit() for c in token))
	)
	if classes < 2:
		return None

	entropy = _shannon_entropy(token)
	if _SECRET_HINT.search(line):
		return 0.6 if len(token) >= 16 and entropy >= 4.0 else None
	# No credential hint nearby: stricter, and never a bare hash or commit id.
	if len(token) < 24 or entropy < 4.8 or _HEX.fullmatch(token):
		return None
	return 0.4


def _shannon_entropy(token: str) -> float:
	counts = Counter(token)
	length = len(token)
	return -sum(
		(count / length) * math.log2(count / length) for count in counts.values()
	)


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

