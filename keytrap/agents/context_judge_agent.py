"""Context judge agent using Anthropic for confidence review."""

from __future__ import annotations

import dataclasses
import json
import os
import threading

import anthropic

from keytrap.agents.base_agent import BaseScannerAgent
from keytrap.engine.redactor import redact
from keytrap.engine.schema import FindingSchema


_SEMAPHORE = threading.Semaphore(10)
_MODEL = "claude-sonnet-4-20250514"
_SYSTEM_PROMPT = (
	"You are a security analyst reviewing potential secret leaks. "
	"Analyze whether this is a real leaked credential or a false positive "
	"(test value, placeholder, example, documentation). Respond with JSON only, "
	"no other text: {is_real: bool, confidence: float, reason: string}"
)


class ContextJudgeAgent(BaseScannerAgent):
	"""Review low-confidence findings with LLM context."""

	def scan(self) -> list[FindingSchema]:
		raise NotImplementedError

	def review(
		self,
		finding: FindingSchema,
		surrounding_lines: list[str],
	) -> FindingSchema:
		if finding.confidence >= 0.75:
			return finding

		if not os.environ.get("ANTHROPIC_API_KEY"):
			return finding

		user_content = (
			f"secret_type: {finding.secret_type}\n"
			f"redacted_value: {redact(finding.secret, finding.provider)}\n"
			f"file_path: {finding.file_path}\n"
			"surrounding_code:\n"
			f"{os.linesep.join(surrounding_lines)}"
		)

		try:
			with _SEMAPHORE:
				client = anthropic.Anthropic()
				response = client.messages.create(
					model=_MODEL,
					max_tokens=200,
					system=_SYSTEM_PROMPT,
					messages=[
						{
							"role": "user",
							"content": user_content,
						}
					],
				)
		except Exception:
			return finding

		payload = _extract_json(response)
		if payload is None:
			return finding

		confidence = payload.get("confidence")
		if not isinstance(confidence, (float, int)):
			return finding

		bounded = max(0.0, min(1.0, float(confidence)))
		return dataclasses.replace(finding, confidence=bounded)


def _extract_json(response: object) -> dict[str, object] | None:
	try:
		content = response.content  # type: ignore[attr-defined]
		if not content:
			return None
		text = content[0].text  # type: ignore[index]
	except Exception:
		return None

	try:
		return json.loads(text)
	except json.JSONDecodeError:
		return None

