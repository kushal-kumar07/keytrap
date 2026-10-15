"""Community rule importer for KeyTrap."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import re
import threading
from typing import Any, Iterable

import httpx
import yaml


_LOGGER = logging.getLogger(__name__)

SOURCE_URLS = {
    "mazen160": (
        "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml",
        "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/main/db/rules-stable.yml",
    ),
    "h33tlit": (
        "https://raw.githubusercontent.com/h33tlit/secret-regex-list/master/README.md",
        "https://raw.githubusercontent.com/h33tlit/secret-regex-list/main/README.md",
    ),
    "odomojuli": (
        "https://raw.githubusercontent.com/odomojuli/regextokens/master/README.md",
        "https://raw.githubusercontent.com/odomojuli/regextokens/main/README.md",
    ),
}

LICENSES = {
    "mazen160": "CC-BY-4.0",
    "h33tlit": "unknown",
    "odomojuli": "unknown",
}

SAMPLES_BY_PROVIDER = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_1234567890abcdefghijklmnopqrstuv",
    "gcp": "AIzaSyD1234567890abcdefghijklmnopqrst",
    "google": "AIzaSyD1234567890abcdefghijklmnopqrst",
    "slack": "xoxb-12345678901-12345678901-abcdefghijklmnopqrstuvwx",
    "stripe": "sk_live_1234567890abcdefghijklmnopqrst",
    "openai": "sk-1234567890ABCDEFGHIJT3BlbkFJ1234567890ABCDEFGHIJ",
    "mailchimp": "0123456789abcdef0123456789abcdef-us12",
    "facebook": "EAACEdEose0cBA1234567890abcdef",
    "twitter": "123456789-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
    "heroku": "12345678-1234-1234-1234-123456789abc",
    "unknown": "keytrap_secret_1234567890abcdefABCDEF",
}


@dataclass(frozen=True)
class ImportedRule:
    rule_id: str
    name: str
    provider: str
    regex: str
    sample: str
    source_url: str
    license: str


def import_rules(source: str, output_dir: Path) -> dict[str, Any]:
    """Import community rules and write KeyTrap YAML files."""
    normalized_source = source.lower()
    if normalized_source not in SOURCE_URLS:
        raise ValueError(f"Unsupported rule source: {source}")

    source_url, text = _fetch_source(normalized_source)
    fp_corpus = _load_fp_corpus()
    candidates = _parse_source(normalized_source, text, source_url)

    passed: list[ImportedRule] = []
    failed: list[dict[str, str]] = []
    for candidate in candidates:
        reason = _validate_rule(candidate, fp_corpus)
        if reason is None:
            passed.append(candidate)
        else:
            failed.append({"id": candidate.rule_id, "reason": reason})
            _LOGGER.warning("Imported rule %s rejected: %s", candidate.rule_id, reason)

    output_dir.mkdir(parents=True, exist_ok=True)
    written_files = _write_rules(passed, output_dir, normalized_source)

    return {
        "source": normalized_source,
        "source_url": source_url,
        "imported": len(passed),
        "failed": len(failed),
        "written_files": [str(path) for path in written_files],
        "failures": failed,
    }


def _fetch_source(source: str) -> tuple[str, str]:
    last_error: Exception | None = None
    for url in SOURCE_URLS[source]:
        try:
            response = httpx.get(url, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
            return url, response.text
        except Exception as exc:  # noqa: BLE001 - try fallback branch
            last_error = exc
    raise RuntimeError(f"Failed to fetch rules for {source}") from last_error


def _parse_source(source: str, text: str, source_url: str) -> list[ImportedRule]:
    if source == "mazen160":
        return _parse_mazen160(text, source_url)
    if source == "h33tlit":
        return _parse_h33tlit(text, source_url)
    if source == "odomojuli":
        return _parse_odomojuli(text, source_url)
    return []


def _parse_mazen160(text: str, source_url: str) -> list[ImportedRule]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []

    candidates: list[ImportedRule] = []
    for item in _walk_mappings(data):
        regex = _first_string(item, "regex", "pattern", "secret_regex", "rule")
        if not regex:
            continue
        name = _first_string(item, "name", "title", "id", "description") or "Imported rule"
        provider = _provider_from_text(
            _first_string(item, "provider", "service", "name", "id", "tags") or name
        )
        sample = _first_string(item, "sample", "example", "test", "valid") or _sample_for(provider)
        candidates.append(
            ImportedRule(
                rule_id=_rule_id("mazen160", provider, name, regex),
                name=name,
                provider=provider,
                regex=regex,
                sample=sample,
                source_url=source_url,
                license=LICENSES["mazen160"],
            )
        )
    return _dedupe_candidates(candidates)


def _parse_h33tlit(text: str, source_url: str) -> list[ImportedRule]:
    return _parse_markdown_regexes("h33tlit", text, source_url)


def _parse_odomojuli(text: str, source_url: str) -> list[ImportedRule]:
    return _parse_markdown_regexes("odomojuli", text, source_url)


def _parse_markdown_regexes(source: str, text: str, source_url: str) -> list[ImportedRule]:
    candidates: list[ImportedRule] = []
    headings: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            if title:
                level = len(stripped) - len(stripped.lstrip("#"))
                headings = headings[: max(0, level - 1)]
                headings.append(title)
            continue

        regexes = re.findall(r"`([^`]{6,})`", stripped)
        for regex in regexes:
            cleaned = _clean_regex(regex)
            if not cleaned or _looks_like_command(cleaned):
                continue
            name = " ".join(headings[-2:]) or "Imported rule"
            provider = _provider_from_text(" ".join(headings) + " " + cleaned)
            candidates.append(
                ImportedRule(
                    rule_id=_rule_id(source, provider, name, cleaned),
                    name=name,
                    provider=provider,
                    regex=cleaned,
                    sample=_sample_for(provider),
                    source_url=source_url,
                    license=LICENSES[source],
                )
            )
    return _dedupe_candidates(candidates)


def _validate_rule(rule: ImportedRule, fp_corpus: list[str]) -> str | None:
    if not rule.rule_id or not rule.regex or not rule.provider:
        return "missing id, regex, or provider"

    try:
        pattern = re.compile(rule.regex)
    except re.error:
        return "regex compile failed"

    if _looks_catastrophic(rule.regex):
        return "regex rejected by heuristic"

    if not _passes_redos_timeout(pattern):
        return "regex failed ReDoS timeout"

    try:
        if pattern.search(rule.sample) is None:
            return "sample did not match"
    except Exception:
        return "sample check failed"

    for fp_value in fp_corpus:
        try:
            if pattern.search(fp_value):
                return "matched false-positive corpus"
        except Exception:
            return "false-positive check failed"

    return None


def _write_rules(
    rules: Iterable[ImportedRule],
    output_dir: Path,
    source: str,
) -> list[Path]:
    grouped: dict[str, list[ImportedRule]] = {}
    for rule in rules:
        grouped.setdefault(rule.provider, []).append(rule)

    import_date = datetime.now(timezone.utc).date().isoformat()
    written: list[Path] = []
    for provider, provider_rules in sorted(grouped.items()):
        payload = {
            "version": 1,
            "rules": [
                _to_keytrap_rule(rule, source, import_date)
                for rule in sorted(provider_rules, key=lambda item: item.rule_id)
            ],
        }
        path = output_dir / f"{provider}.yml"
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        written.append(path)
    return written


def _to_keytrap_rule(rule: ImportedRule, source: str, import_date: str) -> dict[str, Any]:
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "provider": rule.provider,
        "category": "imported",
        "severity": "medium",
        "confidence": 0.8,
        "regex": rule.regex,
        "secret_group": 0,
        "redaction": "keep_prefix_7_suffix_4",
        "tags": ["imported", source, rule.provider],
        "allowlist": {
            "paths": ["tests/", "docs/", "examples/", "fixtures/"],
            "values": [
                "example",
                "placeholder",
                "your_key_here",
                "test_key",
                "fake_secret",
            ],
        },
        "source": {
            "origin": source,
            "license": rule.license,
            "reviewed": False,
            "source_url": rule.source_url,
            "import_date": import_date,
        },
    }


def _load_fp_corpus() -> list[str]:
    corpus_path = Path(__file__).resolve().parents[2] / "rules" / "fp_corpus.txt"
    if not corpus_path.exists():
        return []
    return [
        line.strip()
        for line in corpus_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _passes_redos_timeout(pattern: re.Pattern[str]) -> bool:
    error_holder: list[Exception] = []
    adversarial = "a" * 10000 + "!"

    def worker() -> None:
        try:
            pattern.search(adversarial)
        except Exception as exc:  # pragma: no cover - defensive
            error_holder.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(0.1)
    return not thread.is_alive() and not error_holder


def _walk_mappings(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _first_string(item: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return _clean_regex(value) if key in {"regex", "pattern", "secret_regex", "rule"} else value.strip()
        if isinstance(value, list):
            joined = " ".join(str(part) for part in value)
            if joined.strip():
                return joined.strip()
    return None


def _clean_regex(regex: str) -> str:
    cleaned = regex.strip()
    if cleaned.startswith("/") and cleaned.endswith("/") and len(cleaned) > 2:
        cleaned = cleaned[1:-1]
    return cleaned.strip()


def _looks_like_command(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("git ", "egrep ", "grep ", "http://", "https://"))


def _provider_from_text(text: str) -> str:
    lowered = text.lower()
    checks = (
        ("github", ("github", "ghp_", "gho_", "github_pat")),
        ("aws", ("amazon", "aws", "akia", "secret access key")),
        ("gcp", ("google", "gcp", "aiza", "firebase")),
        ("slack", ("slack", "xoxb", "xoxp")),
        ("stripe", ("stripe", "sk_live", "sk_test")),
        ("openai", ("openai", "sk-proj", "t3blbkfj")),
        ("mailchimp", ("mailchimp", "-us")),
        ("facebook", ("facebook", "eaaced")),
        ("twitter", ("twitter", "tweet")),
        ("heroku", ("heroku",)),
    )
    for provider, needles in checks:
        if any(needle in lowered for needle in needles):
            return provider
    return "unknown"


def _sample_for(provider: str) -> str:
    return SAMPLES_BY_PROVIDER.get(provider, SAMPLES_BY_PROVIDER["unknown"])


def _rule_id(source: str, provider: str, name: str, regex: str) -> str:
    material = hashlib.sha1(f"{source}:{provider}:{name}:{regex}".encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^a-z0-9]+", "_", f"{source}_{provider}_{name.lower()}").strip("_")
    return f"{slug}_{material}"[:120]


def _dedupe_candidates(candidates: list[ImportedRule]) -> list[ImportedRule]:
    seen: set[str] = set()
    deduped: list[ImportedRule] = []
    for candidate in candidates:
        if candidate.regex in seen:
            continue
        seen.add(candidate.regex)
        deduped.append(candidate)
    return deduped


def _looks_catastrophic(pattern: str) -> bool:
    return bool(re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern))
