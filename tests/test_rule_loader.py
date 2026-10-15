"""Tests for rule loading and validation."""

from __future__ import annotations

from pathlib import Path

from keytrap.engine.rule_loader import RuleLoader


def test_core_rules_load_successfully(tmp_path: Path) -> None:
  loader = RuleLoader(production=False)
  root = Path(__file__).resolve().parents[1]
  rules_dir = tmp_path / "rules"
  rules_dir.mkdir(parents=True, exist_ok=True)
  (rules_dir / "keytrap-core.yml").write_text(
    (root / "rules" / "keytrap-core.yml").read_text(encoding="utf-8"),
    encoding="utf-8",
  )

  loaded_count, failed_count = loader.load(rules_dir)

  assert loaded_count == 10
  assert failed_count == 0
  assert len(loader.rules) == 10


def test_missing_required_field_rejected(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
version: 1
rules:
  - id: missing_regex
    name: Missing Regex
    provider: unknown
    category: generic
    severity: low
    confidence: low
    secret_group: 0
    redaction: keep_prefix_7_suffix_4
    tags: [api-key]
    allowlist:
      paths: [tests/]
      values: [example]
    source:
      origin: keytrap-core
      license: internal
      reviewed: true
""".lstrip(),
        encoding="utf-8",
    )

    loader = RuleLoader(production=False)
    loaded_count, failed_count = loader.load(tmp_path)

    assert loaded_count == 0
    assert failed_count == 1


def test_redos_regex_rejected(tmp_path: Path) -> None:
    rules_file = tmp_path / "redos.yml"
    rules_file.write_text(
        """
version: 1
rules:
  - id: redos_rule
    name: Redos Rule
    provider: unknown
    category: generic
    severity: low
    confidence: low
    regex: (a+)+$
    secret_group: 0
    redaction: keep_prefix_7_suffix_4
    tags: [api-key]
    allowlist:
      paths: [tests/]
      values: [example]
    source:
      origin: keytrap-core
      license: internal
      reviewed: true
""".lstrip(),
        encoding="utf-8",
    )

    loader = RuleLoader(production=False)
    loaded_count, failed_count = loader.load(tmp_path)

    assert loaded_count == 0
    assert failed_count == 1
