"""Tests for the community rule importer."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from keytrap.cli import app
from keytrap.engine.rule_importer import import_rules
from keytrap.engine.rule_loader import RuleLoader


class _Response:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        return None


def test_import_from_source_writes_20_plus_rules(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "keytrap.engine.rule_importer.httpx.get",
        lambda *_args, **_kwargs: _Response(_mazen_source(24)),
    )

    result = import_rules("mazen160", tmp_path)

    assert result["imported"] >= 20
    assert result["failed"] == 0
    assert (tmp_path / "aws.yml").exists()


def test_catastrophic_regex_rejected(monkeypatch, tmp_path: Path) -> None:
    source = """
rules:
  - id: bad_redos
    name: Bad ReDoS
    provider: unknown
    regex: '(a+)+$'
    sample: aaaaaaaaaaaaaaaaaaaa
""".lstrip()
    monkeypatch.setattr(
        "keytrap.engine.rule_importer.httpx.get",
        lambda *_args, **_kwargs: _Response(source),
    )

    result = import_rules("mazen160", tmp_path)

    assert result["imported"] == 0
    assert result["failed"] == 1
    assert not list(tmp_path.glob("*.yml"))


def test_fp_corpus_value_not_matched_by_imported_rules(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source = """
rules:
  - id: bad_fp
    name: Bad FP Rule
    provider: unknown
    regex: 'example|keytrap_secret_[A-Za-z0-9]{20,}'
    sample: keytrap_secret_1234567890abcdefABCDEF
""".lstrip()
    monkeypatch.setattr(
        "keytrap.engine.rule_importer.httpx.get",
        lambda *_args, **_kwargs: _Response(source),
    )

    result = import_rules("mazen160", tmp_path)

    assert result["imported"] == 0
    assert result["failed"] == 1
    assert "false-positive" in result["failures"][0]["reason"]


def test_rule_loader_loads_imported_rules_after_import(
    monkeypatch,
    tmp_path: Path,
) -> None:
    imported = tmp_path / "rules" / "imported"
    monkeypatch.setattr(
        "keytrap.engine.rule_importer.httpx.get",
        lambda *_args, **_kwargs: _Response(_mazen_source(21)),
    )
    import_rules("mazen160", imported)

    loader = RuleLoader(production=False)
    loaded, failed = loader.load(tmp_path / "rules")

    assert loaded >= 20
    assert failed == 0
    assert any(rule.source["origin"] == "mazen160" for rule in loader.rules)
    assert all(rule.confidence == 0.8 for rule in loader.rules)


def test_cli_import_rules(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "keytrap.engine.rule_importer.httpx.get",
        lambda *_args, **_kwargs: _Response(_mazen_source(20)),
    )

    result = CliRunner().invoke(
        app,
        ["import-rules", "--source", "mazen160", "--output", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Imported 20 rules" in result.output
    assert (tmp_path / "aws.yml").exists()


def _mazen_source(count: int) -> str:
    rules = []
    for index in range(count):
        rules.append(
            {
                "id": f"aws_rule_{index}",
                "name": f"AWS Imported Rule {index}",
                "provider": "aws",
                "regex": rf"AKIA[0-9A-Z]{{16}}{index:02d}",
                "sample": f"AKIAIOSFODNN7EXAMPLE{index:02d}",
            }
        )
    return "rules:\n" + "\n".join(_yaml_rule(rule) for rule in rules)


def _yaml_rule(rule: dict[str, str]) -> str:
    return (
        f"  - id: {rule['id']}\n"
        f"    name: {rule['name']}\n"
        f"    provider: {rule['provider']}\n"
        f"    regex: '{rule['regex']}'\n"
        f"    sample: {rule['sample']}\n"
    )
