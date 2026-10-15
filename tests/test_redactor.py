"""Tests for secret redaction."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import RAW_SEEDED_VALUES
from keytrap.engine.redactor import redact


def test_provider_rules_redact_expected_prefixes() -> None:
    cases = [
        ("sk_live_51FakeTestingKeyNotRealXXXXXXXXXX", "stripe", "sk_live_****XXXX"),
        ("sk_test_FakeTestKeyNotReal123", "stripe", "sk_test_****l123"),
        ("AKIAIOSFODNN7EXAMPLEFAKEKEY", "aws", "AKIA****EKEY"),
        ("ghp_FakeTokenForTestingOnlyXXXXXXXXXXXX", "github", "ghp_****XXXX"),
        ("gho_FakeTokenForTestingOnlyXXXXXXXXXXXX", "github", "gho_****XXXX"),
        ("xoxb-fake-token-testing-only-xxxx-xxxx", "slack", "xoxb-****xxxx"),
    ]

    for raw_secret, provider, expected in cases:
        redacted = redact(raw_secret, provider)
        assert redacted == expected
        assert raw_secret not in redacted


def test_default_rule_redacts_unknown_provider() -> None:
    raw_secret = "unknownSecretValueNotReal123456"

    redacted = redact(raw_secret, "unknown")

    assert redacted == "****3456"
    assert raw_secret not in redacted


def test_unknown_secret_never_reveals_a_prefix() -> None:
    raw_secret = "Zq8!vR3x#Lm29pWt@db.prod.internal"

    redacted = redact(raw_secret, "unknown")

    assert redacted == "****rnal"
    assert "Zq8" not in redacted


def test_medium_unknown_secret_is_fully_redacted() -> None:
    assert redact("Zq8!vR3x#Lm29pWt", "unknown") == "****"


def test_short_secret_is_fully_redacted() -> None:
    assert redact("tinysecret", "unknown") == "****"


def test_outputs_do_not_contain_seeded_raw_values(outputs_dir: Path) -> None:
    output_file = outputs_dir / "redactor-output.txt"
    output_file.write_text(
        "\n".join(redact(raw_secret, "unknown") for raw_secret in RAW_SEEDED_VALUES),
        encoding="utf-8",
    )
    output = output_file.read_text(encoding="utf-8")

    for raw_secret in RAW_SEEDED_VALUES:
        assert raw_secret not in output
