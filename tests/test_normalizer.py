"""Tests for normalizing scanner output."""

from __future__ import annotations

import dataclasses

import pytest

from keytrap.engine.normalizer import NormalizerError, normalize
from keytrap.engine.schema import FindingSchema


def test_normalize_returns_finding_schema(sample_finding: FindingSchema) -> None:
    raw = dataclasses.asdict(sample_finding)
    raw.pop("finding_id")
    raw.pop("evidence_policy")

    normalized = normalize(raw)

    assert normalized == sample_finding


def test_normalize_raises_field_name_for_missing_field(
    sample_finding: FindingSchema,
) -> None:
    raw = dataclasses.asdict(sample_finding)
    raw.pop("finding_id")
    raw.pop("evidence_policy")
    raw.pop("repo")

    with pytest.raises(NormalizerError) as error:
        normalize(raw)

    assert error.value.field_name == "repo"


def test_normalize_raises_field_name_for_wrong_type(
    sample_finding: FindingSchema,
) -> None:
    raw = dataclasses.asdict(sample_finding)
    raw.pop("finding_id")
    raw.pop("evidence_policy")
    raw["line_start"] = "3"

    with pytest.raises(NormalizerError) as error:
        normalize(raw)

    assert error.value.field_name == "line_start"
