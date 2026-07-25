from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from ares.api.findings import (
    REDACTED_FINDING_EVIDENCE_JSON,
    redact_finding_response_row,
    redact_finding_response_rows,
)


SYNTHETIC_EVIDENCE_MARKER = "SYNTHETIC-RAW-EVIDENCE-MARKER"


def test_redaction_returns_new_row_without_mutating_or_reshaping_input() -> None:
    row = {
        "id": "finding-1",
        "campaign_id": "campaign-1",
        "title": "Synthetic finding title",
        "description": "Synthetic finding description",
        "severity": "high",
        "confidence": 0.75,
        "evidence_json": json.dumps(
            {"nested": {"token": SYNTHETIC_EVIDENCE_MARKER}}
        ),
        "remediation": "Synthetic remediation",
        "host": "host.example.test",
    }
    original = deepcopy(row)

    result = redact_finding_response_row(row)

    assert result is not row
    assert row == original
    assert {
        key: value for key, value in result.items() if key != "evidence_json"
    } == {key: value for key, value in row.items() if key != "evidence_json"}
    assert isinstance(result["evidence_json"], str)
    assert result["evidence_json"] == REDACTED_FINDING_EVIDENCE_JSON
    assert json.loads(result["evidence_json"]) == {"redacted": True}
    assert SYNTHETIC_EVIDENCE_MARKER not in json.dumps(result)


@pytest.mark.parametrize(
    "evidence",
    [
        '{"nested":{"password":"SYNTHETIC-RAW-EVIDENCE-MARKER"}}',
        '["SYNTHETIC-RAW-EVIDENCE-MARKER"]',
        "SYNTHETIC-RAW-EVIDENCE-MARKER",
        '{"hash":"0123456789abcdef0123456789abcdef"}',
        (
            '{"password":"synthetic","token":"synthetic",'
            '"device_code":"synthetic","community":"synthetic",'
            '"snippet":"synthetic","command":"synthetic",'
            '"payload":"synthetic","output":"synthetic"}'
        ),
        '{"malformed":',
        None,
        42,
        {"unexpected": SYNTHETIC_EVIDENCE_MARKER},
    ],
)
def test_redaction_fails_closed_for_every_evidence_shape(evidence: Any) -> None:
    result = redact_finding_response_row(
        {"id": "finding-shape", "evidence_json": evidence}
    )

    assert result["evidence_json"] == REDACTED_FINDING_EVIDENCE_JSON
    assert SYNTHETIC_EVIDENCE_MARKER not in json.dumps(result)


def test_redaction_is_deterministic_idempotent_and_preserves_missing_field() -> None:
    row = {
        "id": "finding-repeat",
        "evidence_json": SYNTHETIC_EVIDENCE_MARKER,
    }
    once = redact_finding_response_row(row)
    twice = redact_finding_response_row(once)
    without_evidence = {"id": "finding-without-evidence", "title": "Metadata only"}

    assert once == twice
    assert redact_finding_response_row(row) == once
    assert redact_finding_response_row(without_evidence) == without_evidence
    assert redact_finding_response_row(without_evidence) is not without_evidence


def test_list_redaction_returns_new_rows_without_mutating_inputs() -> None:
    rows = [
        {"id": "finding-1", "evidence_json": SYNTHETIC_EVIDENCE_MARKER},
        {"id": "finding-2", "title": "Metadata only"},
    ]
    original = deepcopy(rows)

    result = redact_finding_response_rows(rows)

    assert rows == original
    assert result is not rows
    assert all(output is not source for output, source in zip(result, rows, strict=True))
    assert result[0]["evidence_json"] == REDACTED_FINDING_EVIDENCE_JSON
