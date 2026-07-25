"""Response-boundary helpers for campaign finding rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


REDACTED_FINDING_EVIDENCE_JSON = '{"redacted":true}'


def redact_finding_response_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a finding row with evidence removed fail-closed."""
    redacted = dict(row)
    if "evidence_json" in row:
        redacted["evidence_json"] = REDACTED_FINDING_EVIDENCE_JSON
    return redacted


def redact_finding_response_rows(
    rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return response-safe copies of finding rows."""
    return [redact_finding_response_row(row) for row in rows]
