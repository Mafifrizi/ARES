"""Pure contracts used by the PostgreSQL auth-token adapter."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from ares.db.postgres import (
    _parse_postgres_timestamptz,
    _refresh_token_user_lock_key,
)


def test_refresh_token_lock_key_is_stable_namespaced_signed_bigint() -> None:
    user_id = "contract-user"
    expected = int.from_bytes(
        hashlib.sha256(
            b"ares:refresh-token-user:v1\x00" + user_id.encode("utf-8")
        ).digest()[:8],
        byteorder="big",
        signed=True,
    )

    assert _refresh_token_user_lock_key(user_id) == expected
    assert _refresh_token_user_lock_key(user_id) == expected
    assert -(2**63) <= expected < 2**63
    assert _refresh_token_user_lock_key("other-user") != expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2030-01-02 03:04:05", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2030-01-02T03:04:05+00:00", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2030-01-02T08:34:05+05:30", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
    ],
)
def test_parse_postgres_timestamptz_normalizes_to_utc(
    value: str,
    expected: datetime,
) -> None:
    assert _parse_postgres_timestamptz(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-timestamp",
        "2030-99-99 25:61:61",
        "2030-01-02",
        "2030-01-02T03:04:05",
    ],
)
def test_parse_postgres_timestamptz_rejects_malformed_input(value: str) -> None:
    with pytest.raises(ValueError):
        _parse_postgres_timestamptz(value)
