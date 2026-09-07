"""ARES Programmatic API Client SDK.

Exported symbols:
    from ares.sdk.client import (
        AresClient,
        AresClientError,
        AresAuthenticationError,
        AresNotFoundError,
        AresValidationError,
    )
"""
from __future__ import annotations

from ares.sdk.client.client import (
    AresAuthenticationError,
    AresClient,
    AresClientError,
    AresNotFoundError,
    AresValidationError,
)

__all__ = [
    "AresClient",
    "AresClientError",
    "AresAuthenticationError",
    "AresNotFoundError",
    "AresValidationError",
]
