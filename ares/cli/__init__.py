"""
ARES CLI - Typer-based command line interface.

Entry point: ``ares`` console script → ares.cli.main:cli

Public imports:

    from ares.cli import cli, get_store, CampaignStore
"""
from __future__ import annotations

try:
    from ares.cli._store import (  # noqa: F401
        CampaignStore,
        calc_risk,
        get_store,
        load_all_campaigns,
        load_campaign,
        save_campaign,
    )
except ImportError:
    pass

__all__ = [
    "CampaignStore",
    "get_store",
    "load_campaign",
    "load_all_campaigns",
    "save_campaign",
    "calc_risk",
]
