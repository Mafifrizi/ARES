"""Small, server-side runtime state shared by all executions in a campaign."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from ares.credential.vault import CredentialVault
from ares.normalize.artifacts import ArtifactStore
from ares.state.target_state import OperatorSession


@dataclass
class CampaignRuntimeState:
    """Non-response state that is safe to share across a campaign's modules."""

    campaign_id: str
    vault: CredentialVault
    session: OperatorSession
    artifact_store: ArtifactStore
    telemetry: Any = None
    attack_graph: Any = None
    hydrated: bool = False

    def safe_credentials(self) -> list[Any]:
        """Return encrypted credential objects suitable for module context only."""
        return self.vault.credentials_for_reuse(campaign_id=self.campaign_id)


class CampaignRuntimeStateStore:
    """Owns one in-memory runtime state object per campaign for an engine."""

    def __init__(self, encryption_key: str | bytes | None, telemetry: Any = None) -> None:
        self._encryption_key = encryption_key
        self._telemetry = telemetry
        self._states: dict[str, CampaignRuntimeState] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def get(self, campaign_id: str) -> CampaignRuntimeState | None:
        return self._states.get(campaign_id)

    def discard(self, campaign_id: str) -> None:
        self._states.pop(campaign_id, None)
        self._locks.pop(campaign_id, None)

    async def ensure(self, campaign: Any, db: Any = None) -> CampaignRuntimeState:
        """Attach shared state and hydrate durable credentials/hosts once when possible."""
        campaign_id = str(getattr(campaign, "id", ""))
        if not campaign_id:
            raise ValueError("Campaign runtime state requires a campaign id")

        state = self._states.get(campaign_id)
        if state is None:
            state = self._build_state(campaign)
            self._states[campaign_id] = state
        self._attach(campaign, state)

        if db is None or state.hydrated:
            return state

        lock = self._locks.setdefault(campaign_id, asyncio.Lock())
        async with lock:
            if not state.hydrated:
                await self._hydrate_from_db(campaign, state, db)
                state.hydrated = True
        return state

    async def restore_vault(self, campaign: Any, db: Any) -> int:
        """Replace a campaign vault with its durable encrypted credential records."""
        # Hydrate the rest of the state first as well.  In particular this keeps
        # host metadata available to graph requests after a vault-only restore.
        state = await self.ensure(campaign, db)
        records = await db.load_credentials_raw(state.campaign_id)
        vault = CredentialVault(self._encryption_key)
        restored = vault.restore_from_db_records(records if isinstance(records, list) else [])
        state.vault = vault
        state.hydrated = True
        self._attach(campaign, state)
        return restored

    def _build_state(self, campaign: Any) -> CampaignRuntimeState:
        vault = getattr(campaign, "_vault", None)
        if not isinstance(vault, CredentialVault):
            vault = CredentialVault(self._encryption_key)

        session = getattr(campaign, "_session", None)
        if not isinstance(session, OperatorSession):
            session = OperatorSession(
                campaign_id=str(getattr(campaign, "id", "")),
                operator=str(getattr(campaign, "operator", "unknown")),
            )

        artifact_store = getattr(campaign, "_artifact_store", None)
        if not isinstance(artifact_store, ArtifactStore):
            artifact_store = ArtifactStore()

        state = CampaignRuntimeState(
            campaign_id=str(getattr(campaign, "id", "")),
            vault=vault,
            session=session,
            artifact_store=artifact_store,
            telemetry=self._telemetry,
        )
        return state

    def _attach(self, campaign: Any, state: CampaignRuntimeState) -> None:
        """Keep legacy campaign attributes in sync without exposing runtime state."""
        campaign._runtime_state = state
        campaign._vault = state.vault
        campaign._session = state.session
        campaign._artifact_store = state.artifact_store
        state.session.artifact_store = state.artifact_store

    async def _hydrate_from_db(
        self,
        campaign: Any,
        state: CampaignRuntimeState,
        db: Any,
    ) -> None:
        """Rehydrate only encrypted credential records and safe host metadata."""
        try:
            records = await db.load_credentials_raw(state.campaign_id)
            if isinstance(records, list):
                state.vault.restore_from_db_records(records)
        except (AttributeError, TypeError):
            # Lightweight test doubles may intentionally omit durable vault support.
            pass

        try:
            hosts = await db.get_hosts(state.campaign_id)
        except (AttributeError, TypeError):
            return

        if not isinstance(hosts, list):
            return
        for row in hosts:
            if not isinstance(row, dict):
                continue
            ip_address = str(row.get("ip_address", ""))
            if not ip_address:
                continue
            raw_ports = row.get("open_ports_json", [])
            if isinstance(raw_ports, str):
                try:
                    raw_ports = json.loads(raw_ports)
                except (TypeError, ValueError):
                    raw_ports = []
            ports = [int(port) for port in raw_ports if isinstance(port, (int, float, str)) and str(port).isdigit()]
            state.session.add_host(
                ip_address,
                hostname=str(row.get("hostname") or ""),
                fqdn=str(row.get("fqdn") or ""),
                os=str(row.get("os") or ""),
                os_version=str(row.get("os_version") or ""),
                domain=str(row.get("domain") or ""),
                is_dc=bool(row.get("is_dc", False)),
                open_ports=ports,
            )
