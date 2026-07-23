"""Phase 1 regressions for the durable API -> engine -> DB -> graph path."""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ares.api import server
from ares.core.campaign import Campaign, Finding, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.plugin.loader import ModuleRegistry
from ares.credential.vault import Credential, CredentialType, CredentialVault
from ares.db.database import AresDatabase, DBCredential, Host
from ares.modules.base import BaseModule, ModuleResult
from ares.strategy.engine import StrategyEngine


class PhaseOneProbeModule(BaseModule):
    """A no-network module used only to exercise engine persistence."""

    MODULE_ID = "ad.phase1_probe"
    MODULE_NAME = "Phase 1 probe"
    MODULE_CATEGORY = "ad"
    MODULE_DESCRIPTION = "Test-only durable runtime probe"
    contexts: list[Any] = []

    async def validate(self, ctx: Any) -> None:
        return None

    async def execute(self, ctx: Any) -> ModuleResult:
        type(self).contexts.append(ctx)
        ctx.session.add_host("10.10.10.5", hostname="dc01", is_dc=True)
        finding = Finding(
            title="Persisted probe finding",
            description="A safe test finding created without contacting a target.",
            severity=Severity.HIGH,
            host="10.10.10.5",
            module_id=self.MODULE_ID,
        )
        return ModuleResult(
            status="success",
            module_id=self.MODULE_ID,
            findings=[finding],
            raw={"source": "phase1-test"},
        )


def _settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="phase1-test-secret-key-min-32-chars!!",
        ares_encryption_key="phase1-test-encryption-key-min-32chars!!",
        ares_default_admin_password="Phase1TestPassword!",
    )


def _campaign(campaign_id: str = "phase1-campaign") -> Campaign:
    return Campaign(
        id=campaign_id,
        name="Phase 1 durable test",
        client="ARES",
        operator="owner",
        scope=[ScopeEntry(cidr="10.10.10.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )


def _engine(settings: AresSettings, db: AresDatabase) -> AresEngine:
    engine = AresEngine(settings=settings, db=db)
    registry = ModuleRegistry()
    registry.register(PhaseOneProbeModule)
    engine._registry = registry
    return engine


@pytest.mark.asyncio
async def test_db_bound_engine_persists_each_execution_once(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1.db", settings.encryption_key_value)
    campaign = _campaign()
    await db.save_campaign(campaign)
    engine = _engine(settings, db)
    PhaseOneProbeModule.contexts.clear()
    try:
        result = await engine.run_module(
            PhaseOneProbeModule.MODULE_ID,
            campaign,
            {"target": "10.10.10.5"},
            actor_role="team_lead",
        )
        findings, total = await db.list_findings(campaign.id, per_page=20)
        async with db.conn.execute(
            "SELECT COUNT(*) AS n FROM module_runs WHERE campaign_id=?", (campaign.id,)
        ) as cursor:
            module_runs = int((await cursor.fetchone())["n"])

        assert result.status is ModuleStatus.DONE
        assert total == len(findings) == 1
        assert module_runs == 1
        assert PhaseOneProbeModule.contexts[-1].artifact_store is campaign._runtime_state.artifact_store
        assert PhaseOneProbeModule.contexts[-1].vault is campaign._runtime_state.vault
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restored_vault_is_reused_by_the_next_campaign_run(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-vault.db", settings.encryption_key_value)
    campaign = _campaign("phase1-vault")
    await db.save_campaign(campaign)
    source_vault = CredentialVault(settings.encryption_key_value)
    credential = Credential(
        campaign_id=campaign.id,
        username="svc_phase1",
        domain="LAB.LOCAL",
        cred_type=CredentialType.CLEARTEXT,
    )
    source_vault.store(credential, "never-return-this-secret")
    await db.save_credential_preencrypted(DBCredential(
        id=credential.id,
        campaign_id=campaign.id,
        username=credential.username,
        cred_type=credential.cred_type.value,
        secret=credential.secret_enc.decode(),
        domain=credential.domain,
        source_module="phase1.fixture",
    ))
    engine = _engine(settings, db)
    PhaseOneProbeModule.contexts.clear()
    try:
        restored = await engine.restore_campaign_vault(campaign)
        result = await engine.run_module(
            PhaseOneProbeModule.MODULE_ID,
            campaign,
            {"target": "10.10.10.5"},
            actor_role="team_lead",
        )

        assert restored == 1
        assert result.status is ModuleStatus.DONE
        assert PhaseOneProbeModule.contexts[-1].vault is campaign._runtime_state.vault
        assert campaign._runtime_state.vault.get(credential.id) is not None
        assert "never-return-this-secret" not in json.dumps(result.model_dump(mode="json"))
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_plan_and_strategy_rehydrate_durable_state_and_done_is_success(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-plan.db", settings.encryption_key_value)
    campaign = _campaign("phase1-plan")
    await db.save_campaign(campaign)
    engine = _engine(settings, db)
    try:
        plan = ExecutionPlan().add_stage(
            "probe", [PhaseOneProbeModule.MODULE_ID],
            {PhaseOneProbeModule.MODULE_ID: {"target": "10.10.10.5"}},
        )
        plan_results = await engine.run_plan(plan, campaign, actor_role="team_lead")
        assert plan_results[PhaseOneProbeModule.MODULE_ID].status is ModuleStatus.DONE

        strategy = StrategyEngine(ares_engine=engine, settings=settings)
        strategy._run_coverage_predictor = AsyncMock(return_value={
            "detection_score": 0.0,
            "wait_recommendation": {"hours": 0},
        })
        strategy._get_edr_context = AsyncMock(return_value={
            "edr_vendor": "test", "viable_techniques": [], "recommended_approach": None,
        })
        strategy._run_ai_planner = AsyncMock(return_value={
            "confidence_score": 1.0,
            "execution_plan": [{
                "name": "probe",
                "modules": [PhaseOneProbeModule.MODULE_ID],
                "params": {PhaseOneProbeModule.MODULE_ID: {"target": "10.10.10.5"}},
            }],
            "warnings": [],
        })
        strategy_result = await strategy.run_autonomous_engagement(
            campaign=campaign,
            max_rounds=1,
            llm_backend="local",
            actor_role="team_lead",
        )
        assert PhaseOneProbeModule.MODULE_ID in strategy_result.modules_succeeded

        engine.discard_campaign_runtime(campaign.id)
        rehydrated_campaign = _campaign(campaign.id)
        restarted_engine = _engine(settings, db)
        restarted_state = await restarted_engine.ensure_campaign_runtime(rehydrated_campaign)
        findings, total = await db.list_findings(campaign.id, per_page=20)

        assert total == len(findings) >= 2
        assert restarted_state.session.get_host("10.10.10.5") is not None
        assert (await db.get_campaign_graph(campaign.id)) is not None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_strategy_preflight_does_not_reserve_a_slot_for_unknown_campaign(monkeypatch: Any) -> None:
    original_db, original_engine = server._db, server._engine
    server._active_engagements.clear()
    try:
        server._db = SimpleNamespace(get_campaign=AsyncMock(return_value=None))
        server._engine = object()  # preflight exits before engine use
        body = server.AutonomousEngagementRequest(campaign_id="missing", llm_backend="local")
        with pytest.raises(server.HTTPException) as exc_info:
            await server.start_autonomous_engagement(
                body,
                actor=SimpleNamespace(username="owner", role="team_lead"),
            )
        assert exc_info.value.status_code == 404
        assert server._active_engagements == {}
    finally:
        server._db, server._engine = original_db, original_engine
        server._active_engagements.clear()


@pytest.mark.asyncio
async def test_persisted_graph_and_attack_paths_use_safe_durable_rows(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-graph.db", settings.encryption_key_value)
    campaign = _campaign("phase1-graph")
    await db.save_campaign(campaign)
    await db.upsert_host(Host(
        campaign_id=campaign.id,
        ip_address="10.10.10.5",
        hostname="dc01",
        is_dc=True,
    ))
    await db.save_finding(campaign.id, Finding(
        title="Persisted graph finding",
        description="Verified durable graph fixture.",
        severity=Severity.CRITICAL,
        host="10.10.10.5",
        module_id="ad.phase1_probe",
        validated=True,
    ))
    await db.save_credential(DBCredential(
        campaign_id=campaign.id,
        username="svc_graph",
        cred_type="cleartext",
        secret="graph-secret-must-not-leak",
        domain="LAB.LOCAL",
    ))
    engine = _engine(settings, db)
    actor = SimpleNamespace(username="owner", role="team_lead")
    try:
        graph_payload = await server.campaign_graph(campaign.id, actor=actor, engine=engine, db=db)
        path_payload = await server.campaign_attack_paths(
            campaign.id, actor=actor, engine=engine, db=db
        )

        assert graph_payload["stats"]["hosts"] == 1
        assert graph_payload["stats"]["findings"] == 1
        assert "graph-secret-must-not-leak" not in json.dumps(graph_payload)
        assert path_payload["stats"]["nodes"] >= 3
    finally:
        await db.close()
