"""
Unit tests for Gate 1: Minimal Schema Pre-Flight Guard.
Verifies engine validate() enforcement and declarative REQUIRED_PARAMS.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ares.core.campaign import Campaign
from ares.core.engine import AresEngine, EngineModuleResult, ModuleStatus
from ares.core.errors import ModuleValidationError
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.base import BaseModule
from ares.core.execution_admission import _mint_test_dispatch_context


class DummyValidatingModule(BaseModule):
    MODULE_ID = "test.gate1_dummy"
    MODULE_NAME = "Gate 1 Test Module"
    MODULE_CATEGORY = "ad"
    MODULE_DESCRIPTION = "Validating module for Gate 1 tests"
    REQUIRED_PARAMS = ["dc", "domain"]

    async def run(self, **kwargs):
        return [], {"executed": True}


@pytest.fixture
def settings():
    return AresSettings(
        ares_secret_key="test-secret-key-min32-chars-xxxxxx",
        ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
        ares_default_admin_password="TestEnginePass1!",
    )


@pytest.fixture
def campaign():
    from ares.core.campaign import ScopeEntry
    return Campaign(name="Gate 1 Campaign", scope=[ScopeEntry(cidr="10.0.0.0/24")], operator="tester")


class TestBaseModuleRequiredParams:
    @pytest.mark.asyncio
    async def test_required_params_present_passes(self, settings, campaign):
        noise = MagicMock(spec=NoiseController)
        mod = DummyValidatingModule(settings, campaign, noise)

        # Dictionary input
        await mod.validate({"dc": "10.0.0.1", "domain": "corp.local"})

    @pytest.mark.asyncio
    async def test_required_params_missing_raises_validation_error(self, settings, campaign):
        noise = MagicMock(spec=NoiseController)
        mod = DummyValidatingModule(settings, campaign, noise)

        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate({"dc": "10.0.0.1"})  # missing domain

        assert "test.gate1_dummy requires parameter 'domain'" in str(exc_info.value)
        assert exc_info.value.field == "domain"

    @pytest.mark.asyncio
    async def test_required_params_none_raises_validation_error(self, settings, campaign):
        noise = MagicMock(spec=NoiseController)
        mod = DummyValidatingModule(settings, campaign, noise)

        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate({"dc": None, "domain": "corp.local"})

        assert "test.gate1_dummy requires parameter 'dc'" in str(exc_info.value)
        assert exc_info.value.field == "dc"


class TestEngineGate1Enforcement:
    @pytest.mark.asyncio
    async def test_engine_rejects_module_when_validate_fails(self, settings, campaign):
        """Engine must reject execution with ModuleStatus.REJECTED when validate() fails."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        mod_instance = DummyValidatingModule(settings, campaign, MagicMock())
        execute_mock = AsyncMock()
        mod_instance.execute = execute_mock

        # Inject dummy module factory into engine registry
        engine._registry[DummyValidatingModule.MODULE_ID] = MagicMock(return_value=mod_instance)

        candidate = _mint_test_dispatch_context(
            engine,
            campaign.id,
            DummyValidatingModule.MODULE_ID,
        )

        result = await engine.run_module(
            DummyValidatingModule.MODULE_ID,
            campaign,
            {"dc": "10.0.0.1"},  # missing domain -> will fail validate()
            actor_role="team_lead",
            dispatch_context=candidate,
        )

        # Execution must NOT proceed
        execute_mock.assert_not_called()

        # Engine must return REJECTED status with structured error
        assert result.status == ModuleStatus.REJECTED
        assert "Validation failed:" in (result.error or "")
        assert "requires parameter 'domain'" in (result.error or "")
        assert result.outcome == "operator_error"
