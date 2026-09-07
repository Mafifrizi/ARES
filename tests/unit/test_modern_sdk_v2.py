"""Unit tests for ARES SDK v2 Next-Gen Autonomous Architecture.

Tests:
1. Pydantic v2 parameter models (ModuleParams, param, SecretParam, validate_params).
2. Generic BaseModule[P, R] and PARAMS_MODEL integration.
3. @ares_module functional and declarative decorator.
4. ExecutionContext fluent helpers (emit_finding, typed_params, store_artifact, record_credential).
5. ModuleTestHarness and SimulationResult fluent assertions.
6. AresClient async REST client with mock transport and error handling.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ares.core.campaign import Finding, Severity
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.modules.base import ModuleResult, OpsecLevel, normalize_module_metadata
from ares.sdk import (
    AresAuthenticationError,
    AresClient,
    AresNotFoundError,
    AresValidationError,
    BaseModule,
    ModuleParams,
    ModuleTestHarness,
    SecretParam,
    SimulationResult,
    ares_module,
    param,
    validate_params,
)


class SampleParams(ModuleParams):
    target: str = param("Target IP or hostname", min_length=3)
    port: int = param("Target port", required=False, default=445, ge=1, le=65535)
    password: SecretParam = param("Admin password", secret=True, required=False)


# ── 1. Parameter Model Tests ──────────────────────────────────────────────────


def test_params_model_validates_successfully() -> None:
    validated = validate_params(
        SampleParams,
        {"target": "10.0.0.1", "port": 8443, "password": "SuperSecretPassword123!"},
        module_id="test.sample",
    )
    assert validated.target == "10.0.0.1"
    assert validated.port == 8443
    assert validated.password.get_secret_value() == "SuperSecretPassword123!"


def test_params_model_rejects_invalid_values() -> None:
    with pytest.raises(ModuleValidationError) as exc_info:
        validate_params(SampleParams, {"target": "x", "port": 99999}, module_id="test.sample")
    assert "target" in str(exc_info.value) or "port" in str(exc_info.value)
    assert exc_info.value.module_id == "test.sample"


def test_params_safe_dict_redacts_secrets() -> None:
    p = SampleParams.model_validate({"target": "10.0.0.1", "password": "my_secret_token"})
    safe = p.safe_dict()
    assert safe["password"] == "***"
    assert safe["target"] == "10.0.0.1"


# ── 2. BaseModule[P, R] and PARAMS_MODEL Tests ───────────────────────────────


@pytest.mark.asyncio
async def test_base_module_with_params_model_validates_context() -> None:
    class TypedModule(BaseModule[SampleParams, ModuleResult]):
        MODULE_ID = "test.typed_module"
        MODULE_NAME = "Typed Module Test"
        MODULE_CATEGORY = "network"
        PARAMS_MODEL = SampleParams

        async def execute(self, ctx: ExecutionContext[SampleParams]) -> ModuleResult:
            # ctx.params should be automatically parsed into SampleParams!
            assert isinstance(ctx.params, SampleParams)
            ctx.emit_finding(
                title=f"Discovered Port {ctx.params.port}",
                severity=Severity.HIGH,
                mitre_technique="T1046",
            )
            return ModuleResult(status="success", module_id=self.MODULE_ID)

    harness = ModuleTestHarness(TypedModule)
    result = await harness.simulate(params={"target": "192.168.1.10", "port": 3389})

    result.assert_success()
    result.assert_no_errors()
    finding = result.assert_finding(severity=Severity.HIGH, mitre="T1046")
    assert "Discovered Port 3389" in finding.title


def test_normalize_module_metadata_extracts_params_model_schema() -> None:
    class AutoSchemaModule(BaseModule):
        MODULE_ID = "test.auto_schema"
        MODULE_NAME = "Auto Schema Module"
        MODULE_CATEGORY = "network"
        PARAMS_MODEL = SampleParams

    meta = normalize_module_metadata(AutoSchemaModule)
    assert "target" in meta["required_params"]
    assert "port" in meta["optional_params"]
    assert meta["param_schema"]["password"]["secret"] is True


# ── 3. @ares_module Functional Decorator Tests ────────────────────────────────


@pytest.mark.asyncio
async def test_ares_module_functional_decorator() -> None:
    @ares_module(
        id="demo.functional",
        name="Demo Functional Attack",
        category="recon",
        description="Smoke test for @ares_module functional authoring",
        opsec=OpsecLevel.LOW,
        mitre="T1595.002",
        params_model=SampleParams,
    )
    async def demo_attack(ctx: ExecutionContext[SampleParams]) -> ModuleResult:
        assert isinstance(ctx.params, SampleParams)
        ctx.emit_finding(
            title=f"Host Enumerated: {ctx.params.target}",
            severity=Severity.MEDIUM,
            mitre_technique="T1595.002",
        )
        return ModuleResult(
            status="success",
            module_id="demo.functional",
            raw={"probed_port": ctx.params.port},
        )

    assert issubclass(demo_attack, BaseModule)
    assert demo_attack.MODULE_ID == "demo.functional"
    assert demo_attack.MODULE_NAME == "Demo Functional Attack"
    assert demo_attack.PARAMS_MODEL is SampleParams

    harness = ModuleTestHarness(demo_attack)
    result = await harness.simulate(params={"target": "10.10.10.50", "port": 80})

    result.assert_success()
    finding = result.assert_finding(severity=Severity.MEDIUM, mitre="T1595.002")
    assert "10.10.10.50" in finding.title
    assert result.raw["probed_port"] == 80


# ── 4. ExecutionContext Fluent Helper Tests ───────────────────────────────────


def test_execution_context_fluent_helpers() -> None:
    ctx = ExecutionContext[SampleParams].for_test(
        target="10.0.0.5",
        module_id="test.context_helper",
        params={"target": "10.0.0.5", "port": 445},
    )

    # typed_params
    typed = ctx.typed_params(SampleParams)
    assert isinstance(typed, SampleParams)
    assert typed.target == "10.0.0.5"
    assert typed.port == 445

    # emit_finding
    finding = ctx.emit_finding(
        title="Vulnerability Found",
        severity=Severity.CRITICAL,
        description="Dangerous service exposed",
        mitre_technique="T1210",
    )
    assert isinstance(finding, Finding)
    assert finding.severity == Severity.CRITICAL
    assert finding.host == "10.0.0.5"
    assert len(ctx.findings) == 1
    assert ctx.findings[0] is finding


# ── 5. ModuleTestHarness & SimulationResult Assertions ─────────────────────────


@pytest.mark.asyncio
async def test_module_test_harness_catches_validation_failure() -> None:
    class StrictModule(BaseModule):
        MODULE_ID = "test.strict"
        MODULE_NAME = "Strict Module"
        MODULE_CATEGORY = "network"
        PARAMS_MODEL = SampleParams

    harness = ModuleTestHarness(StrictModule)
    # Target length is min_length=3, provide length 1 to trigger validation error
    result = await harness.simulate(params={"target": "x"})

    result.assert_failed()
    assert result.error is not None
    assert "target" in result.error


# ── 6. Programmatic AresClient Tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_ares_client_rest_operations() -> None:
    # Build a mock transport simulating ARES server endpoints
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path

        if path == "/health":
            return httpx.Response(200, json={"status": "ok", "version": "6.0.0", "db": "connected"})

        if path == "/campaigns" and request.method == "GET":
            return httpx.Response(200, json=[{"id": "c-123", "name": "Op-Titan", "scope": ["10.0.0.0/24"]}])

        if path == "/campaigns" and request.method == "POST":
            data = json.loads(request.content.decode("utf-8"))
            return httpx.Response(201, json={"id": "c-new-456", "name": data["name"], "scope": data["scope"]})

        if path == "/campaigns/c-123" and request.method == "GET":
            return httpx.Response(200, json={"id": "c-123", "name": "Op-Titan"})

        if path == "/campaigns/c-123" and request.method == "DELETE":
            return httpx.Response(200, json={"deleted": True, "id": "c-123"})

        if path == "/campaigns/c-123/findings":
            return httpx.Response(200, json=[{"id": "f-1", "title": "Kerberoastable Account", "severity": "high"}])

        if path == "/modules":
            return httpx.Response(200, json=[{"id": "ad.kerberoast", "name": "Kerberoasting"}])

        if path == "/modules/ad.kerberoast/run":
            return httpx.Response(200, json={"execution_id": "e-789", "status": "done"})

        if path == "/not-found":
            return httpx.Response(404, json={"detail": "Not Found"})

        if path == "/unauthorized":
            return httpx.Response(401, json={"detail": "Invalid API Key"})

        return httpx.Response(404, json={"detail": "Not Found"})

    transport = httpx.MockTransport(mock_handler)

    async with AresClient(base_url="http://mock-ares:8000", api_key="ares_test_key", transport=transport) as client:
        # 1. Health check
        health = await client.health()
        assert health["status"] == "ok"
        assert health["version"] == "6.0.0"

        # 2. Campaigns
        campaigns = await client.campaigns.list()
        assert len(campaigns) == 1
        assert campaigns[0]["id"] == "c-123"

        created = await client.campaigns.create(name="Op-Apollo", scope=["192.168.1.0/24"])
        assert created["id"] == "c-new-456"
        assert created["name"] == "Op-Apollo"

        camp = await client.campaigns.get("c-123")
        assert camp["id"] == "c-123"

        findings = await client.campaigns.findings("c-123")
        assert len(findings) == 1
        assert findings[0]["title"] == "Kerberoastable Account"

        deleted = await client.campaigns.delete("c-123")
        assert deleted is True

        # 3. Modules
        modules = await client.modules.list()
        assert len(modules) == 1
        assert modules[0]["id"] == "ad.kerberoast"

        exec_res = await client.modules.run("ad.kerberoast", target="dc01.corp.local")
        assert exec_res["status"] == "done"

        # 4. Error mappings
        with pytest.raises(AresNotFoundError):
            await client._get("/not-found")

        with pytest.raises(AresAuthenticationError):
            await client._get("/unauthorized")
