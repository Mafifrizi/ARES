from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.modules.test_modules import _make_module


def _run(coro):
    return asyncio.run(coro)


def _ctx(params: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        params=params,
        target=params.get("target", "10.0.0.1"),
        domain=params.get("domain", "corp.local"),
        dry_run=False,
        execution_id="adapter-test",
        vault=params.get("vault"),
        best_credential=lambda: None,
    )


@pytest.mark.parametrize(
    ("module_path", "class_name", "params", "expected"),
    [
        (
            "ares.modules.network.http_fingerprint",
            "HttpFingerprintModule",
            {"target": "10.0.0.1", "ports": [8888], "timeout": 1.0},
            {"target": "10.0.0.1", "ports": [8888]},
        ),
        (
            "ares.modules.network.dns_enum",
            "DnsEnumModule",
            {"target": "example.com", "domain": "example.com"},
            {"target": "example.com", "domain": "example.com"},
        ),
        (
            "ares.modules.network.port_scan",
            "PortScanModule",
            {"target": "10.0.0.1", "ports": [80], "timeout": 1.0},
            {"target": "10.0.0.1", "ports": [80]},
        ),
        (
            "ares.modules.network.service_detect",
            "ServiceDetectModule",
            {"target": "10.0.0.1", "ports": [80], "timeout": 1.0},
            {"target": "10.0.0.1", "ports": [80]},
        ),
        (
            "ares.modules.network.snmp_enum",
            "SnmpEnumModule",
            {"target": "10.0.0.1", "port": 161, "communities": ["public"]},
            {"target": "10.0.0.1", "port": 161},
        ),
        (
            "ares.modules.cloud.identity_federation",
            "CloudIdentityFederationModule",
            {
                "tenant_id": "tenant",
                "client_id": "client",
                "client_secret": "secret",
                "access_key": "ak",
                "secret_key": "sk",
                "adfs_url": "https://adfs.example",
                "krbtgt_hash": "a" * 32,
                "domain": "corp.local",
                "mode": "enumerate",
            },
            {"tenant_id": "tenant", "domain": "corp.local", "mode": "enumerate"},
        ),
        (
            "ares.modules.linux.kernel_suggester",
            "KernelSuggesterModule",
            {"target": "10.0.0.1", "username": "user", "password": "pw", "key_path": ""},
            {"target": "10.0.0.1", "username": "user", "password": "pw"},
        ),
        (
            "ares.modules.windows.token_impersonation",
            "TokenImpersonationModule",
            {"target": "10.0.0.1", "username": "user", "password": "pw", "domain": "corp"},
            {"target": "10.0.0.1", "username": "user", "domain": "corp"},
        ),
        (
            "ares.modules.windows.lsa_secrets",
            "LSASecretsModule",
            {"target": "10.0.0.1", "username": "user", "password": "pw", "domain": "corp"},
            {"target": "10.0.0.1", "username": "user", "domain": "corp"},
        ),
        (
            "ares.modules.credential.golden_ticket",
            "GoldenTicketModule",
            {
                "target": "corp.local",
                "domain": "corp.local",
                "krbtgt_hash": "a" * 32,
                "domain_sid": "S-1-5-21-1-2-3",
            },
            {"target": "corp.local", "domain": "corp.local"},
        ),
        (
            "ares.modules.credential.reuse",
            "CredentialReuseModule",
            {"target": "10.0.0.1"},
            {"target": "10.0.0.1", "vault": None},
        ),
        (
            "ares.modules.credential.pass_spray",
            "PassSprayModule",
            {
                "target": "10.0.0.1",
                "domain": "corp.local",
                "users": ["alice"],
                "passwords": ["Password1!"],
            },
            {"target": "10.0.0.1", "domain": "corp.local", "users": ["alice"]},
        ),
    ],
)
def test_execute_adapter_deduplicates_explicit_ctx_params(
    monkeypatch, module_path, class_name, params, expected
):
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    mod, _ = _make_module(cls)
    captured: dict[str, Any] = {}

    async def fake_run(**kwargs):
        captured.update(kwargs)
        return [], {"adapter": "ok"}

    monkeypatch.setattr(mod, "run", fake_run)

    result = _run(mod.execute(_ctx(params)))

    assert result.module_id == mod.MODULE_ID
    for key, value in expected.items():
        assert captured[key] == value


def test_lateral_adapter_deduplicates_execute_and_move_kwargs(monkeypatch):
    from ares.modules.lateral.modules import LateralResult, LateralTechnique, PsExecLateral

    mod, _ = _make_module(PsExecLateral)
    captured: dict[str, Any] = {}

    async def fake_before_request(*args, **kwargs):
        return None

    async def fake_move(target, username, domain, secret, command="whoami /all", **kwargs):
        captured.update(
            {
                "target": target,
                "username": username,
                "domain": domain,
                "secret": secret,
                "command": command,
                "kwargs": kwargs,
            }
        )
        return LateralResult(
            technique=LateralTechnique.PSEXEC,
            source_host="operator",
            target_host=target,
            username=username,
            domain=domain,
            success=False,
            error="not executed",
        )

    monkeypatch.setattr(mod, "before_request", fake_before_request)
    monkeypatch.setattr(mod, "move", fake_move)

    result = _run(
        mod.execute(
            _ctx(
                {
                    "target": "10.0.0.1",
                    "username": "user",
                    "domain": "corp",
                    "secret": "pw",
                    "command": "whoami",
                }
            )
        )
    )

    assert result.module_id == mod.MODULE_ID
    assert captured["target"] == "10.0.0.1"
    assert captured["username"] == "user"
    assert captured["domain"] == "corp"
    assert captured["secret"] == "pw"
    assert captured["command"] == "whoami"
    for key in ("target", "username", "domain", "secret", "command"):
        assert key not in captured["kwargs"]
