from __future__ import annotations

import sys
import types

import pytest

from ares.core.errors import ModuleValidationError, NetworkError


@pytest.mark.asyncio
async def test_asreproast_missing_pyasn1_is_actionable_preflight_error(monkeypatch):
    from ares.modules.ad.asreproast import ASREPRoastModule

    monkeypatch.setitem(sys.modules, "impacket", types.ModuleType("impacket"))
    monkeypatch.setitem(sys.modules, "pyasn1", None)
    monkeypatch.setitem(sys.modules, "pyasn1_modules", types.ModuleType("pyasn1_modules"))

    module = object.__new__(ASREPRoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module.run(
            dc="127.0.0.1",
            domain="corp.local",
            usernames=["alice"],
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "pyasn1"
    assert not isinstance(exc_info.value, NetworkError)
    assert "ad.asreproast" in message
    assert "pyasn1" in message
    assert "Install AD dependencies" in message
    assert "restart the dashboard" in message
    assert "No module named" not in message


@pytest.mark.asyncio
async def test_kerberoast_missing_impacket_is_actionable_preflight_error(monkeypatch):
    from ares.modules.ad.kerberoast import KerberoastModule

    monkeypatch.setitem(sys.modules, "impacket", None)
    monkeypatch.setitem(sys.modules, "pyasn1", types.ModuleType("pyasn1"))
    monkeypatch.setitem(sys.modules, "pyasn1_modules", types.ModuleType("pyasn1_modules"))

    module = object.__new__(KerberoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module.run(
            dc="127.0.0.1",
            username="alice",
            password="Password123!",
            domain="corp.local",
            target_user="HTTP/web.corp.local",
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "impacket"
    assert not isinstance(exc_info.value, NetworkError)
    assert "ad.kerberoast" in message
    assert "impacket" in message
    assert "Install AD dependencies" in message
    assert "restart the dashboard" in message
    assert "No module named" not in message
