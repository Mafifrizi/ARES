from __future__ import annotations

import asyncio
import os
import types
from typing import Any
from unittest.mock import MagicMock, patch
import pytest

from ares.core.config import AresSettings
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleExecutionError, ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.credential.golden_ticket import GoldenTicketModule


def make_module(cls):
    settings = AresSettings()
    campaign = Campaign(
        name="GT-Test",
        client="TestClient",
        operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        domain="corp.local",
        targets=["corp.local"],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


def _run(coro):
    return asyncio.run(coro)


def _setup_impacket_mock_modules(ticketer_available: bool = True, ticketer_cls: Any = None):
    mods: dict[str, Any] = {}
    names = [
        "impacket",
        "impacket.krb5",
        "impacket.krb5.asn1",
        "impacket.krb5.ccache",
        "impacket.krb5.crypto",
        "impacket.krb5.constants",
        "impacket.krb5.types",
        "impacket.krb5.kerberosv5",
        "impacket.krb5.pac",
        "impacket.krb5.ticket",
        "impacket.examples",
    ]
    for n in names:
        m = types.ModuleType(n)
        m.__dict__.update({
            "AS_REP": MagicMock(),
            "EncTicketPart": MagicMock(),
            "TGS_REP": MagicMock(),
            "CCache": MagicMock(),
            "Key": MagicMock(),
            "_enctype_table": MagicMock(),
            "EncryptionTypes": MagicMock(),
            "PrincipalNameType": MagicMock(),
            "ApplicationTagNumbers": MagicMock(),
            "Principal": MagicMock(),
            "KerberosTime": MagicMock(),
            "constants": MagicMock(),
            "getKerberosTGT": MagicMock(),
            "PACTYPE": MagicMock(),
            "PAC_INFO_BUFFER": MagicMock(),
            "PAC_CREDENTIAL_DATA": MagicMock(),
            "Ticket": MagicMock(),
        })
        mods[n] = m

    if ticketer_available:
        tick_mod = types.ModuleType("impacket.examples.ticketer")
        tick_mod.TICKETER = ticketer_cls or MagicMock()
        mods["impacket.examples.ticketer"] = tick_mod
    else:
        mods["impacket.examples.ticketer"] = None
    return mods


def test_golden_ticket_validate_fails_without_impacket():
    mod = make_module(GoldenTicketModule)
    ctx = ExecutionContext(
        target="10.0.0.5",
        domain="corp.local",
        params={
            "target": "10.0.0.5",
            "domain": "corp.local",
            "username": "Administrator",
            "krbtgt_hash": "0123456789abcdef0123456789abcdef",
            "domain_sid": "S-1-5-21-1111111111-2222222222-3333333333",
        },
    )
    with patch.dict("sys.modules", {"impacket.krb5.ticket": None}):
        with pytest.raises(ModuleValidationError) as excinfo:
            _run(mod.validate(ctx))
        assert "requires impacket" in str(excinfo.value)


def test_golden_ticket_fallback_raises_module_execution_error():
    mod = make_module(GoldenTicketModule)
    mock_mods = _setup_impacket_mock_modules(ticketer_available=False)

    with patch.dict("sys.modules", mock_mods):
        with pytest.raises(ModuleExecutionError) as excinfo:
            _run(
                mod.run(
                    domain="corp.local",
                    username="Administrator",
                    krbtgt_hash="0123456789abcdef0123456789abcdef",
                    domain_sid="S-1-5-21-1111111111-2222222222-3333333333",
                )
            )
        assert (
            "impacket ticketer unavailable — fallback ticket construction disabled"
            in str(excinfo.value)
        )
        assert "MOD-035" in str(excinfo.value)


def test_golden_ticket_primary_path_success():
    mod = make_module(GoldenTicketModule)

    mock_ticketer_cls = MagicMock()
    mock_instance = MagicMock()
    mock_ticketer_cls.return_value = mock_instance

    def side_effect_run():
        opts = mock_ticketer_cls.call_args[1]["options"]
        with open(opts.filename, "wb") as f:
            f.write(b"ccache_content_here")

    mock_instance.run = side_effect_run

    mock_mods = _setup_impacket_mock_modules(
        ticketer_available=True, ticketer_cls=mock_ticketer_cls
    )

    with patch.dict("sys.modules", mock_mods):
        findings, raw = _run(
            mod.run(
                domain="corp.local",
                username="Administrator",
                krbtgt_hash="0123456789abcdef0123456789abcdef",
                domain_sid="S-1-5-21-1111111111-2222222222-3333333333",
            )
        )

        assert raw["success"] is True
        assert raw["ticket_data"] == b"ccache_content_here"
        assert len(findings) == 1
        assert "Golden Ticket Forged" in findings[0].title


def test_golden_ticket_ccache_teardown_on_success():
    """MOD-034: ccache file is deleted after successful golden ticket generation."""
    mod = make_module(GoldenTicketModule)
    created_files = []

    mock_ticketer_cls = MagicMock()
    mock_instance = MagicMock()
    mock_ticketer_cls.return_value = mock_instance

    def side_effect_run():
        opts = mock_ticketer_cls.call_args[1]["options"]
        created_files.append(opts.filename)
        with open(opts.filename, "wb") as f:
            f.write(b"sensitive_ticket_data")
        assert os.path.exists(opts.filename)

    mock_instance.run = side_effect_run

    mock_mods = _setup_impacket_mock_modules(
        ticketer_available=True, ticketer_cls=mock_ticketer_cls
    )

    with patch.dict("sys.modules", mock_mods):
        findings, raw = _run(
            mod.run(
                domain="corp.local",
                username="Administrator",
                krbtgt_hash="0123456789abcdef0123456789abcdef",
                domain_sid="S-1-5-21-1111111111-2222222222-3333333333",
            )
        )

    assert raw["success"] is True
    assert raw["ticket_data"] == b"sensitive_ticket_data"
    assert len(created_files) == 1
    assert not os.path.exists(created_files[0]), "ccache file must be unlinked from disk"


def test_golden_ticket_ccache_teardown_on_failure():
    """MOD-034: ccache file is deleted even if ticketer fails mid-execution."""
    mod = make_module(GoldenTicketModule)
    created_files = []

    mock_ticketer_cls = MagicMock()
    mock_instance = MagicMock()
    mock_ticketer_cls.return_value = mock_instance

    def failing_run():
        opts = mock_ticketer_cls.call_args[1]["options"]
        created_files.append(opts.filename)
        with open(opts.filename, "wb") as f:
            f.write(b"partial_ticket")
        raise RuntimeError("Simulated crash mid-ticket-generation")

    mock_instance.run = failing_run

    mock_mods = _setup_impacket_mock_modules(
        ticketer_available=True, ticketer_cls=mock_ticketer_cls
    )

    with patch.dict("sys.modules", mock_mods):
        findings, raw = _run(
            mod.run(
                domain="corp.local",
                username="Administrator",
                krbtgt_hash="0123456789abcdef0123456789abcdef",
                domain_sid="S-1-5-21-1111111111-2222222222-3333333333",
            )
        )

    assert raw["success"] is False
    assert len(created_files) == 1
    assert not os.path.exists(created_files[0]), "ccache file must be cleaned up on failure"

