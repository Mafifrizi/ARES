"""
Unit tests for Grup D - Scope Enforcement on Secondary Targets (MOD-004, MOD-009, MOD-010, MOD-011, MOD-014, MOD-015, MOD-017, MOD-032, MOD-058, MOD-059).
Verifies:
1. ad.coerce enforces scope on listener_ip.
2. ad.sccm skips out-of-scope secondary hosts cleanly.
3. ad.adcs checks ca_host in _submit_csr_to_ca.
4. lateral.ntlm_relay filters out-of-scope targets in _check_relay_targets.
5. lateral.smb_relay filters out-of-scope targets before negotiation.
6. lateral.mssql skips out-of-scope listener and linked_server.
7. network.pivot filters out-of-scope reachable_subnets.
8. credential.reuse isolates Microsoft cloud OAuth probes for RFC1918 internal targets.
9. network.dns_enum checks scope on nameservers before AXFR.
10. network.http_fingerprint blocks out-of-scope HTTP redirects.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController, ScopeViolationError
from ares.modules.ad.adcs import ADCSModule
from ares.modules.ad.coerce import CoerceModule
from ares.modules.ad.sccm import SCCMModule
from ares.modules.credential.reuse import CredentialReuseModule, _audit_oauth_posture_sync
from ares.modules.lateral.mssql import MSSQLModule
from ares.modules.lateral.ntlm_relay import NTLMRelayModule
from ares.modules.lateral.smb_relay import SMBRelayAuditModule
from ares.modules.network.dns_enum import DnsEnumModule
from ares.modules.network.http_fingerprint import HttpFingerprintModule
from ares.modules.network.pivot import PivotModule
from ares.modules.params import (
    ADCSParams,
    CoerceParams,
    CredentialReuseParams,
    DNSEnumParams,
    HTTPFingerprintParams,
    MSSQLParams,
    NTLMRelayParams,
    PivotParams,
    SCCMParams,
    SMBRelayParams,
)


def _make_fixture(scope_cidr: str = "10.0.0.0/24") -> tuple[AresSettings, Campaign, NoiseController]:
    settings = AresSettings(
        ares_secret_key="secret-key-32-chars-minimum-len!",
        ares_encryption_key="enc-key-32-chars-minimum-length!",
    )
    campaign = Campaign(
        name="test-scope",
        client="test-client",
        scope=[ScopeEntry(cidr=scope_cidr)],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    noise.jitter.sleep = AsyncMock()
    return settings, campaign, noise


@pytest.mark.asyncio
async def test_coerce_listener_ip_scope_enforcement():
    """MOD-004: ad.coerce must enforce scope on listener_ip."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = CoerceModule(settings=settings, campaign=campaign, noise=noise)

    # In-scope DC, but OUT-OF-SCOPE listener_ip (8.8.8.8)
    ctx = ExecutionContext(
        execution_id="exec-coerce-scope",
        campaign_id=campaign.id,
        target="10.0.0.1",
        params=CoerceParams(
            dc="10.0.0.1",
            domain="corp.local",
            username="admin",
            password="Password123!",
            listener_ip="8.8.8.8",
        ),
        settings=settings,
        campaign=campaign,
        noise=noise,
        dry_run=False,
    )

    with pytest.raises(ScopeViolationError):
        await mod.execute(ctx)


@pytest.mark.asyncio
async def test_sccm_secondary_targets_scope_enforcement():
    """MOD-010: ad.sccm skips out-of-scope site_server and NAA target without crashing."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = SCCMModule(settings=settings, campaign=campaign, noise=noise)

    # Mock LDAP discovery to return out-of-scope site_server (192.168.1.100)
    fake_discovery = {
        "site_servers": ["192.168.1.100"],
        "site_code": "PS1",
        "management_points": [],
        "distribution_points": ["192.168.1.200"],
    }

    with patch.object(mod, "_discover_sccm", return_value=fake_discovery), \
         patch.object(mod, "_enum_client_push", return_value={}), \
         patch.object(mod, "_extract_naa", return_value={}), \
         patch.object(mod, "_check_pxe", return_value={}), \
         patch.object(mod, "_enum_task_sequences", return_value={}):

        ctx = ExecutionContext(
            execution_id="exec-sccm-scope",
            campaign_id=campaign.id,
            target="10.0.0.1",
            params=SCCMParams(
                dc="10.0.0.1",
                domain="corp.local",
                username="admin",
                password="Password123!",
            ),
            settings=settings,
            campaign=campaign,
            noise=noise,
            dry_run=False,
        )
        res = await mod.execute(ctx)
        # Module should complete and record findings without raising unhandled ScopeViolationError
        assert res.status in ("partial", "success")


def test_adcs_ca_host_scope_enforcement():
    """MOD-009: ad.adcs _submit_csr_to_ca asserts ca_host in scope."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = ADCSModule(settings=settings, campaign=campaign, noise=noise)

    # ca_host 192.168.99.1 is out of scope 10.0.0.0/24
    with pytest.raises(ScopeViolationError):
        mod._submit_csr_to_ca(
            ca_host="192.168.99.1",
            ca_name="Corp-CA",
            template_name="User",
            csr_pem=b"fake-csr",
            username="user",
            password="pwd",
            domain="corp.local",
        )


@pytest.mark.asyncio
async def test_ntlm_relay_check_relay_targets_scope_enforcement():
    """MOD-011: lateral.ntlm_relay skips out-of-scope targets in _check_relay_targets."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = NTLMRelayModule(settings=settings, campaign=campaign, noise=noise)

    # 10.0.0.5 is in-scope, 172.16.1.5 is out-of-scope
    targets = ["10.0.0.5", "172.16.1.5"]

    loop = asyncio.get_running_loop()

    async def fake_executor(executor, func, *args):
        return "not_required"

    with patch.object(loop, "run_in_executor", side_effect=fake_executor):
        results = await mod._check_relay_targets(targets, "10.0.0.1", "corp.local", "user", "pwd")
        # Only the in-scope target (10.0.0.5) should be in results
        result_hosts = [r.host for r in results]
        assert "10.0.0.5" in result_hosts
        assert "172.16.1.5" not in result_hosts


@pytest.mark.asyncio
async def test_smb_relay_targets_scope_enforcement():
    """MOD-015: lateral.smb_relay filters out-of-scope targets before negotiation."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = SMBRelayAuditModule(settings=settings, campaign=campaign, noise=noise)

    # Targets include in-scope and out-of-scope
    ctx = ExecutionContext(
        execution_id="exec-smb-relay-scope",
        campaign_id=campaign.id,
        target="10.0.0.10",
        params=SMBRelayParams(targets=["10.0.0.10", "192.168.5.5"]),
        settings=settings,
        campaign=campaign,
        noise=noise,
        dry_run=False,
    )

    with patch(
        "ares.modules.lateral.smb_relay._check_smb_signing",
        new_callable=AsyncMock,
        return_value={
            "signing_required": False,
            "signing_enabled": False,
            "dialect": "SMB2 0x0210",
            "security_mode": 1,
            "error": "",
        },
    ):
        res = await mod.execute(ctx)
        assert res.status in ("partial", "success")
        per_host = res.raw.get("per_host_results", {})
        assert "10.0.0.10" in per_host
        assert "192.168.5.5" not in per_host


@pytest.mark.asyncio
async def test_mssql_linked_and_listener_scope_enforcement():
    """MOD-014: lateral.mssql checks scope on linked_server and listener."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = MSSQLModule(settings=settings, campaign=campaign, noise=noise)

    # Test out-of-scope unc_coerce listener
    with patch.object(mod, "_enum_server_sync", return_value={"version": "SQL2019", "linked_servers": []}), \
         patch.object(mod, "_unc_coerce_sync") as mock_unc:
        findings, raw = await mod.run(
            target="10.0.0.15",
            username="sa",
            password="pwd",
            technique="unc_coerce",
            listener="172.16.10.10",  # Out of scope
        )
        assert not mock_unc.called

    # Test out-of-scope linked_server
    with patch.object(mod, "_enum_server_sync", return_value={"version": "SQL2019", "linked_servers": ["172.16.20.20"]}), \
         patch.object(mod, "_linked_server_sync") as mock_linked:
        findings, raw = await mod.run(
            target="10.0.0.15",
            username="sa",
            password="pwd",
            technique="linked",
            linked="172.16.20.20",  # Out of scope
            command="whoami",
        )
        assert not mock_linked.called


@pytest.mark.asyncio
async def test_pivot_reachable_subnets_scope_enforcement():
    """MOD-017: network.pivot filters out-of-scope reachable_subnets."""
    from ares.pivot.infrastructure import TunnelState
    settings, campaign, noise = _make_fixture("10.0.0.0/16")
    mod = PivotModule(settings=settings, campaign=campaign, noise=noise)

    mock_tunnel = MagicMock()
    mock_tunnel.state = TunnelState.ACTIVE
    mock_tunnel.tunnel_id = "tun-123"
    mock_tunnel.proxy_url = "socks5://127.0.0.1:1080"
    mock_tunnel.local_port = 1080

    mock_pm = MagicMock()
    mock_pm.establish_socks5 = AsyncMock(return_value=mock_tunnel)
    mock_pm.generate_proxychains_config.return_value = ""

    with patch.dict("ares.modules.network.pivot._PIVOT_MANAGERS", {"test-camp": mock_pm}):
        # 10.0.1.0/24 is in-scope, 192.168.1.0/24 is out-of-scope
        findings, raw = await mod.run(
            target="10.0.0.50",
            username="operator",
            secret="pwd",
            reachable_subnets=["10.0.1.0/24", "192.168.1.0/24"],
            campaign_id="test-camp",
        )
        call_kwargs = mock_pm.establish_socks5.call_args[1]
        assert "10.0.1.0/24" in call_kwargs["reachable_subnets"]
        assert "192.168.1.0/24" not in call_kwargs["reachable_subnets"]


def test_credential_reuse_rfc1918_probe_isolation():
    """MOD-032: credential.reuse does not probe login.microsoftonline.com for private RFC1918 IPs."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"device_code": "xyz"}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = _audit_oauth_posture_sync("10.0.0.5")
        assert mock_urlopen.called
        req_arg = mock_urlopen.call_args[0][0]
        assert "login.microsoftonline.com" not in req_arg.full_url
        assert "10.0.0.5" in req_arg.full_url
        assert result["checked_endpoint"] == "https://10.0.0.5/oauth2/v2.0/devicecode"


@pytest.mark.asyncio
async def test_dns_enum_axfr_nameserver_scope_enforcement():
    """MOD-058: network.dns_enum enforces scope before attempting AXFR on nameservers."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = DnsEnumModule(settings=settings, campaign=campaign, noise=noise)

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = ["8.8.8.8."]

    with patch("dns.resolver.Resolver", return_value=mock_resolver), \
         patch("dns.query.xfr") as mock_xfr:

        findings, raw = await mod.run(target="10.0.0.1", domain="corp.local", brute_force=False)
        assert not mock_xfr.called
        assert not any("Zone Transfer" in f.title for f in findings)


@pytest.mark.asyncio
async def test_http_fingerprint_redirect_scope_enforcement():
    """MOD-059: network.http_fingerprint prevents following redirects to out-of-scope hosts."""
    settings, campaign, noise = _make_fixture("10.0.0.0/24")
    mod = HttpFingerprintModule(settings=settings, campaign=campaign, noise=noise)

    # Create mock response redirecting to external out-of-scope host
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.is_redirect = True
    mock_resp.headers = {"location": "https://external-auth.evil.com/login", "server": "nginx"}
    mock_resp.text = "Redirecting..."

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.head = AsyncMock(return_value=MagicMock(status_code=404))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client):
        findings, raw = await mod.run(target="10.0.0.20", ports=[80])
        # External host was not queried second time because it was out of scope
        assert mock_client.get.call_count == 1
