"""
Unit tests verifying Structured Maintenance & Security Hardening Remediations.

Covers:
1. StagedCollectionModule LOTS cloud egress audit default-disabled invariant & SSL verification.
2. McpScopeGate bracketed IPv6 and host:port parsing against CIDR and wildcard scopes.
3. AresMcpServer error sanitization preventing raw exception string disclosure.
4. Windows UTF-8 invariance across CampaignStore, KeyRegistry, and potfile handling.
"""
from __future__ import annotations

import asyncio
import json
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.mcp.protocol import ErrorCode, JSONRPCRequest
from ares.mcp.security import McpScopeGate
from ares.mcp.server import AresMcpServer
from ares.modules.exfil.staged_collection import StagedCollectionModule, _audit_lots_egress_sync
from ares.modules.params import StagedCollectionParams


def _make_module(cls):
    settings = AresSettings()
    campaign = Campaign(
        name="Maintenance-Test",
        client="TestClient",
        operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8"), ScopeEntry(cidr="2001:db8::/32")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


# ── 1. Staged Collection LOTS Egress Guard & SSL Safety ───────────────────────

class TestStagedCollectionSafety:
    """Verifies that staged collection does not leak un-scoped egress or disable SSL validation."""

    def test_staged_collection_params_defaults_lots_egress_to_false(self):
        params = StagedCollectionParams(
            target="10.0.0.1",
            username="operator",
            destination="/tmp/stage",
        )
        assert params.audit_lots_egress is False

    @pytest.mark.asyncio
    async def test_staged_collection_run_skips_lots_egress_by_default(self):
        mod = _make_module(StagedCollectionModule)
        mod.before_request = AsyncMock()
        mod.noise.jitter.sleep = AsyncMock()
        mod.noise.rate_limiter.acquire = AsyncMock()

        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        with patch("paramiko.SSHClient", return_value=mock_ssh), \
             patch("ares.modules.exfil.staged_collection._audit_lots_egress_sync") as mock_lots:
            findings, raw = await mod.run(
                target="10.0.0.1",
                username="operator",
                destination="/tmp/stage",
            )
            # When audit_lots_egress is False and no custom func is provided, LOTS audit must NOT be called
            assert not mock_lots.called
            assert raw["lots_routes_open"] == []
            assert raw["tenant_restrictions_enforced"] is False
            assert not any("LOTS Exfiltration Route Open" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_staged_collection_run_invokes_lots_when_explicitly_requested(self):
        mod = _make_module(StagedCollectionModule)
        mod.before_request = AsyncMock()
        mod.noise.jitter.sleep = AsyncMock()
        mod.noise.rate_limiter.acquire = AsyncMock()

        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        mock_lots_result = {
            "lots_routes_open": ["m365_graph"],
            "tenant_restrictions_enforced": False,
            "checked_endpoints": ["m365_graph", "aws_s3", "azure_blob"],
        }

        with patch("paramiko.SSHClient", return_value=mock_ssh), \
             patch("ares.modules.exfil.staged_collection._audit_lots_egress_sync", return_value=mock_lots_result) as mock_lots:
            findings, raw = await mod.run(
                target="10.0.0.1",
                username="operator",
                destination="/tmp/stage",
                audit_lots_egress=True,
            )
            assert mock_lots.called
            assert raw["lots_routes_open"] == ["m365_graph"]
            assert any("LOTS Exfiltration Route Open" in f.title for f in findings)

    def test_audit_lots_egress_uses_verified_ssl_context(self):
        """Verifies _audit_lots_egress_sync uses ssl.create_default_context() without CERT_NONE."""
        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("ssl.create_default_context") as mock_ssl_ctx:
            fake_ctx = MagicMock()
            mock_ssl_ctx.return_value = fake_ctx
            mock_resp = MagicMock()
            mock_resp.headers = {}
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            _audit_lots_egress_sync("10.0.0.1")

            assert mock_ssl_ctx.called
            # Ensure CERT_NONE and check_hostname = False were NOT set
            assert fake_ctx.verify_mode != ssl.CERT_NONE
            assert fake_ctx.check_hostname is not False


# ── 2. McpScopeGate IPv6 & Host:Port Parsing ─────────────────────────────────

class TestMcpScopeGateIPv6Parsing:
    """Verifies that McpScopeGate parses bracketed IPv6 and host:port combinations accurately."""

    def test_bracketed_ipv6_with_port_matches_cidr(self):
        scope_rules = ["2001:db8::/32", "10.0.0.0/8"]
        assert McpScopeGate.is_in_scope("[2001:db8::1]:445", scope_rules) is True
        assert McpScopeGate.is_in_scope("[2001:db8::1]", scope_rules) is True
        assert McpScopeGate.is_in_scope("2001:db8::1", scope_rules) is True

    def test_bracketed_ipv6_out_of_scope_rejected(self):
        scope_rules = ["2001:db8::/32"]
        assert McpScopeGate.is_in_scope("[2001:cafe::1]:445", scope_rules) is False
        assert McpScopeGate.is_in_scope("[fe80::1]:80", scope_rules) is False

    def test_ipv4_with_port_matches_cidr(self):
        scope_rules = ["192.168.1.0/24"]
        assert McpScopeGate.is_in_scope("192.168.1.50:8080", scope_rules) is True
        assert McpScopeGate.is_in_scope("192.168.2.50:8080", scope_rules) is False

    def test_hostname_with_port_matches_wildcard(self):
        scope_rules = ["*.corp.local"]
        assert McpScopeGate.is_in_scope("dc01.corp.local:88", scope_rules) is True
        assert McpScopeGate.is_in_scope("fileserver.internal.net:445", scope_rules) is False


# ── 3. AresMcpServer Internal Error Sanitization ──────────────────────────────

class TestAresMcpServerErrorSanitization:
    """Verifies that internal server exceptions do not leak raw details to JSON-RPC clients."""

    @pytest.mark.asyncio
    async def test_internal_error_does_not_leak_raw_exception_string(self):
        server = AresMcpServer()
        # Mock tool_registry.list_tools to raise an internal exception with sensitive paths/queries
        server.tool_registry.list_tools = MagicMock(
            side_effect=RuntimeError("SELECT * FROM credentials WHERE key='SUPER_SECRET_123'; /var/run/ares.sock failed")
        )

        msg = {
            "jsonrpc": "2.0",
            "id": "req-99",
            "method": "tools/list",
            "params": {},
        }
        res = await server.handle_message(msg)

        assert res is not None
        assert res["id"] == "req-99"
        assert "error" in res
        assert res["error"]["code"] == ErrorCode.INTERNAL_ERROR.value
        # Raw exception string MUST NOT be disclosed
        assert "SUPER_SECRET_123" not in res["error"]["message"]
        assert "SELECT * FROM" not in res["error"]["message"]
        assert res["error"]["message"] == "Internal MCP server error. Consult system audit logs."


# ── 4. Cross-Platform UTF-8 Invariance ────────────────────────────────────────

class TestCrossPlatformUtf8Invariance:
    """Verifies that persistence layers read and write UTF-8 safely without Windows code page corruption."""

    def test_campaign_store_roundtrip_with_multibyte_unicode(self, tmp_path):
        from ares.cli._store import save_campaign, load_campaign, campaigns_dir

        with patch("ares.cli._store.campaigns_dir", return_value=tmp_path):
            mock_campaign = MagicMock()
            mock_campaign.id = "camp-unicode-01"
            mock_campaign.model_dump_json.return_value = json.dumps({
                "id": "camp-unicode-01",
                "name": "Audit Keamanan ARES — Uji Aksara & Simbol 🛡️",
                "notes": "Penetrasi sistem internal: Target terkonfirmasi di lab pengujian (Jakarta/IDN).",
                "findings": [],
            }, ensure_ascii=False)

            save_campaign(mock_campaign)
            loaded = load_campaign("camp-unicode-01")

            assert loaded is not None
            assert loaded["id"] == "camp-unicode-01"
            assert "Uji Aksara & Simbol 🛡️" in loaded["name"]
            assert "Jakarta/IDN" in loaded["notes"]

    def test_key_registry_roundtrip_with_utf8(self, tmp_path):
        from ares.core.signing import KeyRegistry

        key_file = tmp_path / "trusted_keys.json"
        rev_file = tmp_path / "revoked_keys.json"

        with patch("ares.core.signing.TRUSTED_KEYS_PATH", key_file), \
             patch("ares.core.signing.REVOKED_KEYS_PATH", rev_file):
            registry = KeyRegistry(path=key_file)
            registry.add_trusted_key(
                key_id="key-001",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nMIIB...IDN\n-----END PUBLIC KEY-----",
                author="Tim Keamanan & Audit — ARES Cyber Security",
                added_by="operator_utama",
            )

            # Reload into a fresh registry instance from disk
            fresh_registry = KeyRegistry(path=key_file)
            assert "key-001" in fresh_registry._keys
            assert "Tim Keamanan & Audit — ARES Cyber Security" in fresh_registry._keys["key-001"]["author"]

    @pytest.mark.asyncio
    async def test_cracking_worker_potfile_utf8_reading(self, tmp_path):
        from ares.credential.cracker import CrackingWorker, CrackJob

        worker = CrackingWorker(vault=MagicMock(), timeout_s=5)
        worker.tmpdir = tmp_path
        worker._hashcat = "hashcat"

        job = CrackJob(
            job_id="job-1",
            hash_value="aad3b435b51404eeaad3b435b51404ee",
            hash_type="ntlm",
        )

        potfile = tmp_path / f"{job.job_id}.pot"
        potfile.write_text("aad3b435b51404eeaad3b435b51404ee:RahasiaKunci2026!🔒\n", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            plain = await worker._run_hashcat(job)
            assert plain == "RahasiaKunci2026!🔒"
