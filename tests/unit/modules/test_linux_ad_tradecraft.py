"""
Unit Tests for Cross-Platform Linux Active Directory Post-Exploitation Modules
(RFC-ARES-2026-001 / Issue #56).

Covers:
  1. Pure-Python binary parsers (TDB/LDB, ccache v4, keytab 0x0502, kirbi ASN.1 codec)
  2. linux.sssd_harvest (offline hashes, Domain Admin privilege escalation, AresVault)
  3. linux.ccache_hunt (ticket hunting in /tmp & /run/user, expiry filtering, TGT elevation)
  4. linux.keytab_abuse (keytab parsing, machine credentials, Silver Ticket configuration)
  5. linux.samba_secrets (Samba secrets.tdb parsing, NTLM hash derivation)
  6. credential.ticket_converter (in-memory bi-directional ccache <-> kirbi transcoding)
"""
from __future__ import annotations

import base64
import os
import struct
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.credential.ticket_converter import TicketConverterModule
from ares.modules.linux._parsers import (
    CcacheParser,
    KeytabParser,
    KirbiASN1Codec,
    TDBParser,
    build_ccache_v4,
    parse_sssd_ldb_entry,
)
from ares.modules.linux.ccache_hunt import CcacheHuntModule
from ares.modules.linux.keytab_abuse import KeytabAbuseModule
from ares.modules.linux.samba_secrets import SambaSecretsModule
from ares.modules.linux.sssd_harvest import SssdHarvestModule
from ares.modules.params import (
    CcacheHuntParams,
    KeytabAbuseParams,
    SambaSecretsParams,
    SssdHarvestParams,
    TicketConverterParams,
)


# ── Fixtures & Mock Context ───────────────────────────────────────────────────

def _make_module(cls: type, noise_profile: str = "normal") -> tuple:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Linux-AD-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile(noise_profile),
    )
    noise = NoiseController(campaign)
    module = cls(settings=settings, campaign=campaign, noise=noise)
    return module, campaign


def _make_test_ctx(params: dict | None = None, dry_run: bool = False, vault: Any = None) -> ExecutionContext:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Linux-AD-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return ExecutionContext(
        execution_id="test-exec-rfc001",
        campaign_id=campaign.id,
        target="10.0.0.50",
        domain="corp.local",
        params=params or {},
        settings=settings,
        campaign=campaign,
        noise=noise,
        dry_run=dry_run,
        vault=vault,
    )


def _synthesize_tdb(records: list[tuple[bytes, bytes]]) -> bytes:
    """Synthesizes a minimal valid TDB database binary stream."""
    hash_size = 13
    header = struct.pack(">IIII", 0x2601196D, 0, hash_size, 0)
    hash_table = b"\x00" * (hash_size * 4)

    record_bodies = bytearray()
    for key, val in records:
        rec_len = len(key) + len(val)
        aligned_len = (rec_len + 3) & ~3
        padding = b"\x00" * (aligned_len - rec_len)
        rec_hdr = struct.pack(
            ">IIIIII",
            0,                     # next_rec
            aligned_len,           # rec_len
            len(key),              # key_len
            len(val),              # data_len
            0x12345678,            # full_hash
            0x2601196D,            # rec_magic (TDB_MAGIC)
        )
        record_bodies.extend(rec_hdr + key + val + padding)

    return header + hash_table + bytes(record_bodies)


def _synthesize_keytab(entries: list[dict[str, Any]]) -> bytes:
    """Synthesizes a valid Kerberos keytab binary file (format 0x0502)."""
    buf = bytearray(struct.pack(">H", 0x0502))
    for e in entries:
        principal = e.get("principal", "HOST$@CORP.LOCAL")
        comps_str, realm = principal.split("@", 1)
        comps = comps_str.split("/")

        entry_buf = bytearray()
        entry_buf.extend(struct.pack(">h", len(comps)))
        realm_b = realm.encode("latin-1")
        entry_buf.extend(struct.pack(">H", len(realm_b)) + realm_b)
        for c in comps:
            cb = c.encode("latin-1")
            entry_buf.extend(struct.pack(">H", len(cb)) + cb)

        keydata = bytes.fromhex(e.get("key_hex", "11" * 32))
        entry_buf.extend(
            struct.pack(
                ">IIBHH",
                e.get("name_type", 1),
                int(time.time()),
                e.get("vno", 2),
                e.get("keytype", 18),
                len(keydata),
            )
            + keydata
        )
        buf.extend(struct.pack(">i", len(entry_buf)) + entry_buf)
    return bytes(buf)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Binary Parsers Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBinaryParsers:
    def test_tdb_parser_extracts_records(self):
        records = [
            (b"SECRETS/MACHINE_PASSWORD/CORP", b"SuperSecretMachinePass123!\x00"),
            (b"name=admin,cn=users,dc=corp", b"dn: name=admin\nname: admin\nuserPassword: $6$rounds=5000$salt$hash\n"),
        ]
        raw_tdb = _synthesize_tdb(records)
        extracted = TDBParser.parse_records(raw_tdb)
        assert len(extracted) >= 2
        keys = [k for k, _ in extracted]
        assert b"SECRETS/MACHINE_PASSWORD/CORP" in keys

    def test_sssd_ldb_entry_parsing_detects_domain_admin_and_hash(self):
        raw_entry = (
            b"dn: name=da_user,cn=users,dc=corp,dc=local\n"
            b"name: da_user\n"
            b"cachedPassword: $6$saltstring$hashedpassword512\n"
            b"memberOf: cn=Domain Admins,cn=users,dc=corp,dc=local\n"
            b"uidNumber: 10001\n"
        )
        parsed = parse_sssd_ldb_entry(raw_entry)
        assert parsed["attributes"]["name"] == "da_user"
        assert parsed["is_domain_admin"] is True
        assert len(parsed["hashes"]) == 1
        assert parsed["hashes"][0].startswith("$6$")

    def test_ccache_parser_roundtrip(self):
        now = int(time.time())
        ticket = {
            "client": "Administrator@CORP.LOCAL",
            "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
            "keytype": 18,
            "keydata": "22" * 32,
            "authtime": now - 300,
            "starttime": now - 300,
            "endtime": now + 36000,
            "renew_till": now + 86400,
            "flags": 0x40810000,
            "is_skey": 0,
            "ticket_bytes": b"\x61\x82\x01\x00synthetic_ticket_data",
        }
        ccache_data = build_ccache_v4("Administrator@CORP.LOCAL", [ticket])
        assert len(ccache_data) > 16

        principal, tickets = CcacheParser.parse(ccache_data, now=now)
        assert principal == "Administrator@CORP.LOCAL"
        assert len(tickets) == 1
        parsed_t = tickets[0]
        assert parsed_t["client"] == "Administrator@CORP.LOCAL"
        assert parsed_t["server"] == "krbtgt/CORP.LOCAL@CORP.LOCAL"
        assert parsed_t["is_tgt"] is True
        assert parsed_t["is_expired"] is False

    def test_keytab_parser_extracts_machine_keys(self):
        entries = [
            {"principal": "UBUNTU-SRV$@CORP.LOCAL", "keytype": 18, "vno": 3, "key_hex": "aa" * 32},
            {"principal": "UBUNTU-SRV$@CORP.LOCAL", "keytype": 23, "vno": 3, "key_hex": "bb" * 16},
        ]
        keytab_data = _synthesize_keytab(entries)
        parsed = KeytabParser.parse(keytab_data)
        assert len(parsed) == 2
        assert parsed[0]["principal"] == "UBUNTU-SRV$@CORP.LOCAL"
        assert parsed[0]["enctype"] == "aes256-cts-hmac-sha1-96"
        assert parsed[1]["enctype"] == "rc4-hmac"

    def test_kirbi_codec_encoding_and_decoding(self):
        now = int(time.time())
        ticket_data = {
            "client": "da_svc@CORP.LOCAL",
            "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
            "keytype": 18,
            "keydata": "44" * 32,
            "authtime": now,
            "starttime": now,
            "endtime": now + 36000,
            "ticket_bytes": b"fake_krb5_ticket",
        }
        kirbi_bytes = KirbiASN1Codec.encode_kirbi(ticket_data)
        assert kirbi_bytes.startswith(b"\x76")  # APPLICATION 22 tag

        decoded = KirbiASN1Codec.decode_kirbi(kirbi_bytes)
        assert decoded["keytype"] == 18
        assert "CORP.LOCAL" in decoded["client"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. linux.sssd_harvest Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSssdHarvestModule:
    @pytest.mark.asyncio
    async def test_validation_and_feasibility(self):
        module, _ = _make_module(SssdHarvestModule)
        ctx = _make_test_ctx(params={"db_path": ""})
        with pytest.raises(ModuleValidationError):
            await module.validate(ctx)

        feasibility = await module.assess_feasibility(ctx)
        assert hasattr(feasibility, "feasible")

    @pytest.mark.asyncio
    async def test_dry_run_execution(self):
        module, _ = _make_module(SssdHarvestModule)
        ctx = _make_test_ctx(dry_run=True)
        res = await module.execute(ctx)
        assert res.status == "dry_run"
        assert "Dry-run preview" in res.raw.get("message", "")

    @pytest.mark.asyncio
    async def test_execute_with_synthetic_sssd_ldb(self):
        module, _ = _make_module(SssdHarvestModule)
        mock_vault = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            ldb_path = os.path.join(tmpdir, "cache_corp.local.ldb")
            records = [
                (
                    b"name=domain_admin,cn=users,dc=corp,dc=local",
                    (
                        b"name: domain_admin\n"
                        b"cachedPassword: $6$salt$hashed512\n"
                        b"memberOf: cn=Domain Admins,cn=users,dc=corp,dc=local\n"
                    ),
                ),
            ]
            with open(ldb_path, "wb") as f:
                f.write(_synthesize_tdb(records))

            ctx = _make_test_ctx(params={"db_path": tmpdir}, vault=mock_vault)
            res = await module.execute(ctx)

            assert res.status == "success"
            assert len(res.findings) >= 1
            f0 = res.findings[0]
            assert f0.severity.value == "critical"
            assert "domain_admin" in f0.title
            assert mock_vault.store.called


# ─────────────────────────────────────────────────────────────────────────────
# 3. linux.ccache_hunt Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCcacheHuntModule:
    @pytest.mark.asyncio
    async def test_validation_requires_list_of_dirs(self):
        module, _ = _make_module(CcacheHuntModule)
        ctx = _make_test_ctx(params={"search_dirs": "not_a_list"})
        with pytest.raises(ModuleValidationError):
            await module.validate(ctx)

    @pytest.mark.asyncio
    async def test_dry_run(self):
        module, _ = _make_module(CcacheHuntModule)
        ctx = _make_test_ctx(dry_run=True)
        res = await module.execute(ctx)
        assert res.status == "dry_run"

    @pytest.mark.asyncio
    async def test_hunt_synthetic_ccache_ticket(self):
        module, _ = _make_module(CcacheHuntModule)
        mock_vault = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            ccache_path = os.path.join(tmpdir, "krb5cc_1000")
            now = int(time.time())
            ticket = {
                "client": "corpadmin@CORP.LOCAL",
                "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                "keytype": 18,
                "keydata": "55" * 32,
                "authtime": now,
                "starttime": now,
                "endtime": now + 36000,
                "renew_till": now + 86400,
                "flags": 0x40810000,
                "is_skey": 0,
                "ticket_bytes": b"real_ticket_bytes_here",
            }
            with open(ccache_path, "wb") as f:
                f.write(build_ccache_v4("corpadmin@CORP.LOCAL", [ticket]))

            ctx = _make_test_ctx(params={"search_dirs": [tmpdir]}, vault=mock_vault)
            res = await module.execute(ctx)

            assert res.status == "success"
            assert len(res.findings) >= 1
            assert "corpadmin@CORP.LOCAL" in res.findings[0].title
            assert res.findings[0].severity.value in ("critical", "high")
            assert mock_vault.store.called


# ─────────────────────────────────────────────────────────────────────────────
# 4. linux.keytab_abuse Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestKeytabAbuseModule:
    @pytest.mark.asyncio
    async def test_dry_run(self):
        module, _ = _make_module(KeytabAbuseModule)
        ctx = _make_test_ctx(dry_run=True)
        res = await module.execute(ctx)
        assert res.status == "dry_run"

    @pytest.mark.asyncio
    async def test_parse_synthetic_keytab_and_silver_ticket(self):
        module, _ = _make_module(KeytabAbuseModule)
        mock_vault = MagicMock()

        with tempfile.NamedTemporaryFile(suffix=".keytab", delete=False) as f:
            keytab_path = f.name
            f.write(_synthesize_keytab([
                {"principal": "DB01$@CORP.LOCAL", "keytype": 18, "vno": 4, "key_hex": "77" * 32}
            ]))

        try:
            ctx = _make_test_ctx(
                params={"keytab_path": keytab_path, "forge_silver_ticket": True, "service_name": "cifs"},
                vault=mock_vault,
            )
            res = await module.execute(ctx)

            assert res.status == "success"
            assert len(res.findings) >= 1
            assert "DB01$@CORP.LOCAL" in res.findings[0].title
            assert res.findings[0].severity.value == "high"
            assert len(res.raw["silver_tickets"]) == 1
            assert res.raw["silver_tickets"][0]["service_spn"] == "cifs/10.0.0.50@CORP.LOCAL"
            assert mock_vault.store.called
        finally:
            if os.path.exists(keytab_path):
                os.remove(keytab_path)


# ─────────────────────────────────────────────────────────────────────────────
# 5. linux.samba_secrets Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSambaSecretsModule:
    @pytest.mark.asyncio
    async def test_dry_run(self):
        module, _ = _make_module(SambaSecretsModule)
        ctx = _make_test_ctx(dry_run=True)
        res = await module.execute(ctx)
        assert res.status == "dry_run"

    @pytest.mark.asyncio
    async def test_extract_machine_password_and_ntlm(self):
        module, _ = _make_module(SambaSecretsModule)
        mock_vault = MagicMock()

        with tempfile.NamedTemporaryFile(suffix=".tdb", delete=False) as f:
            tdb_path = f.name
            records = [
                (b"SECRETS/MACHINE_PASSWORD/CORP", b"P@ssw0rdMachine!\x00"),
            ]
            f.write(_synthesize_tdb(records))

        try:
            ctx = _make_test_ctx(params={"secrets_tdb_path": tdb_path}, vault=mock_vault)
            res = await module.execute(ctx)

            assert res.status == "success"
            assert len(res.findings) >= 1
            assert "CORP$" in res.findings[0].title
            assert res.raw["count"] == 1
            assert res.raw["stored_in_vault"] == 1
            assert mock_vault.store.called
            stored_cred, stored_val = mock_vault.store.call_args[0]
            assert stored_cred.username == "CORP$"
            assert len(stored_val) == 32
        finally:
            if os.path.exists(tdb_path):
                os.remove(tdb_path)


# ─────────────────────────────────────────────────────────────────────────────
# 6. credential.ticket_converter Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTicketConverterModule:
    @pytest.mark.asyncio
    async def test_validation_rejects_empty_or_identical_format(self):
        module, _ = _make_module(TicketConverterModule)
        ctx = _make_test_ctx(params={"ticket_b64": "", "source_format": "ccache", "target_format": "kirbi"})
        with pytest.raises(ModuleValidationError):
            await module.validate(ctx)

        ctx2 = _make_test_ctx(params={"ticket_b64": "AAAA", "source_format": "ccache", "target_format": "ccache"})
        with pytest.raises(ModuleValidationError):
            await module.validate(ctx2)

    @pytest.mark.asyncio
    async def test_dry_run(self):
        module, _ = _make_module(TicketConverterModule)
        ctx = _make_test_ctx(dry_run=True)
        res = await module.execute(ctx)
        assert res.status == "dry_run"

    @pytest.mark.asyncio
    async def test_ccache_to_kirbi_and_back_conversion(self):
        module, _ = _make_module(TicketConverterModule)
        mock_vault = MagicMock()

        # Step A: Create synthetic ccache v4 Base64
        now = int(time.time())
        ticket = {
            "client": "svc_sql@CORP.LOCAL",
            "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
            "keytype": 18,
            "keydata": "88" * 32,
            "authtime": now,
            "starttime": now,
            "endtime": now + 36000,
            "renew_till": now + 86400,
            "flags": 0x40810000,
            "is_skey": 0,
            "ticket_bytes": b"real_ticket_content",
        }
        ccache_raw = build_ccache_v4("svc_sql@CORP.LOCAL", [ticket])
        ccache_b64 = base64.b64encode(ccache_raw).decode("ascii")

        # Step B: Convert ccache -> kirbi
        ctx1 = _make_test_ctx(
            params={"ticket_b64": ccache_b64, "source_format": "ccache", "target_format": "kirbi"},
            vault=mock_vault,
        )
        res1 = await module.execute(ctx1)
        assert res1.status == "success"
        kirbi_b64 = res1.raw["converted_ticket_b64"]
        assert kirbi_b64
        kirbi_bytes = base64.b64decode(kirbi_b64)
        assert kirbi_bytes.startswith(b"\x76")  # ASN.1 Application 22 header

        # Step C: Convert kirbi -> ccache
        ctx2 = _make_test_ctx(
            params={"ticket_b64": kirbi_b64, "source_format": "kirbi", "target_format": "ccache"},
            vault=mock_vault,
        )
        res2 = await module.execute(ctx2)
        assert res2.status == "success"
        roundtrip_ccache = base64.b64decode(res2.raw["converted_ticket_b64"])
        principal, tickets = CcacheParser.parse(roundtrip_ccache, now=now)
        assert principal
        assert len(tickets) >= 1
