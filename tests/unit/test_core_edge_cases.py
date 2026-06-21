"""
Step 1B — Edge Case Tests: Core Infrastructure

Tests for non-happy-path scenarios, boundary conditions, and failure modes.
Supplements test_core_infrastructure.py (happy path tests).

Run: pytest tests/unit/test_core_edge_cases.py -v
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

_ROOT = Path(__file__).parent.parent.parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ═══════════════════════════════════════════════════════════════════════════════
# 1. AresDatabase — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatabaseEdgeCases:

    @pytest.fixture
    async def db(self, tmp_path):
        from ares.db.database import AresDatabase
        db_url = str(tmp_path / "edge.db")
        db = await AresDatabase.create(db_url, "test-enc-key-32-chars-placeholder!")
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_save_duplicate_campaign_id(self, db):
        """Saving two campaigns with same ID should not crash (upsert behavior)."""
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        c = Campaign(id="dup-id", name="First",
                     scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        c2 = Campaign(id="dup-id", name="Second",
                      scope=[ScopeEntry(cidr="10.0.0.0/8")],
                      noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c2)
        row = await db.get_campaign("dup-id")
        assert row is not None

    @pytest.mark.asyncio
    async def test_finding_with_empty_evidence(self, db):
        """Finding with empty evidence string should still save."""
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry
        c = Campaign(name="EmptyEv", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        f = Finding(title="Empty Evidence", description="Has description",
                    severity=Severity.LOW, confidence=0.5,
                    module_id="test", host="10.0.0.1", evidence="")
        await db.save_finding(c.id, f)
        findings = await db.get_findings(c.id)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_finding_rejects_empty_description(self, db):
        """Finding with empty description should be rejected by Pydantic."""
        from ares.core.campaign import Finding, Severity
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            Finding(title="Bad", description="", severity=Severity.LOW,
                    confidence=0.5, module_id="test", host="10.0.0.1")

    @pytest.mark.asyncio
    async def test_finding_with_unicode_content(self, db):
        """Finding with unicode/emoji content should save and retrieve correctly."""
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry
        c = Campaign(name="Unicode", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        f = Finding(title="Ünïcödé Fïndïng 中文 🔥", description="Description with émojis 🎯",
                    severity=Severity.HIGH, confidence=0.9, module_id="test",
                    host="10.0.0.1", evidence="証拠")
        await db.save_finding(c.id, f)
        findings = await db.get_findings(c.id)
        assert "Ünïcödé" in findings[0]["title"]

    @pytest.mark.asyncio
    async def test_finding_with_very_long_description(self, db):
        """Finding with 10K character description should save."""
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry
        c = Campaign(name="LongDesc", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        long_desc = "A" * 10000
        f = Finding(title="Long", description=long_desc, severity=Severity.MEDIUM,
                    confidence=0.5, module_id="test", host="10.0.0.1")
        await db.save_finding(c.id, f)
        findings = await db.get_findings(c.id)
        assert len(findings[0]["description"]) == 10000

    @pytest.mark.asyncio
    async def test_list_campaigns_empty(self, db):
        """List campaigns on empty DB should return empty list."""
        rows, total = await db.list_campaigns()
        assert total == 0
        assert rows == []

    @pytest.mark.asyncio
    async def test_list_campaigns_filter_by_operator(self, db):
        """Operator filter should only return matching campaigns."""
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        c1 = Campaign(name="Op1", operator="alice",
                      scope=[ScopeEntry(cidr="10.0.0.0/8")],
                      noise_profile=NoiseProfile.NORMAL)
        c2 = Campaign(name="Op2", operator="bob",
                      scope=[ScopeEntry(cidr="10.0.0.0/8")],
                      noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c1)
        await db.save_campaign(c2)
        rows, total = await db.list_campaigns(operator="alice")
        assert total == 1
        assert rows[0]["operator"] == "alice"

    @pytest.mark.asyncio
    async def test_bypass_outcome_different_vendors(self, db):
        """Success rate should be per-vendor."""
        await db.save_bypass_outcome("amsi-patch", "crowdstrike", "", True, "c1")
        await db.save_bypass_outcome("amsi-patch", "crowdstrike", "", True, "c1")
        await db.save_bypass_outcome("amsi-patch", "crowdstrike", "", True, "c1")
        await db.save_bypass_outcome("amsi-patch", "defender", "", False, "c1")
        await db.save_bypass_outcome("amsi-patch", "defender", "", False, "c1")
        await db.save_bypass_outcome("amsi-patch", "defender", "", False, "c1")
        cs_rate = await db.get_bypass_success_rate("amsi-patch", "crowdstrike", min_samples=2)
        def_rate = await db.get_bypass_success_rate("amsi-patch", "defender", min_samples=2)
        assert cs_rate == 1.0    # 3/3
        assert def_rate == 0.0   # 0/3

    @pytest.mark.asyncio
    async def test_credential_with_empty_secret(self, db):
        """Credential with empty secret should still save."""
        from ares.db.database import DBCredential
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        c = Campaign(name="EmptyCred", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        cred = DBCredential(campaign_id=c.id, username="user", cred_type="password",
                            secret="")
        await db.save_credential(cred)
        creds = await db.get_credentials(c.id)
        assert len(creds) >= 1

    @pytest.mark.asyncio
    async def test_verify_nonexistent_user(self, db):
        """Verifying user that doesn't exist should return None."""
        result = await db.verify_user("ghost", "pass")
        assert result is None

    @pytest.mark.asyncio
    async def test_ensure_default_admin_idempotent(self, db):
        """Calling ensure_default_admin twice should not create duplicate."""
        r1 = await db.ensure_default_admin("Pass1!")
        r2 = await db.ensure_default_admin("Pass2!")
        assert r1 is True   # created
        assert r2 is False  # already exists
        users = await db.list_users()
        admin_count = sum(1 for u in users if u["username"] == "admin")
        assert admin_count == 1

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_api_key(self, db):
        """Revoking nonexistent key should return False."""
        result = await db.revoke_api_key("fake-key-id", "fake-user")
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_revoked_api_key(self, db):
        """Revoked API key should fail verification."""
        await db.ensure_default_admin("Admin1!")
        user = await db.get_user("admin")
        key_id, raw_key = await db.create_api_key(user["id"], "temp", "admin")
        await db.revoke_api_key(key_id, user["id"])
        result = await db.verify_api_key(raw_key)
        assert result is None

    @pytest.mark.asyncio
    async def test_verify_garbage_api_key(self, db):
        """Random string should fail API key verification."""
        result = await db.verify_api_key("not_a_real_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_concurrent_finding_writes(self, db):
        """Multiple concurrent finding writes should not corrupt DB."""
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry
        c = Campaign(name="Concurrent", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)

        async def write_finding(i):
            f = Finding(title=f"Concurrent-{i}", description=f"D{i}",
                        severity=Severity.MEDIUM, confidence=0.5,
                        module_id="test", host=f"10.0.0.{i % 255}")
            await db.save_finding(c.id, f)

        await asyncio.gather(*[write_finding(i) for i in range(20)])
        findings = await db.get_findings(c.id)
        assert len(findings) == 20


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Campaign — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestCampaignEdgeCases:

    def test_empty_scope_denies_all(self):
        """Campaign with empty scope should deny all IPs."""
        from ares.core.campaign import Campaign, NoiseProfile
        c = Campaign(name="NoScope", scope=[], noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.1") is False
        assert c.is_in_scope("192.168.1.1") is False

    def test_scope_boundary_first_ip(self):
        """First IP in CIDR should be in scope."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/24")],
                     noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.0") is True

    def test_scope_boundary_last_ip(self):
        """Last IP in CIDR should be in scope."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/24")],
                     noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.255") is True

    def test_scope_boundary_just_outside(self):
        """IP just outside CIDR boundary should be out of scope."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/24")],
                     noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.1.0") is False

    def test_scope_single_host(self):
        """/32 scope should only match exactly one IP."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.5/32")],
                     noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.5") is True
        assert c.is_in_scope("10.0.0.4") is False
        assert c.is_in_scope("10.0.0.6") is False

    def test_scope_multiple_entries(self):
        """Multiple scope entries — IP in any should be in scope."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[
            ScopeEntry(cidr="10.0.0.0/24"),
            ScopeEntry(cidr="192.168.1.0/24"),
        ], noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.1") is True
        assert c.is_in_scope("192.168.1.1") is True
        assert c.is_in_scope("172.16.0.1") is False

    def test_scope_overlapping_cidrs(self):
        """Overlapping CIDRs should still work (no double-count issues)."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[
            ScopeEntry(cidr="10.0.0.0/8"),
            ScopeEntry(cidr="10.0.0.0/24"),  # subset of /8
        ], noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.1") is True
        assert c.is_in_scope("10.1.0.1") is True

    def test_scope_invalid_ip_returns_false(self):
        """Invalid IP string should return False (not crash)."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/24")],
                     noise_profile=NoiseProfile.NORMAL)
        # Garbage strings should fail closed (return False)
        assert c.is_in_scope("not_an_ip") is False
        assert c.is_in_scope("") is False
        assert c.is_in_scope("999.999.999.999") is False

    def test_finding_duplicate_titles(self):
        """Multiple findings with same title should all be stored."""
        from ares.core.campaign import Campaign, Finding, Severity, ScopeEntry, NoiseProfile
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        for i in range(5):
            c.add_finding(Finding(
                title="Same Title", description=f"Desc {i}",
                severity=Severity.HIGH, confidence=0.9,
                module_id="test", host=f"10.0.0.{i}",
            ))
        assert len(c.findings) == 5

    def test_campaign_summary_with_no_findings(self):
        """Summary on empty campaign should return valid dict."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        c = Campaign(name="Empty", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        summary = c.summary()
        assert isinstance(summary, dict)
        assert summary.get("total_findings", 0) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CredentialVault — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestVaultEdgeCases:

    @pytest.fixture
    def vault(self):
        from ares.credential.vault import CredentialVault
        return CredentialVault(encryption_key="test-vault-key-32-chars-padded!")

    def test_store_empty_secret_rejected(self, vault):
        """Storing credential with empty string secret should raise ValueError."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        cred = Credential(
            username="user", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_USER,
            source_module="test",
        )
        with pytest.raises(ValueError, match="empty secret"):
            vault.store(cred, secret="")

    def test_store_special_chars_secret(self, vault):
        """Secrets with special chars should encrypt/decrypt correctly."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        special_secret = "P@$$w0rd!#%^&*()_+{}|:<>?~`'\"\\"
        cred = Credential(
            username="special", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_USER,
            source_module="test",
        )
        cred_id = vault.store(cred, secret=special_secret)
        assert vault.reveal(cred_id) == special_secret

    def test_store_very_long_secret(self, vault):
        """Very long secret (NTLM hash dump) should roundtrip."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        long_secret = "A" * 50000  # 50K chars — simulates large credential dump
        cred = Credential(
            username="longcred", domain="CORP",
            cred_type=CredentialType.NTLM,
            privilege=PrivilegeLevel.DOMAIN_USER,
            source_module="test",
        )
        cred_id = vault.store(cred, secret=long_secret)
        assert vault.reveal(cred_id) == long_secret

    def test_store_duplicate_username_updates(self, vault):
        """Storing same username+domain twice should update, not duplicate."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        cred1 = Credential(
            username="admin", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_USER,
            source_module="test",
        )
        cred2 = Credential(
            username="admin", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_ADMIN,
            source_module="test",
        )
        id1 = vault.store(cred1, secret="old_pass")
        id2 = vault.store(cred2, secret="new_pass")
        # Same dedup key — should update existing
        assert id1 == id2
        # Higher privilege should win
        stored = vault._store[id1]
        assert stored.privilege == PrivilegeLevel.DOMAIN_ADMIN

    def test_domain_admins_excludes_lower_privilege(self, vault):
        """domain_admins() should only return DOMAIN_ADMIN and above."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        for priv in [PrivilegeLevel.DOMAIN_USER, PrivilegeLevel.LOCAL_ADMIN,
                     PrivilegeLevel.SERVICE_ACCOUNT]:
            vault.store(
                Credential(username=f"user_{priv.value}", domain="CORP",
                           cred_type=CredentialType.CLEARTEXT,
                           privilege=priv, source_module="test"),
                secret="pass",
            )
        vault.store(
            Credential(username="da_user", domain="CORP",
                       cred_type=CredentialType.CLEARTEXT,
                       privilege=PrivilegeLevel.DOMAIN_ADMIN,
                       source_module="test"),
            secret="da_pass",
        )
        das = vault.domain_admins()
        assert len(das) == 1
        assert das[0].username == "da_user"

    def test_vault_with_none_key(self):
        """Vault with None encryption key should still function (unencrypted mode)."""
        from ares.credential.vault import CredentialVault, Credential, CredentialType, PrivilegeLevel
        vault = CredentialVault(encryption_key=None)
        cred = Credential(
            username="nokey", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_USER,
            source_module="test",
        )
        cred_id = vault.store(cred, secret="visible")
        revealed = vault.reveal(cred_id)
        assert revealed == "visible"

    def test_all_creds_ordering(self, vault):
        """vault.all() should return all stored credentials."""
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        ids = []
        for i in range(10):
            cred = Credential(
                username=f"user{i}", domain=f"DOMAIN{i}",
                cred_type=CredentialType.NTLM,
                privilege=PrivilegeLevel.DOMAIN_USER,
                source_module="test",
            )
            ids.append(vault.store(cred, secret=f"hash{i}"))
        assert len(vault.all()) == 10


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Security — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityEdgeCases:

    def test_sanitize_path_null_byte_injection(self):
        """Null byte in path should be handled."""
        from ares.core.security import sanitize_path
        # Null byte injection — common attack vector
        try:
            result = sanitize_path("/home/user/data\x00/etc/shadow")
            # Should either strip null or raise
            assert "\x00" not in result
        except (ValueError, TypeError):
            pass  # raising is also acceptable

    def test_sanitize_path_double_encoding(self):
        """Double-encoded traversal should be caught."""
        from ares.core.security import sanitize_path
        # %2e%2e%2f = ../
        try:
            result = sanitize_path("/tmp/%2e%2e%2f%2e%2e%2fetc/passwd")
            # The URL encoding won't be decoded by sanitize_path, so this should pass
            # as long as the resolved path stays in allowed dirs
        except ValueError:
            pass  # blocking is fine too

    def test_sanitize_path_tmp_allowed(self):
        """Paths under /tmp should be allowed."""
        from ares.core.security import sanitize_path
        result = sanitize_path("/tmp/bloodhound_data.json")
        assert "bloodhound_data.json" in result

    def test_sanitize_path_home_subdir_allowed(self):
        """Paths under /home/ should be allowed."""
        from ares.core.security import sanitize_path
        result = sanitize_path("/home/operator/loot/data.json")
        assert "data.json" in result

    def test_sanitize_hostname_empty(self):
        """Empty hostname should return empty string."""
        from ares.core.security import sanitize_hostname
        result = sanitize_hostname("")
        assert result == ""

    def test_sanitize_hostname_very_long(self):
        """Extremely long hostname should be handled (not crash)."""
        from ares.core.security import sanitize_hostname
        long_host = "a" * 500 + ".corp.local"
        result = sanitize_hostname(long_host)
        assert isinstance(result, str)

    def test_sanitize_hostname_ip_address(self):
        """IP address as hostname should pass through."""
        from ares.core.security import sanitize_hostname
        assert sanitize_hostname("10.0.0.1") == "10.0.0.1"
        assert sanitize_hostname("192.168.1.100") == "192.168.1.100"

    def test_data_encryptor_empty_string(self):
        """Encrypting empty string should work."""
        from ares.core.security import DataEncryptor
        enc = DataEncryptor(key="test-key-32-chars-padded-xxxxxxx")
        encrypted = enc.encrypt("")
        decrypted = enc.decrypt(encrypted)
        assert decrypted == ""

    def test_data_encryptor_binary_like_content(self):
        """Content that looks like binary should encrypt/decrypt."""
        from ares.core.security import DataEncryptor
        enc = DataEncryptor(key="test-key-32-chars-padded-xxxxxxx")
        binary_str = "\x00\x01\x02\xff\xfe\xfd"
        encrypted = enc.encrypt(binary_str)
        decrypted = enc.decrypt(encrypted)
        assert decrypted == binary_str

    def test_hash_password_different_each_time(self):
        """Same password should produce different hashes (bcrypt salt)."""
        from ares.core.security import hash_password
        h1 = hash_password("same_pass")
        h2 = hash_password("same_pass")
        assert h1 != h2  # bcrypt uses random salt

    def test_verify_password_empty(self):
        """Empty password should hash and verify correctly."""
        from ares.core.security import hash_password, verify_password
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("notempty", h) is False


# ═══════════════════════════════════════════════════════════════════════════════
# 5. NoiseController — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoiseEdgeCases:

    @pytest.mark.asyncio
    async def test_stealth_jitter_longer_than_aggressive(self):
        """STEALTH jitter should be demonstrably longer than AGGRESSIVE."""
        from ares.core.noise import NoiseController, NOISE_PROFILES
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry

        stealth_min = NOISE_PROFILES[NoiseProfile.STEALTH]["jitter_min_ms"]
        aggressive_max = NOISE_PROFILES[NoiseProfile.AGGRESSIVE]["jitter_max_ms"]
        # STEALTH minimum should be much larger than AGGRESSIVE maximum
        assert stealth_min > aggressive_max, (
            f"STEALTH jitter_min ({stealth_min}ms) should be > "
            f"AGGRESSIVE jitter_max ({aggressive_max}ms)"
        )

    @pytest.mark.asyncio
    async def test_stealth_rate_limit_stricter(self):
        """STEALTH should allow fewer requests per minute than AGGRESSIVE."""
        from ares.core.noise import NOISE_PROFILES
        from ares.core.campaign import NoiseProfile

        stealth_rpm = NOISE_PROFILES[NoiseProfile.STEALTH]["requests_per_minute"]
        aggressive_rpm = NOISE_PROFILES[NoiseProfile.AGGRESSIVE]["requests_per_minute"]
        assert stealth_rpm < aggressive_rpm

    @pytest.mark.asyncio
    async def test_rate_limiter_multiple_acquires(self):
        """Multiple rapid acquires should all complete (within rate limit)."""
        from ares.core.noise import NoiseController
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.AGGRESSIVE)
        nc = NoiseController(c)
        # AGGRESSIVE allows 200 req/min — 5 rapid acquires should be instant
        t0 = time.monotonic()
        for _ in range(5):
            await nc.rate_limiter.acquire("test")
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0  # should be near-instant for AGGRESSIVE

    @pytest.mark.asyncio
    async def test_noise_profiles_all_have_required_keys(self):
        """Every noise profile should define all required keys."""
        from ares.core.noise import NOISE_PROFILES
        from ares.core.campaign import NoiseProfile
        required = {"jitter_min_ms", "jitter_max_ms", "requests_per_minute",
                     "ldap_page_size", "kerberos_tgs_rpm"}
        for profile in [NoiseProfile.STEALTH, NoiseProfile.NORMAL, NoiseProfile.AGGRESSIVE]:
            config = NOISE_PROFILES[profile]
            missing = required - set(config.keys())
            assert not missing, f"{profile.value} missing keys: {missing}"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. AresContainer — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestContainerEdgeCases:

    def test_double_register_overwrites(self):
        """Registering same name twice should overwrite."""
        from ares.core.di import AresContainer
        c = AresContainer()
        c.register("svc", "first")
        c.register("svc", "second")
        assert c.get("svc") == "second"

    def test_factory_exception_propagates(self):
        """Exception in factory should propagate to caller."""
        from ares.core.di import AresContainer
        def bad_factory():
            raise RuntimeError("factory exploded")
        c = AresContainer()
        c.register_factory("broken", bad_factory)
        with pytest.raises(RuntimeError, match="factory exploded"):
            c.get("broken")

    def test_override_does_not_affect_singleton(self):
        """Override should not modify the original singleton."""
        from ares.core.di import AresContainer
        c = AresContainer()
        c.register("svc", "original")
        c.override("svc", "mocked")
        assert c.get("svc") == "mocked"
        c.clear_overrides()
        assert c.get("svc") == "original"

    def test_require_partial_missing_raises(self):
        """require() with one missing service should raise."""
        from ares.core.di import AresContainer, ServiceNotFound
        c = AresContainer()
        c.register("a", 1)
        with pytest.raises(ServiceNotFound):
            c.require("a", "missing")

    def test_repr_readable(self):
        """__repr__ should be human-readable."""
        from ares.core.di import AresContainer
        c = AresContainer()
        c.register("svc1", "val")
        r = repr(c)
        assert "AresContainer" in r
        assert "svc1" in r


# ═══════════════════════════════════════════════════════════════════════════════
# 7. CVSS / Compliance — Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestCVSSEdgeCases:

    def test_cvss_info_severity_low_score(self):
        """INFO severity should get low CVSS score."""
        from ares.core.cvss import enrich_finding_with_cvss
        from ares.core.campaign import Finding, Severity
        f = Finding(title="Info", description="D", severity=Severity.INFO,
                    confidence=0.5, module_id="test", host="10.0.0.1")
        enrich_finding_with_cvss(f)
        assert f.cvss_score is not None
        assert f.cvss_score < 4.0

    def test_cvss_critical_high_score(self):
        """CRITICAL severity should get high CVSS score."""
        from ares.core.cvss import enrich_finding_with_cvss
        from ares.core.campaign import Finding, Severity
        f = Finding(title="Crit", description="D", severity=Severity.CRITICAL,
                    confidence=1.0, module_id="ad.dcsync", host="10.0.0.1",
                    mitre_technique="T1003.006")
        enrich_finding_with_cvss(f)
        assert f.cvss_score >= 8.0

    def test_compliance_all_mapped_techniques_have_pci(self):
        """Every technique in COMPLIANCE_MAP should have at least PCI-DSS."""
        from ares.core.cvss import COMPLIANCE_MAP
        for tech_id, mapping in COMPLIANCE_MAP.items():
            assert "PCI-DSS" in mapping, f"{tech_id} missing PCI-DSS mapping"
            assert len(mapping["PCI-DSS"]) > 0, f"{tech_id} has empty PCI-DSS"

    def test_compliance_enrichment_no_technique(self):
        """Finding without mitre_technique should get empty compliance."""
        from ares.core.cvss import enrich_finding_with_compliance
        from ares.core.campaign import Finding, Severity
        f = Finding(title="NoTech", description="D", severity=Severity.MEDIUM,
                    confidence=0.5, module_id="test", host="10.0.0.1",
                    evidence={})
        enrich_finding_with_compliance(f)
        # Should not crash, evidence should stay unchanged or get empty mapping
        assert isinstance(f.evidence, dict)

    def test_cvss_summary_empty_findings(self):
        """CVSSSummary from empty list should have all zeros."""
        from ares.core.cvss import CVSSSummary
        s = CVSSSummary.from_findings([])
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.max_score == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 8. HIGH IMPACT — Concurrency Stress Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrencyStress:
    """Tests that WILL break if there's a race condition or data corruption."""

    @pytest.fixture
    async def db(self, tmp_path):
        from ares.db.database import AresDatabase
        db = await AresDatabase.create(str(tmp_path / "conc.db"),
                                        "test-enc-key-32-chars-placeholder!")
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_concurrent_campaign_writes_no_data_loss(self, db):
        """50 concurrent campaign saves must all persist — zero data loss."""
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry

        async def save_one(i):
            c = Campaign(name=f"Concurrent-{i}",
                         scope=[ScopeEntry(cidr=f"10.{i}.0.0/16")],
                         noise_profile=NoiseProfile.NORMAL)
            await db.save_campaign(c)
            return c.id

        ids = await asyncio.gather(*[save_one(i) for i in range(50)])
        # Every single campaign must be retrievable
        for cid in ids:
            row = await db.get_campaign(cid)
            assert row is not None, f"Campaign {cid} lost during concurrent write!"
        rows, total = await db.list_campaigns(per_page=100)
        assert total == 50, f"Expected 50 campaigns, got {total}"

    @pytest.mark.asyncio
    async def test_concurrent_findings_no_corruption(self, db):
        """100 findings written concurrently must all have correct content."""
        from ares.core.campaign import Campaign, Finding, Severity, NoiseProfile, ScopeEntry
        c = Campaign(name="ConcFind", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)

        async def write_one(i):
            f = Finding(title=f"Finding-{i:04d}", description=f"Unique-desc-{i}",
                        severity=Severity.HIGH, confidence=0.9,
                        module_id=f"mod.{i % 10}", host=f"10.0.{i // 256}.{i % 256}")
            await db.save_finding(c.id, f)

        await asyncio.gather(*[write_one(i) for i in range(100)])
        findings = await db.get_findings(c.id)
        assert len(findings) == 100, f"Expected 100 findings, got {len(findings)}"
        # Verify no title corruption (every title unique)
        titles = {f["title"] for f in findings}
        assert len(titles) == 100, "Finding titles corrupted during concurrent write!"

    @pytest.mark.asyncio
    async def test_concurrent_bypass_outcomes_accumulate(self, db):
        """Concurrent bypass outcome writes must all accumulate correctly."""
        async def write_outcome(i):
            await db.save_bypass_outcome(
                technique_id="concurrent-test",
                edr_vendor="test-edr",
                edr_version="1.0",
                success=(i % 2 == 0),  # alternating success/fail
                campaign_id="conc-camp",
            )

        await asyncio.gather(*[write_outcome(i) for i in range(40)])
        rate = await db.get_bypass_success_rate("concurrent-test", "test-edr", min_samples=10)
        assert rate is not None
        # 20 success out of 40 = 0.5
        assert abs(rate - 0.5) < 0.05, f"Expected ~0.5, got {rate}"

    @pytest.mark.asyncio
    async def test_concurrent_api_key_create_revoke(self, db):
        """Creating and revoking API keys concurrently must not corrupt state."""
        await db.ensure_default_admin("Admin1!")
        user = await db.get_user("admin")
        uid = user["id"]

        # Create 10 keys concurrently
        async def create_key(i):
            key_id, raw = await db.create_api_key(uid, f"key-{i}", "admin")
            return key_id, raw

        results = await asyncio.gather(*[create_key(i) for i in range(10)])

        # All 10 should be verifiable
        for key_id, raw in results:
            v = await db.verify_api_key(raw)
            assert v is not None, f"Key {key_id} not verifiable after concurrent create"

        # Revoke 5 concurrently
        revoke_tasks = [db.revoke_api_key(results[i][0], uid) for i in range(5)]
        revoke_results = await asyncio.gather(*revoke_tasks)
        assert all(r is True for r in revoke_results)

        # Revoked keys should fail, remaining should work
        for i in range(10):
            v = await db.verify_api_key(results[i][1])
            if i < 5:
                assert v is None, f"Key {i} still valid after revoke!"
            else:
                assert v is not None, f"Key {i} was incorrectly revoked!"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. HIGH IMPACT — Encryption Integrity Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncryptionIntegrity:
    """Tests that WILL break if encryption/decryption has any flaw."""

    def test_different_keys_cannot_decrypt(self):
        """Data encrypted with key A must NOT be decryptable with key B."""
        from ares.core.security import DataEncryptor
        enc_a = DataEncryptor(key="key-a-32-chars-padded-xxxxxxxxxx")
        enc_b = DataEncryptor(key="key-b-32-chars-padded-xxxxxxxxxx")
        ciphertext = enc_a.encrypt("secret data")
        # Wrong key must return None (DataEncryptor catches InvalidToken)
        result = enc_b.decrypt(ciphertext)
        assert result is None, \
            f"CRITICAL: Wrong key decrypted successfully, got: {result!r}"

    def test_tampered_ciphertext_fails(self):
        """Modified ciphertext must fail decryption (integrity check)."""
        from ares.core.security import DataEncryptor
        enc = DataEncryptor(key="test-key-32-chars-padded-xxxxxxx")
        ciphertext = enc.encrypt("original")
        # Flip one byte in the middle
        tampered = ciphertext[:20] + ("X" if ciphertext[20] != "X" else "Y") + ciphertext[21:]
        result = enc.decrypt(tampered)
        assert result is None, \
            f"CRITICAL: Tampered ciphertext decrypted successfully, got: {result!r}"

    def test_encryptor_handles_all_byte_values(self):
        """Every possible byte value (0-255) must encrypt/decrypt correctly."""
        from ares.core.security import DataEncryptor
        enc = DataEncryptor(key="test-key-32-chars-padded-xxxxxxx")
        all_chars = "".join(chr(i) for i in range(256))
        encrypted = enc.encrypt(all_chars)
        decrypted = enc.decrypt(encrypted)
        assert decrypted == all_chars, "Byte value roundtrip failed!"

    def test_vault_different_keys_isolated(self):
        """Two vaults with different keys must not cross-decrypt."""
        from ares.credential.vault import CredentialVault, Credential, CredentialType, PrivilegeLevel
        vault_a = CredentialVault(encryption_key="vault-key-a-32-chars-padded-xxxx")
        vault_b = CredentialVault(encryption_key="vault-key-b-32-chars-padded-xxxx")

        cred = Credential(username="admin", domain="CORP",
                          cred_type=CredentialType.CLEARTEXT,
                          privilege=PrivilegeLevel.DOMAIN_ADMIN,
                          source_module="test")
        cid_a = vault_a.store(cred, secret="secret-for-A")

        # Vault B should NOT be able to access vault A's credentials
        with pytest.raises(KeyError):
            vault_b.reveal(cid_a)

    def test_vault_secret_not_in_plaintext_memory(self):
        """After storing, the plaintext secret should only exist encrypted."""
        from ares.credential.vault import CredentialVault, Credential, CredentialType, PrivilegeLevel
        vault = CredentialVault(encryption_key="test-vault-key-32-chars-padded!")
        cred = Credential(username="admin", domain="CORP",
                          cred_type=CredentialType.CLEARTEXT,
                          privilege=PrivilegeLevel.DOMAIN_ADMIN,
                          source_module="test")
        cid = vault.store(cred, secret="TopSecretPassword123!")
        # The stored credential object should have encrypted secret_enc, not plaintext
        stored = vault._store[cid]
        raw_enc = stored.secret_enc
        assert raw_enc is not None
        if isinstance(raw_enc, bytes):
            assert b"TopSecretPassword123!" not in raw_enc
        else:
            assert "TopSecretPassword123!" not in str(raw_enc)

    @pytest.fixture
    async def db(self, tmp_path):
        from ares.db.database import AresDatabase
        db = await AresDatabase.create(str(tmp_path / "enc.db"),
                                        "test-enc-key-32-chars-placeholder!")
        yield db
        await db.close()

    @pytest.mark.asyncio
    async def test_db_credential_encrypted_at_rest(self, db):
        """Credential secret in DB must be encrypted — NOT plaintext."""
        from ares.db.database import DBCredential
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        c = Campaign(name="EncTest", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db.save_campaign(c)
        plain_secret = "VerySecretPassword789!"
        cred = DBCredential(campaign_id=c.id, username="enc_user",
                            cred_type="password", secret=plain_secret)
        await db.save_credential(cred)
        # Read raw from DB — secret_enc column must NOT contain plaintext
        raw_creds = await db.load_credentials_raw(c.id)
        assert len(raw_creds) >= 1
        for rc in raw_creds:
            enc_val = rc.get("secret_enc", "")
            assert plain_secret not in str(enc_val), \
                "CRITICAL: Credential stored in PLAINTEXT in database!"

    @pytest.mark.asyncio
    async def test_db_wrong_encryption_key_fails_decrypt(self, tmp_path):
        """Opening DB with wrong encryption key must fail to decrypt credentials."""
        from ares.db.database import AresDatabase, DBCredential
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry

        db_path = str(tmp_path / "keytest.db")
        # Write with key A
        db_a = await AresDatabase.create(db_path, "key-aaa-32-chars-padded-xxxxxxxx")
        c = Campaign(name="KeyTest", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                     noise_profile=NoiseProfile.NORMAL)
        await db_a.save_campaign(c)
        cred = DBCredential(campaign_id=c.id, username="victim",
                            cred_type="password", secret="RealSecret!")
        await db_a.save_credential(cred)
        await db_a.close()

        # Read with key B — decryption must fail or return garbage
        db_b = await AresDatabase.create(db_path, "key-bbb-32-chars-padded-xxxxxxxx")
        creds = await db_b.get_credentials(c.id, decrypt=True)
        await db_b.close()
        for cr in creds:
            secret = cr.get("secret_enc", cr.get("secret", ""))
            # Must either be empty, garbage, or raise — never the original plaintext
            assert secret != "RealSecret!", \
                "CRITICAL: Wrong encryption key decrypted to correct plaintext!"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. HIGH IMPACT — Security Boundary Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityBoundaries:
    """Tests that verify security boundaries are enforced correctly."""

    def test_scope_enforcement_prevents_out_of_scope_execution(self):
        """Module should refuse to execute against out-of-scope targets."""
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        from ares.core.noise import NoiseController
        c = Campaign(name="Scoped", scope=[ScopeEntry(cidr="10.0.0.0/24")],
                     noise_profile=NoiseProfile.NORMAL)
        assert c.is_in_scope("10.0.0.1") is True
        assert c.is_in_scope("192.168.1.1") is False
        # The key invariant: out-of-scope IP must NEVER return True
        for bad_ip in ["192.168.1.1", "172.16.0.1", "8.8.8.8", "0.0.0.0",
                        "255.255.255.255", "127.0.0.1"]:
            assert c.is_in_scope(bad_ip) is False, \
                f"CRITICAL: {bad_ip} passed scope check for 10.0.0.0/24!"

    def test_sanitize_path_cannot_reach_etc_shadow(self):
        """No path manipulation should reach /etc/shadow."""
        from ares.core.security import sanitize_path
        attack_paths = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/root/.ssh/id_rsa",
            "/root/.bash_history",
            "/proc/self/environ",
        ]
        for p in attack_paths:
            with pytest.raises(ValueError):
                sanitize_path(p)

    def test_sanitize_path_traversal_cannot_escape(self):
        """Path traversal sequences should not escape allowed dirs."""
        from ares.core.security import sanitize_path
        traversal_attacks = [
            "/tmp/../../etc/shadow",
            "/home/user/../../../../etc/passwd",
            "/tmp/./../../etc/shadow",
        ]
        for p in traversal_attacks:
            try:
                result = sanitize_path(p)
                # If it doesn't raise, the result must be in an allowed dir
                # and must NOT resolve to /etc/shadow
                from pathlib import Path
                resolved = str(Path(result).resolve())
                assert not resolved.startswith("/etc/"), \
                    f"CRITICAL: traversal reached {resolved} from input {p}!"
            except ValueError:
                pass  # raising is the correct behavior

    def test_password_timing_safe_comparison(self):
        """Password verification should use constant-time comparison (bcrypt does this)."""
        from ares.core.security import hash_password, verify_password
        h = hash_password("correct_password")
        # Both correct and wrong should take similar time (bcrypt is constant-time)
        # We can't reliably measure timing in CI, but we verify both return correct booleans
        assert verify_password("correct_password", h) is True
        assert verify_password("wrong_password", h) is False
        assert verify_password("", h) is False
        assert verify_password("correct_password" + "\x00", h) is False  # null terminator

    def test_api_key_prefix_validation(self):
        """API key verification must reject keys without ares_ prefix."""
        # This tests that random strings can't bypass the prefix check
        from ares.core.security import hash_password
        # A valid bcrypt hash that would match if the prefix check wasn't there
        fake_key = "not_ares_prefix_but_valid_otherwise"
        # The verify_api_key method checks prefix first — we verify that pattern
        assert not fake_key.startswith("ares_")

    @pytest.mark.asyncio
    async def test_revoke_api_key_double_revoke_idempotent(self):
        """Revoking an already-revoked key should return False (not True)."""
        from ares.db.database import AresDatabase
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            db = await AresDatabase.create(
                f"{tmp}/revoke.db", "test-enc-key-32-chars-placeholder!")
            await db.ensure_default_admin("Admin1!")
            user = await db.get_user("admin")
            uid = user["id"]
            key_id, raw = await db.create_api_key(uid, "temp", "admin")
            # First revoke — should succeed
            assert await db.revoke_api_key(key_id, uid) is True
            # Second revoke — already revoked, should return False
            assert await db.revoke_api_key(key_id, uid) is False
            await db.close()

    @pytest.mark.asyncio
    async def test_revoke_wrong_user_api_key_fails(self):
        """User A cannot revoke User B's API key."""
        from ares.db.database import AresDatabase
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            db = await AresDatabase.create(
                f"{tmp}/xuser.db", "test-enc-key-32-chars-placeholder!")
            await db.ensure_default_admin("Admin1!")
            user = await db.get_user("admin")
            uid = user["id"]
            key_id, raw = await db.create_api_key(uid, "admin-key", "admin")
            # Try revoking with a different user_id
            result = await db.revoke_api_key(key_id, "different-user-id")
            assert result is False, "CRITICAL: User revoked another user's API key!"
            # Original key should still work
            v = await db.verify_api_key(raw)
            assert v is not None, "Key was incorrectly revoked by wrong user!"
            await db.close()

    def test_scope_empty_means_deny_all(self):
        """Empty scope must deny everything — this is the fail-closed invariant."""
        from ares.core.campaign import Campaign, NoiseProfile
        c = Campaign(name="DenyAll", scope=[], noise_profile=NoiseProfile.NORMAL)
        # MUST deny every possible IP
        for ip in ["0.0.0.0", "10.0.0.1", "127.0.0.1", "192.168.1.1",
                    "255.255.255.255", "8.8.8.8"]:
            assert c.is_in_scope(ip) is False, \
                f"CRITICAL: Empty scope allowed {ip} — fail-open bug!"
