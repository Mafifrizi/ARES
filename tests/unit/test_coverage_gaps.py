"""
Unit tests covering previously untested modules:
  - credential/vault.py
  - fingerprint/engine.py
  - knowledge/base.py
  - telemetry/collector.py

Written against the actual source APIs — verified before writing.
"""
from __future__ import annotations
import pytest
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# credential/vault.py
# ─────────────────────────────────────────────────────────────────────────────

class TestCredentialVault:
    """
    API verified:
        CredentialVault(encryption_key)  — None = ephemeral auto key
        vault.store(cred, secret)        — raises ValueError on empty secret
        vault.add(cred, secret)          — alias for store()
        vault.all()                      — list of all Credential objects
        vault.domain_admins()            — DOMAIN_ADMIN + ENTERPRISE_ADMIN creds
        vault.by_privilege(level)        — filter by PrivilegeLevel
        vault.reveal(cred_id)            — decrypt → plaintext
    """

    @pytest.fixture
    def vault(self):
        from ares.credential.vault import CredentialVault
        return CredentialVault(encryption_key=None)

    @pytest.fixture
    def cleartext_cred(self):
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        return Credential(
            username="administrator", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            privilege=PrivilegeLevel.DOMAIN_ADMIN,
            source_module="ad.dcsync",
        )

    @pytest.fixture
    def service_cred(self):
        from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
        return Credential(
            username="svc_sql", domain="CORP",
            cred_type=CredentialType.NTLM,
            privilege=PrivilegeLevel.SERVICE_ACCOUNT,
            source_module="ad.dcsync",
        )

    def test_init_with_none_key(self, vault):
        assert vault is not None
        assert vault.all() == []

    def test_init_with_string_key(self):
        from ares.credential.vault import CredentialVault
        v = CredentialVault(encryption_key="test-key-for-vault")
        assert v is not None

    def test_store_and_retrieve(self, vault, cleartext_cred):
        cred_id = vault.store(cleartext_cred, "Password123!")
        assert cred_id
        all_creds = vault.all()
        assert len(all_creds) == 1
        assert all_creds[0].username == "administrator"

    def test_add_is_alias_for_store(self, vault, service_cred):
        cred_id = vault.add(service_cred, "aad3b435:31d6cfe0d16ae931")
        assert cred_id
        assert len(vault.all()) == 1

    def test_empty_secret_raises(self, vault, cleartext_cred):
        with pytest.raises(ValueError):
            vault.store(cleartext_cred, "")

    def test_reveal_returns_plaintext(self, vault, cleartext_cred):
        secret = "SuperSecret99!"
        cred_id = vault.store(cleartext_cred, secret)
        assert vault.reveal(cred_id) == secret

    def test_domain_admins_filter(self, vault, cleartext_cred, service_cred):
        vault.store(cleartext_cred, "AdminPass1!")
        vault.store(service_cred,   "hash:hash")
        admins = vault.domain_admins()
        assert any(c.username == "administrator" for c in admins)
        assert not any(c.username == "svc_sql" for c in admins)

    def test_by_privilege_filter(self, vault, cleartext_cred, service_cred):
        from ares.credential.vault import PrivilegeLevel
        vault.store(cleartext_cred, "AdminPass1!")
        vault.store(service_cred,   "hash:hash")
        svc = vault.by_privilege(PrivilegeLevel.SERVICE_ACCOUNT)
        assert any(c.username == "svc_sql" for c in svc)

    def test_deduplication(self, vault, cleartext_cred):
        vault.store(cleartext_cred, "Pass1!")
        vault.store(cleartext_cred, "Pass2!")   # same domain+username+type
        assert len(vault.all()) == 1

    def test_empty_vault_domain_admins(self, vault):
        assert vault.domain_admins() == []


# ─────────────────────────────────────────────────────────────────────────────
# fingerprint/engine.py
# ─────────────────────────────────────────────────────────────────────────────

class TestFingerprintEngine:
    """
    API verified:
        class EnvironmentFingerprinter  (NOT HostFingerprinter)
        FingerprintResult fields: host, os_type, os_version, open_ports — NO 'confidence'
        OSType.WINDOWS = "windows_10", OSType.LINUX = "linux_ubuntu" (convenience aliases)
        to_dict() → flat dict with 'host', 'os_type', 'open_ports'
    """

    def test_result_creates_with_host(self):
        from ares.fingerprint.engine import FingerprintResult
        r = FingerprintResult(host="10.0.0.1")
        assert r.host == "10.0.0.1"
        assert r.ip_address == "10.0.0.1"   # auto-synced in __post_init__

    def test_result_os_type_default_unknown(self):
        from ares.fingerprint.engine import FingerprintResult, OSType
        r = FingerprintResult(host="10.0.0.1")
        assert r.os_type == OSType.UNKNOWN

    def test_result_with_windows_os(self):
        from ares.fingerprint.engine import FingerprintResult, OSType
        r = FingerprintResult(host="10.0.0.1", os_type=OSType.WINDOWS_10,
                              os_version="Windows 10 Pro")
        assert r.os_type == OSType.WINDOWS_10
        assert r.os_version == "Windows 10 Pro"

    def test_result_with_open_ports(self):
        from ares.fingerprint.engine import FingerprintResult
        r = FingerprintResult(host="10.0.0.1", open_ports=[445, 139, 3389])
        assert 445 in r.open_ports
        assert 3389 in r.open_ports

    def test_result_to_dict_keys(self):
        from ares.fingerprint.engine import FingerprintResult
        r = FingerprintResult(host="10.0.0.1", open_ports=[22, 80])
        d = r.to_dict()
        assert "host"       in d
        assert "os_type"    in d
        assert "open_ports" in d
        assert d["host"] == "10.0.0.1"

    def test_os_type_windows_alias(self):
        from ares.fingerprint.engine import OSType
        assert OSType.WINDOWS.value == "windows_10"

    def test_os_type_linux_alias(self):
        from ares.fingerprint.engine import OSType
        assert OSType.LINUX.value == "linux_ubuntu"

    def test_edr_vendor_enum_has_entries(self):
        from ares.fingerprint.engine import EDRVendor
        vendors = list(EDRVendor)
        assert len(vendors) >= 3

    def test_fingerprinter_instantiates(self):
        from ares.fingerprint.engine import EnvironmentFingerprinter
        fp = EnvironmentFingerprinter()
        assert fp is not None
        assert hasattr(fp, "fingerprint")

    def test_fingerprinter_fingerprint_is_coroutine(self):
        import asyncio
        from ares.fingerprint.engine import EnvironmentFingerprinter
        assert asyncio.iscoroutinefunction(EnvironmentFingerprinter().fingerprint)

    def test_result_is_dc_flag(self):
        from ares.fingerprint.engine import FingerprintResult, DomainRole
        r = FingerprintResult(host="10.0.0.1", is_dc=True,
                              domain_role=DomainRole.DOMAIN_CONTROLLER)
        assert r.is_dc is True
        assert r.domain_role == DomainRole.DOMAIN_CONTROLLER


# ─────────────────────────────────────────────────────────────────────────────
# knowledge/base.py
# ─────────────────────────────────────────────────────────────────────────────

class TestKnowledgeBase:
    """
    API verified:
        suggest(host_state: dict)  — takes a DICT, not OperatorSession
        success_rate(module_id)    — 0.5 neutral prior when no history
        record_outcome(id, bool)
        all_entries()
        get(entry_id)

    OutcomeTracker persists to ~/.ares/kb_outcomes.json.
    Tests use a tmp_path-isolated tracker to avoid cross-test contamination.
    """

    @pytest.fixture
    def kb(self, tmp_path: Path):
        """Fresh KB with isolated OutcomeTracker — never reads ~/.ares/kb_outcomes.json."""
        from ares.knowledge.base import AttackKnowledgeBase, OutcomeTracker
        kb = AttackKnowledgeBase()
        # Override tracker to use tmp_path so disk state doesn't leak across tests
        kb._tracker = OutcomeTracker(path=tmp_path / "kb_outcomes.json")
        return kb

    def test_init_has_entries(self, kb):
        assert len(kb._entries) >= 3

    def test_all_entries_returns_list(self, kb):
        entries = kb.all_entries()
        assert isinstance(entries, list)
        assert len(entries) >= 3

    def test_entries_have_required_fields(self, kb):
        for e in kb.all_entries():
            assert e.entry_id or e.module_id
            assert e.description or e.title

    def test_success_rate_neutral_without_history(self, kb):
        # Fresh tmp_path tracker — no prior data
        rate = kb.success_rate("ad.kerberoast")
        assert rate == 0.5

    def test_record_outcome_success_increases_rate(self, kb):
        for _ in range(5):
            kb.record_outcome("ad.kerberoast", success=True)
        assert kb.success_rate("ad.kerberoast") > 0.5

    def test_record_outcome_failure_decreases_rate(self, kb):
        for _ in range(5):
            kb.record_outcome("ad.dcsync", success=False)
        assert kb.success_rate("ad.dcsync") < 0.5

    def test_success_rate_bounded_0_to_1(self, kb):
        for _ in range(100):
            kb.record_outcome("test.module", success=True)
        rate = kb.success_rate("test.module")
        assert 0.0 <= rate <= 1.0

    def test_suggest_takes_dict(self, kb):
        result = kb.suggest({})
        assert isinstance(result, list)

    def test_suggest_with_domain_condition(self, kb):
        result = kb.suggest({"domain_joined": True, "has_domain_creds": True})
        assert isinstance(result, list)

    def test_suggest_empty_state_no_auth_required_entries(self, kb):
        result = kb.suggest({})
        for e in result:
            if e.requires_auth:
                pytest.fail(f"Entry {e.entry_id} requires auth but conditions not in state")

    def test_get_known_entry(self, kb):
        entry = kb.get("kb-001")
        assert entry is not None
        assert entry.entry_id == "kb-001"

    def test_get_nonexistent_returns_none(self, kb):
        assert kb.get("nonexistent-xyz") is None


# ─────────────────────────────────────────────────────────────────────────────
# telemetry/collector.py
# ─────────────────────────────────────────────────────────────────────────────

class TestTelemetryCollector:
    """
    API verified:
        record_execution(module_id, duration_ms, success, ...)
        record_finding(count=1)      — NO severity kwarg
        record_credential(count=1)   — NO cred_type kwarg
        record_host_discovered/owned(count=1)
        snapshot(campaign_id="")     → TelemetrySnapshot
        snapshot().to_dict()         → {'modules': ..., 'findings': ..., ...}
        snapshot().to_prometheus()   → Prometheus text string
        worker_health()              → list[dict]
        get_collector()              → global singleton
    """

    @pytest.fixture
    def collector(self):
        from ares.telemetry.collector import TelemetryCollector
        return TelemetryCollector()   # fresh instance per test

    def test_init_empty(self, collector):
        snap = collector.snapshot()
        assert snap.total_modules_run == 0
        assert snap.findings_total == 0

    def test_record_execution_success(self, collector):
        collector.record_execution(module_id="ad.kerberoast",
                                   duration_ms=150.0, success=True)
        snap = collector.snapshot()
        assert snap.total_modules_run == 1
        assert snap.successful_modules == 1
        assert snap.failed_modules == 0

    def test_record_execution_failure(self, collector):
        collector.record_execution(module_id="ad.dcsync",
                                   duration_ms=50.0, success=False)
        snap = collector.snapshot()
        assert snap.failed_modules == 1
        assert snap.successful_modules == 0

    def test_record_finding_increments(self, collector):
        collector.record_finding(count=3)
        assert collector.snapshot().findings_total == 3

    def test_record_finding_default_count_one(self, collector):
        collector.record_finding()
        assert collector.snapshot().findings_total == 1

    def test_record_credential_increments(self, collector):
        collector.record_credential(count=2)
        assert collector.snapshot().credentials_found == 2

    def test_record_host_discovered(self, collector):
        collector.record_host_discovered(count=5)
        assert collector.snapshot().hosts_discovered == 5

    def test_record_host_owned(self, collector):
        collector.record_host_owned(count=2)
        assert collector.snapshot().hosts_owned == 2

    def test_snapshot_to_dict_structure(self, collector):
        d = collector.snapshot().to_dict()
        assert "modules"    in d
        assert "findings"   in d
        assert "hosts"      in d
        assert "workers"    in d
        assert "latency_ms" in d

    def test_snapshot_to_prometheus(self, collector):
        collector.record_execution("ad.kerberoast", 100.0, True)
        prom = collector.snapshot().to_prometheus()
        assert isinstance(prom, str)
        assert "ares_modules_total" in prom
        assert "ares_findings_total" in prom

    def test_worker_health_returns_list(self, collector):
        assert isinstance(collector.worker_health(), list)

    def test_singleton_is_same_instance(self):
        from ares.telemetry.collector import get_collector
        assert get_collector() is get_collector()


# ─────────────────────────────────────────────────────────────────────────────
# goal/engine.py CapabilityGraph — circular dependency handling
# ─────────────────────────────────────────────────────────────────────────────

class TestCapabilityGraphEdgeCases:
    """
    Tests for CapabilityGraph.resolve_chain() edge cases:
    circular dependencies, empty registries, and ordering.
    """

    def _make_registry(self, modules: dict):
        """
        Build a mock registry with modules dict:
        { module_id: (requires, outputs) }
        """
        from unittest.mock import MagicMock

        class FakeModule:
            pass

        classes = []
        for mid, (reqs, outs) in modules.items():
            cls = type(f"Mod_{mid.replace('.','_')}", (), {
                "MODULE_ID": mid,
                "REQUIRES":  reqs,
                "OUTPUTS":   outs,
            })
            classes.append(cls)

        reg = MagicMock()
        reg.all.return_value = classes
        return reg

    def test_simple_linear_chain_ordered(self):
        """A → B → C should resolve in dependency order: A, B, C."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry({
            "mod.a": ([], ["cap_x"]),
            "mod.b": (["cap_x"], ["cap_y"]),
            "mod.c": (["cap_y"], ["cap_z"]),
        })
        cg    = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain(["cap_z"])
        assert "mod.a" in chain
        assert "mod.b" in chain
        assert "mod.c" in chain
        # Order: a before b before c
        assert chain.index("mod.a") < chain.index("mod.b")
        assert chain.index("mod.b") < chain.index("mod.c")

    def test_circular_dependency_does_not_loop(self):
        """
        Circular deps (A requires cap_b, B requires cap_a)
        should NOT loop infinitely — visited set prevents it.
        """
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry({
            "mod.a": (["cap_b"], ["cap_a"]),  # A requires what B produces
            "mod.b": (["cap_a"], ["cap_b"]),  # B requires what A produces
        })
        cg = CapabilityGraph.from_registry(reg)
        # Should not hang or raise
        chain = cg.resolve_chain(["cap_a"], max_depth=8)
        assert isinstance(chain, list)   # completed without recursion error
        # Both may or may not be in chain, but no crash
        assert len(chain) <= 2

    def test_diamond_dependency_no_duplicates(self):
        """
        A produces cap_x, B and C both require cap_x, D requires cap_y + cap_z.
        B produces cap_y, C produces cap_z, D requires both.
        A should appear only once in chain.
        """
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry({
            "mod.a": ([], ["cap_x"]),
            "mod.b": (["cap_x"], ["cap_y"]),
            "mod.c": (["cap_x"], ["cap_z"]),
            "mod.d": (["cap_y", "cap_z"], ["cap_final"]),
        })
        cg    = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain(["cap_final"])
        assert chain.count("mod.a") == 1, "mod.a should appear exactly once (no duplicates)"
        assert "mod.d" in chain
        assert chain.index("mod.a") < chain.index("mod.b")
        assert chain.index("mod.a") < chain.index("mod.c")

    def test_unavailable_modules_excluded(self):
        """When available_modules filter set, exclude modules not in the set."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry({
            "mod.a": ([], ["cap_x"]),
            "mod.b": (["cap_x"], ["cap_y"]),
        })
        cg = CapabilityGraph.from_registry(reg)
        # Only mod.a is available
        chain = cg.resolve_chain(["cap_y"], available_modules=["mod.a"])
        assert "mod.b" not in chain   # filtered out — not in available_modules
        assert chain == []             # no available module produces cap_y

    def test_empty_registry_returns_empty_chain(self):
        """Empty registry → empty chain."""
        from ares.goal.engine import CapabilityGraph
        from unittest.mock import MagicMock
        reg = MagicMock()
        reg.all.return_value = []
        cg = CapabilityGraph.from_registry(reg)
        chain = cg.resolve_chain(["domain_admin_creds"])
        assert chain == []

    def test_capability_summary_correct(self):
        """capability_summary() returns all capabilities and producers."""
        from ares.goal.engine import CapabilityGraph
        reg = self._make_registry({
            "mod.a": ([], ["cap_x", "cap_y"]),
            "mod.b": (["cap_x"], ["cap_z"]),
        })
        cg      = CapabilityGraph.from_registry(reg)
        summary = cg.capability_summary()
        assert summary["total_capabilities"] == 3   # cap_x, cap_y, cap_z
        assert summary["total_modules"]      == 2
        assert "cap_x" in summary["capabilities"]
        assert "mod.a" in summary["capabilities"]["cap_x"]
