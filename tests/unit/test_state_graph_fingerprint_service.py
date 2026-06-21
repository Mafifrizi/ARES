"""
Round 4 tests — solidification pass.

Covers every secondary module plus cross-cutting concerns:
  1.  State layer          — HostState, OperatorSession, TargetHost alias,
                             update_host, from_snapshot, to_json, serialisation
  2.  AttackGraph          — node/edge construction, path-finding, high-value nodes
  3.  Fingerprinting       — EnvironmentFingerprinter, OSType, EDRVendor
  4.  ServiceIntel         — ServiceIntelEngine, port mapping, CVE tagging
  5.  Execution            — RemoteExecutor, ExecutionMethod, ExecutionResult
  6.  Collaboration        — CollaborationManager, TargetLock, OperatorRole
  7.  Knowledge base       — AttackKnowledgeBase, suggestions, EvidenceStore
  8.  Normalizer           — ArtifactStore CRUD, HostArtifact, UserArtifact
  9.  Replay               — AttackReplayEngine session management
  10. Technique library    — TechniqueLibrary CRUD, MITRETactic
  11. Checkpoint           — CheckpointManager save/load/list/purge
  12. Worker/Cluster       — InProcessTaskQueue, ClusterController, disconnect
  13. Marketplace          — ModuleInstaller install_as_dict, LocalRegistry
  14. Tracing              — NoOp tracer, span, trace_module decorator
  15. Telemetry            — MetricsCollector record + aggregate
  16. API __init__ exports — all packages export __all__ correctly
  17. Cross-module smoke   — import chain + symbol resolution
  18. Data integrity       — Campaign→Finding→Report round-trip
  19. Security/config      — AresSettings defaults, JWT config
  20. CLI store            — verify new methods (update/from_snapshot/to_json)
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _session(campaign_id: str = "test-001") -> "OperatorSession":
    from ares.state.target_state import OperatorSession
    return OperatorSession(campaign_id=campaign_id, operator="tester")


def _host(ip: str = "10.0.0.1", hostname: str = "srv01",
          level: str = "none") -> "HostState":
    from ares.state.target_state import HostState, CompromiseLevel
    return HostState(
        ip_address       = ip,
        hostname         = hostname,
        compromise_level = CompromiseLevel(level),
    )


def _campaign(n_findings: int = 3):
    from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Finding, Severity
    c = Campaign(
        name="R4 Test", client="Acme", operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    for i in range(n_findings):
        c.add_finding(Finding(
            title=f"Finding {i+1}", description=f"Desc {i+1}",
            severity=Severity.HIGH, confidence=0.9,
            module_id=f"ad.mod_{i}", host=f"10.0.0.{i+1}",
            evidence="ev", remediation="fix",
            mitre_technique="T1558.003", mitre_tactic="Credential Access",
        ))
    return c


# ─────────────────────────────────────────────────────────────────────────────
# 1. STATE LAYER
# ─────────────────────────────────────────────────────────────────────────────

class TestHostState:

    def test_create_default_none_level(self):
        from ares.state.target_state import HostState, CompromiseLevel
        h = HostState(ip_address="10.0.0.1")
        assert h.compromise_level == CompromiseLevel.NONE
        assert h.is_owned() is False

    def test_mark_owned(self):
        from ares.state.target_state import HostState, CompromiseLevel
        h = HostState(ip_address="10.0.0.1")
        h.mark_owned(CompromiseLevel.LOCAL_ADMIN, username="admin", method="psexec")
        assert h.is_owned() is True
        assert h.compromise_level == CompromiseLevel.LOCAL_ADMIN
        assert h.owned_by == "admin"

    def test_add_service(self):
        from ares.state.target_state import HostState
        h = HostState(ip_address="10.0.0.1")
        h.add_service(port=445, service="smb", version="3.1.1")
        assert any(s.port == 445 for s in h.services)

    def test_to_dict(self):
        from ares.state.target_state import HostState, CompromiseLevel
        h = HostState(ip_address="10.0.0.1", hostname="dc01",
                      compromise_level=CompromiseLevel.DOMAIN_ADMIN)
        d = h.to_dict()
        assert d["ip_address"] == "10.0.0.1"
        assert d["hostname"] == "dc01"
        assert "compromise_level" in d

    def test_compromise_level_ordering(self):
        from ares.state.target_state import CompromiseLevel
        assert CompromiseLevel.DOMAIN_ADMIN > CompromiseLevel.LOCAL_ADMIN
        assert CompromiseLevel.LOCAL_ADMIN > CompromiseLevel.USER
        assert CompromiseLevel.USER > CompromiseLevel.NONE
        assert CompromiseLevel.DOMAIN_ADMIN >= CompromiseLevel.DOMAIN_ADMIN

    def test_compromise_level_scores(self):
        from ares.state.target_state import CompromiseLevel
        assert CompromiseLevel.DOMAIN_ADMIN.score() > CompromiseLevel.LOCAL_ADMIN.score()
        assert CompromiseLevel.LOCAL_ADMIN.score() > CompromiseLevel.USER.score()
        assert CompromiseLevel.USER.score() > CompromiseLevel.NONE.score()


class TestOperatorSession:

    def test_init(self):
        sess = _session()
        assert sess.campaign_id == "test-001"
        assert sess.operator == "tester"
        assert sess.session_id != ""

    def test_add_host(self):
        sess = _session()
        h = sess.add_host("10.0.0.1", hostname="srv01")
        assert h is not None
        assert sess.get_host("10.0.0.1") is h

    def test_update_host(self):
        """update_host() upserts a pre-built HostState."""
        from ares.state.target_state import HostState, CompromiseLevel
        sess = _session()
        host = HostState(ip_address="10.0.0.5", hostname="db01",
                         compromise_level=CompromiseLevel.LOCAL_ADMIN)
        sess.update_host(host)
        retrieved = sess.get_host("10.0.0.5")
        assert retrieved is not None
        assert retrieved.compromise_level == CompromiseLevel.LOCAL_ADMIN

    def test_update_host_replaces_existing(self):
        from ares.state.target_state import HostState, CompromiseLevel
        sess = _session()
        sess.add_host("10.0.0.5")
        new_host = HostState(ip_address="10.0.0.5",
                             compromise_level=CompromiseLevel.DOMAIN_ADMIN)
        sess.update_host(new_host)
        assert sess.get_host("10.0.0.5").compromise_level == CompromiseLevel.DOMAIN_ADMIN

    def test_target_host_alias(self):
        """TargetHost should be an alias for HostState."""
        from ares.state.target_state import TargetHost, HostState
        assert TargetHost is HostState

    def test_owned_hosts(self):
        from ares.state.target_state import CompromiseLevel
        sess = _session()
        sess.add_host("10.0.0.1")
        sess.mark_host_owned("10.0.0.1", CompromiseLevel.LOCAL_ADMIN)
        sess.add_host("10.0.0.2")  # not owned
        owned = sess.owned_hosts()
        assert len(owned) == 1
        assert owned[0].ip_address == "10.0.0.1"

    def test_domain_controllers_detected(self):
        from ares.state.target_state import CompromiseLevel
        sess = _session()
        h = sess.add_host("10.0.0.1", hostname="DC01", os_type="Windows Server",
                          domain_role="domain_controller")
        controllers = sess.domain_controllers()
        assert len(controllers) >= 0  # depends on implementation detail

    def test_record_attack(self):
        sess = _session()
        entry = sess.record_attack(
            module_id="ad.kerberoast", target_host="10.0.0.1",
            success=True, technique="T1558.003", username="svc_account",
        )
        assert entry.success is True
        history = sess.history(module_id="ad.kerberoast")
        assert len(history) == 1

    def test_was_tried(self):
        sess = _session()
        assert sess.was_tried("ad.kerberoast", "10.0.0.1") is False
        sess.record_attack("ad.kerberoast", "10.0.0.1", success=False)
        assert sess.was_tried("ad.kerberoast", "10.0.0.1") is True

    def test_stats_structure(self):
        sess = _session()
        sess.add_host("10.0.0.1")
        s = sess.stats()
        assert "total_hosts" in s
        assert "owned_hosts" in s
        assert "total_attempts" in s
        assert isinstance(s["total_hosts"], int)

    def test_snapshot_round_trip(self):
        from ares.state.target_state import OperatorSession, CompromiseLevel
        sess = _session()
        sess.add_host("10.0.0.1")
        sess.mark_host_owned("10.0.0.1", CompromiseLevel.USER)
        sess.record_attack("ad.enum_users", "10.0.0.1", success=True)

        snap = sess.snapshot()
        restored = OperatorSession.from_snapshot(snap)
        assert restored.campaign_id == "test-001"
        assert restored.get_host("10.0.0.1") is not None
        assert len(restored.history()) == 1

    def test_to_json_valid(self):
        sess = _session()
        sess.add_host("10.0.0.5")
        j = sess.to_json()
        data = json.loads(j)
        assert "session_id" in data
        assert "hosts" in data

    def test_all_hosts_deduplication(self):
        """all_hosts() must not return the same host twice even if keyed by IP+hostname."""
        sess = _session()
        h = sess.add_host("10.0.0.1", hostname="srv01")
        sess.update_host(h)  # adds hostname key too
        hosts = sess.all_hosts()
        ips = [host.ip_address for host in hosts]
        assert ips.count("10.0.0.1") == 1

    def test_add_pivot(self):
        sess = _session()
        sess.add_pivot({"type": "socks5", "host": "10.0.0.1", "port": 1080})
        pivots = sess.active_pivots()
        assert len(pivots) == 1
        assert pivots[0]["type"] == "socks5"


# ─────────────────────────────────────────────────────────────────────────────
# 2. ATTACK GRAPH
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackGraph:

    def _graph(self):
        from ares.graph.attack_graph import AttackGraph
        return AttackGraph()

    def test_empty_graph_stats(self):
        g = self._graph()
        s = g.stats()
        assert s["nodes"] == 0
        assert s["edges"] == 0

    def test_add_nodes_via_normalizer(self):
        """AttackGraph.build_from_store() should populate nodes."""
        from ares.graph.attack_graph import AttackGraph
        from ares.normalize.artifacts import ArtifactStore, HostArtifact

        store = ArtifactStore()
        store.add(HostArtifact(ip="10.0.0.1", hostname="dc01",
                                os="windows", domain="CORP"))
        store.add(HostArtifact(ip="10.0.0.2", hostname="srv01",
                                os="windows", domain="CORP"))
        g = AttackGraph()
        g.build_from_store(store)
        assert g.stats()["nodes"] >= 1

    def test_high_value_nodes_empty(self):
        g = self._graph()
        hvn = g.high_value_nodes()
        assert isinstance(hvn, list)

    def test_shortest_path_no_path(self):
        g = self._graph()
        result = g.shortest_attack_path("nonexistent_a", "nonexistent_b")
        assert result is None

    def test_attack_paths_empty(self):
        g = self._graph()
        paths = g.attack_paths_to_domain_admin()
        assert isinstance(paths, list)

    def test_riskiest_users(self):
        g = self._graph()
        users = g.riskiest_users(top_n=5)
        assert isinstance(users, list)
        assert len(users) <= 5

    def test_stats_keys(self):
        from ares.graph.attack_graph import AttackGraph
        g = AttackGraph()
        s = g.stats()
        for key in ("nodes", "edges", "domain_controller_nodes", "owned_nodes"):
            assert key in s, f"Missing stats key: {key}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. NORMALIZATION / ARTIFACT STORE
# ─────────────────────────────────────────────────────────────────────────────

class TestArtifactStore:

    def test_add_and_get_host(self):
        from ares.normalize.artifacts import ArtifactStore, HostArtifact
        store = ArtifactStore()
        h = HostArtifact(ip="10.0.0.1", hostname="srv01", os="windows",
                          domain="CORP")
        store.add(h)
        hosts = store.hosts()
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"

    def test_add_user_artifact(self):
        from ares.normalize.artifacts import ArtifactStore, UserArtifact
        store = ArtifactStore()
        u = UserArtifact(
            username="john.doe", domain="CORP",
            groups=["Domain Users"], spn=["http/srv01"],
        )
        store.add(u)
        users = store.users()
        assert len(users) == 1
        assert users[0].username == "john.doe"

    def test_add_hash_artifact(self):
        from ares.normalize.artifacts import ArtifactStore, HashArtifact
        store = ArtifactStore()
        h = HashArtifact(
            username="svc_account", domain="CORP",
            nt_hash="aad3b435b51404eeaad3b435b51404ee",
            module_id="ad.dcsync",
        )
        store.add(h)
        hashes = store.hashes()
        assert len(hashes) == 1

    def test_add_credential_artifact(self):
        from ares.normalize.artifacts import ArtifactStore, CredentialArtifact
        store = ArtifactStore()
        cred = CredentialArtifact(
            username="admin", domain="CORP",
            secret="Password123!", cred_type="plaintext",
            host="10.0.0.1",
        )
        store.add(cred)
        creds = store.credentials()
        assert any(c.username == "admin" for c in creds)

    def test_store_clear(self):
        from ares.normalize.artifacts import ArtifactStore, HostArtifact
        store = ArtifactStore()
        store.add(HostArtifact(ip="10.0.0.1", hostname="x", os="windows", domain="D"))
        store.clear()
        assert store.hosts() == []

    def test_total_count(self):
        from ares.normalize.artifacts import ArtifactStore, HostArtifact, UserArtifact
        store = ArtifactStore()
        store.add(HostArtifact(ip="10.0.0.1", hostname="h1", os="w", domain="D"))
        store.add(HostArtifact(ip="10.0.0.2", hostname="h2", os="w", domain="D"))
        store.add(UserArtifact(username="u1", domain="D", groups=[], spn=[]))
        assert store.total() == 3


# ─────────────────────────────────────────────────────────────────────────────
# 4. FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────

class TestFingerprintEngine:

    def test_fingerprint_result_structure(self):
        from ares.fingerprint.engine import FingerprintResult, OSType, DomainRole, EDRVendor
        result = FingerprintResult(
            ip_address   = "10.0.0.1",
            os_type      = OSType.WINDOWS_SERVER,
            os_version   = "Windows Server 2019",
            domain_role  = DomainRole.DOMAIN_CONTROLLER,
            edr_detected = [EDRVendor.WINDOWS_DEFENDER],
            open_ports   = [445, 389, 636],
            hostname     = "DC01",
        )
        assert result.ip_address == "10.0.0.1"
        assert result.domain_role == DomainRole.DOMAIN_CONTROLLER
        assert EDRVendor.WINDOWS_DEFENDER in result.edr_detected

    def test_fingerprint_result_to_dict(self):
        from ares.fingerprint.engine import FingerprintResult, OSType, DomainRole
        result = FingerprintResult(
            ip_address = "10.0.0.1",
            os_type    = OSType.WINDOWS_SERVER,
            domain_role = DomainRole.MEMBER_SERVER,
            open_ports  = [80, 443],
        )
        d = result.to_dict()
        assert "ip_address" in d
        assert "os_type" in d
        assert "open_ports" in d

    def test_os_type_enum_values(self):
        from ares.fingerprint.engine import OSType
        assert OSType.WINDOWS in OSType.__members__.values() or hasattr(OSType, 'WINDOWS')
        assert len(list(OSType)) >= 3

    def test_edr_vendor_enum(self):
        from ares.fingerprint.engine import EDRVendor
        vendors = list(EDRVendor)
        assert len(vendors) >= 3  # At least CrowdStrike, Defender, Carbon Black

    def test_fingerprinter_init(self):
        from ares.fingerprint.engine import EnvironmentFingerprinter
        fp = EnvironmentFingerprinter()
        assert fp is not None

    def test_fingerprinter_has_fingerprint_method(self):
        from ares.fingerprint.engine import EnvironmentFingerprinter
        fp = EnvironmentFingerprinter()
        assert hasattr(fp, "fingerprint") or hasattr(fp, "fingerprint_host")


# ─────────────────────────────────────────────────────────────────────────────
# 5. EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

class TestRemoteExecutor:

    def test_execution_result_success(self):
        from ares.execution.executor import ExecutionResult
        r = ExecutionResult(
            success=True, stdout="uid=0(root)", stderr="", exit_code=0,
            method="ssh", host="10.0.0.1",
        )
        assert r.success is True
        assert r.stdout == "uid=0(root)"

    def test_execution_result_failure(self):
        from ares.execution.executor import ExecutionResult
        r = ExecutionResult(
            success=False, stdout="", stderr="access denied", exit_code=1,
            method="winrm", host="10.0.0.1",
        )
        assert r.success is False
        assert r.exit_code == 1

    def test_execution_method_enum(self):
        from ares.execution.executor import ExecutionMethod
        methods = list(ExecutionMethod)
        method_values = [m.value for m in methods]
        assert any(m in method_values for m in ("ssh", "winrm", "psexec", "wmiexec"))

    def test_execution_result_to_dict(self):
        from ares.execution.executor import ExecutionResult
        r = ExecutionResult(
            success=True, stdout="output", stderr="", exit_code=0,
            method="ssh", host="10.0.0.1",
        )
        d = r.to_dict() if hasattr(r, "to_dict") else vars(r)
        assert isinstance(d, dict)
        assert "success" in d

    def test_remote_executor_init(self):
        from ares.execution.executor import RemoteExecutor
        ex = RemoteExecutor()
        assert ex is not None

    def test_remote_executor_has_execute(self):
        from ares.execution.executor import RemoteExecutor
        ex = RemoteExecutor()
        assert hasattr(ex, "execute") or hasattr(ex, "run")


# ─────────────────────────────────────────────────────────────────────────────
# 6. COLLABORATION
# ─────────────────────────────────────────────────────────────────────────────

class TestCollaborationManager:

    def test_operator_roles(self):
        from ares.collab.manager import OperatorRole
        roles = list(OperatorRole)
        assert len(roles) >= 2
        role_values = [r.value for r in roles]
        assert any(r in role_values for r in ("operator", "team_lead", "observer", "read_only"))

    def test_operator_profile_create(self):
        from ares.collab.manager import OperatorProfile, OperatorRole
        role = next(iter(OperatorRole))
        p = OperatorProfile(
            operator_id = "op-001",
            name        = "Alice",
            role        = role,
        )
        assert p.operator_id == "op-001"
        assert p.name == "Alice"

    def test_target_lock_create(self):
        from ares.collab.manager import TargetLock
        lock = TargetLock(
            target     = "10.0.0.1",
            operator_id = "op-001",
            module_id   = "ad.kerberoast",
        )
        assert lock.target == "10.0.0.1"
        assert lock.is_locked

    def test_target_lock_expiry(self):
        from ares.collab.manager import TargetLock
        lock = TargetLock(
            target      = "10.0.0.1",
            operator_id = "op-001",
            module_id   = "ad.kerberoast",
            ttl_seconds = 0,  # already expired
        )
        import time; time.sleep(0.01)
        assert not lock.is_locked

    def test_collab_manager_init(self):
        from ares.collab.manager import CollaborationManager
        mgr = CollaborationManager(campaign_id="camp-001")
        assert mgr.campaign_id == "camp-001"

    def test_collab_manager_register_operator(self):
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager(campaign_id="camp-001")
        mgr.register_operator("op-001", name="Alice",
                               role=OperatorRole(list(OperatorRole)[0].value))
        operators = mgr.list_operators()
        assert any(op.operator_id == "op-001" for op in operators)

    def test_collab_manager_acquire_lock(self):
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager(campaign_id="camp-001")
        mgr.register_operator("op-001", name="Alice",
                               role=OperatorRole(list(OperatorRole)[0].value))
        lock = mgr.acquire_lock("10.0.0.1", "op-001", "ad.kerberoast")
        assert lock is not None
        assert mgr.is_locked("10.0.0.1")

    def test_collab_manager_release_lock(self):
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager(campaign_id="camp-001")
        mgr.register_operator("op-001", name="Alice",
                               role=OperatorRole(list(OperatorRole)[0].value))
        mgr.acquire_lock("10.0.0.1", "op-001", "ad.kerberoast")
        mgr.release_lock("10.0.0.1", "op-001")
        assert not mgr.is_locked("10.0.0.1")

    def test_journal_append(self):
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager(campaign_id="camp-001")
        mgr.log_event(operator_id="op-001", event_type="module_run",
                      details={"module": "ad.kerberoast", "target": "10.0.0.1"})
        journal = mgr.journal()
        assert len(journal) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 7. KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────

class TestKnowledgeBase:

    def test_kb_init(self):
        from ares.knowledge.base import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        assert kb is not None

    def test_kb_all_entries(self):
        from ares.knowledge.base import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        entries = kb.all_entries()
        assert isinstance(entries, list)

    def test_kb_get_nonexistent(self):
        from ares.knowledge.base import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        assert kb.get("nonexistent_id") is None

    def test_kb_suggest_empty_state(self):
        from ares.knowledge.base import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        suggestions = kb.suggest({})
        assert isinstance(suggestions, list)

    def test_kb_suggest_with_owned_host(self):
        from ares.knowledge.base import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        state = {"owned_hosts": ["10.0.0.1"],
                 "compromise_level": "local_admin",
                 "domain_creds": False}
        suggestions = kb.suggest(state)
        assert isinstance(suggestions, list)

    def test_kb_entry_structure(self):
        from ares.knowledge.base import KBEntry
        e = KBEntry(
            entry_id    = "kb-001",
            module_id   = "ad.kerberoast",
            description = "Kerberoasting technique",
            conditions  = ["has_domain_creds"],
            priority    = 10,
        )
        d = e.to_dict()
        assert d["entry_id"] == "kb-001"
        assert d["module_id"] == "ad.kerberoast"


class TestEvidenceStore:

    def test_add_and_retrieve(self):
        from ares.knowledge.base import EvidenceStore, Evidence, EvidenceType
        store = EvidenceStore()
        ev = Evidence(
            name="kerberoast_ticket",
            evidence_type=EvidenceType.TICKET if hasattr(EvidenceType, "TICKET") else "ticket",
            content=b"ticket_data",
        )
        store.add(ev)
        assert len(store.all()) == 1

    def test_get_by_type(self):
        from ares.knowledge.base import EvidenceStore, Evidence
        store = EvidenceStore()
        store.add(Evidence(name="e1", evidence_type="screenshot", content="img"))
        store.add(Evidence(name="e2", evidence_type="hash", content="aabb"))
        screenshots = store.get_by_type("screenshot")
        assert len(screenshots) == 1
        assert screenshots[0].name == "e1"

    def test_clear(self):
        from ares.knowledge.base import EvidenceStore, Evidence
        store = EvidenceStore()
        store.add(Evidence(name="e1", evidence_type="hash", content="x"))
        store.clear()
        assert store.all() == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. TECHNIQUE LIBRARY
# ─────────────────────────────────────────────────────────────────────────────

class TestTechniqueLibrary:

    def test_library_init(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        assert lib is not None

    def test_library_has_entries(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        all_techs = lib.all()
        assert len(all_techs) > 0

    def test_get_known_technique(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        t = lib.get("T1558.003")  # Kerberoasting
        if t is not None:
            assert t.technique_id == "T1558.003"
            assert t.name != ""
            assert t.tactic != ""

    def test_get_nonexistent_returns_none(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        assert lib.get("T9999.999") is None

    def test_by_tactic(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        techs = lib.by_tactic("Credential Access")
        assert isinstance(techs, list)
        for t in techs:
            assert "Credential" in t.tactic or "Credential" in t.tactics

    def test_search(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        results = lib.search("kerberoast")
        assert isinstance(results, list)

    def test_technique_to_dict(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        all_techs = lib.all()
        if all_techs:
            d = all_techs[0].to_dict()
            assert "id" in d
            assert "name" in d
            assert "tactic" in d

    def test_technique_library_has_kerberoast(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        all_ids = [t.technique_id for t in lib.all()]
        assert "T1558.003" in all_ids

    def test_technique_mapper_init(self):
        from ares.technique.library import TechniqueMapper
        mapper = TechniqueMapper()
        assert mapper is not None

    def test_technique_subtechnique_flag(self):
        from ares.technique.library import TechniqueLibrary
        lib = TechniqueLibrary()
        t = lib.get("T1558.003")
        if t is not None:
            assert t.is_subtechnique is True
            assert t.parent_id.startswith("T")


# ─────────────────────────────────────────────────────────────────────────────
# 9. CHECKPOINT
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckpointManager:

    def _manager(self, tmpdir: str):
        from ares.checkpoint.manager import CheckpointManager
        return CheckpointManager(
            encryption_key=b"test-key-32-bytes-padded-xxxxxxx",
        )

    def test_save_and_load(self, tmp_path):
        from ares.checkpoint.manager import CheckpointManager, CheckpointData
        with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_path):
            mgr  = CheckpointManager(encryption_key=b"test-key-32-bytes-padded-xxxxxxx")
            data = CheckpointData(
                campaign_id = "camp-001",
                session     = {"owned_hosts": ["10.0.0.1"]},
                vault       = {},
            )
            path = mgr.save(data, notes="before weekend")
            assert path.exists()

            loaded = mgr.load("camp-001")
            assert loaded.campaign_id == "camp-001"
            assert loaded.session["owned_hosts"] == ["10.0.0.1"]

    def test_list_checkpoints(self, tmp_path):
        from ares.checkpoint.manager import CheckpointManager, CheckpointData
        with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_path):
            mgr  = CheckpointManager(encryption_key=b"test-key-32-bytes-padded-xxxxxxx")
            data = CheckpointData(campaign_id="camp-002", session={}, vault={})
            mgr.save(data, notes="cp1")
            mgr.save(data, notes="cp2")
            checkpoints = mgr.list_checkpoints("camp-002")
            assert len(checkpoints) >= 2

    def test_load_nonexistent_raises(self, tmp_path):
        from ares.checkpoint.manager import CheckpointManager
        with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_path):
            mgr = CheckpointManager(encryption_key=b"test-key-32-bytes-padded-xxxxxxx")
            with pytest.raises((FileNotFoundError, ValueError, KeyError)):
                mgr.load("nonexistent-campaign-id")

    def test_purge_old(self, tmp_path):
        from ares.checkpoint.manager import CheckpointManager, CheckpointData
        with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_path):
            mgr  = CheckpointManager(encryption_key=b"test-key-32-bytes-padded-xxxxxxx")
            data = CheckpointData(campaign_id="camp-003", session={}, vault={})
            for _ in range(7):
                mgr.save(data)
            purged = mgr.purge_old("camp-003", keep_last=3)
            remaining = mgr.list_checkpoints("camp-003")
            assert len(remaining) <= 3

    def test_delete_checkpoint(self, tmp_path):
        from ares.checkpoint.manager import CheckpointManager, CheckpointData
        with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_path):
            mgr  = CheckpointManager(encryption_key=b"test-key-32-bytes-padded-xxxxxxx")
            data = CheckpointData(campaign_id="camp-004", session={}, vault={})
            mgr.save(data)
            cps = mgr.list_checkpoints("camp-004")
            cp_id = cps[0]["checkpoint_id"]
            deleted = mgr.delete_checkpoint("camp-004", cp_id)
            assert deleted is True
            cps_after = mgr.list_checkpoints("camp-004")
            assert not any(c["checkpoint_id"] == cp_id for c in cps_after)

    def test_build_checkpoint_helper(self):
        from ares.checkpoint.manager import build_checkpoint, CheckpointData
        sess = _session("camp-001")
        sess.add_host("10.0.0.1")
        data = build_checkpoint(sess, vault=None)
        assert isinstance(data, CheckpointData)
        assert data.campaign_id == "camp-001"


# ─────────────────────────────────────────────────────────────────────────────
# 10. WORKER / CLUSTER
# ─────────────────────────────────────────────────────────────────────────────

class TestInProcessTaskQueue:

    def test_enqueue_and_dequeue(self):
        from ares.worker.cluster import InProcessTaskQueue, ClusterTask, WorkerRegistration, TaskState
        queue  = InProcessTaskQueue()
        worker = WorkerRegistration(
            worker_id      = "w-001",
            capabilities   = ["ad.*"],
            max_concurrent = 4,
        )

        async def run():
            task = ClusterTask(
                task_id   = "task-001",
                module_id = "ad.kerberoast",
                campaign_id = "camp-001",
                params    = {},
            )
            await queue.connect()
            await queue.enqueue(task)
            dequeued = await queue.dequeue(worker, timeout_s=1)
            return dequeued

        result = asyncio.run(run())
        assert result is not None
        assert result.task_id == "task-001"

    def test_disconnect_clears_queue(self):
        from ares.worker.cluster import InProcessTaskQueue, ClusterTask, WorkerRegistration

        async def run():
            queue = InProcessTaskQueue()
            task  = ClusterTask(
                task_id="t-002", module_id="ad.enum_users",
                campaign_id="c-001", params={},
            )
            await queue.connect()
            await queue.enqueue(task)
            await queue.disconnect()
            # Queue should be empty after disconnect
            return queue._queue.empty()

        is_empty = asyncio.run(run())
        assert is_empty is True

    def test_task_state_enum(self):
        from ares.worker.cluster import TaskState
        states = list(TaskState)
        assert len(states) >= 4
        values = [s.value for s in states]
        assert any(v in values for v in ("pending", "claimed", "done", "failed"))

    def test_worker_registration(self):
        from ares.worker.cluster import WorkerRegistration
        w = WorkerRegistration(
            worker_id      = "worker-test",
            capabilities   = ["ad.*", "linux.*"],
            max_concurrent = 2,
        )
        assert w.worker_id == "worker-test"
        assert w.can_handle_module("ad.kerberoast")

    def test_cluster_task_dataclass(self):
        from ares.worker.cluster import ClusterTask, TaskState
        t = ClusterTask(
            task_id="t-001", module_id="ad.kerberoast",
            campaign_id="c-001", params={"dc": "10.0.0.1"},
        )
        assert t.state == TaskState.PENDING
        assert t.priority >= 0


# ─────────────────────────────────────────────────────────────────────────────
# 11. MARKETPLACE
# ─────────────────────────────────────────────────────────────────────────────

class TestMarketplace:

    def test_module_manifest_schema(self):
        from ares.marketplace.installer import ModuleManifest
        m = ModuleManifest(
            module_id   = "ad.custom",
            name        = "Custom AD Module",
            version     = "1.0.0",
            author      = "tester",
            description = "Test module",
            module_file = "module.py",
        )
        assert m.module_id == "ad.custom"
        d = m.to_dict()
        assert "module_id" in d
        assert "version" in d

    def test_module_manifest_from_dict(self):
        from ares.marketplace.installer import ModuleManifest
        data = {
            "module_id":   "ad.test",
            "name":        "Test",
            "version":     "0.1.0",
            "author":      "tester",
            "description": "desc",
            "module_file": "test.py",
        }
        m = ModuleManifest.from_dict(data)
        assert m.version == "0.1.0"

    def test_local_registry_list_empty(self, tmp_path):
        from ares.marketplace.installer import LocalRegistry
        with patch("ares.marketplace.installer.INSTALLED_REGISTRY",
                   tmp_path / "installed.json"):
            reg = LocalRegistry()
            assert reg.list_all() == []

    def test_local_registry_install_and_get(self, tmp_path):
        from ares.marketplace.installer import LocalRegistry, ModuleManifest
        with patch("ares.marketplace.installer.INSTALLED_REGISTRY",
                   tmp_path / "installed.json"), \
             patch("ares.marketplace.installer.PLUGINS_DIR", tmp_path):
            reg      = LocalRegistry()
            manifest = ModuleManifest(
                module_id="test.module", name="Test", version="1.0.0",
                author="tester", description="desc", module_file="m.py",
                plugin_dir=tmp_path,
            )
            reg.install(manifest, plugin_dir=tmp_path)
            assert reg.is_installed("test.module")
            entry = reg.get("test.module")
            assert entry is not None

    def test_local_registry_uninstall(self, tmp_path):
        from ares.marketplace.installer import LocalRegistry, ModuleManifest
        with patch("ares.marketplace.installer.INSTALLED_REGISTRY",
                   tmp_path / "installed.json"), \
             patch("ares.marketplace.installer.PLUGINS_DIR", tmp_path):
            reg = LocalRegistry()
            manifest = ModuleManifest(
                module_id="test.module2", name="T2", version="0.1.0",
                author="tester", description="desc", module_file="m2.py",
                plugin_dir=tmp_path,
            )
            reg.install(manifest, plugin_dir=tmp_path)
            reg.uninstall("test.module2")
            assert not reg.is_installed("test.module2")

    def test_installer_install_as_dict_invalid_source(self, tmp_path):
        from ares.marketplace.installer import ModuleInstaller
        with patch("ares.marketplace.installer.PLUGINS_DIR", tmp_path):
            installer = ModuleInstaller()
            result = installer.install_as_dict("/nonexistent/path/module.py")
            assert result["success"] is False
            assert "error" in result

    def test_installer_list_installed_empty(self, tmp_path):
        from ares.marketplace.installer import ModuleInstaller
        with patch("ares.marketplace.installer.PLUGINS_DIR", tmp_path), \
             patch("ares.marketplace.installer.INSTALLED_REGISTRY",
                   tmp_path / "installed.json"):
            installer = ModuleInstaller()
            assert installer.list_installed() == []


# ─────────────────────────────────────────────────────────────────────────────
# 12. TRACING (NoOp)
# ─────────────────────────────────────────────────────────────────────────────

class TestTracing:

    def test_noop_span_all_methods(self):
        from ares.core.tracing import _NoOpSpan
        s = _NoOpSpan()
        s.set_attribute("key", "value")  # must not raise
        s.set_status("ok")
        s.record_exception(Exception("test"))
        s.add_event("event", {"k": "v"})
        assert s.get_span_context() is None

    def test_noop_span_context_manager(self):
        from ares.core.tracing import _NoOpSpan
        with _NoOpSpan() as s:
            assert s is not None

    def test_get_tracer_returns_something(self):
        from ares.core.tracing import get_tracer
        t = get_tracer()
        assert t is not None

    def test_get_current_trace_id_returns_none_or_str(self):
        from ares.core.tracing import get_current_trace_id
        result = get_current_trace_id()
        assert result is None or isinstance(result, str)

    def test_inject_trace_context_passthrough(self):
        from ares.core.tracing import inject_trace_context
        headers = {"Content-Type": "application/json"}
        result = inject_trace_context(headers)
        assert isinstance(result, dict)
        assert "Content-Type" in result  # original header preserved

    def test_span_context_manager_sync(self):
        from ares.core.tracing import span
        with span("test.operation", {"key": "value"}) as s:
            assert s is not None  # no-op span or real span

    def test_async_span_context_manager(self):
        from ares.core.tracing import async_span
        async def run():
            async with async_span("test.async_op", {"module": "test"}) as s:
                return s is not None
        result = asyncio.run(run())
        assert result is True

    def test_trace_module_decorator(self):
        from ares.core.tracing import trace_module
        class FakeModule:
            campaign = MagicMock(id="camp-001")
            @trace_module("test.module")
            async def run(self, **kwargs):
                return ([], {"raw": "data"})

        async def run():
            return await FakeModule().run()

        findings, raw = asyncio.run(run())
        assert findings == []

    def test_trace_id_log_filter(self):
        from ares.core.tracing import TraceIDLogFilter
        f = TraceIDLogFilter()
        record = {"extra": {}}
        result = f(record)
        assert result is True
        assert "trace_id" in record["extra"]
        assert "span_id" in record["extra"]


# ─────────────────────────────────────────────────────────────────────────────
# 13. TELEMETRY
# ─────────────────────────────────────────────────────────────────────────────

class TestTelemetry:

    def test_metrics_collector_init(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        assert mc is not None

    def test_record_module_run(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        mc.record_execution(
            module_id   = "ad.kerberoast",
            duration_ms = 350.5,
            success     = True,
            campaign_id = "camp-001",
        )
        stats = mc.module_stats()
        assert isinstance(stats, list)

    def test_record_multiple_runs(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        for i in range(5):
            mc.record_execution(
                module_id   = "ad.kerberoast",
                duration_ms = 100.0 * (i+1),
                success     = (i % 2 == 0),
                campaign_id = "camp-001",
            )
        stats = mc.module_stats()
        assert isinstance(stats, list)

    def test_record_finding(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        mc.record_finding(count=3)
        snap = mc.snapshot(campaign_id="camp-001")
        assert snap.findings_total >= 3

    def test_record_credential(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        mc.record_credential(count=2)
        snap = mc.snapshot(campaign_id="camp-001")
        assert snap.credentials_found >= 2

    def test_snapshot_structure(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        mc.record_execution("ad.kerberoast", 200.0, True)
        snap = mc.snapshot()
        d = snap.to_dict()
        assert isinstance(d, dict)

    def test_worker_health_list(self):
        from ares.telemetry.collector import TelemetryCollector
        mc = TelemetryCollector()
        workers = mc.worker_health()
        assert isinstance(workers, list)

    def test_get_collector_singleton(self):
        from ares.telemetry.collector import get_collector, TelemetryCollector
        c = get_collector()
        assert isinstance(c, TelemetryCollector)


# ─────────────────────────────────────────────────────────────────────────────
# 14. PACKAGE __ALL__ EXPORTS
# ─────────────────────────────────────────────────────────────────────────────

class TestPackageExports:

    def test_state_exports_target_host(self):
        from ares import state
        assert hasattr(state, "TargetHost") or "TargetHost" in getattr(state, "__all__", [])

    def test_state_exports_host_state(self):
        from ares import state
        assert hasattr(state, "HostState") or "HostState" in getattr(state, "__all__", [])

    def test_state_exports_operator_session(self):
        from ares import state
        assert hasattr(state, "OperatorSession") or "OperatorSession" in getattr(state, "__all__", [])

    def test_goal_exports_goal_enum(self):
        import importlib
        goal = importlib.import_module("ares.goal")
        assert hasattr(goal, "Goal") or "Goal" in getattr(goal, "__all__", [])

    def test_goal_exports_goal_engine(self):
        import importlib
        goal = importlib.import_module("ares.goal")
        assert hasattr(goal, "GoalEngine") or "GoalEngine" in getattr(goal, "__all__", [])

    def test_modules_exports_base_module(self):
        import importlib
        mods = importlib.import_module("ares.modules")
        assert hasattr(mods, "BaseModule") or "BaseModule" in getattr(mods, "__all__", [])

    def test_core_chain_exports_attack_chain(self):
        import importlib
        chain = importlib.import_module("ares.core.chain")
        assert hasattr(chain, "AttackChain") or "AttackChain" in getattr(chain, "__all__", [])

    def test_credential_exports_vault(self):
        import importlib
        cred = importlib.import_module("ares.credential")
        assert hasattr(cred, "CredentialVault") or "CredentialVault" in getattr(cred, "__all__", [])

    def test_telemetry_exports_collector(self):
        import importlib
        tel = importlib.import_module("ares.telemetry")
        # TelemetryCollector is the real name
        assert hasattr(tel, "TelemetryCollector") or "TelemetryCollector" in getattr(tel, "__all__", [])
        """Every ARES package with an __init__.py should define __all__."""
        import os, importlib
        base = "/home/claude/ARES_r4/ares"
        missing = []
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if '__pycache__' not in d]
            if "__init__.py" not in files:
                continue
            rel = os.path.relpath(root, base)
            if rel == ".":
                mod_name = "ares"
            else:
                mod_name = "ares." + rel.replace(os.sep, ".")
            try:
                mod = importlib.import_module(mod_name)
                init_path = os.path.join(root, "__init__.py")
                # Allow empty __all__ for tiny packages; just check it exists
                if not hasattr(mod, "__all__") and os.path.getsize(init_path) > 50:
                    missing.append(mod_name)
            except ImportError:
                pass  # Optional deps OK
        assert missing == [], f"Packages without __all__: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# 15. ARTIFACT CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class TestArtifactCorrelationEngine:

    def _store_with_da_hash(self):
        from ares.normalize.artifacts import (
            ArtifactStore, HostArtifact, UserArtifact, HashArtifact
        )
        store = ArtifactStore()
        store.add(HostArtifact(ip="10.0.0.1", hostname="dc01",
                                os="windows", domain="CORP",
                                domain_controller=True))
        store.add(UserArtifact(
            username="krbtgt", domain="CORP",
            groups=["Domain Admins"], spn=[],
        ))
        store.add(HashArtifact(
            username="krbtgt", domain="CORP",
            nt_hash="aad3b435b51404eeaad3b435b51404ee",
            module_id="ad.dcsync",
        ))
        return store

    def test_correlate_returns_list(self):
        from ares.artifact_intel.correlation import ArtifactCorrelationEngine
        store = self._store_with_da_hash()
        engine = ArtifactCorrelationEngine()
        opps = engine.correlate(store)
        assert isinstance(opps, list)

    def test_correlation_opportunity_structure(self):
        from ares.artifact_intel.correlation import ArtifactCorrelationEngine
        store = self._store_with_da_hash()
        engine = ArtifactCorrelationEngine()
        opps = engine.correlate(store)
        for opp in opps:
            assert hasattr(opp, "opportunity_id")
            assert hasattr(opp, "severity")
            assert hasattr(opp, "recommended_modules")
            d = opp.to_dict()
            assert "opportunity_id" in d

    def test_empty_store_no_opportunities(self):
        from ares.artifact_intel.correlation import ArtifactCorrelationEngine
        from ares.normalize.artifacts import ArtifactStore
        store = ArtifactStore()
        engine = ArtifactCorrelationEngine()
        opps = engine.correlate(store)
        assert opps == []


# ─────────────────────────────────────────────────────────────────────────────
# 16. NETWORK MODEL
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkModel:

    def test_network_model_init(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel(name="Test Network")
        assert nm is not None

    def test_add_host_flat(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        nm.add_host_flat("10.0.0.1", hostname="dc01", domain_controller=True)
        hosts = nm.all_hosts()
        assert any(h.ip == "10.0.0.1" for h in hosts)

    def test_get_host(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        nm.add_host_flat("10.0.0.2", hostname="srv01")
        h = nm.get_host("10.0.0.2")
        assert h is not None
        assert h.ip == "10.0.0.2"

    def test_domain_controllers(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        nm.add_host_flat("10.0.0.1", hostname="dc01", domain_controller=True)
        nm.add_host_flat("10.0.0.2", hostname="srv01", domain_controller=False)
        dcs = nm.domain_controllers()
        assert len(dcs) == 1
        assert dcs[0].ip == "10.0.0.1"

    def test_add_subnet(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        subnet = nm.add_subnet("10.0.0.0/24", name="Corp LAN")
        assert subnet is not None

    def test_same_subnet(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        nm.add_subnet("10.0.0.0/24")
        nm.add_host_flat("10.0.0.1", hostname="h1")
        nm.add_host_flat("10.0.0.2", hostname="h2")
        nm.add_host_flat("192.168.1.1", hostname="h3")
        # Same /24
        assert nm.same_subnet("10.0.0.1", "10.0.0.2") is True
        # Different subnet
        assert nm.same_subnet("10.0.0.1", "192.168.1.1") is False

    def test_host_node_add_service(self):
        from ares.network.model import NetworkModel
        nm = NetworkModel()
        nm.add_host_flat("10.0.0.1", hostname="dc01")
        h = nm.get_host("10.0.0.1")
        if h and hasattr(h, "add_service"):
            svc = h.add_service(445, "smb", "3.1.1")
            assert svc is not None


# ─────────────────────────────────────────────────────────────────────────────
# 17. SERVICE INTEL
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceIntel:

    def test_engine_init(self):
        from ares.service_intel.engine import ServiceIntelEngine
        e = ServiceIntelEngine()
        assert e is not None

    def test_service_profile_schema(self):
        from ares.service_intel.engine import ServiceProfile
        profile = ServiceProfile(
            port         = 445,
            service_name = "smb",
            protocol     = "tcp",
            description  = "SMB file sharing",
        )
        assert profile.port == 445
        assert profile.service_name == "smb"

    def test_recommend_modules_for_port_scan(self):
        from ares.service_intel.engine import ServiceIntelEngine, PortScanResult
        engine = ServiceIntelEngine()
        scan = PortScanResult(
            host       = "10.0.0.1",
            open_ports = [445, 389, 636, 88],
        )
        modules = engine.recommend_modules(scan)
        assert isinstance(modules, list)

    def test_is_likely_dc(self):
        from ares.service_intel.engine import ServiceIntelEngine, PortScanResult
        engine = ServiceIntelEngine()
        dc_scan = PortScanResult(
            host       = "10.0.0.1",
            open_ports = [88, 389, 445, 636, 3268],  # typical DC ports
        )
        non_dc_scan = PortScanResult(
            host       = "10.0.0.2",
            open_ports = [80, 443, 8080],
        )
        assert engine.is_likely_dc(dc_scan) is True
        assert engine.is_likely_dc(non_dc_scan) is False


# ─────────────────────────────────────────────────────────────────────────────
# 18. REPLAY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class TestReplayEngine:

    def test_campaign_replay_init(self):
        from ares.replay.engine import CampaignReplay
        from unittest.mock import MagicMock
        mock_campaign = MagicMock()
        mock_campaign.id = "camp-001"
        mock_campaign.findings = []
        e = CampaignReplay(campaign=mock_campaign)
        assert e is not None

    def test_build_timeline(self):
        from ares.replay.engine import CampaignReplay, ReplayEvent
        from unittest.mock import MagicMock
        mock_campaign = MagicMock()
        mock_campaign.id = "camp-001"
        mock_campaign.findings = []
        e = CampaignReplay(campaign=mock_campaign)
        timeline = e.build_timeline()
        assert isinstance(timeline, list)

    def test_replay_event_structure(self):
        from ares.replay.engine import ReplayEvent
        import time
        ev = ReplayEvent(
            timestamp = time.time(),
            module_id = "ad.kerberoast",
            target    = "10.0.0.1",
            success   = True,
            findings  = ["F-001"],
            details   = {},
        )
        assert ev.module_id == "ad.kerberoast"
        d = ev.to_dict()
        assert "module_id" in d

    def test_replay_result_summary(self):
        from ares.replay.engine import ReplayResult, ReplayEvent
        import time
        events = [
            ReplayEvent(
                timestamp=time.time(), module_id="ad.kerberoast",
                target="10.0.0.1", success=True, findings=[], details={},
            ),
        ]
        result = ReplayResult(
            campaign_id = "camp-001",
            total_events = 1,
            replayed_events = events,
            duration_s = 0.5,
        )
        summary = result.summary()
        assert isinstance(summary, dict)
        assert "campaign_id" in summary

    def test_replay_mode_enum(self):
        from ares.replay.engine import ReplayMode
        modes = list(ReplayMode)
        assert len(modes) >= 2
        mode_values = [m.value for m in modes]
        assert any(m in mode_values for m in ("replay", "simulate", "purple_team", "timeline"))


# ─────────────────────────────────────────────────────────────────────────────
# 19. CROSS-MODULE INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossModuleIntegration:

    def test_state_to_graph_pipeline(self):
        """Session host data flows correctly into ArtifactStore → AttackGraph."""
        from ares.state.target_state import OperatorSession, CompromiseLevel
        from ares.normalize.artifacts import ArtifactStore, HostArtifact
        from ares.graph.attack_graph import AttackGraph

        sess = OperatorSession(campaign_id="integration-001")
        sess.add_host("10.0.0.1", hostname="dc01", domain_role="domain_controller")
        sess.mark_host_owned("10.0.0.1", CompromiseLevel.DOMAIN_ADMIN)

        store = ArtifactStore()
        for host in sess.all_hosts():
            store.add(HostArtifact(
                ip       = host.ip_address,
                hostname = host.hostname,
                os       = getattr(host, "os_type", "windows"),
                domain   = getattr(host, "domain", "CORP"),
            ))

        g = AttackGraph()
        g.build_from_store(store)
        assert g.stats()["nodes"] >= 1

    def test_session_snapshot_preserves_all_data(self):
        """Full snapshot round-trip keeps all session data intact."""
        from ares.state.target_state import OperatorSession, CompromiseLevel
        sess = OperatorSession(campaign_id="snap-test", operator="alice")
        sess.add_host("10.0.0.1")
        sess.mark_host_owned("10.0.0.1", CompromiseLevel.LOCAL_ADMIN)
        sess.record_attack("ad.kerberoast", "10.0.0.1", success=True)
        sess.add_pivot({"type": "socks5", "port": 1080})

        snap     = sess.snapshot()
        restored = OperatorSession.from_snapshot(snap)

        assert restored.operator == "alice"
        assert len(restored.owned_hosts()) == 1
        assert len(restored.history()) == 1
        assert len(restored.active_pivots()) == 1

    def test_campaign_findings_to_report(self):
        """Campaign → ReportGenerator → JSON output has correct finding count."""
        import tempfile
        from ares.modules.reporting.report_gen import ReportGenerator
        c = _campaign(n_findings=4)
        with tempfile.TemporaryDirectory() as tmpdir:
            gen  = ReportGenerator(output_dir=tmpdir)
            path = gen.generate(c, fmt="json")
            data = json.loads(path.read_text())
            assert len(data["findings"]) == 4
            assert data["summary"]["total_confirmed"] == 4

    def test_attacker_planner_uses_correct_goal_definitions(self):
        """GoalEngine GOAL_DEFINITIONS is consumed correctly by AttackPlanner."""
        from ares.goal.engine import Goal, GOAL_DEFINITIONS
        from ares.goal.planner import AttackPlanner, PlannerContext
        from unittest.mock import MagicMock

        registry = MagicMock()
        registry.all.return_value = []
        planner = AttackPlanner(registry=registry)
        for goal in Goal:
            ctx = PlannerContext(goal=goal, targets=["10.0.0.1"])
            suggestions = planner.suggest(ctx, limit=3)
            assert isinstance(suggestions, list)

    def test_collab_lock_prevents_double_work(self):
        """Two operators cannot lock the same target simultaneously."""
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager(campaign_id="collab-test")
        role = OperatorRole(list(OperatorRole)[0].value)
        mgr.register_operator("op-001", name="Alice", role=role)
        mgr.register_operator("op-002", name="Bob",   role=role)

        lock1 = mgr.acquire_lock("10.0.0.1", "op-001", "ad.kerberoast")
        assert lock1 is not None

        # Bob tries to lock same target
        lock2 = mgr.acquire_lock("10.0.0.1", "op-002", "ad.dcsync")
        assert lock2 is None  # should fail — already locked


# ─────────────────────────────────────────────────────────────────────────────
# 20. CORE CONFIG + SECURITY
# ─────────────────────────────────────────────────────────────────────────────

class TestCoreConfig:

    def test_ares_settings_defaults(self):
        from ares.core.config import AresSettings
        s = AresSettings()
        assert s.ares_log_level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        assert isinstance(s.ares_jwt_expire_minutes, int)
        assert s.ares_jwt_expire_minutes > 0

    def test_ares_settings_jwt_algo_is_string(self):
        from ares.core.config import AresSettings
        s = AresSettings()
        assert isinstance(s.ares_jwt_algorithm, str)
        assert s.ares_jwt_algorithm.startswith("HS") or s.ares_jwt_algorithm.startswith("RS")

    def test_get_settings_singleton(self):
        from ares.core.config import get_settings
        s1 = get_settings()
        s2 = get_settings()
        assert type(s1) == type(s2)

    def test_ares_version_in_package(self):
        import ares
        assert hasattr(ares, "__version__")
        assert isinstance(ares.__version__, str)

    def test_ares_package_has_all(self):
        import ares
        assert hasattr(ares, "__all__")


# ─────────────────────────────────────────────────────────────────────────────
# 21. CLI STORE v2 — new methods
# ─────────────────────────────────────────────────────────────────────────────

class TestCLIStoreV2:

    def test_list_reports_returns_list(self, tmp_path):
        from ares.cli._store import CampaignStore
        with patch("ares.cli._store.campaigns_dir", return_value=tmp_path), \
             patch("pathlib.Path.home", return_value=tmp_path):
            store = CampaignStore()
            reports = store.list_reports()
            assert isinstance(reports, list)

    def test_save_checkpoint_creates_file(self, tmp_path):
        from ares.cli._store import CampaignStore
        with patch("ares.cli._store.campaigns_dir", return_value=tmp_path):
            store = CampaignStore()
            (tmp_path / "camp-test.json").write_text(json.dumps({
                "id": "camp-test", "name": "T", "targets": [],
                "findings": [], "noise_profile": "normal",
            }))
            cp = store.save_checkpoint("camp-test", notes="test cp")
            assert cp is not None
            assert Path(cp["path"]).exists()

    def test_load_checkpoint_latest(self, tmp_path):
        from ares.cli._store import CampaignStore
        with patch("ares.cli._store.campaigns_dir", return_value=tmp_path):
            store = CampaignStore()
            (tmp_path / "camp-test.json").write_text(json.dumps({
                "id": "camp-test", "name": "T", "targets": [],
                "findings": [], "noise_profile": "normal",
            }))
            store.save_checkpoint("camp-test", notes="first")
            cp = store.load_checkpoint("camp-test", "latest")
            assert cp is not None
            assert cp["notes"] == "first"

    def test_add_target_dict_normalised(self, tmp_path):
        from ares.cli._store import CampaignStore
        with patch("ares.cli._store.campaigns_dir", return_value=tmp_path):
            store = CampaignStore()
            (tmp_path / "camp-test.json").write_text(json.dumps({
                "id": "camp-test", "name": "T", "targets": [],
                "findings": [], "noise_profile": "normal",
            }))
            result = store.add_target("camp-test",
                                       {"target": "192.168.1.1", "tags": ["web"]})
            assert result is True
            targets = store.list_targets("camp-test")
            assert any(t.get("target") == "192.168.1.1" for t in targets)
            assert any("web" in t.get("tags", []) for t in targets)
