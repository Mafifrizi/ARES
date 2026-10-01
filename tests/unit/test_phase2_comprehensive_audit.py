"""
tests/unit/test_phase2_comprehensive_audit.py
Verification suite for Phase 2 comprehensive audit:
- Hypothesis 1: Replay event attribution and deduplication by host
- Hypothesis 2: Attack graph multi-target DA pathfinding and UTF-8 DOT output
- Hypothesis 3: Collaboration target locking active_targets multi-lock state preservation
- Hypothesis 4: Service intelligence declarative scope enforcement
- Hypothesis 5: Scrubbing disabled & phantom module references across templates and KB
"""
import pytest
from unittest.mock import MagicMock
from pathlib import Path


# ── Hypothesis 1: Replay Event Attribution & Deduplication ───────────────────

def test_replay_multihost_finding_attribution():
    from ares.replay.engine import CampaignReplay, ReplayMode
    from ares.state.target_state import AttackHistoryEntry

    h1 = AttackHistoryEntry(module_id="network.port_scan", target_host="10.0.0.1", timestamp=100.0, success=True)
    h2 = AttackHistoryEntry(module_id="network.port_scan", target_host="10.0.0.2", timestamp=200.0, success=True)

    f1 = MagicMock()
    f1.module_id = "network.port_scan"
    f1.title = "Port 80 Open on 10.0.0.1"
    f1.host = "10.0.0.1"
    f1.severity.value = "low"

    f2 = MagicMock()
    f2.module_id = "network.port_scan"
    f2.title = "Port 445 Open on 10.0.0.2"
    f2.host = "10.0.0.2"
    f2.severity.value = "medium"

    replay = CampaignReplay(campaign_id="test_camp", history=[h1, h2], findings=[f1, f2])
    timeline = replay.build_timeline()

    assert len(timeline) == 2, f"Expected exactly 2 events without duplication, got {len(timeline)}"
    assert timeline[0].target == "10.0.0.1"
    assert timeline[0].finding_title == "Port 80 Open on 10.0.0.1"
    assert timeline[1].target == "10.0.0.2"
    assert timeline[1].finding_title == "Port 445 Open on 10.0.0.2"


def test_replay_unassigned_finding_attached_once():
    from ares.replay.engine import CampaignReplay
    from ares.state.target_state import AttackHistoryEntry

    h1 = AttackHistoryEntry(module_id="ad.domain_enum", target_host="dc01", timestamp=100.0, success=True)
    h2 = AttackHistoryEntry(module_id="ad.domain_enum", target_host="dc02", timestamp=200.0, success=True)

    # Domain finding without a specific host
    f = MagicMock()
    f.id = "f-domain-01"
    f.module_id = "ad.domain_enum"
    f.title = "Domain Password Policy Weak"
    f.host = ""
    f.severity.value = "high"

    replay = CampaignReplay(campaign_id="test_camp", history=[h1, h2], findings=[f])
    timeline = replay.build_timeline()

    assert len(timeline) == 2
    # First entry receives the finding, second entry is marked clean run
    assert timeline[0].finding_title == "Domain Password Policy Weak"
    assert timeline[1].finding_title == ""


# ── Hypothesis 2: Attack Graph Multi-Target DA & UTF-8 DOT ───────────────────

def test_attack_graph_multi_target_da_pathfinding():
    from ares.graph.attack_graph import AttackGraph, GraphNode, GraphEdge

    g = AttackGraph()
    g._add_node(GraphNode(node_id="user:alice", label="alice", node_type="user"))
    # Two DA groups: DA_SUB unreachable, DA_ROOT reachable
    g._add_node(GraphNode(node_id="group:DA_SUB", label="DOMAIN ADMINS SUB", node_type="group", is_target=True))
    g._add_node(GraphNode(node_id="group:DA_ROOT", label="DOMAIN ADMINS ROOT", node_type="group", is_target=True))
    g._add_edge(GraphEdge(source="user:alice", target="group:DA_ROOT", edge_type="member_of", weight=1.0))

    report = g.shortest_path_to_da("user:alice")
    assert report is not None, "Failed to find path to DA when a reachable DA group exists"
    assert report["end"] == "DOMAIN ADMINS ROOT"
    assert report["total_score"] == 1.0


def test_attack_graph_to_dot_utf8(tmp_path: Path):
    from ares.graph.attack_graph import AttackGraph, GraphNode

    g = AttackGraph()
    # Cyrillic and international characters in Active Directory objects
    g._add_node(GraphNode(node_id="user:админ", label="Иван Иванов", node_type="user"))
    dot_file = tmp_path / "test_graph.dot"
    g.to_dot(str(dot_file))

    content = dot_file.read_text(encoding="utf-8")
    assert "Иван Иванов" in content
    assert "user:админ" in content


# ── Hypothesis 3: Collaboration Multi-Lock State Preservation ─────────────────

def test_collab_target_lock_active_targets_preservation():
    from ares.collab.manager import CollaborationManager, OperatorRole

    cm = CollaborationManager("camp-collab-01")
    op = cm.register_operator("op_test", "alice", role=OperatorRole.OPERATOR)

    ok1, lock1 = cm.acquire_lock("op_test", "host_a", "lateral.psexec")
    ok2, lock2 = cm.acquire_lock("op_test", "host_a", "windows.lsass_dump")
    assert ok1 and ok2
    assert op.active_targets == ["host_a"]

    # Releasing first lock should keep host_a because second lock is active
    cm.release_lock(lock1)
    assert op.active_targets == ["host_a"], "active_targets prematurely cleared while another lock was active"
    assert cm.is_locked("host_a") is True

    # Releasing second lock should now clear host_a
    cm.release_lock(lock2)
    assert op.active_targets == []
    assert cm.is_locked("host_a") is False


# ── Hypothesis 4: Service Intelligence Scope Enforcement ──────────────────────

@pytest.mark.asyncio
async def test_service_intel_scope_guard_enforcement():
    from ares.service_intel.engine import ServiceIntelEngine
    from ares.core.campaign import Campaign, ScopeEntry
    from ares.core.noise import ScopeGuard
    from ares.core.errors import ScopeViolationError

    campaign = Campaign(
        id="test_scope",
        name="Test Scope",
        scope=[ScopeEntry(cidr="192.168.1.0/24")],
    )
    guard = ScopeGuard(campaign)
    engine = ServiceIntelEngine()

    # In-scope check does not raise ScopeViolationError
    assert guard.check("192.168.1.50") is True

    # Out-of-scope check raises ScopeViolationError and blocks connect
    with pytest.raises(ScopeViolationError):
        await engine.scan_host("10.50.50.50", ports=[80], scope_guard=guard)


# ── Hypothesis 5: Catalog & Template Incoherence Scrubbing ────────────────────

def test_catalog_and_template_scrubbed_from_disabled_modules():
    from ares.core.engine import CAMPAIGN_TEMPLATES
    from ares.marketplace.installer import _BUNDLED_INDEX
    from ares.knowledge.base import _KB_ENTRIES

    # 1. assumed_breach template uses windows.lsa_secrets, not windows.dpapi
    win_template = CAMPAIGN_TEMPLATES["assumed_breach"]
    all_modules = [m for stage in win_template["stages"] for m in stage["modules"]]
    assert "windows.dpapi" not in all_modules
    assert "windows.lsa_secrets" in all_modules

    # 2. _BUNDLED_INDEX does not list disabled windows.token_impersonation
    bundled_ids = [m["id"] for m in _BUNDLED_INDEX["modules"]]
    assert "windows.token_impersonation" not in bundled_ids
    assert "windows.lsass_dump" in bundled_ids
    assert "windows.lsa_secrets" in bundled_ids

    # 3. _KB_ENTRIES points to windows.lsa_secrets instead of windows.dpapi
    kb_modules = [m for entry in _KB_ENTRIES for m in entry.attack_modules]
    assert "windows.dpapi" not in kb_modules
    assert "windows.lsa_secrets" in kb_modules
