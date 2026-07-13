"""
ARES test suite — conftest.py
Shared pytest fixtures, PYTHONPATH bootstrap, and async configuration.
Auto-discovered by pytest. All fixtures are available to every test file.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── PYTHONPATH bootstrap ──────────────────────────────────────────────────────
# Ensures `import ares.*` works without installing the package.
_REPO_ROOT = Path(__file__).parent.parent.resolve()
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# ── Required env vars for AresSettings ───────────────────────────────────────
# AresSettings has Field(...) on secret_key and encryption_key — no defaults.
# This session-scoped fixture runs automatically before every test (unit AND
# integration) so AresSettings() and AresContainer.for_test() never crash due
# to missing env vars in local/CI environments without a .env file.
@pytest.fixture(autouse=True, scope="session")
def set_test_env():
    """Set required env vars for the entire test session."""
    original_webhook_url = os.environ.get("ARES_WEBHOOK_URL")
    os.environ.setdefault("ARES_SECRET_KEY",             "test-secret-key-min-32-chars-placeholder!!")
    os.environ.setdefault("ARES_ENCRYPTION_KEY",         "test-enc-key-min-32-chars-placeholder-32!!")
    os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestPassword1!")
    os.environ["ARES_WEBHOOK_URL"] = ""
    yield
    if original_webhook_url is not None:
        os.environ["ARES_WEBHOOK_URL"] = original_webhook_url
    else:
        os.environ.pop("ARES_WEBHOOK_URL", None)


# ── Temporary directories ─────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def forbid_unmocked_pdf_browser_launch(monkeypatch: pytest.MonkeyPatch):
    """Unit tests must mock PDF browser execution instead of launching Chrome/Edge."""
    from ares.modules.reporting.report_gen import ReportGenerator

    real_runner = ReportGenerator._run_pdf_browser
    browser_names = {
        "chrome",
        "chrome.exe",
        "chromium",
        "chromium-browser",
        "chromium.exe",
        "google-chrome",
        "msedge",
        "msedge.exe",
    }

    def guarded_runner(self: Any, cmd: list[str]):
        executable = Path(str(cmd[0]))
        if executable.name.lower() in browser_names:
            raise AssertionError(
                "Unit tests must mock PDF browser execution; attempted to launch "
                f"{executable}"
            )
        return real_runner(self, cmd)

    monkeypatch.setattr(ReportGenerator, "_run_pdf_browser", guarded_runner)


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Isolated temp directory (alias for tmp_path)."""
    return tmp_path


@pytest.fixture
def tmp_reports_dir(tmp_path: Path) -> Path:
    d = tmp_path / "reports"; d.mkdir(); return d


@pytest.fixture
def tmp_checkpoint_dir(tmp_path: Path) -> Path:
    d = tmp_path / "checkpoints"; d.mkdir(); return d


# ── Core domain objects ───────────────────────────────────────────────────────

@pytest.fixture
def minimal_campaign():
    """Minimal Campaign with one /8 scope entry."""
    from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
    return Campaign(
        name="Test Campaign",
        client="ACME Corp",
        operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )


@pytest.fixture
def campaign_with_findings(minimal_campaign):
    """Campaign pre-loaded with 3 HIGH + 1 CRITICAL finding."""
    from ares.core.campaign import Finding, Severity
    for i, sev in enumerate([Severity.HIGH]*3 + [Severity.CRITICAL]):
        minimal_campaign.add_finding(Finding(
            title=f"Finding {i+1}", description=f"Desc {i+1}",
            severity=sev, confidence=0.9, module_id=f"ad.mod_{i}",
            host=f"10.0.0.{i+1}", evidence=f"ev_{i}",
            remediation=f"fix_{i}", mitre_technique="T1558.003",
            mitre_tactic="Credential Access",
        ))
    return minimal_campaign


@pytest.fixture
def operator_session():
    """Fresh OperatorSession."""
    from ares.state.target_state import OperatorSession
    return OperatorSession(campaign_id="test-001", operator="tester")


@pytest.fixture
def session_with_hosts(operator_session):
    """OperatorSession with 3 pre-added hosts."""
    from ares.state.target_state import CompromiseLevel
    operator_session.add_host("10.0.0.1", hostname="DC01",
                              domain_role="domain_controller")
    operator_session.add_host("10.0.0.2", hostname="SRV01")
    operator_session.mark_host_owned("10.0.0.2", CompromiseLevel.LOCAL_ADMIN)
    operator_session.add_host("10.0.0.3", hostname="WS01")
    return operator_session


@pytest.fixture
def artifact_store():
    """Empty ArtifactStore."""
    from ares.normalize.artifacts import ArtifactStore
    return ArtifactStore()


@pytest.fixture
def populated_artifact_store(artifact_store):
    """ArtifactStore with hosts, users, hashes."""
    from ares.normalize.artifacts import HostArtifact, UserArtifact, HashArtifact
    artifact_store.add(HostArtifact(
        ip="10.0.0.1", hostname="DC01", os="windows",
        domain="CORP", domain_controller=True,
    ))
    artifact_store.add(UserArtifact(
        username="Administrator", domain="CORP",
        groups=["Domain Admins"], spn=["http/DC01"],
    ))
    artifact_store.add(HashArtifact(
        username="Administrator", domain="CORP",
        nt_hash="aad3b435b51404eeaad3b435b51404ee",
        module_id="ad.dcsync",
    ))
    return artifact_store


@pytest.fixture
def report_generator(tmp_reports_dir):
    """ReportGenerator pointing at tmp directory."""
    from ares.modules.reporting.report_gen import ReportGenerator
    return ReportGenerator(output_dir=str(tmp_reports_dir))


@pytest.fixture
def checkpoint_manager(tmp_checkpoint_dir):
    """CheckpointManager with test encryption key + isolated dir."""
    from ares.checkpoint.manager import CheckpointManager
    with patch("ares.checkpoint.manager.CHECKPOINT_DIR", tmp_checkpoint_dir):
        yield CheckpointManager(
            encryption_key=b"test-key-32-bytes-padded-xxxxxxx"
        )


@pytest.fixture
def technique_library():
    """Fully loaded TechniqueLibrary."""
    from ares.technique.library import TechniqueLibrary
    return TechniqueLibrary()


@pytest.fixture
def goal_engine():
    """GoalEngine with mock registry and operator session."""
    from ares.goal.engine import GoalEngine
    from ares.state.target_state import OperatorSession
    from unittest.mock import MagicMock
    mock_registry = MagicMock()
    mock_registry.__iter__ = lambda self: iter([])
    mock_registry.all.return_value = []   # ModuleRegistry uses .all() not .all_modules()
    mock_registry.get.return_value = None
    # CapabilityGraph.from_registry is called in __init__ — mock it
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "ares.goal.engine.CapabilityGraph.from_registry",
        return_value=MagicMock()
    ):
        session = OperatorSession(campaign_id="test-campaign", operator="tester")
        return GoalEngine(registry=mock_registry, session=session)


@pytest.fixture
def attack_chain():
    """Fresh empty AttackChain."""
    from ares.core.chain.chain import AttackChain
    return AttackChain(name="test-chain")


@pytest.fixture
def telemetry_collector():
    """Fresh TelemetryCollector (not the global singleton)."""
    from ares.telemetry.collector import TelemetryCollector
    return TelemetryCollector()


@pytest.fixture
def collaboration_manager():
    """CollaborationManager for test campaign."""
    from ares.collab.manager import CollaborationManager
    return CollaborationManager(campaign_id="collab-test-001")


@pytest.fixture
def network_model():
    """Empty NetworkModel."""
    from ares.network.model import NetworkModel
    return NetworkModel(name="Test Network")


@pytest.fixture
def network_topology():
    """Empty NetworkTopology (legacy API)."""
    from ares.network.model import NetworkTopology
    return NetworkTopology(campaign_id="topo-test-001")


@pytest.fixture
def attack_graph():
    """Empty AttackGraph."""
    from ares.graph.attack_graph import AttackGraph
    return AttackGraph()


@pytest.fixture
def knowledge_base():
    """Loaded AttackKnowledgeBase."""
    from ares.knowledge.base import AttackKnowledgeBase
    return AttackKnowledgeBase()


@pytest.fixture
def evidence_store():
    """Empty EvidenceStore."""
    from ares.knowledge.base import EvidenceStore
    return EvidenceStore()


@pytest.fixture
def campaign_store(tmp_path):
    """CampaignStore backed by an isolated temp directory."""
    from ares.cli._store import CampaignStore
    with patch("ares.cli._store.campaigns_dir", return_value=tmp_path):
        yield CampaignStore()


@pytest.fixture
def network_host():
    """Simple NetworkHost for legacy tests."""
    from ares.network.model import NetworkHost
    return NetworkHost(ip="10.0.0.1", hostname="dc01")


# ── Mock helpers ──────────────────────────────────────────────────────────────

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_campaign    = AsyncMock(return_value=None)
    db.list_campaigns  = AsyncMock(return_value=[])
    db.get_findings    = AsyncMock(return_value=[])
    db.get_hosts       = AsyncMock(return_value=[])
    return db


@pytest.fixture
def mock_engine():
    eng = MagicMock()
    eng.run_plan   = AsyncMock(return_value=[])
    eng.run_module = AsyncMock(return_value=([], {}))
    return eng


@pytest.fixture
def mock_registry():
    reg = MagicMock()
    reg.all.return_value = []
    reg.get.return_value = None
    return reg


# ── API test client ───────────────────────────────────────────────────────────

@pytest.fixture
def dashboard_client():
    """HTTPX async client for dashboard. Returns None if deps missing."""
    try:
        from httpx import AsyncClient
        from ares.api.dashboard.app import dashboard_app
        return AsyncClient(app=dashboard_app, base_url="http://test")
    except ImportError:
        return None
