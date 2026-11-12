"""Audit run-1 API hardening regressions: H3 (BloodHound ingest path sandbox)
and H4 (graph topology fabrication gated off by default)."""

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


def _mock_campaign():
    campaign = MagicMock()
    campaign.id = "graph-h4-001"
    campaign.name = "Graph H4 Test"
    campaign.scope = [{"cidr": "10.0.0.0/24"}]

    dc = MagicMock()
    dc.compromise_level = MagicMock(value="domain_admin")
    dc.is_dc = True
    dc.hostname = "dc01"
    dc.is_owned = True
    dc.open_ports = [389, 445, 88]
    dc.os_info = "Windows Server 2019"
    dc.attack_history = []
    dc.discovered_from = None

    srv = MagicMock()
    srv.compromise_level = MagicMock(value="local_admin")
    srv.is_dc = False
    srv.hostname = "sql01-srv"
    srv.is_owned = True
    srv.open_ports = [445, 1433]
    srv.os_info = "Windows Server 2022"
    srv.attack_history = []
    srv.discovered_from = "10.0.0.1"

    session = MagicMock()
    session.hosts = {"10.0.0.1": dc, "10.0.0.2": srv}
    session.get_host = lambda ip: session.hosts.get(ip)
    campaign.session = session
    campaign.findings = []
    campaign.vault = None
    return campaign


# ── H4: heuristic topology must be opt-in ───────────────────────────────────

def _edge_sources(graph):
    return [e.get("data", {}).get("source") for e in graph["edges"]]


def test_graph_default_has_no_fabricated_topology():
    from ares.api.graph import build_campaign_graph

    graph = build_campaign_graph(_mock_campaign())
    assert not any(n["type"] == "firewall" for n in graph["nodes"])
    assert "hostname_heuristic" not in _edge_sources(graph)


def test_graph_heuristic_opt_in_is_tagged():
    from ares.api.graph import build_campaign_graph

    graph = build_campaign_graph(_mock_campaign(), include_heuristic=True)
    fw = [n for n in graph["nodes"] if n["type"] == "firewall"]
    assert fw, "perimeter node should appear when include_heuristic=True"
    assert fw[0]["data"].get("source") == "hostname_heuristic"
    heuristic_edges = [e for e in graph["edges"]
                       if e.get("data", {}).get("source") == "hostname_heuristic"]
    assert heuristic_edges, "heuristic pivot edges should appear when opted in"


# ── H3: BloodHound ingest path must stay inside the campaign sandbox ─────────

def test_bloodhound_ingest_rejects_traversal():
    from ares.api.server import _resolve_bloodhound_ingest_path

    with pytest.raises(HTTPException) as ei:
        _resolve_bloodhound_ingest_path("../../../../etc/passwd", "camp-h3")
    assert ei.value.status_code == 400
    assert ei.value.detail == "Invalid BloodHound ingest path"


def test_bloodhound_ingest_rejects_absolute_outside_sandbox():
    from ares.api.server import _resolve_bloodhound_ingest_path

    outside = "C:/Windows/win.ini" if __import__("os").name == "nt" else "/etc/hostname"
    with pytest.raises(HTTPException) as ei:
        _resolve_bloodhound_ingest_path(outside, "camp-h3")
    assert ei.value.status_code == 400


def test_bloodhound_ingest_accepts_relative_json_in_sandbox():
    from ares.api.server import _report_root, _resolve_bloodhound_ingest_path

    resolved = _resolve_bloodhound_ingest_path("sharphound.json", "camp-h3")
    sandbox = (_report_root() / "camp-h3" / "bloodhound").resolve()
    assert resolved.is_relative_to(sandbox)
    assert resolved.name == "sharphound.json"
