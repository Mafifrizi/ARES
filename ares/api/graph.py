"""
ARES Campaign Graph API
Builds the attack graph data structure for frontend visualization.

Returns JSON with:
  nodes  — hosts, users, credentials, pivots, findings
  edges  — attack paths, credential flows, lateral movement
  layout — suggested layout hints (hierarchical, force-directed)

Frontend can render with:
  - D3.js (force-directed)
  - Cytoscape.js (attack graph)
  - vis.js (timeline + network)

Node types:
  host        — discovered hosts (color by compromise level)
  credential  — credentials (color by privilege)
  user        — AD users / service accounts
  pivot       — pivot tunnels
  finding     — individual findings (severity → color)
  dc          — Domain Controllers (special shape)

Edge types:
  compromise  — "host A was compromised via module X"
  credential  — "credential flows from A to B"
  lateral     — "lateral movement A → B"
  pivot       — "pivot route A → B"
  discovery   — "B was discovered from A"

Usage:
    from ares.api.graph import build_campaign_graph
    graph_data = build_campaign_graph(campaign)
    # Returns dict suitable for JSON serialization
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


# ── Graph types ────────────────────────────────────────────────────────────────

@dataclass
class APIGraphNode:  # renamed from GraphNode to avoid collision with graph/attack_graph.py
    id:       str
    type:     str    # host | credential | user | pivot | finding | dc
    label:    str
    data:     dict[str, Any] = field(default_factory=dict)
    color:    str = "#6c757d"
    shape:    str = "circle"
    size:     int = 20

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":    self.id,
            "type":  self.type,
            "label": self.label,
            "data":  self.data,
            "style": {"color": self.color, "shape": self.shape, "size": self.size},
        }


@dataclass
class APIGraphEdge:  # renamed from GraphEdge to avoid collision with graph/attack_graph.py
    source:    str
    target:    str
    type:      str     # compromise | credential | lateral | pivot | discovery
    label:     str = ""
    weight:    float = 1.0
    data:      dict[str, Any] = field(default_factory=dict)
    color:     str = "#adb5bd"
    dashed:    bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type":   self.type,
            "label":  self.label,
            "weight": self.weight,
            "data":   self.data,
            "style":  {"color": self.color, "dashed": self.dashed},
        }


# ── Color palettes ─────────────────────────────────────────────────────────────

_COMPROMISE_COLORS = {
    "none":         "#6c757d",   # grey
    "recon":        "#0dcaf0",   # cyan
    "user":         "#ffc107",   # yellow
    "local_admin":  "#fd7e14",   # orange
    "system":       "#dc3545",   # red
    "domain_admin": "#6f42c1",   # purple (pwned)
}

_SEVERITY_COLORS = {
    "critical":  "#dc3545",
    "high":      "#fd7e14",
    "medium":    "#ffc107",
    "low":       "#0dcaf0",
    "info":      "#6c757d",
}

_PRIVILEGE_COLORS = {
    "domain_admin": "#6f42c1",
    "local_admin":  "#fd7e14",
    "service_account": "#0dcaf0",
    "user":         "#6c757d",
}


# ── Graph builder ──────────────────────────────────────────────────────────────

def build_campaign_graph(campaign: Any) -> dict[str, Any]:
    """
    Build the complete campaign graph from Campaign state.

    Args:
        campaign: Campaign object (with findings, session state)

    Returns:
        dict with nodes, edges, stats, layout_hint
    """
    nodes: list[APIGraphNode] = []
    edges: list[APIGraphEdge] = []
    node_ids: set[str] = set()

    def add_node(node: APIGraphNode) -> None:
        if node.id not in node_ids:
            nodes.append(node)
            node_ids.add(node.id)

    # ── Hosts from session ──────────────────────────────────────────────────
    session = getattr(campaign, "session", None) or getattr(campaign, "_session", None)

    if session:
        hosts = getattr(session, "hosts", {})
        for ip, host in hosts.items():
            c_level = getattr(getattr(host, "compromise_level", None), "value", "none")
            is_dc   = getattr(host, "is_dc", False)
            hostname = getattr(host, "hostname", "") or ip

            add_node(APIGraphNode(
                id    = f"host:{ip}",
                type  = "dc" if is_dc else "host",
                label = f"{hostname}\n{ip}" if hostname != ip else ip,
                data  = {
                    "ip":               ip,
                    "hostname":         hostname,
                    "compromise_level": c_level,
                    "is_dc":            is_dc,
                    "open_ports":       getattr(host, "open_ports", []),
                    "os_info":          getattr(host, "os_info", ""),
                    "owned":            getattr(host, "is_owned", False),
                },
                color = _COMPROMISE_COLORS.get(c_level, "#6c757d"),
                shape = "diamond" if is_dc else "circle",
                size  = 35 if is_dc else (28 if getattr(host, "is_owned", False) else 20),
            ))

            # Edges: discovery chain
            via_host = getattr(host, "discovered_from", None)
            if via_host and f"host:{via_host}" in node_ids:
                edges.append(APIGraphEdge(
                    source = f"host:{via_host}",
                    target = f"host:{ip}",
                    type   = "discovery",
                    label  = "discovered",
                    color  = "#0dcaf0",
                    dashed = True,
                ))

            # Edges: lateral movement
            attack_history = getattr(host, "attack_history", [])
            for attack in attack_history:
                src_ip  = getattr(attack, "from_host", None)
                module  = getattr(attack, "module_id", "")
                success = getattr(attack, "success", False)
                if src_ip and success and f"host:{src_ip}" in node_ids:
                    edges.append(APIGraphEdge(
                        source = f"host:{src_ip}",
                        target = f"host:{ip}",
                        type   = "lateral",
                        label  = module.split(".")[-1] if module else "lateral",
                        color  = "#dc3545",
                        weight = 2.0,
                        data   = {"module": module},
                    ))

    # ── Credentials ────────────────────────────────────────────────────────
    vault = getattr(campaign, "vault", None)
    if vault:
        creds = getattr(vault, "_credentials", {})
        for cred_id, cred in creds.items():
            username  = getattr(cred, "username", "")
            domain    = getattr(cred, "domain", "")
            privilege = getattr(cred, "privilege", "user")
            label     = f"{domain}\\{username}" if domain else username

            cred_node_id = f"cred:{cred_id[:8]}"
            add_node(APIGraphNode(
                id    = cred_node_id,
                type  = "credential",
                label = label,
                data  = {
                    "username":  username,
                    "domain":    domain,
                    "privilege": privilege,
                    "cred_type": getattr(cred, "cred_type", ""),
                    "cracked":   getattr(cred, "cracked", False),
                },
                color = _PRIVILEGE_COLORS.get(privilege, "#6c757d"),
                shape = "square",
                size  = 18 if privilege != "domain_admin" else 26,
            ))

            # Edge: cred → host where it was found
            source_host = getattr(cred, "source_host", None)
            if source_host and f"host:{source_host}" in node_ids:
                edges.append(APIGraphEdge(
                    source = f"host:{source_host}",
                    target = cred_node_id,
                    type   = "credential",
                    label  = "harvested",
                    color  = "#ffc107",
                ))

    # ── Findings from campaign ──────────────────────────────────────────────
    findings = getattr(campaign, "findings", [])
    for finding in findings:
        sev      = getattr(getattr(finding, "severity", None), "value", "info")
        title    = getattr(finding, "title", "")
        host     = getattr(finding, "host", None)
        fid      = getattr(finding, "id", "")
        short_id = str(fid)[:8] if fid else hashlib.sha256(title.encode()).hexdigest()[:8]

        find_node_id = f"finding:{short_id}"
        add_node(APIGraphNode(
            id    = find_node_id,
            type  = "finding",
            label = f"[{sev.upper()}]\n{title[:30]}",
            data  = {
                "title":           title,
                "severity":        sev,
                "mitre_technique": getattr(finding, "mitre_technique", ""),
                "mitre_tactic":    getattr(finding, "mitre_tactic", ""),
                "module_id":       getattr(finding, "module_id", ""),
                "description":     getattr(finding, "description", "")[:200],
            },
            color = _SEVERITY_COLORS.get(sev, "#6c757d"),
            shape = "triangle",
            size  = {"critical": 28, "high": 22, "medium": 18, "low": 14}.get(sev, 14),
        ))

        # Edge: finding → affected host
        if host and f"host:{host}" in node_ids:
            edges.append(APIGraphEdge(
                source = f"host:{host}",
                target = find_node_id,
                type   = "compromise",
                label  = sev,
                color  = _SEVERITY_COLORS.get(sev, "#6c757d"),
                weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 1),
            ))

    # ── Pivots ─────────────────────────────────────────────────────────────
    try:
        from ares.pivot.infrastructure import PivotManager
        # Check if campaign has a pivot manager attached
        pm = getattr(campaign, "pivot_manager", None)
        if pm:
            for t_id, tunnel in getattr(pm, "_tunnels", {}).items():
                pivot_id = f"pivot:{t_id[:8]}"
                local_ip = getattr(tunnel, "local_addr", "")
                remote   = getattr(tunnel, "remote_host", "")
                add_node(APIGraphNode(
                    id    = pivot_id,
                    type  = "pivot",
                    label = f"Pivot\n{local_ip}→{remote}",
                    data  = {
                        "tunnel_type": getattr(getattr(tunnel, "tunnel_type", None), "value", ""),
                        "local":       local_ip,
                        "remote":      remote,
                    },
                    color = "#20c997",
                    shape = "hexagon",
                    size  = 22,
                ))
                # Edges: pivot between hosts
                if f"host:{local_ip}" in node_ids and f"host:{remote}" in node_ids:
                    edges.append(APIGraphEdge(
                        source = f"host:{local_ip}",
                        target = f"host:{remote}",
                        type   = "pivot",
                        label  = "pivot",
                        color  = "#20c997",
                        dashed = True,
                    ))
    except (ImportError, AttributeError):
        pass

    # ── Statistics ──────────────────────────────────────────────────────────
    crit_findings = sum(
        1 for n in nodes
        if n.type == "finding" and n.data.get("severity") == "critical"
    )
    owned_hosts = sum(
        1 for n in nodes
        if n.type in ("host", "dc") and n.data.get("owned")
    )

    return {
        "campaign_id": getattr(campaign, "id", ""),
        "campaign_name": getattr(campaign, "name", ""),
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
        "stats": {
            "total_nodes":   len(nodes),
            "total_edges":   len(edges),
            "hosts":         sum(1 for n in nodes if n.type in ("host", "dc")),
            "credentials":   sum(1 for n in nodes if n.type == "credential"),
            "findings":      sum(1 for n in nodes if n.type == "finding"),
            "pivots":        sum(1 for n in nodes if n.type == "pivot"),
            "owned_hosts":   owned_hosts,
            "crit_findings": crit_findings,
        },
        "layout_hint": (
            "hierarchical" if len(nodes) < 20
            else "force_directed"
        ),
        "legend": {
            "node_types": {
                "host":       "Discovered host",
                "dc":         "Domain Controller",
                "credential": "Harvested credential",
                "finding":    "Security finding",
                "pivot":      "Pivot tunnel",
            },
            "edge_types": {
                "lateral":    "Lateral movement",
                "credential": "Credential harvest",
                "discovery":  "Host discovery",
                "compromise": "Compromise path",
                "pivot":      "Pivot route",
            },
            "colors": {
                "compromise_levels": _COMPROMISE_COLORS,
                "severity":          _SEVERITY_COLORS,
                "privilege":         _PRIVILEGE_COLORS,
            },
        },
    }

# Backward-compatible aliases
GraphNode = APIGraphNode
GraphEdge = APIGraphEdge
