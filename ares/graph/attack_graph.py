"""
ARES Attack Knowledge Graph
NetworkX-based directed graph of attack relationships.

Nodes = artifacts (hosts, users, credentials, permissions)
Edges = attack relationships (can_kerberoast, has_access, can_dcsync, owns)

Example graph after AD recon:
  CORP.LOCAL (domain)
    └─[has_user]──► svc_sql (user)
         └─[has_spn]──► MSSQLSvc/db01 (service)
              └─[kerberoastable]──► krb5tgs hash (hash)

  CORP.LOCAL (domain)
    └─[has_acl]──► svc_backup (user)
         └─[writedacl_on]──► Domain Admins (group)
              └─[dcsync_path]──► NTDS hashes (credential)

Attack path query:
  graph.shortest_attack_path("low_priv_user", "domain_admin")
  → [user → WriteDACL → Domain Admins → DCSync → hash → crack → DA]

JSON export is compatible with D3.js force graph visualization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ares.core.logger import get_logger
from ares.normalize.artifacts import (
    ArtifactStore, ArtifactType, CredentialArtifact, DomainArtifact,
    HashArtifact, HostArtifact, NormalizedArtifact, PermissionArtifact, UserArtifact,
)

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False

logger = get_logger("ares.graph")

_GRAPH_SECRET_KEYS = {
    "secret", "secret_enc", "password", "passwd", "token", "api_key",
    "private_key", "hash_value", "nt_hash", "lm_hash", "cracked_value",
}


def _safe_graph_value(value: Any) -> Any:
    """Drop secret-bearing fields before graph data is persisted or returned."""
    if isinstance(value, dict):
        return {
            str(key): _safe_graph_value(item)
            for key, item in value.items()
            if str(key).lower() not in _GRAPH_SECRET_KEYS
        }
    if isinstance(value, list):
        return [_safe_graph_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# ── Edge types ────────────────────────────────────────────────────────────────

class EdgeType(str):
    HAS_USER        = "has_user"
    HAS_GROUP       = "has_group"
    HAS_HOST        = "has_host"
    MEMBER_OF       = "member_of"
    HAS_SPN         = "has_spn"
    KERBEROASTABLE  = "kerberoastable"
    ASREPROASTABLE  = "asreproastable"
    HAS_CRED        = "has_credential"
    ACE             = "ace"               # principal→right→target
    DCSYNC_PATH     = "dcsync_path"
    CAN_ACCESS      = "can_access"
    OWNS            = "owns"
    ADMIN_ON        = "admin_on"
    HAS_SESSION     = "has_session"
    TRUST           = "trust"


# ── Graph node ────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    node_id:       str
    label:         str
    node_type:     str    # host | user | group | credential | domain | hash | permission
    properties:    dict[str, Any] = field(default_factory=dict)
    risk_score:    float = 0.0
    is_target:     bool = False   # high-value targets: DA, DC, krbtgt


@dataclass
class GraphEdge:
    source:        str
    target:        str
    edge_type:     str
    label:         str = ""
    weight:        float = 1.0    # lower weight = easier attack path
    properties:    dict[str, Any] = field(default_factory=dict)


# ── Attack graph ──────────────────────────────────────────────────────────────

class AttackGraph:
    """
    Directed graph of attack relationships.
    Built from normalized artifacts, queryable for attack paths.

    Usage:
        graph = AttackGraph()
        graph.build_from_store(artifact_store)
        paths = graph.attack_paths_to_domain_admin()
        viz   = graph.to_d3_json()
    """

    # Node type → visual color (for dashboard/D3)
    NODE_COLORS: dict[str, str] = {
        "domain":     "#ef4444",   # red
        "host":       "#3b82f6",   # blue
        "user":       "#10b981",   # green
        "group":      "#f59e0b",   # yellow
        "credential": "#8b5cf6",   # purple
        "hash":       "#ec4899",   # pink
        "permission": "#f97316",   # orange
        "cloud":      "#06b6d4",   # cyan
    }

    # High-value targets - finding a path to these is the goal
    HIGH_VALUE_LABELS = {
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "krbtgt", "NTDS.dit",
    }

    def __init__(self) -> None:
        if not _NX_AVAILABLE:
            raise ImportError(
                "networkx is required for attack graph: pip install networkx"
            )
        self._g: Any = nx.DiGraph()  # type: ignore[attr-defined]
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    @classmethod
    def from_d3_json(cls, payload: dict[str, Any]) -> "AttackGraph":
        """Rehydrate a graph snapshot produced by :meth:`to_d3_json`."""
        graph = cls()
        graph.load_d3_json(payload)
        return graph

    def load_d3_json(self, payload: dict[str, Any]) -> "AttackGraph":
        """Load safe D3 graph metadata into this graph instance."""
        for raw_node in payload.get("nodes", []):
            if not isinstance(raw_node, dict) or not raw_node.get("id"):
                continue
            node = GraphNode(
                node_id=str(raw_node["id"]),
                label=str(raw_node.get("label") or raw_node["id"]),
                node_type=str(raw_node.get("type") or "unknown"),
                properties=_safe_graph_value(raw_node.get("properties", {})),
                risk_score=float(raw_node.get("risk", 0.0) or 0.0),
                is_target=bool(raw_node.get("is_target", False)),
            )
            self._add_node(node)
        for raw_edge in payload.get("links", []):
            if not isinstance(raw_edge, dict):
                continue
            source, target = raw_edge.get("source"), raw_edge.get("target")
            if not source or not target:
                continue
            self._add_edge(GraphEdge(
                source=str(source),
                target=str(target),
                edge_type=str(raw_edge.get("type") or "related"),
                label=str(raw_edge.get("label") or ""),
                weight=float(raw_edge.get("weight", 1.0) or 1.0),
                properties=_safe_graph_value(raw_edge.get("properties", {})),
            ))
        return self

    def add_persisted_campaign_data(
        self,
        hosts: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        credentials: list[dict[str, Any]],
    ) -> "AttackGraph":
        """Add durable host/finding/credential metadata without any secret values."""
        host_ids: dict[str, str] = {}
        for host in hosts:
            ip = str(host.get("ip_address") or "")
            if not ip:
                continue
            node_id = f"host:{ip}"
            host_ids[ip.lower()] = node_id
            hostname = str(host.get("hostname") or "").strip().lower()
            if hostname:
                host_ids[hostname] = node_id
                if "." in hostname:
                    host_ids[hostname.split(".")[0]] = node_id
            fqdn = str(host.get("fqdn") or "").strip().lower()
            if fqdn:
                host_ids[fqdn] = node_id
                if "." in fqdn:
                    host_ids[fqdn.split(".")[0]] = node_id

            label = str(host.get("hostname") or ip)
            self._add_node(GraphNode(
                node_id=node_id,
                label=label,
                node_type="domain_controller" if host.get("is_dc") else "host",
                properties={
                    "ip": ip,
                    "hostname": host.get("hostname") or "",
                    "os": host.get("os") or "",
                    "domain": host.get("domain") or "",
                    "open_ports": host.get("open_ports_json") or [],
                },
                risk_score=4.0 if host.get("is_dc") else 2.0,
                is_target=bool(host.get("is_dc")),
            ))

        # Lateral movement paths between hosts in the environment
        dc_ids = [f"host:{h.get('ip_address')}" for h in hosts if h.get("is_dc")]
        ws_ids = [
            f"host:{h.get('ip_address')}" for h in hosts
            if not h.get("is_dc") and any(w in str(h.get("hostname", "")).lower() for w in ("ws", "pc", "client", "workstation"))
        ]
        srv_ids = [
            f"host:{h.get('ip_address')}" for h in hosts
            if not h.get("is_dc") and any(s in str(h.get("hostname", "")).lower() for s in ("sql", "fs", "srv"))
        ]
        for ws_id in ws_ids:
            for srv_id in srv_ids:
                if ws_id in self._g and srv_id in self._g and ws_id != srv_id:
                    self._add_edge(GraphEdge(
                        source=ws_id, target=srv_id,
                        edge_type="lateral", label="pivot", weight=1.5,
                    ))
        for srv_id in srv_ids:
            for dc_id in dc_ids:
                if srv_id in self._g and dc_id in self._g and srv_id != dc_id:
                    self._add_edge(GraphEdge(
                        source=srv_id, target=dc_id,
                        edge_type="lateral", label="domain_admin", weight=2.0,
                    ))

        for finding in findings:
            finding_id = str(finding.get("id") or "")
            title = str(finding.get("title") or "Finding")
            node_id = f"finding:{finding_id or title[:80]}"
            self._add_node(GraphNode(
                node_id=node_id,
                label=title,
                node_type="finding",
                properties={
                    "severity": finding.get("severity") or "info",
                    "module_id": finding.get("module_id") or "",
                    "cvss_score": finding.get("cvss_score") or 0.0,
                    "mitre_technique": finding.get("mitre_technique") or "",
                    "trace_id": finding.get("trace_id") or "",
                },
                risk_score=float(finding.get("cvss_score") or 0.0),
            ))
            host = str(finding.get("host") or "").strip().lower()
            target_host_node = host_ids.get(host)
            if not target_host_node and "." in host:
                target_host_node = host_ids.get(host.split(".")[0])
            if not target_host_node and host and host not in ("localhost", "127.0.0.1"):
                target_host_node = f"host:{host}"
                host_ids[host] = target_host_node
                self._add_node(GraphNode(
                    node_id=target_host_node,
                    label=host,
                    node_type="host",
                    properties={"ip": host, "hostname": host},
                    risk_score=2.0,
                    is_target=False,
                ))
            if not target_host_node and len(host_ids) == 1:
                target_host_node = list(host_ids.values())[0]

            if target_host_node and target_host_node in self._g:
                self._add_edge(GraphEdge(
                    source=target_host_node, target=node_id,
                    edge_type="finding", label="finding", weight=1.0,
                ))
        for credential in credentials:
            cred_id = str(credential.get("id") or "")
            username = str(credential.get("username") or "credential")
            domain = str(credential.get("domain") or "")
            self._add_node(GraphNode(
                node_id=f"credential:{cred_id or username}",
                label=f"{domain}\\{username}" if domain else username,
                node_type="credential",
                properties={
                    "cred_type": credential.get("cred_type") or "",
                    "source_module": credential.get("source_module") or "",
                    "cracked": bool(credential.get("cracked", False)),
                },
                risk_score=2.0,
            ))
        return self

    # ── Build from artifact store ──────────────────────────────────────────

    def build_from_store(self, store: ArtifactStore) -> "AttackGraph":
        """
        Automatically build graph from all artifacts in a store.
        This is the main entry point - call after a campaign run.
        """
        for host in store.hosts():
            self._add_host(host)

        for user in store.users():
            self._add_user(user)

        for perm in store.permissions():
            self._add_permission(perm)

        for h in store.hashes():
            self._add_hash(h)

        for cred in store.credentials():
            self._add_credential(cred)

        logger.info(
            "graph_built",
            nodes=self._g.number_of_nodes(),
            edges=self._g.number_of_edges(),
        )
        return self

    def _add_host(self, host: HostArtifact) -> None:
        nid = host.uid
        self._add_node(GraphNode(
            node_id=nid, label=host.hostname or host.ip_address,
            node_type="host" if not host.is_dc else "domain_controller",
            properties={"ip": host.ip_address, "os": host.os, "is_dc": host.is_dc},
            risk_score=4.0 if host.is_dc else 2.0,
            is_target=host.is_dc,
        ))

    def _add_user(self, user: UserArtifact) -> None:
        nid = user.uid
        self._add_node(GraphNode(
            node_id=nid, label=f"{user.domain}\\{user.username}",
            node_type="user",
            properties={
                "username": user.username, "domain": user.domain,
                "is_admin": user.is_admin, "enabled": user.enabled,
                "spns": user.spns, "no_preauth": user.no_preauth,
            },
            risk_score=5.0 if user.is_admin else (3.0 if user.spns else 1.0),
            is_target=user.is_admin or "Domain Admins" in user.member_of,
        ))

        # User → group membership edges
        for group in user.member_of:
            group_nid = f"group:{user.domain}:{group}"
            self._add_node(GraphNode(
                node_id=group_nid, label=group,
                node_type="group",
                is_target=group in self.HIGH_VALUE_LABELS,
                risk_score=5.0 if group in self.HIGH_VALUE_LABELS else 2.0,
            ))
            self._add_edge(GraphEdge(
                source=nid, target=group_nid,
                edge_type=EdgeType.MEMBER_OF, label="member of",
                weight=0.5,
            ))

        # SPN → kerberoastable edge
        if user.is_kerberoastable:
            hash_nid = f"hash:krb5tgs:{user.uid}"
            self._add_node(GraphNode(
                node_id=hash_nid, label=f"TGS:{user.username}",
                node_type="hash",
                properties={"hashcat_mode": 13100, "hash_type": "krb5tgs"},
                risk_score=3.5,
            ))
            self._add_edge(GraphEdge(
                source=nid, target=hash_nid,
                edge_type=EdgeType.KERBEROASTABLE,
                label="kerberoastable",
                weight=1.0,
                properties={"attack": "ad.kerberoast"},
            ))

        # ASREPRoastable edge
        if user.is_asreproastable:
            hash_nid = f"hash:krb5asrep:{user.uid}"
            self._add_node(GraphNode(
                node_id=hash_nid, label=f"AS-REP:{user.username}",
                node_type="hash",
                properties={"hashcat_mode": 18200, "hash_type": "krb5asrep"},
                risk_score=3.5,
            ))
            self._add_edge(GraphEdge(
                source=nid, target=hash_nid,
                edge_type=EdgeType.ASREPROASTABLE,
                label="asreproastable (no creds needed)",
                weight=0.5,  # lower = easier
                properties={"attack": "ad.asreproast"},
            ))

    def _add_permission(self, perm: PermissionArtifact) -> None:
        if not perm.is_dangerous:
            return
        p_nid = f"user:{perm.domain}:{perm.principal}"
        t_nid = f"object:{perm.domain}:{perm.target}"

        # Ensure principal node exists
        if p_nid not in self._nodes:
            self._add_node(GraphNode(node_id=p_nid, label=perm.principal, node_type="user"))

        # Target node
        self._add_node(GraphNode(
            node_id=t_nid, label=perm.target,
            node_type="group" if "Admins" in perm.target else "object",
            is_target=perm.target in self.HIGH_VALUE_LABELS,
        ))

        self._add_edge(GraphEdge(
            source=p_nid, target=t_nid,
            edge_type=EdgeType.ACE,
            label=perm.right,
            weight=0.3,  # ACL abuse is very powerful
            properties={"right": perm.right, "attack": "ad.enum_acl"},
        ))

        # WriteDACL / GenericAll → can reach DCSync
        if perm.right in ("WriteDACL", "GenericAll", "DS-Replication-Get-Changes-All"):
            dcsync_nid = f"hash:ntds:{perm.domain}"
            self._add_node(GraphNode(
                node_id=dcsync_nid, label=f"NTDS:{perm.domain}",
                node_type="credential",
                risk_score=5.0, is_target=True,
            ))
            self._add_edge(GraphEdge(
                source=t_nid, target=dcsync_nid,
                edge_type=EdgeType.DCSYNC_PATH,
                label="dcsync → all hashes",
                weight=0.2,
                properties={"attack": "ad.dcsync"},
            ))

    def _add_hash(self, h: HashArtifact) -> None:
        nid = h.uid
        self._add_node(GraphNode(
            node_id=nid, label=f"{h.hash_type}:{h.username}",
            node_type="hash",
            properties={"hashcat_mode": h.hashcat_mode, "domain": h.domain},
            risk_score=3.0,
        ))

    def _add_credential(self, cred: CredentialArtifact) -> None:
        nid = cred.uid
        self._add_node(GraphNode(
            node_id=nid, label=f"CRED:{cred.domain}\\{cred.username}",
            node_type="credential",
            properties={"cred_type": cred.cred_type, "cracked": cred.cracked},
            risk_score=4.5 if cred.cracked else 2.0,
        ))

    # ── Graph internals ────────────────────────────────────────────────────

    def _add_node(self, node: GraphNode) -> None:
        self._nodes[node.node_id] = node
        self._g.add_node(
            node.node_id,
            label=node.label,
            node_type=node.node_type,
            risk_score=node.risk_score,
            is_target=node.is_target,
            properties=node.properties,
        )

    def _add_edge(self, edge: GraphEdge) -> None:
        self._edges.append(edge)
        self._g.add_edge(
            edge.source, edge.target,
            edge_type=edge.edge_type,
            label=edge.label,
            weight=edge.weight,
            properties=edge.properties,
        )

    # ── Attack path queries ────────────────────────────────────────────────

    def attack_paths_to_domain_admin(self) -> list[list[str]]:
        """Find all attack paths leading to Domain Admin / high-value nodes."""
        targets = [
            nid for nid, data in self._g.nodes(data=True)
            if data.get("is_target")
        ]
        sources = [
            nid for nid, data in self._g.nodes(data=True)
            if not data.get("is_target") and data.get("node_type") == "user"
        ]

        paths: list[list[str]] = []
        for src in sources:
            for tgt in targets:
                try:
                    path = nx.shortest_path(self._g, src, tgt, weight="weight")
                    if len(path) > 1:
                        paths.append(path)
                except nx.NetworkXNoPath:
                    pass
                except nx.NodeNotFound:
                    pass

        return sorted(paths, key=len)  # shortest first

    def shortest_attack_path(self, source_id: str, target_id: str) -> list[str] | None:
        """Dijkstra shortest path between two specific nodes."""
        try:
            return nx.dijkstra_path(self._g, source_id, target_id, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    # ── Path finding (user-facing) ─────────────────────────────────────────

    def find_path(self, source_label: str, target_label: str) -> list[str] | None:
        """
        Find shortest attack path between two nodes identified by label (not ID).
        More user-friendly than shortest_attack_path() which requires exact IDs.

        Example:
            graph.find_path("jsmith", "Domain Admins")
            graph.find_path("10.0.0.5", "krbtgt")
        """
        src_id = self._find_node_by_label(source_label)
        tgt_id = self._find_node_by_label(target_label)
        if not src_id or not tgt_id:
            return None
        return self.shortest_attack_path(src_id, tgt_id)

    def _find_node_by_label(self, label: str) -> str | None:
        """Fuzzy label lookup - returns first matching node ID."""
        label_lower = label.lower()
        # Exact match first
        for nid, data in self._g.nodes(data=True):
            if data.get("label", "").lower() == label_lower:
                return nid
        # Partial match fallback
        for nid, data in self._g.nodes(data=True):
            if label_lower in data.get("label", "").lower():
                return nid
        return None

    def score_path(self, path: list[str]) -> float:
        """
        Compute total attack difficulty score for a path.
        Lower score = easier path (attacker perspective).
        Sum of edge weights along the path.
        """
        if len(path) < 2:
            return 0.0
        total = 0.0
        for i in range(len(path) - 1):
            edge_data = self._g.get_edge_data(path[i], path[i + 1]) or {}
            total += edge_data.get("weight", 1.0)
        return round(total, 3)

    def path_to_report(self, path: list[str]) -> dict[str, Any]:
        """
        Convert a path (list of node IDs) into a human-readable report dict.
        Includes node labels, edge attack modules, and total score.

        Example output:
            {
              "path": ["jsmith → TGS:svc_sql → Domain Admins"],
              "steps": [
                {"from": "jsmith", "to": "TGS:svc_sql", "attack": "ad.kerberoast", "weight": 1.0},
                ...
              ],
              "total_score": 1.2,
              "attack_modules": ["ad.kerberoast", "ad.dcsync"],
            }
        """
        steps = []
        modules_used: list[str] = []
        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            edge_data = self._g.get_edge_data(src, tgt) or {}
            src_node  = self._nodes.get(src)
            tgt_node  = self._nodes.get(tgt)
            attack    = edge_data.get("properties", {}).get("attack", edge_data.get("edge_type", ""))
            if attack and attack not in modules_used:
                modules_used.append(attack)
            steps.append({
                "from":   src_node.label if src_node else src,
                "to":     tgt_node.label if tgt_node else tgt,
                "edge":   edge_data.get("label", edge_data.get("edge_type", "")),
                "attack": attack,
                "weight": edge_data.get("weight", 1.0),
            })

        return {
            "path_length":    len(path),
            "total_score":    self.score_path(path),
            "steps":          steps,
            "attack_modules": modules_used,
            "start":          self._nodes[path[0]].label if path and path[0] in self._nodes else (path[0] if path else ""),
            "end":            self._nodes[path[-1]].label if path and path[-1] in self._nodes else (path[-1] if path else ""),
        }

    def top_paths(self, n: int = 5) -> list[dict[str, Any]]:
        """
        Return the top-N attack paths sorted by difficulty score (easiest first).
        Each entry is the output of path_to_report().
        """
        all_paths = self.attack_paths_to_domain_admin()
        scored = []
        for p in all_paths:
            scored.append((self.score_path(p), p))
        scored.sort(key=lambda x: x[0])  # lowest score = easiest
        return [self.path_to_report(p) for _, p in scored[:n]]

    def high_value_nodes(self) -> list[GraphNode]:
        """Return all high-value target nodes (DC, Domain Admins, krbtgt, etc.)."""
        return [
            self._nodes.get(
                nid,
                GraphNode(
                    node_id=nid,
                    label=str(data.get("label", nid)),
                    node_type=str(data.get("node_type", "unknown")),
                    properties=_safe_graph_value(data.get("properties", {})),
                    risk_score=float(data.get("risk_score", 0.0) or 0.0),
                    is_target=True,
                ),
            )
            for nid, data in self._g.nodes(data=True)
            if data.get("is_target")
        ]

    def riskiest_users(self, top_n: int = 10) -> list[GraphNode]:
        """Users sorted by risk score - best attack starting points."""
        users = [
            n for n in self._nodes.values()
            if n.node_type in ("user", "service_account")
        ]
        return sorted(users, key=lambda n: -n.risk_score)[:top_n]

    def stats(self) -> dict[str, Any]:
        dc_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == "domain_controller" or d.get("is_dc")
        ]
        owned_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("owned") or d.get("is_owned")
        ]
        return {
            "nodes":                   self._g.number_of_nodes(),
            "edges":                   self._g.number_of_edges(),
            "high_value":              len(self.high_value_nodes()),
            "attack_paths":            len(self.attack_paths_to_domain_admin()),
            "density":                 round(nx.density(self._g), 4),
            "domain_controller_nodes": len(dc_nodes),
            "owned_nodes":             len(owned_nodes),
        }

    # ── Export ─────────────────────────────────────────────────────────────

    def to_d3_json(self) -> dict[str, Any]:
        """
        Export as D3.js force-directed graph JSON.
        Plug directly into the dashboard's graph view.

        Format:
          {"nodes": [{id, label, type, color, risk, is_target}],
           "links": [{source, target, label, type, weight}]}
        """
        nodes = []
        for nid, data in self._g.nodes(data=True):
            ntype = data.get("node_type", "unknown")
            nodes.append({
                "id":       nid,
                "label":    data.get("label", nid),
                "type":     ntype,
                "color":    self.NODE_COLORS.get(ntype, "#94a3b8"),
                "risk":     data.get("risk_score", 1.0),
                "is_target": data.get("is_target", False),
                "properties": _safe_graph_value(data.get("properties", {})),
            })

        links = []
        for src, tgt, data in self._g.edges(data=True):
            links.append({
                "source":    src,
                "target":    tgt,
                "label":     data.get("label", ""),
                "type":      data.get("edge_type", ""),
                "weight":    data.get("weight", 1.0),
                "properties": _safe_graph_value(data.get("properties", {})),
            })

        return {"nodes": nodes, "links": links}

    def to_graphml(self, path: str) -> None:
        """Export to GraphML (compatible with Gephi, yEd)."""
        nx.write_graphml(self._g, path)
        logger.info("graph_exported_graphml", path=path)

    def to_dot(self, path: str) -> None:
        """Export to DOT format (compatible with Graphviz)."""
        try:
            from networkx.drawing.nx_pydot import write_dot
            write_dot(self._g, path)
        except ImportError:
            # Manual DOT generation if pydot not available
            lines = ["digraph ARES {"]
            for nid, data in self._g.nodes(data=True):
                label = data.get("label", nid).replace('"', '\\"')
                ntype = data.get("node_type", "unknown")
                lines.append(f'  "{nid}" [label="{label}" type="{ntype}"];')
            for src, tgt, data in self._g.edges(data=True):
                elabel = data.get("label", "").replace('"', '\\"')
                lines.append(f'  "{src}" -> "{tgt}" [label="{elabel}"];')
            lines.append("}")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        logger.info("graph_exported_dot", path=path)

    # ── Bloodhound JSON Ingest ────────────────────────────────────────────────

    # ── Bloodhound Ingest Pipeline (Two-Pass Architecture) ────────────────────

    def ingest_bloodhound(self, json_path: str) -> dict[str, int]:
        """
        Import BloodHound/SharpHound collection into the ARES attack graph.

        Supports BloodHound CE (v5+), legacy (v4) JSON formats, and SharpHound .zip archives.
        Parses: computers, users, groups, domains, sessions, LocalAdmins, and ACLs/ACEs.
        Uses a two-pass resolution pipeline to prevent SID vs. Name split-brain disconnection.
        After ingest, use find_path() / top_paths() / shortest_path_to_da() to compute attack paths.

        Args:
            json_path: Path to BloodHound JSON file, .zip archive, or directory containing JSON files.

        Returns:
            dict with counts: {"nodes_added": N, "edges_added": N, "file_count": N}
        """
        import json as _json
        import zipfile
        from pathlib import Path

        if not _NX_AVAILABLE:
            logger.warning("bloodhound_ingest_requires_networkx")
            return {"nodes_added": 0, "edges_added": 0, "error": "networkx not installed"}

        p = Path(json_path)
        raw_payloads: list[tuple[str, dict]] = []

        if p.is_file() and (p.suffix.lower() == ".zip" or zipfile.is_zipfile(p)):
            try:
                with zipfile.ZipFile(p, "r") as zf:
                    for name in sorted(zf.namelist()):
                        if name.lower().endswith(".json") and not name.startswith("__MACOSX"):
                            try:
                                with zf.open(name) as fh:
                                    data = _json.loads(fh.read().decode("utf-8", errors="replace"))
                                    raw_payloads.append((name, data))
                            except Exception as exc:
                                logger.warning("bloodhound_zip_member_error", member=name, error=str(exc)[:100])
            except Exception as exc:
                logger.warning("bloodhound_zip_read_error", file=str(p), error=str(exc)[:100])
                return {"nodes_added": 0, "edges_added": 0, "error": f"Failed to read zip archive: {str(exc)[:100]}"}

        elif p.is_dir():
            for fp in sorted(p.glob("*.json")):
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        raw_payloads.append((fp.name, _json.load(fh)))
                except Exception as exc:
                    logger.warning("bloodhound_parse_error", file=str(fp), error=str(exc)[:100])

        elif p.is_file():
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    raw_payloads.append((p.name, _json.load(fh)))
            except Exception as exc:
                logger.warning("bloodhound_parse_error", file=str(p), error=str(exc)[:100])
                return {"nodes_added": 0, "edges_added": 0, "error": f"Failed to parse JSON file: {str(exc)[:100]}"}

        else:
            return {"nodes_added": 0, "edges_added": 0, "error": f"Path not found: {json_path}"}

        if not raw_payloads:
            return {"nodes_added": 0, "edges_added": 0, "file_count": 0}

        nodes_before = self._g.number_of_nodes()
        edges_before = self._g.number_of_edges()

        # Two-pass parsing across all collected payloads
        self._parse_bloodhound_datasets(raw_payloads)

        nodes_added = self._g.number_of_nodes() - nodes_before
        edges_added = self._g.number_of_edges() - edges_before
        logger.info(
            "bloodhound_ingest_complete",
            nodes=nodes_added,
            edges=edges_added,
            files=len(raw_payloads),
        )
        return {
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "file_count": len(raw_payloads),
        }

    def _parse_bloodhound_json(self, data: dict) -> None:
        """Backward-compatible single-payload ingest helper."""
        self._parse_bloodhound_datasets([("data.json", data)])

    def _parse_bloodhound_datasets(self, raw_payloads: list[tuple[str, dict]]) -> None:
        """Two-pass ingestion of BloodHound datasets to eliminate SID vs. Name split-brain."""
        sid_to_id: dict[str, str] = {}
        name_to_id: dict[str, str] = {}
        normalized_items: list[tuple[str, dict]] = []

        # ── PASS 1: Identify all entities, index SIDs and canonical Names ───────────
        for _fname, data in raw_payloads:
            if not isinstance(data, dict):
                continue
            meta = data.get("meta") or {}
            bh_type = str(meta.get("type") or "").strip().lower()
            items = data.get("data")

            # Legacy fallback: top-level key detection
            if items is None:
                for key in ("computers", "users", "groups", "domains", "sessions", "ous", "gpos"):
                    if key in data and isinstance(data[key], list):
                        items = data[key]
                        bh_type = key
                        break

            if not items or not isinstance(items, list):
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue
                normalized_items.append((bh_type, item))
                props = item.get("Properties") or item.get("properties") or {}
                raw_name = str(props.get("name") or item.get("name") or "").strip()
                name = raw_name.upper()

                # Extract SIDs / ObjectIdentifiers
                oid = str(
                    item.get("ObjectIdentifier")
                    or props.get("objectid")
                    or props.get("domainsid")
                    or ""
                ).strip().upper()

                # Normalize category
                entity_type = "object"
                if bh_type in ("computers", "computer"):
                    entity_type = "computer"
                elif bh_type in ("users", "user"):
                    entity_type = "user"
                elif bh_type in ("groups", "group"):
                    entity_type = "group"
                elif bh_type in ("domains", "domain"):
                    entity_type = "domain"
                elif bh_type in ("ous", "ou"):
                    entity_type = "ou"
                elif bh_type in ("gpos", "gpo"):
                    entity_type = "gpo"
                elif bh_type in ("sessions", "session"):
                    continue

                canonical_id = f"{entity_type}:{name}" if name else (f"{entity_type}:{oid}" if oid else "")
                if not canonical_id:
                    continue

                if oid:
                    sid_to_id[oid] = canonical_id
                    sid_to_id[f"{entity_type}:{oid}"] = canonical_id
                if name:
                    name_to_id[name] = canonical_id
                    name_to_id[f"{entity_type}:{name}"] = canonical_id
                    if "@" in name:
                        name_to_id[name.split("@")[0]] = canonical_id
                    if "." in name:
                        name_to_id[name.split(".")[0]] = canonical_id

                # Register canonical node in GraphNode dictionary and NetworkX
                is_target = False
                label = raw_name or oid
                node_type = entity_type

                if entity_type == "computer":
                    is_dc = bool(props.get("isdc", props.get("isDC", False)))
                    node_type = "domain_controller" if is_dc else "host"
                    is_target = is_dc
                elif entity_type == "user":
                    is_admin = bool(props.get("admincount", False))
                    is_target = is_admin or ("ADMIN" in name)
                elif entity_type == "group":
                    is_da = "DOMAIN ADMINS" in name or "ENTERPRISE ADMINS" in name or "ADMINISTRATORS" in name
                    is_target = is_da
                elif entity_type == "domain":
                    is_target = True

                self._add_node(GraphNode(
                    node_id=canonical_id,
                    label=label,
                    node_type=node_type,
                    properties={
                        "name": raw_name,
                        "sid": oid,
                        "domain": str(props.get("domain") or "").upper(),
                        "enabled": props.get("enabled", True),
                        "has_spn": props.get("hasspn", False),
                        "no_preauth": props.get("dontreqpreauth", False),
                        "os": props.get("operatingsystem", ""),
                    },
                    risk_score=5.0 if is_target else 1.0,
                    is_target=is_target,
                ))

        # Helper to resolve any SID, Name, or typed reference to canonical node ID
        def _resolve_node(ref: Any, default_type: str = "object") -> str:
            if not ref or not isinstance(ref, (str, int)):
                return ""
            r_str = str(ref).strip()
            r_upper = r_str.upper()

            if r_upper in sid_to_id:
                return sid_to_id[r_upper]
            if r_upper in name_to_id:
                return name_to_id[r_upper]

            if ":" in r_str:
                _pfx, rest = r_str.split(":", 1)
                rest_upper = rest.strip().upper()
                if rest_upper in sid_to_id:
                    return sid_to_id[rest_upper]
                if rest_upper in name_to_id:
                    return name_to_id[rest_upper]
            else:
                for pfx in ("user", "computer", "group", "domain"):
                    pfx_key = f"{pfx}:{r_upper}"
                    if pfx_key in sid_to_id:
                        return sid_to_id[pfx_key]
                    if pfx_key in name_to_id:
                        return name_to_id[pfx_key]

            # If not in registry, create dummy canonical node to preserve graph connectivity
            fallback_id = r_str.lower() if ":" in r_str else f"{default_type}:{r_str}".lower()
            if fallback_id not in self._nodes and fallback_id not in self._g:
                self._add_node(GraphNode(
                    node_id=fallback_id,
                    label=r_str,
                    node_type=default_type or "object",
                    is_target=False,
                ))
            return fallback_id

        _DANGEROUS_RIGHTS = {
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
            "AllExtendedRights", "ForceChangePassword", "AddMember",
            "ReadLAPSPassword", "ReadGMSAPassword", "DCSync",
            "Owns", "AddSelf", "AddAllowedToAct",
        }
        _RIGHT_WEIGHTS = {
            "DCSync": 0.1,
            "GenericAll": 0.15,
            "WriteOwner": 0.2,
            "WriteDacl": 0.2,
            "Owns": 0.2,
            "ForceChangePassword": 0.25,
            "AddMember": 0.25,
            "AllExtendedRights": 0.3,
            "ReadLAPSPassword": 0.35,
            "ReadGMSAPassword": 0.35,
            "GenericWrite": 0.4,
            "AddSelf": 0.4,
            "AddAllowedToAct": 0.45,
        }

        # ── PASS 2: Stitch all edges across resolved canonical nodes ────────────────
        for bh_type, item in normalized_items:
            props = item.get("Properties") or item.get("properties") or {}
            raw_name = str(props.get("name") or item.get("name") or "").strip()
            name = raw_name.upper()
            oid = str(item.get("ObjectIdentifier") or props.get("objectid") or "").strip().upper()

            entity_type = "computer" if bh_type in ("computers", "computer") else (
                "user" if bh_type in ("users", "user") else (
                    "group" if bh_type in ("groups", "group") else (
                        "domain" if bh_type in ("domains", "domain") else "object"
                    )
                )
            )
            target_node = _resolve_node(oid or name, default_type=entity_type)
            domain_name = str(props.get("domain") or "").strip().upper()
            domain_node = _resolve_node(domain_name, default_type="domain") if domain_name else ""

            # Domain hierarchy edges
            if domain_node and target_node and domain_node != target_node:
                rel_label = f"has_{entity_type}"
                self._add_edge(GraphEdge(
                    source=domain_node,
                    target=target_node,
                    edge_type=rel_label,
                    label=rel_label,
                    weight=0.1,
                ))

            # 1. Access Control Entries (ACEs)
            aces = item.get("Aces") or item.get("aces") or []
            for ace in aces:
                if not isinstance(ace, dict):
                    continue
                right = ace.get("RightName") or ace.get("rightname") or ""
                principal_sid = ace.get("PrincipalSID") or ace.get("principalsid") or ""
                ptype = str(ace.get("PrincipalType") or ace.get("principaltype") or "user").lower()

                if right in _DANGEROUS_RIGHTS and principal_sid:
                    src_node = _resolve_node(principal_sid, default_type=ptype)
                    if src_node and target_node and src_node != target_node:
                        w = _RIGHT_WEIGHTS.get(right, 0.5)
                        self._add_edge(GraphEdge(
                            source=src_node,
                            target=target_node,
                            edge_type=EdgeType.ACE,
                            label=right.lower(),
                            weight=w,
                            properties={"right": right, "inherited": ace.get("IsInherited", False)},
                        ))

            # 2. Group Membership
            if bh_type in ("groups", "group"):
                members = item.get("Members") or item.get("members") or []
                for m in members:
                    if not isinstance(m, dict):
                        continue
                    m_ref = m.get("MemberId") or m.get("ObjectIdentifier") or ""
                    m_type = str(m.get("MemberType") or m.get("ObjectType") or "user").lower()
                    src_member = _resolve_node(m_ref, default_type=m_type)
                    if src_member and target_node and src_member != target_node:
                        self._add_edge(GraphEdge(
                            source=src_member,
                            target=target_node,
                            edge_type=EdgeType.MEMBER_OF,
                            label="member_of",
                            weight=0.05,
                        ))

            # 3. Computer Local Admins & Permissions
            if bh_type in ("computers", "computer"):
                def _process_comp_members(data_field: str, rel_type: str, weight: float) -> None:
                    raw_block = item.get(data_field)
                    entries = raw_block.get("Results", []) if isinstance(raw_block, dict) else (
                        raw_block if isinstance(raw_block, list) else []
                    )
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        e_ref = entry.get("ObjectIdentifier") or entry.get("MemberId") or ""
                        e_type = str(entry.get("ObjectType") or entry.get("MemberType") or "user").lower()
                        src = _resolve_node(e_ref, default_type=e_type)
                        if src and target_node and src != target_node:
                            self._add_edge(GraphEdge(
                                source=src,
                                target=target_node,
                                edge_type=rel_type,
                                label=rel_type,
                                weight=weight,
                            ))

                _process_comp_members("LocalAdmins", "admin_to", 0.2)
                _process_comp_members("RemoteDesktopUsers", "can_rdp", 0.4)
                _process_comp_members("DcomUsers", "execute_dcom", 0.4)

                # Computer Sessions (Inside computer item)
                raw_sess = item.get("Sessions")
                sess_entries = raw_sess.get("Results", []) if isinstance(raw_sess, dict) else (
                    raw_sess if isinstance(raw_sess, list) else []
                )
                for s in sess_entries:
                    if not isinstance(s, dict):
                        continue
                    u_ref = s.get("UserId") or s.get("UserName") or ""
                    user_node = _resolve_node(u_ref, default_type="user")
                    if target_node and user_node and target_node != user_node:
                        # Compromising computer yields user credential session
                        self._add_edge(GraphEdge(
                            source=target_node,
                            target=user_node,
                            edge_type=EdgeType.HAS_SESSION,
                            label="has_session",
                            weight=0.3,
                        ))

            # 4. Standalone Sessions File
            if bh_type in ("sessions", "session"):
                c_ref = item.get("ComputerId") or item.get("ComputerName") or ""
                u_ref = item.get("UserId") or item.get("UserName") or ""
                c_node = _resolve_node(c_ref, default_type="computer")
                u_node = _resolve_node(u_ref, default_type="user")
                if c_node and u_node and c_node != u_node:
                    self._add_edge(GraphEdge(
                        source=c_node,
                        target=u_node,
                        edge_type=EdgeType.HAS_SESSION,
                        label="has_session",
                        weight=0.3,
                    ))

    def shortest_path_to_da(self, start_node: str | None = None) -> dict[str, Any] | None:
        """
        Compute shortest attack path from start_node (or any user) to Domain Admins group.

        Uses Dijkstra with edge weights (lower = easier to exploit).
        Returns structured report dict with steps, weights, and techniques, or None if no path exists.
        """
        if not _NX_AVAILABLE or not self._g.nodes:
            return None

        # Find DA group node
        da_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("is_target") and any(
                term in d.get("label", "").upper()
                for term in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS")
            )
        ]
        if not da_nodes:
            da_nodes = [n for n in self._g.nodes if "domain admin" in str(n).lower()]
        if not da_nodes:
            return None

        # If start specified, resolve it via registry or labels
        if start_node:
            resolved_start = start_node
            if start_node not in self._g:
                # Try finding by label or suffix
                for n, d in self._g.nodes(data=True):
                    if d.get("label") == start_node or str(n).upper() == start_node.upper():
                        resolved_start = n
                        break
            start_nodes = [resolved_start] if resolved_start in self._g else []
        else:
            start_nodes = [
                n for n, d in self._g.nodes(data=True)
                if d.get("node_type") == "user" and not d.get("is_target")
            ]

        best_path: list = []
        best_cost = float("inf")

        for src in start_nodes[:50]:
            for da_target in da_nodes:
                try:
                    cost = nx.shortest_path_length(self._g, src, da_target, weight="weight")
                    if cost < best_cost:
                        path = nx.shortest_path(self._g, src, da_target, weight="weight")
                        best_cost = cost
                        best_path = path
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        if not best_path:
            return None

        return self.path_to_report(best_path)
