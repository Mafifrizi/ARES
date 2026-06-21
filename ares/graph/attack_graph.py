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

    # High-value targets — finding a path to these is the goal
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

    # ── Build from artifact store ──────────────────────────────────────────

    def build_from_store(self, store: ArtifactStore) -> "AttackGraph":
        """
        Automatically build graph from all artifacts in a store.
        This is the main entry point — call after a campaign run.
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
        """Fuzzy label lookup — returns first matching node ID."""
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
            self._nodes[nid]
            for nid, data in self._g.nodes(data=True)
            if data.get("is_target")
        ]

    def riskiest_users(self, top_n: int = 10) -> list[GraphNode]:
        """Users sorted by risk score — best attack starting points."""
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
                "properties": data.get("properties", {}),
            })

        links = []
        for src, tgt, data in self._g.edges(data=True):
            links.append({
                "source":    src,
                "target":    tgt,
                "label":     data.get("label", ""),
                "type":      data.get("edge_type", ""),
                "weight":    data.get("weight", 1.0),
                "properties": data.get("properties", {}),
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
            with open(path, "w") as f:
                f.write("\n".join(lines))
        logger.info("graph_exported_dot", path=path)

    # ── Bloodhound JSON Ingest ────────────────────────────────────────────────

    def ingest_bloodhound(self, json_path: str) -> dict[str, int]:
        """
        Import BloodHound/SharpHound JSON collection into the ARES attack graph.

        Supports BloodHound CE (v5+) and legacy (v4) JSON formats.
        Parses: computers, users, groups, domains, sessions, ACLs.
        After ingest, use find_path() / top_paths() to compute attack paths.

        Args:
            json_path: Path to BloodHound JSON file (computers.json, users.json, etc.)
                       or a directory containing multiple .json files.

        Returns:
            dict with counts: {"nodes_added": N, "edges_added": N, "file_count": N}
        """
        import json as _json
        from pathlib import Path

        if not _NX_AVAILABLE:
            logger.warning("bloodhound_ingest_requires_networkx")
            return {"nodes_added": 0, "edges_added": 0, "error": "networkx not installed"}

        p = Path(json_path)
        files: list[Path] = []
        if p.is_dir():
            files = sorted(p.glob("*.json"))
        elif p.is_file():
            files = [p]
        else:
            return {"nodes_added": 0, "edges_added": 0, "error": f"Path not found: {json_path}"}

        nodes_before = self._g.number_of_nodes()
        edges_before = self._g.number_of_edges()

        for fp in files:
            try:
                with open(fp) as fh:
                    data = _json.load(fh)
                self._parse_bloodhound_json(data)
            except Exception as exc:
                logger.warning("bloodhound_parse_error", file=str(fp), error=str(exc)[:100])

        nodes_added = self._g.number_of_nodes() - nodes_before
        edges_added = self._g.number_of_edges() - edges_before
        logger.info("bloodhound_ingest_complete",
                     nodes=nodes_added, edges=edges_added, files=len(files))
        return {"nodes_added": nodes_added, "edges_added": edges_added,
                "file_count": len(files)}

    def _parse_bloodhound_json(self, data: dict) -> None:
        """Parse a single BloodHound JSON file (computers, users, groups, etc.)."""
        # BloodHound CE format: {"data": [...], "meta": {"type": "computers"}}
        # Legacy format: {"computers": [...]} or {"users": [...]}
        meta = data.get("meta", {})
        bh_type = meta.get("type", "").lower()
        items = data.get("data", [])

        # Legacy fallback: detect type from top-level keys
        if not items:
            for key in ("computers", "users", "groups", "domains", "sessions", "ous", "gpos"):
                if key in data:
                    items = data[key]
                    bh_type = key
                    break

        if not items:
            return

        for item in items:
            props = item.get("Properties", item.get("properties", {}))
            aces  = item.get("Aces", item.get("aces", []))
            members = item.get("Members", item.get("members", []))

            if bh_type in ("computers", "computer"):
                self._bh_add_computer(props, aces)
            elif bh_type in ("users", "user"):
                self._bh_add_user(props, aces)
            elif bh_type in ("groups", "group"):
                self._bh_add_group(props, aces, members)
            elif bh_type in ("domains", "domain"):
                self._bh_add_domain(props, aces)

    def _bh_add_computer(self, props: dict, aces: list) -> None:
        name = props.get("name", "").upper()
        if not name:
            return
        node_id = f"computer:{name}"
        is_dc = props.get("isdc", props.get("isDC", False))
        self._g.add_node(node_id, label=name, node_type="host",
                          is_target=is_dc,
                          os=props.get("operatingsystem", ""),
                          enabled=props.get("enabled", True))
        # Domain membership
        domain = props.get("domain", "")
        if domain:
            dom_id = f"domain:{domain.upper()}"
            self._g.add_node(dom_id, label=domain.upper(), node_type="domain",
                              is_target=True)
            self._g.add_edge(dom_id, node_id, label="has_host", weight=0.1)
        self._bh_process_aces(node_id, aces)

    def _bh_add_user(self, props: dict, aces: list) -> None:
        name = props.get("name", "").upper()
        if not name:
            return
        node_id = f"user:{name}"
        is_admin = props.get("admincount", False)
        self._g.add_node(node_id, label=name, node_type="user",
                          is_target=is_admin,
                          enabled=props.get("enabled", True),
                          has_spn=props.get("hasspn", False),
                          no_preauth=props.get("dontreqpreauth", False))
        # Mark kerberoastable users
        if props.get("hasspn", False):
            self._g.add_edge(node_id, f"technique:kerberoast:{name}",
                              label="kerberoastable", weight=0.3)
        if props.get("dontreqpreauth", False):
            self._g.add_edge(node_id, f"technique:asreproast:{name}",
                              label="asreproastable", weight=0.2)
        domain = props.get("domain", "")
        if domain:
            dom_id = f"domain:{domain.upper()}"
            self._g.add_edge(dom_id, node_id, label="has_user", weight=0.1)
        self._bh_process_aces(node_id, aces)

    def _bh_add_group(self, props: dict, aces: list, members: list) -> None:
        name = props.get("name", "").upper()
        if not name:
            return
        node_id = f"group:{name}"
        is_da = "DOMAIN ADMINS" in name or "ENTERPRISE ADMINS" in name
        self._g.add_node(node_id, label=name, node_type="group",
                          is_target=is_da)
        for member in members:
            mid = member.get("MemberId", member.get("ObjectIdentifier", ""))
            mtype = member.get("MemberType", member.get("ObjectType", "")).lower()
            if mid:
                member_node = f"{mtype}:{mid}" if ":" not in mid else mid
                self._g.add_edge(member_node, node_id, label="member_of",
                                  weight=0.1)
        self._bh_process_aces(node_id, aces)

    def _bh_add_domain(self, props: dict, aces: list) -> None:
        name = props.get("name", "").upper()
        if not name:
            return
        node_id = f"domain:{name}"
        self._g.add_node(node_id, label=name, node_type="domain",
                          is_target=True)
        self._bh_process_aces(node_id, aces)

    def _bh_process_aces(self, target_id: str, aces: list) -> None:
        """Convert BloodHound ACEs to graph edges."""
        _DANGEROUS_RIGHTS = {
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
            "AllExtendedRights", "ForceChangePassword", "AddMember",
            "ReadLAPSPassword", "ReadGMSAPassword", "DCSync",
            "Owns", "AddSelf", "AddAllowedToAct",
        }
        _RIGHT_WEIGHTS = {
            "GenericAll": 0.9, "WriteOwner": 0.8, "WriteDacl": 0.8,
            "DCSync": 1.0, "ForceChangePassword": 0.7, "AddMember": 0.6,
            "ReadLAPSPassword": 0.5, "ReadGMSAPassword": 0.5,
            "AddAllowedToAct": 0.7, "Owns": 0.8,
        }
        for ace in aces:
            right = ace.get("RightName", ace.get("rightname", ""))
            principal = ace.get("PrincipalSID", ace.get("principalsid", ""))
            ptype = ace.get("PrincipalType", ace.get("principaltype", "")).lower()
            if right in _DANGEROUS_RIGHTS and principal:
                src = f"{ptype}:{principal}" if ":" not in principal else principal
                w = _RIGHT_WEIGHTS.get(right, 0.5)
                self._g.add_edge(src, target_id, label=right.lower(),
                                  weight=w,
                                  properties={"right": right, "inherited": ace.get("IsInherited", False)})

    def shortest_path_to_da(self, start_node: str | None = None) -> list[dict]:
        """
        Compute shortest attack path from start_node (or any user) to Domain Admins group.

        Uses Dijkstra with edge weights (lower = easier to exploit).
        Returns list of steps with edge labels (attack technique at each hop).
        """
        if not _NX_AVAILABLE or not self._g.nodes:
            return []

        # Find DA group node
        da_nodes = [n for n, d in self._g.nodes(data=True)
                    if d.get("is_target") and "DOMAIN ADMINS" in d.get("label", "").upper()]
        if not da_nodes:
            da_nodes = [n for n in self._g.nodes if "domain admin" in n.lower()]
        if not da_nodes:
            return []

        da_target = da_nodes[0]

        # If no start specified, try all user nodes and return shortest
        if start_node:
            start_nodes = [start_node]
        else:
            start_nodes = [n for n, d in self._g.nodes(data=True)
                           if d.get("node_type") == "user" and not d.get("is_target")]

        best_path: list = []
        best_len = float("inf")

        for src in start_nodes[:50]:  # cap to avoid excessive computation
            try:
                path = nx.shortest_path(self._g, src, da_target, weight="weight")
                if len(path) < best_len:
                    best_len = len(path)
                    best_path = path
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        if not best_path:
            return []

        return self.path_to_report(best_path)
