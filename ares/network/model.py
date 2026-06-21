"""
ARES Target Network Model
Hierarchical model of the target network for pivot routing and lateral movement planning.

Model hierarchy:
  NetworkModel
    └── Subnet × N
          └── HostNode × N
                ├── ServiceNode × N
                └── UserNode × N (local users)

Capabilities:
  - Find pivot route between any two hosts
  - Identify network boundaries (DMZ, internal, cloud)
  - Track reachability (which hosts can reach which)
  - Export as D3.js network graph

Usage:
    model = NetworkModel("CORP Lab")
    subnet = model.add_subnet("10.0.0.0/24", "Internal LAN", zone="internal")
    dc = subnet.add_host("10.0.0.1", hostname="dc01", is_dc=True)
    dc.add_service(445, "smb")
    dc.add_service(88, "kerberos")

    route = model.pivot_route("10.0.0.50", "10.1.0.1")
    # → ["10.0.0.50", "10.0.0.1", "10.1.0.1"] via pivot
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ares.core.logger import get_logger
from ares.state.target_state import HostState, ServiceEntry

logger = get_logger("ares.network")

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


class NetworkZone(str):
    INTERNET  = "internet"
    DMZ       = "dmz"
    INTERNAL  = "internal"
    TRUSTED   = "trusted"
    CLOUD_VPC = "cloud_vpc"
    OT        = "ot"            # Operational Technology


@dataclass
class ServiceNode:
    port:     int
    name:     str
    version:  str = ""
    is_auth:  bool = False      # authentication service
    is_data:  bool = False      # data store


@dataclass
class HostNode:
    """A host in the network model."""
    ip_address:  str
    hostname:    str = ""
    fqdn:        str = ""
    domain:      str = ""
    os:          str = ""
    is_dc:       bool = False
    is_router:   bool = False    # can route/forward
    is_pivot:    bool = False    # ARES has a shell/session here
    zone:        str  = NetworkZone.INTERNAL
    services:    list[ServiceNode] = field(default_factory=list)
    users:       list[str]         = field(default_factory=list)
    reachable:   list[str]         = field(default_factory=list)  # IPs this host can reach

    @property
    def ip(self) -> str:
        """Alias for ip_address."""
        return self.ip_address

    def add_service(self, port: int, name: str, version: str = "") -> ServiceNode:
        svc = ServiceNode(
            port=port, name=name, version=version,
            is_auth=name in ("ldap", "ldaps", "kerberos", "ssh", "winrm", "smb"),
            is_data=name in ("mssql", "mysql", "postgresql", "mongodb", "redis"),
        )
        self.services.append(svc)
        return svc

    def attack_surface(self) -> list[dict[str, Any]]:
        """Return list of attackable services with their module recommendations."""
        from ares.service_intel.engine import PORT_SERVICE_MAP
        result = []
        for svc in self.services:
            profile = PORT_SERVICE_MAP.get(svc.port)
            if profile and profile.attack_modules:
                result.append({
                    "port":    svc.port,
                    "service": svc.name,
                    "modules": profile.attack_modules,
                    "opsec":   profile.opsec_risk,
                })
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip":        self.ip_address,
            "hostname":  self.hostname,
            "domain":    self.domain,
            "os":        self.os,
            "is_dc":     self.is_dc,
            "is_pivot":  self.is_pivot,
            "zone":      self.zone,
            "ports":     [s.port for s in self.services],
            "reachable": self.reachable,
        }


@dataclass
class Subnet:
    """An IP subnet in the target network."""
    cidr:        str
    name:        str = ""
    zone:        str = NetworkZone.INTERNAL
    gateway:     str = ""
    vlan_id:     int = 0
    _hosts:      dict[str, HostNode] = field(default_factory=dict)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr, strict=False)

    def contains(self, ip: str) -> bool:
        try:
            return ipaddress.IPv4Address(ip) in self.network
        except ValueError:
            return False

    def add_host(
        self, ip: str, hostname: str = "", is_dc: bool = False, **kwargs: Any
    ) -> HostNode:
        if "domain_controller" in kwargs:
            is_dc = kwargs.pop("domain_controller")
        node = HostNode(ip_address=ip, hostname=hostname, is_dc=is_dc,
                        zone=self.zone, **kwargs)
        self._hosts[ip] = node
        return node

    def hosts(self) -> list[HostNode]:
        return list(self._hosts.values())

    def get_host(self, ip: str) -> HostNode | None:
        return self._hosts.get(ip)


# ── Network Model ──────────────────────────────────────────────────────────────

class NetworkModel:
    """
    Complete model of the target network.
    Tracks hosts, subnets, zones, and pivot routes.
    """

    def __init__(self, name: str = "Target Network") -> None:
        self.name     = name
        self._subnets: list[Subnet] = []
        self._hosts:   dict[str, HostNode] = {}   # ip → HostNode (flat index)
        self._pivots:  list[str] = []             # IPs where ARES has sessions

    def add_subnet(
        self,
        cidr: str,
        name: str = "",
        zone: str = NetworkZone.INTERNAL,
        gateway: str = "",
        vlan_id: int = 0,
    ) -> Subnet:
        subnet = Subnet(cidr=cidr, name=name, zone=zone, gateway=gateway, vlan_id=vlan_id)
        self._subnets.append(subnet)
        logger.info("subnet_added", cidr=cidr, zone=zone)
        return subnet

    def add_host_flat(
        self, ip: str, hostname: str = "", is_dc: bool = False, **kwargs: Any
    ) -> HostNode:
        """Add a host without assigning to a subnet."""
        # Translate domain_controller kwarg → is_dc
        if "domain_controller" in kwargs:
            is_dc = kwargs.pop("domain_controller")
        node = HostNode(ip_address=ip, hostname=hostname, is_dc=is_dc, **kwargs)
        self._hosts[ip] = node
        return node

    def register_pivot(self, ip: str) -> None:
        """Mark a host as a pivot point (ARES has a session here)."""
        if ip not in self._pivots:
            self._pivots.append(ip)
        host = self.get_host(ip)
        if host:
            host.is_pivot = True
        logger.info("pivot_registered", ip=ip)

    def get_host(self, ip: str) -> HostNode | None:
        """Look up a host by IP across all subnets and the flat index."""
        if ip in self._hosts:
            return self._hosts[ip]
        for subnet in self._subnets:
            h = subnet.get_host(ip)
            if h:
                return h
        return None

    def all_hosts(self) -> list[HostNode]:
        """All hosts across all subnets and flat index."""
        hosts: dict[str, HostNode] = {}
        for h in self._hosts.values():
            hosts[h.ip_address] = h
        for subnet in self._subnets:
            for h in subnet.hosts():
                hosts[h.ip_address] = h
        return list(hosts.values())

    def pivot_hosts(self) -> list[HostNode]:
        return [h for h in self.all_hosts() if h.is_pivot]

    def domain_controllers(self) -> list[HostNode]:
        return [h for h in self.all_hosts() if h.is_dc]

    def subnet_for(self, ip: str) -> Subnet | None:
        for subnet in self._subnets:
            if subnet.contains(ip):
                return subnet
        return None

    def same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are on the same subnet."""
        s1 = self.subnet_for(ip1)
        s2 = self.subnet_for(ip2)
        return s1 is not None and s1 is s2

    # ── Pivot routing ──────────────────────────────────────────────────────

    def pivot_route(
        self,
        source_ip: str,
        target_ip: str,
    ) -> list[str] | None:
        """
        Find a pivot route from source to target through owned hosts.
        Uses BFS through reachability graph.

        Returns list of IP hops: [source, pivot1, ..., target]
        Returns None if no route found.
        """
        if not _NX:
            return self._bfs_pivot_route(source_ip, target_ip)

        # Build directed reachability graph
        G = nx.DiGraph()
        for host in self.all_hosts():
            G.add_node(host.ip_address)
            for reachable in host.reachable:
                G.add_edge(host.ip_address, reachable)
            # Same-subnet hosts are mutually reachable
            subnet = self.subnet_for(host.ip_address)
            if subnet:
                for peer in subnet.hosts():
                    if peer.ip_address != host.ip_address:
                        G.add_edge(host.ip_address, peer.ip_address)

        try:
            return nx.shortest_path(G, source_ip, target_ip)
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return None

    def _bfs_pivot_route(self, source: str, target: str) -> list[str] | None:
        """Pure-Python BFS pivot route (no networkx)."""
        from collections import deque
        visited  = {source}
        queue: deque[list[str]] = deque([[source]])
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == target:
                return path
            host = self.get_host(node)
            if not host:
                continue
            neighbors = list(host.reachable)
            subnet = self.subnet_for(node)
            if subnet:
                neighbors += [h.ip_address for h in subnet.hosts()]
            for n in neighbors:
                if n not in visited:
                    visited.add(n)
                    queue.append(path + [n])
        return None

    def reachable_from_pivots(self) -> list[HostNode]:
        """Return all hosts reachable from any current pivot."""
        reachable: set[str] = set()
        for pivot_ip in self._pivots:
            for host in self.all_hosts():
                route = self.pivot_route(pivot_ip, host.ip_address)
                if route:
                    reachable.add(host.ip_address)
        return [h for h in self.all_hosts() if h.ip_address in reachable]

    # ── Import from session ────────────────────────────────────────────────

    def import_from_session(self, session_snapshot: dict[str, Any]) -> None:
        """Populate model from OperatorSession.snapshot()."""
        for ip, host_data in session_snapshot.get("hosts", {}).items():
            node = self.add_host_flat(
                ip,
                hostname=host_data.get("hostname", ""),
                is_dc=host_data.get("is_dc", False),
                domain=host_data.get("domain", ""),
                os=host_data.get("os", ""),
            )
            for svc in host_data.get("services", []):
                node.add_service(svc["port"], svc["service"])
            for reach_ip in host_data.get("can_reach", []):
                node.reachable.append(reach_ip)
            if host_data.get("owned"):
                node.is_pivot = True
                self._pivots.append(ip)

    def to_d3_json(self) -> dict[str, Any]:
        """Export network model as D3.js force graph JSON."""
        nodes = []
        links = []
        colors = {
            "domain_controller": "#ef4444",
            "pivot":             "#10b981",
            "host":              "#3b82f6",
        }

        for host in self.all_hosts():
            ntype = "domain_controller" if host.is_dc else ("pivot" if host.is_pivot else "host")
            nodes.append({
                "id":      host.ip_address,
                "label":   host.hostname or host.ip_address,
                "type":    ntype,
                "color":   colors.get(ntype, "#94a3b8"),
                "zone":    host.zone,
                "ports":   [s.port for s in host.services],
                "is_pivot": host.is_pivot,
            })
            for reachable in host.reachable:
                links.append({"source": host.ip_address, "target": reachable})

        return {"nodes": nodes, "links": links, "name": self.name}


# ═══════════════════════════════════════════════════════════════════════════════
# Legacy-compatible classes (ARES ≤ 0.4 API — kept for backward compatibility)
# New code should use HostNode / NetworkModel.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkHost:
    """
    Lightweight host record compatible with ARES ≤ 0.4.

    Attributes:
        ip:         IPv4 / IPv6 address string.
        hostname:   Resolved hostname (empty if unknown).
        open_ports: List of open TCP port numbers discovered.
        services:   Mapping port → service/banner string.
    """

    ip:         str
    hostname:   str                 = ""
    open_ports: list[int]           = field(default_factory=list)
    services:   dict[int, str]      = field(default_factory=dict)

    def add_port(self, port: int, service: str, banner: str = "") -> None:
        """Record an open port with optional service name / banner."""
        if port not in self.open_ports:
            self.open_ports.append(port)
        self.services[port] = banner or service

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "ip":         self.ip,
            "hostname":   self.hostname,
            "open_ports": sorted(self.open_ports),
            "services":   {str(k): v for k, v in self.services.items()},
        }

    def to_host_node(self) -> HostNode:
        """Convert to the richer HostNode for use with NetworkModel."""
        node = HostNode(ip_address=self.ip, hostname=self.hostname)
        for port, banner in self.services.items():
            node.add_service(port=port, name=banner or "unknown")
        return node


@dataclass
class NetworkTopology:
    """
    Simple network topology container compatible with ARES ≤ 0.4.

    Attributes:
        campaign_id: Campaign this topology was captured for.
        hosts:       Dict of IP → NetworkHost entries.
    """

    campaign_id: str
    hosts:       dict[str, "NetworkHost"] = field(default_factory=dict)

    def add_host(self, host: "NetworkHost") -> None:
        """Register *host* under its IP address."""
        self.hosts[host.ip] = host

    def get_host(self, ip: str) -> "NetworkHost | None":
        """Return the host for *ip*, or ``None`` if unknown."""
        return self.hosts.get(ip)

    def all_hosts(self) -> "list[NetworkHost]":
        """Return every registered host as a list."""
        return list(self.hosts.values())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "campaign_id": self.campaign_id,
            "hosts":       {ip: h.to_dict() for ip, h in self.hosts.items()},
        }
