"""
ARES Pivot Infrastructure
Manages SOCKS5 proxies, reverse tunnels, and port forwards
established through compromised hosts.

Topology:
  Operator (10.10.10.1)
    └─SSH tunnel─► Pivot Host (192.168.1.5, port 1080 SOCKS5)
                      └─routes traffic─► Internal Network (10.0.0.0/8)
                                           ├─ DC (10.0.0.1:389)
                                           └─ FileServer (10.0.0.10:445)

PivotManager:
  - Tracks all established tunnels
  - Generates proxychains / proxy config
  - Routes requests through correct pivot for target IP
  - Supports chained pivots (pivot1 → pivot2 → target)
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import audit, get_logger

logger = get_logger("ares.pivot")


class TunnelType(str, Enum):
    SOCKS5          = "socks5"
    SSH_LOCAL_FWD   = "ssh_local_fwd"    # -L: local_port:remote_host:remote_port
    SSH_REMOTE_FWD  = "ssh_remote_fwd"   # -R: remote_port:local_host:local_port
    SSH_DYNAMIC     = "ssh_dynamic"      # -D: dynamic SOCKS proxy
    REVERSE_TCP     = "reverse_tcp"      # netcat/socat reverse tunnel
    HTTP_CONNECT    = "http_connect"     # HTTP CONNECT proxy tunnel


class TunnelState(str, Enum):
    ESTABLISHING = "establishing"
    ACTIVE       = "active"
    DEGRADED     = "degraded"    # partial connectivity
    DEAD         = "dead"


@dataclass
class PivotTunnel:
    """A single tunnel through a pivot host."""
    tunnel_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tunnel_type:    TunnelType = TunnelType.SOCKS5
    state:          TunnelState = TunnelState.ESTABLISHING

    # Pivot host (where we have a shell/session)
    pivot_host:     str = ""
    pivot_port:     int = 22        # SSH port on pivot

    # Listener (local side — operator machine)
    local_host:     str = "127.0.0.1"
    local_port:     int = 0         # 0 = auto-assigned

    # Target (remote side — what we're reaching through pivot)
    remote_host:    str = ""        # for port-forward tunnels
    remote_port:    int = 0         # for port-forward tunnels

    # Authentication
    username:       str = ""
    auth_type:      str = "password"   # password | key

    # Metadata
    via_chain:      list[str] = field(default_factory=list)   # chained pivots
    operator:       str = ""
    established_at: float = field(default_factory=time.time)
    bytes_sent:     int = 0
    bytes_recv:     int = 0
    connection_count: int = 0

    # Reachable subnets through this tunnel
    reachable_subnets: list[str] = field(default_factory=list)

    # Runtime handles — typed as Any to avoid hard dependency on asyncssh/subprocess
    # These are populated during establish_* methods and cleaned up in teardown()
    _conn:      Any = field(default=None, repr=False, compare=False)
    _forwarder: Any = field(default=None, repr=False, compare=False)
    _proc:      Any = field(default=None, repr=False, compare=False)
    _listener:  Any = field(default=None, repr=False, compare=False)

    @property
    def proxy_url(self) -> str:
        if self.tunnel_type in (TunnelType.SOCKS5, TunnelType.SSH_DYNAMIC):
            return f"socks5://{self.local_host}:{self.local_port}"
        return f"{self.local_host}:{self.local_port}"

    @property
    def uptime_s(self) -> float:
        return time.time() - self.established_at

    def to_proxychains_entry(self) -> str:
        """Generate proxychains.conf line."""
        return f"socks5  {self.local_host}  {self.local_port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tunnel_id":         self.tunnel_id,
            "type":              self.tunnel_type.value,
            "state":             self.state.value,
            "pivot_host":        self.pivot_host,
            "local_port":        self.local_port,
            "proxy_url":         self.proxy_url,
            "reachable_subnets": self.reachable_subnets,
            "uptime_s":          round(self.uptime_s, 0),
            "connections":       self.connection_count,
        }


@dataclass
class PortForward:
    """A single port forward entry."""
    fwd_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    local_port:  int = 0
    remote_host: str = ""
    remote_port: int = 0
    via_tunnel:  str = ""    # tunnel_id
    description: str = ""
    created_at:  float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":          self.fwd_id,
            "local_port":  self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "via_tunnel":  self.via_tunnel,
            "description": self.description,
        }


class PivotManager:
    """
    Manages all active pivots, tunnels, and port forwards
    for the current red team engagement.

    Automatically routes traffic to the correct proxy
    based on target IP/subnet.

    Usage:
        pm = PivotManager(operator="tester")
        tunnel = await pm.establish_socks5("10.0.1.5", username="svc", secret="<from_vault>")
        fwd    = pm.add_port_forward(4430, "10.0.0.1", 443, via_tunnel=tunnel.tunnel_id)
        config = pm.generate_proxychains_config()
    """

    def __init__(self, operator: str = "unknown") -> None:
        self.operator   = operator
        self._tunnels:  dict[str, PivotTunnel] = {}
        self._forwards: dict[str, PortForward] = {}
        self._next_port = 1080   # auto-assign SOCKS ports from here

    # ── Tunnel management ──────────────────────────────────────────────────

    async def establish_socks5(
        self,
        pivot_host:     str,
        username:       str,
        secret:         str,
        local_port:     int = 0,
        ssh_port:       int = 22,
        reachable_subnets: list[str] | None = None,
        key_path:       str = "",
    ) -> PivotTunnel:
        """
        Open a SOCKS5 proxy through pivot_host via SSH -D.
        Uses asyncssh if available, falls back to paramiko subprocess tunnel.
        Returns tunnel on success.
        """
        local_port = local_port or self._alloc_port()
        tunnel = PivotTunnel(
            tunnel_type       = TunnelType.SSH_DYNAMIC,
            pivot_host        = pivot_host,
            pivot_port        = ssh_port,
            local_host        = "127.0.0.1",
            local_port        = local_port,
            username          = username,
            operator          = self.operator,
            reachable_subnets = reachable_subnets or [],
        )

        try:
            import asyncssh

            connect_kwargs: dict = {
                "host":        pivot_host,
                "port":        ssh_port,
                "username":    username,
                "known_hosts": None,
            }
            if key_path:
                connect_kwargs["client_keys"] = [key_path]
            else:
                connect_kwargs["password"] = secret

            conn = await asyncssh.connect(**connect_kwargs)
            # Start dynamic SOCKS5 forwarder on local_port
            forwarder = await conn.forward_socks("127.0.0.1", local_port)
            # Store connection reference for teardown
            tunnel._conn = conn
            tunnel._forwarder = forwarder
            tunnel.state = TunnelState.ACTIVE
            logger.info("socks5_asyncssh_established",
                        pivot=pivot_host, local_port=local_port)

        except ImportError:
            # Fallback: paramiko with SSH -D subprocess
            try:
                import paramiko, subprocess, shutil

                if shutil.which("ssh"):
                    # Use system ssh -D (most reliable for SOCKS5)
                    cmd = [
                        "ssh", "-N", "-D", str(local_port),
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "ServerAliveInterval=30",
                        "-p", str(ssh_port),
                    ]
                    if key_path:
                        cmd += ["-i", key_path]
                    # Sanitize username and pivot_host before building SSH args.
                    # SSH interprets option-like strings (e.g. "user -o ProxyCommand=…")
                    # even when passed as list args on some SSH versions.
                    import re as _re
                    _safe_user = _re.sub(r"[^a-zA-Z0-9._@-]", "", username)
                    _safe_host = _re.sub(r"[^a-zA-Z0-9._:-]", "", pivot_host)
                    if _safe_user != username or _safe_host != pivot_host:
                        logger.warning(
                            "ssh_pivot_arg_sanitized",
                            original_user=username, safe_user=_safe_user,
                            original_host=pivot_host, safe_host=_safe_host,
                        )
                    cmd.append(f"{_safe_user}@{_safe_host}")

                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    # Brief wait to confirm it starts
                    await asyncio.sleep(1.5)
                    if proc.poll() is not None:
                        tunnel.state = TunnelState.DEAD
                        logger.warning("socks5_ssh_subprocess_failed", pivot=pivot_host)
                    else:
                        tunnel._proc = proc
                        tunnel.state = TunnelState.ACTIVE
                        logger.info("socks5_subprocess_established",
                                    pivot=pivot_host, local_port=local_port)
                else:
                    # asyncssh not installed and no ssh binary — record as active
                    # (operator must establish tunnel externally)
                    tunnel.state = TunnelState.ACTIVE
                    logger.warning("socks5_no_backend_available",
                                   pivot=pivot_host,
                                   hint="Install asyncssh: pip install asyncssh")
            except (OSError, ImportError) as exc:
                tunnel.state = TunnelState.DEAD
                logger.error("socks5_establishment_failed", pivot=pivot_host, error=str(exc))

        except Exception as exc:
            tunnel.state = TunnelState.DEAD
            logger.error("socks5_asyncssh_failed", pivot=pivot_host, error=str(exc)[:200])

        self._tunnels[tunnel.tunnel_id] = tunnel
        if tunnel.state == TunnelState.ACTIVE:
            audit("pivot_established", actor=self.operator,
                  pivot=pivot_host, local_port=local_port, type="socks5")
        logger.info("socks5_tunnel_result",
                    tunnel_id=tunnel.tunnel_id, pivot=pivot_host,
                    port=local_port, state=tunnel.state.value)
        return tunnel

    async def establish_local_forward(
        self,
        pivot_host:  str,
        username:    str,
        secret:      str,
        remote_host: str,
        remote_port: int,
        local_port:  int = 0,
        ssh_port:    int = 22,
        key_path:    str = "",
    ) -> PivotTunnel:
        """
        SSH -L: forward local_port → remote_host:remote_port via pivot.
        Example: forward localhost:1433 → 10.0.0.20:1433 (MSSQL behind pivot).
        """
        local_port = local_port or self._alloc_port()
        tunnel = PivotTunnel(
            tunnel_type  = TunnelType.SSH_LOCAL_FWD,
            pivot_host   = pivot_host,
            pivot_port   = ssh_port,
            local_host   = "127.0.0.1",
            local_port   = local_port,
            remote_host  = remote_host,
            remote_port  = remote_port,
            username     = username,
            operator     = self.operator,
        )

        try:
            import asyncssh

            connect_kwargs: dict = {
                "host":        pivot_host,
                "port":        ssh_port,
                "username":    username,
                "known_hosts": None,
            }
            if key_path:
                connect_kwargs["client_keys"] = [key_path]
            else:
                connect_kwargs["password"] = secret

            conn = await asyncssh.connect(**connect_kwargs)
            listener = await conn.forward_local_port(
                "127.0.0.1", local_port, remote_host, remote_port
            )
            tunnel._conn     = conn
            tunnel._listener = listener
            tunnel.state = TunnelState.ACTIVE
            logger.info("local_fwd_asyncssh_established",
                        local_port=local_port, remote=f"{remote_host}:{remote_port}")

        except ImportError:
            import shutil, subprocess
            if shutil.which("ssh"):
                cmd = [
                    "ssh", "-N",
                    "-L", f"{local_port}:{remote_host}:{remote_port}",
                    "-o", "StrictHostKeyChecking=no",
                    "-p", str(ssh_port),
                ]
                if key_path:
                    cmd += ["-i", key_path]
                import re as _re
                _safe_user = _re.sub(r"[^a-zA-Z0-9._@-]", "", username)
                _safe_host = _re.sub(r"[^a-zA-Z0-9._:-]", "", pivot_host)
                if _safe_user != username or _safe_host != pivot_host:
                    logger.warning(
                        "ssh_local_fwd_arg_sanitized",
                        original_user=username, safe_user=_safe_user,
                        original_host=pivot_host, safe_host=_safe_host,
                    )
                cmd.append(f"{_safe_user}@{_safe_host}")
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                await asyncio.sleep(1.5)
                if proc.poll() is not None:
                    tunnel.state = TunnelState.DEAD
                else:
                    tunnel._proc = proc
                    tunnel.state = TunnelState.ACTIVE
            else:
                tunnel.state = TunnelState.ACTIVE
                logger.warning("local_fwd_no_backend", hint="pip install asyncssh")

        except Exception as exc:
            tunnel.state = TunnelState.DEAD
            logger.error("local_fwd_failed", error=str(exc)[:200])

        self._tunnels[tunnel.tunnel_id] = tunnel
        if tunnel.state == TunnelState.ACTIVE:
            audit("port_forward_established", actor=self.operator,
                  pivot=pivot_host, local_port=local_port,
                  remote=f"{remote_host}:{remote_port}")
        logger.info("local_fwd_result",
                    local_port=local_port, remote=f"{remote_host}:{remote_port}",
                    state=tunnel.state.value)
        return tunnel

    def add_port_forward(
        self,
        local_port:  int,
        remote_host: str,
        remote_port: int,
        via_tunnel:  str,
        description: str = "",
    ) -> PortForward:
        """Register a manual port forward (e.g., established externally)."""
        fwd = PortForward(
            local_port=local_port, remote_host=remote_host,
            remote_port=remote_port, via_tunnel=via_tunnel,
            description=description,
        )
        self._forwards[fwd.fwd_id] = fwd
        logger.info("port_forward_added",
                    local=local_port, remote=f"{remote_host}:{remote_port}")
        return fwd

    def teardown(self, tunnel_id: str) -> bool:
        """Close and remove a tunnel — closes asyncssh conn or subprocess."""
        tunnel = self._tunnels.get(tunnel_id)
        if not tunnel:
            return False
        tunnel.state = TunnelState.DEAD

        # Close asyncssh connection if present
        conn = tunnel._conn
        if conn is not None:
            try:
                conn.close()
            except (OSError, AttributeError):
                pass

        # Terminate subprocess tunnel (ssh -D / -L via system ssh binary)
        proc = tunnel._proc
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (OSError, AttributeError):
                pass

        del self._tunnels[tunnel_id]
        self._forwards = {
            fid: f for fid, f in self._forwards.items()
            if f.via_tunnel != tunnel_id
        }
        audit("pivot_torn_down", actor=self.operator, tunnel_id=tunnel_id)
        logger.info("tunnel_torn_down", tunnel_id=tunnel_id)
        return True

    def teardown_all(self) -> int:
        """Tear down ALL tunnels. Call at campaign end or shutdown."""
        tunnel_ids = list(self._tunnels.keys())
        count = 0
        for tid in tunnel_ids:
            if self.teardown(tid):
                count += 1
        logger.info("pivot_teardown_all", count=count)
        return count

    def health_check(self) -> dict[str, str]:
        """Check health of all tunnels. Kill dead ones."""
        report: dict[str, str] = {}
        for tid, tunnel in list(self._tunnels.items()):
            if tunnel._proc is not None:
                rc = tunnel._proc.poll()
                if rc is not None:
                    tunnel.state = TunnelState.DEAD
                    report[tid] = f"dead (exit={rc})"
                    self.teardown(tid)
                else:
                    report[tid] = "alive"
            elif tunnel._conn is not None:
                report[tid] = "alive (asyncssh)"
            else:
                report[tid] = "external"
        return report

    # ── Routing ────────────────────────────────────────────────────────────

    def proxy_for_target(self, target_ip: str) -> PivotTunnel | None:
        """
        Find the best tunnel to reach target_ip.
        Checks reachable_subnets for each active tunnel.
        """
        import ipaddress
        try:
            addr = ipaddress.IPv4Address(target_ip)
        except ValueError:
            return None

        for tunnel in self.active_tunnels():
            for subnet in tunnel.reachable_subnets:
                try:
                    if addr in ipaddress.IPv4Network(subnet, strict=False):
                        return tunnel
                except ValueError:
                    pass

        # Fall back: return first active SOCKS tunnel
        socks = [t for t in self.active_tunnels()
                 if t.tunnel_type in (TunnelType.SOCKS5, TunnelType.SSH_DYNAMIC)]
        return socks[0] if socks else None

    # ── Configuration generation ───────────────────────────────────────────

    def generate_proxychains_config(self) -> str:
        """Generate proxychains.conf content for all active SOCKS tunnels."""
        lines = [
            "strict_chain",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
        ]
        for tunnel in self.active_tunnels():
            if tunnel.tunnel_type in (TunnelType.SOCKS5, TunnelType.SSH_DYNAMIC):
                lines.append(tunnel.to_proxychains_entry())
        return "\n".join(lines)

    def generate_curl_args(self, target_ip: str) -> str:
        """Return curl proxy args for reaching a specific target."""
        tunnel = self.proxy_for_target(target_ip)
        if tunnel:
            return f"--proxy {tunnel.proxy_url}"
        return ""

    # ── State ──────────────────────────────────────────────────────────────

    def active_tunnels(self) -> list[PivotTunnel]:
        return [t for t in self._tunnels.values() if t.state == TunnelState.ACTIVE]

    def all_tunnels(self) -> list[PivotTunnel]:
        return list(self._tunnels.values())

    def all_forwards(self) -> list[PortForward]:
        return list(self._forwards.values())

    def summary(self) -> dict[str, Any]:
        return {
            "active_tunnels": len(self.active_tunnels()),
            "total_tunnels":  len(self._tunnels),
            "port_forwards":  len(self._forwards),
            "tunnels":        [t.to_dict() for t in self.active_tunnels()],
            "forwards":       [f.to_dict() for f in self._forwards.values()],
        }

    def _alloc_port(self) -> int:
        port = self._next_port
        self._next_port += 1
        return port
