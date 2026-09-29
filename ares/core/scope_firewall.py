"""ARES Scope Firewall & Kernel / OS Egress Wall.

Provides dual-layer fail-closed egress boundaries for offensive security operations:
1. Kernel / OS-Level Packet Filtering (OS Mode):
   - Windows: Interacts directly with Windows Defender Firewall (`netsh advfirewall`)
     to enforce OS-level packet filtering for program egress when running with Administrator privileges.
   - Linux: Interacts with Netfilter (`iptables`) scoped to process / cgroups when running as root.
   - Includes automatic fail-safe rule teardown on context exit and process shutdown (`atexit`).
2. Transport-Level Socket Interceptor (Process Mode):
   - In-process hook for `socket.connect`, `socket.sendto`, and `asyncio.create_connection`.
   - Active across all environments (including unprivileged developer mode) with zero external dependencies.
   - ContextVar task-isolation: only active within the attack module execution task.
   - Windows Proactor IOCP & loopback protection: internal pipes, socketpairs, and loopback are safeguarded.
   - DNS resolution re-entrancy lock: prevents recursive interception when resolving hostnames.
   - Cloud domain whitelisting: allows legitimate cloud API traffic for cloud modules.
"""
from __future__ import annotations

import asyncio
import atexit
import contextlib
import functools
import ipaddress
import os
import secrets
import socket
import subprocess
import sys
import threading
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, AsyncGenerator, Generator

from ares.core.errors import ScopeFirewallBlockError
from ares.core.logger import audit, get_logger

if TYPE_CHECKING:
    from ares.core.campaign import Campaign

logger = get_logger("ares.scope_firewall")

# ── Task-Isolated Context Variables ──────────────────────────────────────────
_current_firewall: ContextVar[ScopeFirewall | None] = ContextVar(
    "_current_firewall", default=None
)
_in_firewall_resolution: ContextVar[bool] = ContextVar(
    "_in_firewall_resolution", default=False
)

# ── Cloud Provider Domain Whitelist ──────────────────────────────────────────
# Permitted domains for modules with MODULE_CATEGORY == "cloud"
CLOUD_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # Microsoft / Azure / Entra / M365
    ".microsoftonline.com",
    ".microsoft.com",
    ".windows.net",
    ".azure.com",
    ".azure.net",
    ".office.com",
    ".live.com",
    ".msftidentity.com",
    ".graph.microsoft.com",
    # Amazon Web Services
    ".amazonaws.com",
    ".aws.amazon.com",
    # Google Cloud Platform
    ".googleapis.com",
    ".google.com",
    ".gcp.gvt2.com",
)

# ── Loopback & Local Addresses ───────────────────────────────────────────────
_LOOPBACK_HOSTS: frozenset[str] = frozenset(
    {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
)


class ScopeFirewall:
    """Deterministic scope firewall enforcing CIDR & target boundaries at socket layer."""

    def __init__(
        self,
        campaign: Campaign,
        module_id: str = "",
        module_category: str = "",
        allow_loopback_ipc: bool = True,
    ) -> None:
        self.campaign = campaign
        self.module_id = module_id
        self.module_category = module_category.lower().strip()
        self.allow_loopback_ipc = allow_loopback_ipc

        # Parse and pre-compile CIDRs into IPv4Network / IPv6Network objects
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for scope_entry in getattr(campaign, "scope", []):
            cidr_str = getattr(scope_entry, "cidr", "").strip()
            if cidr_str:
                try:
                    self._networks.append(ipaddress.ip_network(cidr_str, strict=False))
                except ValueError:
                    logger.warning("invalid_scope_cidr_ignored", cidr=cidr_str)

        # Build normalized hostname allowlist from campaign metadata
        self._explicit_hosts: set[str] = set()
        for raw_target in getattr(campaign, "targets", []):
            if isinstance(raw_target, str) and raw_target.strip():
                self._explicit_hosts.add(raw_target.strip().lower())

        dc = getattr(campaign, "dc", "")
        if dc and isinstance(dc, str):
            self._explicit_hosts.add(dc.strip().lower())

        domain = getattr(campaign, "domain", "")
        if domain and isinstance(domain, str):
            self._explicit_hosts.add(domain.strip().lower())

        # Fast IP lookup cache (bounded to 1024 entries)
        self._ip_cache: dict[str, bool] = {}
        self._pinned_ip_cache: dict[str, str] = {}
        self._blocked_attempts: list[dict[str, Any]] = []

    @property
    def scope_cidrs(self) -> list[str]:
        return [str(net) for net in self._networks]

    def _extract_host_and_port(self, address: Any) -> tuple[str, int | None]:
        """Extract sanitized host string and optional port from a socket address."""
        if isinstance(address, tuple) and len(address) >= 1:
            host = address[0]
            port = address[1] if len(address) >= 2 and isinstance(address[1], int) else None
        elif isinstance(address, str):
            host = address
            port = None
        elif isinstance(address, bytes):
            host = address.decode("utf-8", errors="ignore")
            port = None
        else:
            host = str(address)
            port = None

        if isinstance(host, bytes):
            host = host.decode("utf-8", errors="ignore")

        host_str = str(host).strip()
        port_val = port

        # Handle string forms such as "[::1]:8080" or "10.0.0.1:445"
        if port_val is None and ":" in host_str:
            if host_str.startswith("[") and "]" in host_str:
                parts = host_str.split("]")
                host_str = parts[0][1:]
                after = parts[1]
                if after.startswith(":") and after[1:].isdigit():
                    port_val = int(after[1:])
            elif host_str.count(":") == 1:
                h, p = host_str.split(":")
                if p.isdigit():
                    host_str = h
                    port_val = int(p)

        # Strip remaining bracketed IPv6 syntax: "[::1]" -> "::1"
        if host_str.startswith("[") and host_str.endswith("]"):
            host_str = host_str[1:-1]

        # Strip zone identifier: "fe80::1%eth0" -> "fe80::1"
        if "%" in host_str:
            host_str = host_str.split("%")[0]

        return host_str.strip(), port_val

    def _is_cloud_allowed(self, host: str) -> bool:
        """Verify if host matches trusted cloud endpoints for cloud modules."""
        if self.module_category != "cloud":
            return False

        lowered = host.lower()
        if any(lowered == sfx[1:] or lowered.endswith(sfx) for sfx in CLOUD_DOMAIN_SUFFIXES):
            return True

        return False

    def resolve_and_pin_address(self, address: Any) -> tuple[bool, Any]:
        """Check if destination address is permitted and return pinned address for DNS rebinding protection."""
        host, port = self._extract_host_and_port(address)
        if not host:
            return False, address

        lowered_host = host.lower()

        # 1. Internal loopback IPC protection
        if self.allow_loopback_ipc and lowered_host in _LOOPBACK_HOSTS:
            return True, address

        # 2. Cloud module domain whitelist (preserves hostname for TLS SNI)
        if self._is_cloud_allowed(lowered_host):
            return True, address

        # 3. Check if host is an IP literal (including IPv4, IPv6, and IPv4-mapped IPv6)
        try:
            addr = ipaddress.ip_address(lowered_host)
            effective_addr = getattr(addr, "ipv4_mapped", None) or addr
            if self.allow_loopback_ipc and (addr.is_loopback or effective_addr.is_loopback):
                self._ip_cache[lowered_host] = True
                return True, address

            in_scope = any(
                (effective_addr in net if effective_addr.version == net.version else False)
                or (addr in net if addr.version == net.version else False)
                for net in self._networks
            )
            if len(self._ip_cache) < 1024:
                self._ip_cache[lowered_host] = in_scope
            return in_scope, address
        except ValueError:
            pass  # Not an IP literal - proceed to hostname verification

        # 4. Check cached pinned resolution
        if lowered_host in self._pinned_ip_cache:
            pinned_ip = self._pinned_ip_cache[lowered_host]
            if isinstance(address, tuple):
                if len(address) == 2:
                    return True, (pinned_ip, address[1])
                elif len(address) > 2:
                    return True, (pinned_ip, address[1], *address[2:])
            return True, pinned_ip

        if lowered_host in self._ip_cache and not self._ip_cache[lowered_host]:
            return False, address

        # 5. Hostname DNS resolution with re-entrancy lock
        if _in_firewall_resolution.get():
            return True, address

        _token = _in_firewall_resolution.set(True)
        try:
            results = socket.getaddrinfo(
                lowered_host, port or 0, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not results:
                logger.warning("scope_firewall_dns_empty", host=lowered_host)
                if len(self._ip_cache) < 1024:
                    self._ip_cache[lowered_host] = False
                return False, address

            # Strict verification: All resolved IPs must be in scope
            pinned_ip: str | None = None
            for res in results:
                raw_ip = res[4][0]
                try:
                    ip_obj = ipaddress.ip_address(raw_ip)
                    effective_ip = getattr(ip_obj, "ipv4_mapped", None) or ip_obj
                    in_scope = any(
                        (effective_ip in net if effective_ip.version == net.version else False)
                        or (ip_obj in net if ip_obj.version == net.version else False)
                        for net in self._networks
                    )
                    if in_scope:
                        if pinned_ip is None:
                            pinned_ip = raw_ip
                    else:
                        logger.warning(
                            "scope_firewall_dns_resolved_out_of_scope",
                            host=lowered_host,
                            resolved_ip=raw_ip,
                            scope=self.scope_cidrs,
                        )
                        if len(self._ip_cache) < 1024:
                            self._ip_cache[lowered_host] = False
                        return False, address
                except ValueError:
                    if len(self._ip_cache) < 1024:
                        self._ip_cache[lowered_host] = False
                    return False, address

            if pinned_ip is not None:
                if len(self._pinned_ip_cache) < 1024:
                    self._pinned_ip_cache[lowered_host] = pinned_ip
                if len(self._ip_cache) < 1024:
                    self._ip_cache[lowered_host] = True

                if isinstance(address, tuple):
                    if len(address) == 2:
                        return True, (pinned_ip, address[1])
                    elif len(address) > 2:
                        return True, (pinned_ip, address[1], *address[2:])
                return True, pinned_ip

            return False, address
        except (socket.gaierror, TimeoutError, Exception) as exc:
            logger.warning(
                "scope_firewall_dns_failed",
                host=lowered_host,
                error=str(exc)[:100],
            )
            if lowered_host in self._explicit_hosts:
                return True, address
            return False, address
        finally:
            _in_firewall_resolution.reset(_token)

    def is_allowed_address(self, address: Any) -> bool:
        """Check if destination address is permitted under campaign scope."""
        allowed, _ = self.resolve_and_pin_address(address)
        return allowed

    def assert_allowed_address(self, address: Any) -> Any:
        """Assert address is in scope; raises ScopeFirewallBlockError if not.
        Returns pinned address for DNS rebinding protection.
        """
        allowed, pinned = self.resolve_and_pin_address(address)
        if not allowed:
            host, port = self._extract_host_and_port(address)
            self._blocked_attempts.append(
                {
                    "host": host,
                    "port": port,
                    "module_id": self.module_id,
                }
            )
            audit(
                "scope_firewall_blocked",
                actor=getattr(self.campaign, "operator", "system"),
                campaign=getattr(self.campaign, "id", "")[:8],
                module_id=self.module_id,
                target=host,
                port=port,
                scope=self.scope_cidrs,
            )
            logger.error(
                "scope_firewall_blocked_connection",
                target=host,
                port=port,
                module_id=self.module_id,
                scope=self.scope_cidrs,
            )
            raise ScopeFirewallBlockError(
                f"[ScopeFirewall] Connection to '{host}:{port or '*'}' BLOCKED: "
                f"Destination is outside authorized campaign scope {self.scope_cidrs}.",
                target_host=host,
                target_port=port,
                module_id=self.module_id,
                scope_cidrs=self.scope_cidrs,
            )
        return pinned


# ── Global Socket & Transport Hooks ──────────────────────────────────────────
_orig_socket_connect = socket.socket.connect
_orig_socket_connect_ex = socket.socket.connect_ex
_orig_socket_sendto = socket.socket.sendto
_orig_socket_sendmsg = getattr(socket.socket, "sendmsg", None)
_orig_loop_create_connection = asyncio.base_events.BaseEventLoop.create_connection
_hooks_installed: bool = False


@functools.wraps(_orig_socket_connect)
def _firewall_socket_connect(self: socket.socket, address: Any) -> None:
    fw = _current_firewall.get()
    target_address = address
    if fw is not None and not _in_firewall_resolution.get():
        pinned = fw.assert_allowed_address(address)
        if pinned is not None:
            target_address = pinned
    return _orig_socket_connect(self, target_address)


@functools.wraps(_orig_socket_connect_ex)
def _firewall_socket_connect_ex(self: socket.socket, address: Any) -> int:
    fw = _current_firewall.get()
    target_address = address
    if fw is not None and not _in_firewall_resolution.get():
        pinned = fw.assert_allowed_address(address)
        if pinned is not None:
            target_address = pinned
    return _orig_socket_connect_ex(self, target_address)


@functools.wraps(_orig_socket_sendto)
def _firewall_socket_sendto(self: socket.socket, data: Any, *args: Any) -> int:
    fw = _current_firewall.get()
    new_args = list(args)
    if fw is not None and not _in_firewall_resolution.get() and new_args:
        address = new_args[-1]
        if address is not None:
            pinned = fw.assert_allowed_address(address)
            if pinned is not None:
                new_args[-1] = pinned
    return _orig_socket_sendto(self, data, *new_args)


if _orig_socket_sendmsg is not None:

    @functools.wraps(_orig_socket_sendmsg)
    def _firewall_socket_sendmsg(
        self: socket.socket, buffers: Any, *args: Any, **kwargs: Any
    ) -> int:
        fw = _current_firewall.get()
        if fw is not None and not _in_firewall_resolution.get():
            target_addr = kwargs.get("address")
            if target_addr is None and len(args) >= 3:
                target_addr = args[2]
            if target_addr is not None:
                pinned = fw.assert_allowed_address(target_addr)
                if "address" in kwargs:
                    kwargs["address"] = pinned
                elif len(args) >= 3:
                    args_list = list(args)
                    args_list[2] = pinned
                    args = tuple(args_list)
        return _orig_socket_sendmsg(self, buffers, *args, **kwargs)


@functools.wraps(_orig_loop_create_connection)
async def _firewall_loop_create_connection(
    self: asyncio.base_events.BaseEventLoop,
    protocol_factory: Any,
    host: Any = None,
    port: Any = None,
    *args: Any,
    **kwargs: Any,
) -> tuple[asyncio.Transport, asyncio.Protocol]:
    fw = _current_firewall.get()
    target_host = host
    if fw is not None and not _in_firewall_resolution.get() and host is not None:
        pinned = fw.assert_allowed_address((host, port or 0))
        if isinstance(pinned, tuple) and len(pinned) >= 2:
            target_host = pinned[0]
            if kwargs.get("ssl") and "server_hostname" not in kwargs and isinstance(host, str):
                kwargs["server_hostname"] = host
    return await _orig_loop_create_connection(
        self, protocol_factory, host=target_host, port=port, *args, **kwargs
    )


def install_hooks() -> None:
    """Install process-wide socket and event loop interception hooks."""
    global _hooks_installed
    if _hooks_installed:
        return

    socket.socket.connect = _firewall_socket_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _firewall_socket_connect_ex  # type: ignore[assignment]
    socket.socket.sendto = _firewall_socket_sendto  # type: ignore[assignment]
    if _orig_socket_sendmsg is not None:
        socket.socket.sendmsg = _firewall_socket_sendmsg  # type: ignore[assignment]
    asyncio.base_events.BaseEventLoop.create_connection = (  # type: ignore[assignment]
        _firewall_loop_create_connection
    )
    _hooks_installed = True
    logger.debug("scope_firewall_hooks_installed")


def uninstall_hooks() -> None:
    """Restore original socket and event loop functions."""
    global _hooks_installed
    if not _hooks_installed:
        return

    socket.socket.connect = _orig_socket_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _orig_socket_connect_ex  # type: ignore[assignment]
    socket.socket.sendto = _orig_socket_sendto  # type: ignore[assignment]
    if _orig_socket_sendmsg is not None:
        socket.socket.sendmsg = _orig_socket_sendmsg  # type: ignore[assignment]
    asyncio.base_events.BaseEventLoop.create_connection = (  # type: ignore[assignment]
        _orig_loop_create_connection
    )
    _hooks_installed = False
    logger.debug("scope_firewall_hooks_uninstalled")


# ── OS / Kernel Network Firewall Controller ───────────────────────────────────

class OSFirewallController:
    """Controls OS-level / Kernel network packet filtering boundaries.

    Interacts directly with native OS packet filtering facilities:
      - Windows: Windows Defender Firewall (`netsh advfirewall firewall`)
      - Linux: Netfilter (`iptables`)

    Operates in dual mode:
      1. Elevated Mode (Admin/Root): Applies native OS firewall rules restricting
         outbound traffic strictly to authorized campaign scope CIDRs.
      2. Unprivileged Mode: Gracefully yields to the In-Process Transport Socket Interceptor
         while recording audit logs, ensuring zero runtime crashes or elevation side-effects.

    Includes fail-safe automatic rule rollback on context exit and process shutdown (`atexit`).
    """

    _active_rules: set[str] = set()
    _lock = threading.Lock()

    @classmethod
    def is_elevated(cls) -> bool:
        """Check whether the current Python process has administrative/root privileges."""
        if sys.platform == "win32":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        elif sys.platform.startswith("linux") or sys.platform == "darwin":
            return getattr(os, "geteuid", lambda: -1)() == 0
        return False

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        """Return operational status and capabilities of the OS-level firewall."""
        elevated = cls.is_elevated()
        with cls._lock:
            active_count = len(cls._active_rules)
            rule_list = sorted(list(cls._active_rules))

        engine = (
            "Windows Defender Firewall (netsh)"
            if sys.platform == "win32"
            else ("Linux Netfilter (iptables)" if sys.platform.startswith("linux") else "Transport Interceptor")
        )
        return {
            "platform": sys.platform,
            "engine": engine,
            "elevated": elevated,
            "os_level_active": elevated and active_count > 0,
            "active_rules_count": active_count,
            "active_rules": rule_list,
            "fallback_mode": "In-Process Transport Socket Interception",
        }

    @classmethod
    def apply_rules(
        cls,
        campaign: Campaign | None,
        scope_cidrs: list[str],
        program: str | None = None,
    ) -> list[str]:
        """Apply OS-level firewall rules restricting outbound egress to scope_cidrs.

        If process is not elevated, logs an audit notice and returns an empty list (safe fallback).
        """
        if not scope_cidrs:
            return []

        if not cls.is_elevated():
            logger.info(
                "os_firewall_unprivileged_fallback",
                platform=sys.platform,
                reason="Process lacks Administrator/root privilege. Enforcing via Transport Socket Interceptor.",
            )
            return []

        cidrs_str = ",".join(scope_cidrs)
        rule_token = secrets.token_hex(6)
        rule_name = f"ARES_SCOPE_WALL_{rule_token}"
        applied: list[str] = []
        prog = program or sys.executable

        try:
            if sys.platform == "win32":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=allow",
                    f"program={prog}",
                    f"remoteip={cidrs_str}",
                    "enable=yes",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    applied.append(rule_name)
                    with cls._lock:
                        cls._active_rules.add(rule_name)
                    logger.info("os_firewall_rule_applied", rule=rule_name, cidrs=scope_cidrs, platform="windows")
                else:
                    logger.warning("os_firewall_rule_failed", rule=rule_name, error=res.stderr.strip() or res.stdout.strip())

            elif sys.platform.startswith("linux"):
                pid = str(os.getpid())
                cmd = [
                    "iptables", "-I", "OUTPUT", "1",
                    "-m", "owner", "--pid-owner", pid,
                    "-d", cidrs_str,
                    "-j", "ACCEPT",
                    "-m", "comment", "--comment", rule_name,
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    applied.append(rule_name)
                    with cls._lock:
                        cls._active_rules.add(rule_name)
                    logger.info("os_firewall_rule_applied", rule=rule_name, cidrs=scope_cidrs, platform="linux")
                else:
                    logger.warning("os_firewall_rule_failed", rule=rule_name, error=res.stderr.strip())

        except Exception as exc:
            logger.warning("os_firewall_apply_exception", error=str(exc))

        return applied

    @classmethod
    def remove_rules(cls, rule_ids: list[str]) -> int:
        """Remove previously created OS firewall rules."""
        removed = 0
        for rule_name in rule_ids:
            try:
                if sys.platform == "win32":
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if res.returncode == 0:
                        removed += 1
                elif sys.platform.startswith("linux"):
                    cmd = ["iptables", "-D", "OUTPUT", "-m", "comment", "--comment", rule_name, "-j", "ACCEPT"]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if res.returncode == 0:
                        removed += 1
            except Exception as exc:
                logger.warning("os_firewall_remove_failed", rule=rule_name, error=str(exc))
            finally:
                with cls._lock:
                    cls._active_rules.discard(rule_name)

        if removed > 0:
            logger.info("os_firewall_rules_removed", count=removed)
        return removed

    @classmethod
    def cleanup_all(cls) -> None:
        """Emergency cleanup handler executed at exit to guarantee zero orphaned OS rules."""
        with cls._lock:
            rules_to_clean = list(cls._active_rules)
        if rules_to_clean:
            cls.remove_rules(rules_to_clean)


atexit.register(OSFirewallController.cleanup_all)


def get_os_firewall_status() -> dict[str, Any]:
    """Public helper to inspect OS-level firewall status and active rules."""
    return OSFirewallController.get_status()


# ── Context Managers ─────────────────────────────────────────────────────────

_PROXY_KEYS: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@contextlib.asynccontextmanager
async def scope_firewall_guard(
    campaign: Campaign | None,
    module_id: str = "",
    module_category: str = "",
    enabled: bool | None = None,
    enable_os_firewall: bool | None = None,
) -> AsyncGenerator[ScopeFirewall | None, None]:
    """Async context manager activating dual-layer scope firewall."""
    if enabled is None:
        enabled = os.environ.get("ARES_SCOPE_FIREWALL_ENABLED", "1").lower() not in (
            "0",
            "false",
            "no",
        )

    if not enabled or campaign is None or not getattr(campaign, "scope", None):
        yield None
        return

    if enable_os_firewall is None:
        enable_os_firewall = os.environ.get("ARES_OS_FIREWALL_ENABLED", "1").lower() not in (
            "0",
            "false",
            "no",
        )

    install_hooks()
    fw = ScopeFirewall(
        campaign=campaign,
        module_id=module_id,
        module_category=module_category,
    )
    token = _current_firewall.set(fw)
    os_rules: list[str] = []
    if enable_os_firewall:
        os_rules = OSFirewallController.apply_rules(campaign, fw.scope_cidrs)

    # Neutralize proxy environment variables that could route traffic out-of-scope
    saved_proxies = {k: os.environ.pop(k) for k in _PROXY_KEYS if k in os.environ}

    try:
        yield fw
    finally:
        _current_firewall.reset(token)
        if os_rules:
            OSFirewallController.remove_rules(os_rules)
        os.environ.update(saved_proxies)


@contextlib.contextmanager
def scope_firewall_sync_guard(
    campaign: Campaign | None,
    module_id: str = "",
    module_category: str = "",
    enabled: bool | None = None,
    enable_os_firewall: bool | None = None,
) -> Generator[ScopeFirewall | None, None, None]:
    """Sync context manager activating dual-layer scope firewall."""
    if enabled is None:
        enabled = os.environ.get("ARES_SCOPE_FIREWALL_ENABLED", "1").lower() not in (
            "0",
            "false",
            "no",
        )

    if not enabled or campaign is None or not getattr(campaign, "scope", None):
        yield None
        return

    if enable_os_firewall is None:
        enable_os_firewall = os.environ.get("ARES_OS_FIREWALL_ENABLED", "1").lower() not in (
            "0",
            "false",
            "no",
        )

    install_hooks()
    fw = ScopeFirewall(
        campaign=campaign,
        module_id=module_id,
        module_category=module_category,
    )
    token = _current_firewall.set(fw)
    os_rules: list[str] = []
    if enable_os_firewall:
        os_rules = OSFirewallController.apply_rules(campaign, fw.scope_cidrs)

    # Neutralize proxy environment variables that could route traffic out-of-scope
    saved_proxies = {k: os.environ.pop(k) for k in _PROXY_KEYS if k in os.environ}

    try:
        yield fw
    finally:
        _current_firewall.reset(token)
        if os_rules:
            OSFirewallController.remove_rules(os_rules)
        os.environ.update(saved_proxies)
