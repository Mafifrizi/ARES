"""
SOCKS5 / SSH Tunnel Management — network.pivot
MITRE: T1090.001 — Proxy: Internal Proxy
       T1021.004 — Remote Services: SSH

Thin wrapper around ares/pivot/infrastructure.py (580 lines, fully implemented).
Creates and manages SSH SOCKS5 tunnels through compromised pivot hosts.

Once established, ALL subsequent ARES modules can reach internal network
segments through the tunnel — transparent to the module.

PivotManager auto-routes: request to 10.0.0.x → tunnel with matching subnet.
Generates proxychains.conf automatically.

Tunnel types supported:
  SOCKS5 / SSH_DYNAMIC   — SSH -D (most common)
  SSH_LOCAL_FWD          — SSH -L for specific port forwards
  REVERSE_TCP            — for outbound-only pivot hosts

OPSEC: LOW — SSH dynamic port forward uses encrypted SSH protocol.
       Appears as normal SSH connection. No new tools on target.
"""
from __future__ import annotations

from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.pivot")

# Campaign-level singleton PivotManager (shared across module runs)
_PIVOT_MANAGERS: dict[str, "Any"] = {}   # campaign_id → PivotManager


class PivotModule(BaseModule):
    """
    network.pivot — Create SOCKS5/SSH tunnels through compromised hosts. All subsequent modules route through tunnel

    OPSEC: LOW
    MITRE: "T1090.001", "T1021.004"
    REQUIRES: "target", "credential"
    OUTPUTS:  "pivot_tunnel", "proxy_url", "proxychains_config"
    """
    MODULE_ID          = "network.pivot"
    MODULE_NAME        = "Pivot Tunnel Management"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "Create SOCKS5/SSH tunnels through compromised hosts. "
        "All subsequent modules route through tunnel automatically. "
        "Generates proxychains.conf. Supports chained pivots."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["target", "credential"]
    OUTPUTS            = ["pivot_tunnel", "proxy_url", "proxychains_config"]
    MITRE_TECHNIQUES   = ["T1090.001", "T1021.004"]
    MODULE_TIMEOUT_SECONDS: int | None = 60  # seconds

    async def validate(self, ctx: "Any") -> None:
        """Enforce pivot host + credentials."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "network.pivot requires 'target' — IP or hostname of the pivot host "
                "(a host where you have SSH access).",
                module_id=self.MODULE_ID, field="target",
            )
        username = ctx.params.get("username", "")
        if not username:
            raise ModuleValidationError(
                "network.pivot requires 'username' for SSH authentication.",
                module_id=self.MODULE_ID, field="username",
            )
        has_secret = bool(ctx.params.get("password") or ctx.params.get("key_path") or
                          ctx.params.get("secret") or
                          (getattr(ctx, "vault", None) and
                           getattr(getattr(ctx, "vault", None), "_store", None)))
        if not has_secret:
            raise ModuleValidationError(
                "network.pivot requires SSH credentials — "
                "pass 'password', 'key_path', or provide a vault credential.",
                module_id=self.MODULE_ID, field="password",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})

        target   = sanitize_hostname(
            getattr(ctx, "target", "") or ctx.params.get("target", "")
        )
        username = ctx.params.get("username", "")
        secret   = ctx.params.get("password", "") or ctx.params.get("secret", "")
        key_path = ctx.params.get("key_path", "")
        ssh_port = int(ctx.params.get("ssh_port", 22))
        local_port      = int(ctx.params.get("local_port", 0))
        reachable_nets  = ctx.params.get("reachable_subnets", [])
        campaign_id     = getattr(getattr(self, "campaign", None), "id", "default")

        # Reveal from vault if no plaintext secret
        if not secret and not key_path:
            vault = getattr(ctx, "vault", None)
            cred  = getattr(ctx, "best_credential", lambda: None)()
            if cred and vault:
                try:
                    secret = vault.reveal(cred.id) or ""
                except Exception:
                    pass

        findings, raw = await self.run(
            target=target, username=username, secret=secret,
            key_path=key_path, ssh_port=ssh_port, local_port=local_port,
            reachable_subnets=reachable_nets, campaign_id=campaign_id,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.pivot")
    async def run(self, target: str, username: str, secret: str = "",
                  key_path: str = "", ssh_port: int = 22, local_port: int = 0,
                  reachable_subnets: list[str] | None = None,
                  campaign_id: str = "default", **kwargs: Any):
        from ares.pivot.infrastructure import PivotManager, TunnelState

        logger.info("pivot_establish", target=target, username=username)
        audit("network_pivot", actor=username, technique="T1090.001",
              source="operator", target=target)

        await self.before_request(target, "default")

        # Get or create campaign-level PivotManager
        if campaign_id not in _PIVOT_MANAGERS:
            _PIVOT_MANAGERS[campaign_id] = PivotManager(operator="ares")
        pm = _PIVOT_MANAGERS[campaign_id]

        try:
            tunnel = await pm.establish_socks5(
                pivot_host        = target,
                username          = username,
                secret            = secret,
                local_port        = local_port,
                ssh_port          = ssh_port,
                reachable_subnets = reachable_subnets or [],
                key_path          = key_path,
            )
        except Exception as exc:
            raise self._classify_error(exc) from exc

        if tunnel.state != TunnelState.ACTIVE:
            logger.warning("pivot_not_active", target=target, state=tunnel.state.value)
            return [], {
                "error": f"Tunnel state: {tunnel.state.value}",
                "target": target,
            }

        proxychains = pm.generate_proxychains_config()
        proxy_url   = tunnel.proxy_url

        logger.info("pivot_active",
                    tunnel_id=tunnel.tunnel_id,
                    proxy_url=proxy_url,
                    local_port=tunnel.local_port)

        self.finding(
            title       = f"Pivot Tunnel Active: {target} → {proxy_url}",
            description = (
                f"SOCKS5 tunnel established through {target} (port {tunnel.local_port}). "
                f"All ARES modules can now reach internal networks "
                f"{', '.join(reachable_subnets) if reachable_subnets else '(auto-routed)'}. "
                f"Use proxychains or set proxy_url={proxy_url} in subsequent modules."
            ),
            severity    = Severity.INFO,
            mitre_technique = "T1090.001",
            mitre_tactic    = "Command and Control",
            evidence = {
                "tunnel_id":         tunnel.tunnel_id,
                "pivot_host":        target,
                "proxy_url":         proxy_url,
                "local_port":        tunnel.local_port,
                "reachable_subnets": reachable_subnets or [],
                "proxychains_conf":  proxychains,
            },
            remediation = (
                "Restrict SSH access to jump hosts. Enable SSH bastion host logging. "
                "Monitor for SSH -D dynamic port forward connections in SSH logs."
            ),
            host = target, confidence = 1.0,
        )

        raw = {
            "tunnel_id":       tunnel.tunnel_id,
            "tunnel_type":     tunnel.tunnel_type.value,
            "state":           tunnel.state.value,
            "pivot_host":      target,
            "proxy_url":       proxy_url,
            "local_port":      tunnel.local_port,
            "proxychains_conf": proxychains,
            "reachable_subnets": reachable_subnets or [],
            "all_tunnels":     [t.to_dict() for t in pm.all_tunnels()],
        }
        raw["pivot_tunnel"] = raw.get("tunnel_id", "")  # OUTPUTS key
        raw["proxychains_config"] = raw.get("proxychains_conf", "")  # OUTPUTS key
        return self._findings[:], raw

    async def teardown(self, campaign_id: str = "default") -> None:
        """Close all tunnels for this campaign. Called when campaign ends."""
        pm = _PIVOT_MANAGERS.get(campaign_id)
        if not pm:
            return
        for tunnel in pm.all_tunnels():
            try:
                # Close SSH connection handle
                if tunnel._conn:
                    tunnel._conn.close()
                elif tunnel._proc:
                    tunnel._proc.terminate()
            except Exception:
                pass
        _PIVOT_MANAGERS.pop(campaign_id, None)
        logger.info("pivot_teardown", campaign_id=campaign_id)
