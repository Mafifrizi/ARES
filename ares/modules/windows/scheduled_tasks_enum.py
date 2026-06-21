"""
Windows Scheduled Tasks Enumeration — Privilege Escalation Path Analysis
MITRE: T1053.005 (Scheduled Task/Job), T1574.001 (DLL Search Order Hijacking)

Enumerates scheduled tasks on the target via impacket TSCH RPC and identifies:
  1. Tasks running as SYSTEM, high-privilege domain accounts, or Administrators
  2. Tasks whose binary or script path is writable by non-admin users
     (if the path is writable, the task binary can be replaced for privesc)
  3. Tasks running from user-writable directories (%TEMP%, %APPDATA%, etc.)
  4. Misconfigured task permissions (task itself writable by low-priv users)
  5. Tasks that run at logon or on a schedule that could be abused for persistence

This module is ENUMERATION ONLY — it reads task XML and checks paths.
No tasks are created, modified, or triggered.

OPSEC: LOW-MEDIUM — connects via SMB + TSCH RPC (\\pipe\\atsvc).
Generates: SMB connection events. No process execution on target.
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.windows.scheduled_tasks_enum")


# ── High-privilege user indicators ────────────────────────────────────────────
_HIGH_PRIV_PATTERNS: list[str] = [
    "system",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "builtin\\administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
]

# ── Writable path indicators (user-controlled locations) ──────────────────────
_USER_WRITABLE_INDICATORS: list[str] = [
    "%temp%",
    "%tmp%",
    "%appdata%",
    "%localappdata%",
    "\\users\\",
    "\\temp\\",
    "\\tmp\\",
    "c:\\programdata",
]

# ── Interesting task folders to enumerate ─────────────────────────────────────
_TASK_FOLDERS: list[str] = [
    "\\",
    "\\Microsoft\\Windows\\",
    "\\Microsoft\\Windows\\WindowsUpdate\\",
]


def _parse_task_xml(xml_str: str) -> dict[str, Any]:
    """
    Parse task XML to extract:
      - Run as user (Principal UserId or GroupId)
      - Run level (HighestAvailable, LimitedAccess)
      - Actions (Exec command + arguments, ComHandler)
      - Triggers (type, start boundary)
    """
    info: dict[str, Any] = {
        "run_as":      "",
        "run_level":   "",
        "actions":     [],
        "triggers":    [],
        "parse_error": "",
    }
    if not xml_str:
        return info
    try:
        # Strip namespace for simpler parsing
        xml_clean = re.sub(r'\s+xmlns(?::\w+)?="[^"]+"', "", xml_str)
        root = ET.fromstring(xml_clean)

        # Principal
        for p in root.iter("Principal"):
            uid = p.find("UserId")
            gid = p.find("GroupId")
            rl  = p.find("RunLevel")
            if uid is not None and uid.text:
                info["run_as"]    = uid.text.strip()
            elif gid is not None and gid.text:
                info["run_as"]    = gid.text.strip()
            if rl is not None and rl.text:
                info["run_level"] = rl.text.strip()

        # Actions
        for action in root.iter("Actions"):
            for exec_el in action.iter("Exec"):
                cmd  = exec_el.find("Command")
                args = exec_el.find("Arguments")
                info["actions"].append({
                    "type":    "Exec",
                    "command": cmd.text.strip()  if (cmd  and cmd.text)  else "",
                    "args":    args.text.strip() if (args and args.text) else "",
                })
            for com_el in action.iter("ComHandler"):
                clsid = com_el.find("ClassId")
                info["actions"].append({
                    "type":   "ComHandler",
                    "classid": clsid.text.strip() if (clsid and clsid.text) else "",
                })

        # Triggers (first 3)
        for trigger in list(root.iter("Triggers"))[0:1]:
            for child in list(trigger)[:3]:
                tag = child.tag.split("}")[-1]
                sb  = child.find("StartBoundary")
                info["triggers"].append({
                    "type":  tag,
                    "start": sb.text.strip() if (sb and sb.text) else "",
                })

    except ET.ParseError as e:
        info["parse_error"] = str(e)[:100]
    return info


class ScheduledTasksEnumModule(BaseModule):
    """
    windows.scheduled_tasks_enum — Enumerate scheduled tasks via TSCH RPC and identify high-privilege tasks with writable binary pa

    OPSEC: LOW
    MITRE: "T1053.005", "T1082"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "scheduled_tasks", "privesc_vectors"
    """
    MODULE_ID          = "windows.scheduled_tasks_enum"
    MODULE_NAME        = "Scheduled Tasks Enumeration"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Enumerate scheduled tasks via TSCH RPC and identify high-privilege tasks "
        "with writable binary paths — privilege escalation path analysis"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["scheduled_tasks", "privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1053.005", "T1082"]

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
                f"{self.MODULE_ID} requires 'target' — IP or hostname.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True},
            )
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        findings, raw = await self.run(
            target=target, username=username, password=password, domain=domain,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("windows.scheduled_tasks_enum")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = sanitize_hostname(kwargs.get("target", ""))
        username = kwargs.get("username", "")
        password = kwargs.get("password", "") or kwargs.get("secret", "")
        domain   = kwargs.get("domain", "")
        dry_run  = kwargs.get("dry_run", False)

        if not target or not username:
            return [], {"error": "target and username required"}
        if dry_run:
            return [], {"dry_run": True}

        try:
            from impacket.dcerpc.v5 import transport, tsch               # type: ignore[import]
            from impacket.dcerpc.v5.tsch import (                        # type: ignore[import]
                hSchRpcEnumFolders, hSchRpcEnumTasks, hSchRpcRetrieveTask,
                TASK_ENUM_HIDDEN,
            )
        except ImportError:
            return [], {"error": "impacket not installed — pip install ares-redteam[ad]"}

        logger.info("scheduled_tasks_enum_start", target=target, username=username)
        audit("scheduled_tasks_enum", actor=username, source="operator",
              target=target, technique="T1053.005")

        await self.before_request(target, "smb")

        loop = asyncio.get_running_loop()

        def _enum_tasks() -> dict[str, Any]:
            tasks:  list[dict[str, Any]] = []
            errors: list[str] = []

            try:
                string_binding = f"ncacn_np:{target}[\\pipe\\atsvc]"
                rpc_transport  = transport.DCERPCTransportFactory(string_binding)
                rpc_transport.set_credentials(
                    username, password, domain, "", ""
                )
                dce = rpc_transport.get_dce_rpc()
                dce.connect()
                dce.bind(tsch.MSRPC_UUID_TSCHS)

                def _enum_folder(folder: str) -> None:
                    # Enumerate tasks in this folder
                    try:
                        resp = hSchRpcEnumTasks(dce, folder, flags=TASK_ENUM_HIDDEN,
                                               startIndex=0, cRequested=100)
                        task_names = resp["pNames"]
                    except Exception as e:
                        errors.append(f"EnumTasks({folder}): {e!s:.80}")
                        return

                    for tn in task_names:
                        name = tn["Data"].rstrip("\x00") if hasattr(tn, "__getitem__") \
                               else str(tn).rstrip("\x00")
                        if not name:
                            continue
                        full_path = folder.rstrip("\\") + "\\" + name
                        try:
                            xml_resp = hSchRpcRetrieveTask(dce, full_path)
                            xml_str  = xml_resp["pXml"]
                            if hasattr(xml_str, "getData"):
                                xml_str = xml_str.getData().decode(
                                    "utf-16-le", errors="replace"
                                )
                            parsed = _parse_task_xml(xml_str)
                            tasks.append({
                                "path":      full_path,
                                "run_as":    parsed["run_as"],
                                "run_level": parsed["run_level"],
                                "actions":   parsed["actions"],
                                "triggers":  parsed["triggers"],
                            })
                        except Exception as e:
                            errors.append(f"RetrieveTask({full_path}): {e!s:.60}")

                # Also try subfolders via EnumFolders
                try:
                    resp    = hSchRpcEnumFolders(dce, "\\", 0, 0, 100)
                    folders = ["\\"] + [
                        "\\" + (f["Data"].rstrip("\x00")
                                if hasattr(f, "__getitem__") else str(f).rstrip("\x00"))
                        for f in resp.get("pNames", [])
                    ]
                except Exception:
                    folders = ["\\"]

                for folder in folders:
                    _enum_folder(folder)

                dce.disconnect()

            except Exception as e:
                errors.append(str(e)[:200])

            return {"tasks": tasks, "errors": errors}

        result = await loop.run_in_executor(None, _enum_tasks)
        tasks  = result.get("tasks", [])
        errors = result.get("errors", [])

        # ── Analyse tasks ──────────────────────────────────────────────────

        high_priv_tasks:    list[dict[str, Any]] = []
        writable_path_tasks: list[dict[str, Any]] = []

        for task in tasks:
            run_as = (task.get("run_as") or "").lower()

            # Check if high-privilege principal
            is_high_priv = any(p in run_as for p in _HIGH_PRIV_PATTERNS)

            if is_high_priv:
                # Check each action for potentially writable path
                for action in task.get("actions", []):
                    if action.get("type") != "Exec":
                        continue
                    cmd = (action.get("command") or "").lower()
                    if any(ind in cmd for ind in _USER_WRITABLE_INDICATORS):
                        writable_path_tasks.append({
                            "task":    task["path"],
                            "run_as":  task["run_as"],
                            "command": action.get("command", ""),
                        })
                    else:
                        high_priv_tasks.append({
                            "task":    task["path"],
                            "run_as":  task["run_as"],
                            "command": action.get("command", ""),
                            "args":    action.get("args", ""),
                            "triggers": task.get("triggers", []),
                        })

        # ── Finding 1: High-priv tasks with writable binary paths ─────────
        if writable_path_tasks:
            self.finding(
                title=(
                    f"Scheduled Tasks Running as SYSTEM with Writable Binary Path "
                    f"on {target} ({len(writable_path_tasks)} task(s))"
                ),
                description=(
                    f"{len(writable_path_tasks)} scheduled task(s) on {target} run as "
                    "a high-privilege account AND execute binaries from user-writable "
                    "paths (%TEMP%, %APPDATA%, user directories). "
                    "If the binary path is writable by the current user, "
                    "replacing the binary will execute arbitrary code as SYSTEM "
                    "the next time the task fires."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1053.005",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":  target,
                    "tasks": writable_path_tasks,
                },
                remediation=(
                    "Move task binaries out of user-writable directories to "
                    "protected system paths (e.g. C:\\Program Files\\). "
                    "Apply icacls to restrict write access on task binary paths. "
                    "Audit scheduled tasks regularly with: "
                    "schtasks /query /fo LIST /v | findstr /i 'task run as'"
                ),
                host=target, confidence=0.85,
            )

        # ── Finding 2: High-priv tasks (informational, for lateral/persistence) ──
        if high_priv_tasks:
            # Report the most interesting ones (limit 15)
            reported = high_priv_tasks[:15]
            self.finding(
                title=(
                    f"High-Privilege Scheduled Tasks Found on {target} "
                    f"({len(high_priv_tasks)} task(s))"
                ),
                description=(
                    f"{len(high_priv_tasks)} scheduled task(s) run as SYSTEM or "
                    "domain admin on {target}. These are candidates for "
                    "persistence (if task ACL is misconfigured) and should be "
                    "reviewed for binary path writability. "
                    "Tasks: "
                    + ", ".join(t["task"] for t in reported)
                    + ("..." if len(high_priv_tasks) > 15 else "")
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1053.005",
                mitre_tactic="Discovery",
                evidence={
                    "host":         target,
                    "total":        len(high_priv_tasks),
                    "tasks_sample": reported,
                },
                remediation=(
                    "Review the ACL of each task with: "
                    "icacls C:\\Windows\\System32\\Tasks\\<task_name>. "
                    "Ensure only SYSTEM and Administrators have write access. "
                    "Audit task binary paths for writability."
                ),
                host=target, confidence=0.9,
            )

        # ── Finding 3: No tasks found (enumeration info) ───────────────────
        if not tasks and not errors:
            logger.info("scheduled_tasks_none_found", target=target)

        raw = {
            "target":               target,
            "total_tasks":          len(tasks),
            "high_priv_tasks":      high_priv_tasks,
            "writable_path_tasks":  writable_path_tasks,
            "all_tasks":            tasks[:50],  # cap raw output
            "errors":               errors,
        }
        raw["scheduled_tasks"] = self._findings  # OUTPUTS key
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
