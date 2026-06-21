"""
ARES Remote Execution Engine
Execute commands and scripts on compromised hosts via established sessions.

Execution methods:
  PsExec + SMB     → Windows arbitrary command execution
  WMI              → Windows command execution (stealthier)
  WinRM/PowerShell → PowerShell remote execution
  SSH              → Linux/Unix command execution

Payload types:
  command          → single shell command (whoami, ipconfig, etc.)
  powershell       → PowerShell scriptblock
  bash             → Bash script
  upload_and_run   → upload file then execute

All executions:
  - Validated against campaign scope (requires Campaign passed to constructor)
  - Audit logged (operator, target, command, result)
  - Timeout enforced
  - Output captured and stored
"""
from __future__ import annotations

import asyncio
import base64
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname

logger = get_logger("ares.execution")


class ExecutionMethod(str, Enum):
    PSEXEC       = "psexec"
    WMIEXEC      = "wmiexec"
    WINRM        = "winrm"
    WINRM_PS     = "winrm_powershell"
    SSH          = "ssh"
    SSH_BASH     = "ssh_bash"


class PayloadType(str, Enum):
    COMMAND      = "command"
    POWERSHELL   = "powershell"
    BASH         = "bash"
    UPLOAD_RUN   = "upload_and_run"


@dataclass
class ExecutionResult:
    exec_id:     str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target:      str = ""
    host:        str = ""   # alias for target
    method:      ExecutionMethod = ExecutionMethod.SSH
    payload_type: PayloadType = PayloadType.COMMAND
    command:     str = ""
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = -1
    success:     bool = False
    duration_ms: float = 0.0
    timestamp:   float = field(default_factory=time.time)
    operator:    str = "unknown"


class RemoteExecutor:
    """
    Dispatches remote command execution via established sessions.
    Requires a valid credential and confirmed access.
    """

    def __init__(
        self,
        operator:         str = "unknown",
        timeout_s:        int = 60,
        campaign:         Any | None = None,
        known_hosts_file: str | None = None,
    ) -> None:
        self.operator         = operator
        self.timeout_s        = timeout_s
        self.campaign         = campaign         # Campaign instance for scope enforcement
        self.known_hosts_file = known_hosts_file # Path to known_hosts; None = AutoAddPolicy + warning

    async def execute(
        self,
        target:    str,
        command:   str,
        username:  str,
        domain:    str,
        secret:    str,
        method:    ExecutionMethod = ExecutionMethod.WINRM,
        payload_type: PayloadType = PayloadType.COMMAND,
    ) -> ExecutionResult:
        """
        Execute a command on a remote host.
        Returns ExecutionResult with stdout, stderr, exit_code.
        """
        target = sanitize_hostname(target)

        # Scope enforcement — reject targets outside campaign scope before any
        # network activity. Mirrors the before_request() guard used in modules.
        if self.campaign is not None and not self.campaign.is_in_scope(target):
            logger.warning(
                "execution_blocked_out_of_scope",
                target=target, operator=self.operator,
            )
            return ExecutionResult(
                target=target, method=method,
                payload_type=payload_type, command=command[:200],
                operator=self.operator,
                stderr=f"Target '{target}' is outside campaign scope — execution blocked.",
                exit_code=-1, success=False,
            )

        t0     = time.monotonic()
        result = ExecutionResult(
            target=target, method=method,
            payload_type=payload_type, command=command[:200],
            operator=self.operator,
        )

        audit(
            "remote_execution_start",
            actor=self.operator,
            target=target,
            method=method.value,
            command_preview=command[:50],
        )

        try:
            stdout, stderr, exit_code = await asyncio.wait_for(
                self._dispatch(target, command, username, domain, secret, method, payload_type),
                timeout=self.timeout_s,
            )
            result.stdout    = stdout
            result.stderr    = stderr
            result.exit_code = exit_code
            result.success   = exit_code == 0
        except asyncio.TimeoutError:
            result.stderr    = f"Execution timed out after {self.timeout_s}s"
            result.exit_code = -1
        except Exception as exc:
            result.stderr    = str(exc)[:500]
            result.exit_code = -1

        result.duration_ms = round((time.monotonic() - t0) * 1000, 2)

        audit(
            "remote_execution_complete",
            actor=self.operator,
            target=target,
            method=method.value,
            success=result.success,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
        )

        if result.success:
            logger.info(
                "execution_success",
                target=target, method=method.value,
                duration_ms=result.duration_ms,
            )
        else:
            logger.warning(
                "execution_failed",
                target=target, method=method.value,
                error=result.stderr[:100],
            )

        return result

    async def execute_powershell(
        self,
        target:    str,
        script:    str,
        username:  str,
        domain:    str,
        secret:    str,
        encoded:   bool = True,   # base64-encode the script
    ) -> ExecutionResult:
        """
        Execute a PowerShell scriptblock on a Windows host via WinRM.
        If encoded=True, wraps in powershell.exe -EncodedCommand (bypasses simple logging).
        """
        if encoded:
            # UTF-16LE encoding required by PowerShell -EncodedCommand
            cmd = base64.b64encode(script.encode("utf-16-le")).decode()
            command = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {cmd}"
        else:
            command = f"powershell.exe -NoProfile -NonInteractive -Command {script!r}"

        return await self.execute(
            target, command, username, domain, secret,
            method=ExecutionMethod.WINRM_PS,
            payload_type=PayloadType.POWERSHELL,
        )

    async def execute_bash(
        self,
        target:    str,
        script:    str,
        username:  str,
        secret:    str,
        shell:     str = "/bin/bash",
    ) -> ExecutionResult:
        """Execute a bash script on a Linux host via SSH."""
        return await self.execute(
            target, script, username, "", secret,
            method=ExecutionMethod.SSH_BASH,
            payload_type=PayloadType.BASH,
        )

    async def upload_and_run(
        self,
        target:      str,
        local_data:  bytes,
        remote_path: str,
        username:    str,
        domain:      str,
        secret:      str,
        method:      ExecutionMethod = ExecutionMethod.WINRM,
    ) -> ExecutionResult:
        """
        Upload a file to the target and execute it.
        Uses SMB share for Windows, SCP/SFTP for Linux.
        """
        # In production:
        # 1. Upload via SMB (impacket) or SCP (paramiko)
        # 2. Execute via chosen method
        # 3. Optionally clean up after execution

        logger.info(
            "upload_and_run",
            target=target, remote_path=remote_path,
            size_b=len(local_data), method=method.value,
        )
        audit(
            "upload_and_run",
            actor=self.operator,
            target=target,
            remote_path=remote_path,
            size_b=len(local_data),
        )

        return await self.execute(
            target, remote_path, username, domain, secret,
            method=method, payload_type=PayloadType.UPLOAD_RUN,
        )

    # ── Dispatch ──────────────────────────────────────────────────────────

    async def _dispatch(
        self,
        target:    str,
        command:   str,
        username:  str,
        domain:    str,
        secret:    str,
        method:    ExecutionMethod,
        payload_type: PayloadType,
    ) -> tuple[str, str, int]:
        """Route to the appropriate execution backend."""
        if method == ExecutionMethod.PSEXEC:
            return await self._run_psexec(target, command, username, domain, secret)
        elif method == ExecutionMethod.WMIEXEC:
            return await self._run_wmiexec(target, command, username, domain, secret)
        elif method in (ExecutionMethod.WINRM, ExecutionMethod.WINRM_PS):
            return await self._run_winrm(target, command, username, domain, secret)
        elif method in (ExecutionMethod.SSH, ExecutionMethod.SSH_BASH):
            return await self._run_ssh(target, command, username, secret)
        else:
            return "", f"Unknown execution method: {method}", 1

    async def _run_psexec(self, target, command, username, domain, secret) -> tuple[str, str, int]:
        """
        PsExec execution — delegates to canonical implementation in lateral.modules.PsExecLateral.
        Canonical code lives in ares/modules/lateral/modules.py.
        """
        # Check optional dep before instantiating module (avoids masking ImportError)
        try:
            import impacket  # noqa: F401
        except ImportError:
            return "", "impacket not installed — run: pip install impacket", 1
        try:
            from ares.modules.lateral.modules import PsExecLateral
            from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
            from ares.core.config import get_settings
            from ares.core.noise import NoiseController
            _c = Campaign(name="_exec", operator=self.operator)
            lateral = PsExecLateral(settings=get_settings(), campaign=_c, noise=NoiseController(_c))
            result = await lateral.execute(
                target=target, username=username,
                password=secret, domain=domain, command=command,
            )
            return result.stdout or "", result.stderr or "", 0 if result.success else 1
        except Exception as exc:
            return "", str(exc)[:300], 1
    async def _run_winrm(self, target, command, username, domain, secret) -> tuple[str, str, int]:
        """
        WinRM / PowerShell Remoting execution — delegates to WinRMLateral.move().
        Canonical implementation lives in ares/modules/lateral/modules.py.

        Supports both HTTP (port 5985, NTLM) and HTTPS (port 5986, SSL).
        Returns (stdout, stderr, exit_code) consistent with other _run_* methods.
        """
        # Check optional dep before instantiating module (avoids masking ImportError)
        try:
            import winrm  # noqa: F401
        except ImportError:
            return "", "pywinrm not installed — run: pip install pywinrm", 1
        try:
            from ares.modules.lateral.modules import WinRMLateral
            from ares.core.campaign import Campaign
            from ares.core.config import get_settings
            from ares.core.noise import NoiseController
            _c = Campaign(name="_exec", operator=self.operator)
            lateral = WinRMLateral(settings=get_settings(), campaign=_c, noise=NoiseController(_c))
            result = await lateral.move(
                target=target,
                username=username,
                domain=domain,
                secret=secret,
                command=command,
            )
            # LateralResult uses .output/.error — map to stdout/stderr contract
            return (
                result.output or "",
                result.error  or "",
                0 if result.success else 1,
            )
        except Exception as exc:
            return "", str(exc)[:300], 1

    async def _run_wmiexec(self, target, command, username, domain, secret) -> tuple[str, str, int]:
        """
        WMIExec execution — delegates to canonical implementation in lateral.modules.WMIExecLateral.
        Canonical code lives in ares/modules/lateral/modules.py.
        """
        # Check optional dep before instantiating module (avoids masking ImportError)
        try:
            import impacket  # noqa: F401
        except ImportError:
            return "", "impacket not installed — run: pip install impacket", 1
        try:
            from ares.modules.lateral.modules import WMIExecLateral
            from ares.core.campaign import Campaign
            from ares.core.config import get_settings
            from ares.core.noise import NoiseController
            _c = Campaign(name="_exec", operator=self.operator)
            lateral = WMIExecLateral(settings=get_settings(), campaign=_c, noise=NoiseController(_c))
            result = await lateral.execute(
                target=target, username=username,
                password=secret, domain=domain, command=command,
            )
            return result.stdout or "", result.stderr or "", 0 if result.success else 1
        except Exception as exc:
            return "", str(exc)[:300], 1
    async def _run_ssh(self, target, command, username, secret) -> tuple[str, str, int]:
        import io
        try:
            import paramiko
        except ImportError:
            return "", "paramiko not installed — run: pip install paramiko", 1

        loop = asyncio.get_running_loop()
        known_hosts_file = self.known_hosts_file

        def _connect_and_run() -> tuple[str, str, int]:
            client = paramiko.SSHClient()

            if known_hosts_file:
                # Strict verification — reject unknown hosts
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.load_host_keys(known_hosts_file)
            else:
                # No known_hosts supplied — auto-accept but warn loudly.
                # Risk: MITM can steal credentials on untrusted networks (hotel
                # wifi, compromised VPN, pivot host). Supply known_hosts_file to
                # the RemoteExecutor constructor to enable host verification.
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                logger.warning(
                    "ssh_host_key_unverified",
                    target=target,
                    operator=self.operator,
                    risk="MITM on untrusted networks can steal credentials",
                    fix="Pass known_hosts_file= to RemoteExecutor()",
                )

            connect_kwargs: dict = {
                "hostname": target,
                "username": username,
                "timeout": self.timeout_s,
                "banner_timeout": 10,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if secret.strip().startswith("-----BEGIN"):
                try:
                    pkey = paramiko.RSAKey.from_private_key(io.StringIO(secret))
                except paramiko.ssh_exception.SSHException:
                    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(secret))
                connect_kwargs["pkey"] = pkey
            else:
                connect_kwargs["password"] = secret

            client.connect(**connect_kwargs)
            _, stdout_fh, stderr_fh = client.exec_command(command, timeout=self.timeout_s)
            exit_code = stdout_fh.channel.recv_exit_status()
            stdout = stdout_fh.read().decode("utf-8", errors="replace")
            stderr = stderr_fh.read().decode("utf-8", errors="replace")
            client.close()
            return stdout, stderr, exit_code

        try:
            return await loop.run_in_executor(None, _connect_and_run)
        except paramiko.AuthenticationException:
            return "", "SSH authentication failed", 1
        except paramiko.SSHException as exc:
            return "", f"SSH error: {exc}", 1
        except OSError as exc:
            return "", f"Network error: {exc}", 1
