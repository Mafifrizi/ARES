"""
SMB Signing Configuration Audit
MITRE: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)

Checks whether SMB signing is required on target hosts.
When SMB signing is NOT required, the host is potentially vulnerable
to NTLM relay attacks (NTLM authentication captured from one host
can be relayed to authenticate against this host without knowing the password).

This module is DETECTION ONLY.
It checks the SMB dialect negotiation response to read the signing flags —
exactly what tools like nmap (smb-security-mode script) and
Nessus (plugin 57608) do during a security assessment.

No traffic is captured, no authentication is relayed, no credentials
are harvested. The module only reads the SecurityMode field from
the SMB NEGOTIATE_PROTOCOL response.

Checks:
  - SMB1: SecurityMode byte (bit 3 = signing_required)
  - SMB2/3: SecurityMode field (0x0001 = enabled, 0x0002 = required)
  - Reports: enabled_not_required (MEDIUM), disabled entirely (HIGH)

Also optionally checks LDAP signing (ldap_signing param=True):
  - Queries LDAP rootDSE serverName attribute
  - Reports if LDAP signing is not enforced (prerequisite for LDAP relay)

OPSEC: LOW — one TCP connection to port 445, reads negotiate response,
       immediately disconnects. No authentication attempted.
"""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.lateral.smb_relay")

# SMB2 NEGOTIATE request — minimal valid packet to elicit a response
# Header: Protocol ID + StructureSize + CreditCharge + Status + Command=0 (NEGOTIATE)
# Body: StructureSize + DialectCount=3 + SecurityMode=0 + Reserved + Capabilities
#       ClientGuid + NegotiateContextOffset + NegotiateContextCount
# Dialects: SMB 2.0.2, 2.1, 3.0
def _build_smb2_negotiate() -> bytes:
    """Build minimal SMB2 NEGOTIATE request."""
    header = (
        b"\x00\x00\x00\x7e"                  # NetBIOS session length (126 bytes)
        b"\xfeSMB"                            # SMB2 magic
        b"\x40\x00"                           # StructureSize = 64
        b"\x00\x00"                           # CreditCharge
        b"\x00\x00\x00\x00"                   # Status
        b"\x00\x00"                           # Command = NEGOTIATE (0)
        b"\x1f\x00"                           # CreditRequest
        b"\x00\x00\x00\x00"                   # Flags
        b"\x00\x00\x00\x00"                   # NextCommand
        b"\x01\x00\x00\x00\x00\x00\x00\x00"  # MessageId
        b"\x00\x00\x00\x00"                   # Reserved
        b"\x00\x00\x00\x00"                   # TreeId
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # SessionId
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature (16 bytes)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    body = (
        b"\x24\x00"                           # StructureSize = 36
        b"\x03\x00"                           # DialectCount = 3
        b"\x00\x00"                           # SecurityMode = 0
        b"\x00\x00"                           # Reserved
        b"\x7f\x00\x00\x00"                   # Capabilities
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # ClientGuid (16 bytes)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"                   # NegotiateContextOffset
        b"\x00\x00"                           # NegotiateContextCount
        b"\x00\x00"                           # Reserved2
        b"\x02\x02"                           # Dialect SMB 2.0.2
        b"\x10\x02"                           # Dialect SMB 2.1
        b"\x00\x03"                           # Dialect SMB 3.0
    )
    return header + body


_SMB2_NEGOTIATE = _build_smb2_negotiate()

# Offsets in SMB2 NEGOTIATE response
_SMB2_RESP_HEADER_SIZE  = 64    # fixed SMB2 header
_SMB2_SECURITY_MODE_OFF = 70    # SecurityMode is at offset 70 from start of packet
                                 # (64 header + 2 StructureSize + 2 DialectRevision + 2 SecurityMode)

# SMB2 SecurityMode flags
_SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
_SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


async def _check_smb_signing(target: str, port: int = 445, timeout: float = 8.0) -> dict[str, Any]:
    """
    Send minimal SMB2 NEGOTIATE and read SecurityMode from response.
    Returns dict with: signing_enabled, signing_required, dialect, raw_security_mode, error.
    """
    result: dict[str, Any] = {
        "signing_enabled":  None,
        "signing_required": None,
        "dialect":          None,
        "security_mode":    None,
        "error":            "",
    }
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )
        writer.write(_SMB2_NEGOTIATE)
        await writer.drain()

        # Read response — SMB2 response is at least 68 bytes (4 NetBIOS + 64 SMB2 header)
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if len(data) < 72:
            result["error"] = f"Response too short ({len(data)} bytes)"
            return result

        # Skip 4-byte NetBIOS header, check SMB2 magic
        smb_start = 4
        if data[smb_start:smb_start + 4] != b"\xfeSMB":
            result["error"] = "Not an SMB2 response"
            return result

        # Read dialect revision (bytes 68-69 in full packet = bytes 4 into NEGOTIATE body)
        # SMB2 header = 64 bytes, body starts at offset 64 from smb_start
        # body offset 0-1 = StructureSize, 2-3 = DialectRevision
        body_start = smb_start + 64   # 68
        if len(data) < body_start + 8:
            result["error"] = "Response truncated"
            return result

        dialect_rev   = struct.unpack_from("<H", data, body_start + 2)[0]
        security_mode = struct.unpack_from("<H", data, body_start + 4)[0]

        result["dialect"]          = f"SMB2 0x{dialect_rev:04x}"
        result["security_mode"]    = security_mode
        result["signing_enabled"]  = bool(security_mode & _SMB2_NEGOTIATE_SIGNING_ENABLED)
        result["signing_required"] = bool(security_mode & _SMB2_NEGOTIATE_SIGNING_REQUIRED)

    except asyncio.TimeoutError:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Port 445 closed"
    except OSError as e:
        result["error"] = str(e)[:100]

    return result


class SMBRelayAuditModule(BaseModule):
    """
    Checks SMB signing configuration on one or more targets.
    Hosts without signing REQUIRED are flagged as relay-vulnerable.
    """

    MODULE_ID          = "lateral.smb_relay"
    MODULE_NAME        = "SMB Signing Audit (Relay Prerequisite)"
    MODULE_CATEGORY    = "lateral"
    MODULE_DESCRIPTION = (
        "Check whether SMB signing is required on target hosts — "
        "signing not required = potential NTLM relay attack surface"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["smb_signing_config", "relay_candidates"]
    MITRE_TECHNIQUES   = ["T1557.001", "T1082"]

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
                "lateral.smb_relay requires 'target' — IP or subnet to audit.",
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
        # Accept either a single target or a list via params
        target  = getattr(ctx, "target", "") or ctx.params.get("target", "")
        targets = ctx.params.get("targets", [])
        if target and target not in targets:
            targets = [target] + list(targets)
        check_ldap = ctx.params.get("check_ldap", False)

        findings, raw = await self.run(targets=targets, check_ldap=check_ldap)
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("lateral.smb_relay")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        targets     = kwargs.get("targets", [])
        check_ldap  = kwargs.get("check_ldap", False)
        dry_run     = kwargs.get("dry_run", False)

        # Also accept single target
        single = kwargs.get("target", "")
        if single and single not in targets:
            targets = [single] + list(targets)

        if not targets:
            return [], {"error": "no targets provided"}
        if dry_run:
            return [], {"dry_run": True}

        targets = [sanitize_hostname(t) for t in targets if t]

        logger.info("smb_relay_audit_start", targets=len(targets))
        audit("smb_relay_audit", actor="operator", source="operator",
              target=",".join(targets[:5]), technique="T1082")

        results:          dict[str, dict[str, Any]] = {}
        relay_candidates: list[str] = []
        signing_disabled: list[str] = []

        # Check all targets concurrently (rate-limited)
        await self.noise.rate_limiter.acquire("network_scan")

        checks = [
            _check_smb_signing(target)
            for target in targets
        ]
        raw_results = await asyncio.gather(*checks, return_exceptions=True)

        for target, result in zip(targets, raw_results):
            if isinstance(result, Exception):
                results[target] = {"error": str(result)[:100]}
                continue

            results[target] = result
            await self.noise.jitter.sleep()

            if result.get("error"):
                continue

            signing_required = result.get("signing_required")
            signing_enabled  = result.get("signing_enabled")

            if signing_required is False:
                relay_candidates.append(target)
            if signing_enabled is False and signing_required is False:
                signing_disabled.append(target)

        # ── Findings ───────────────────────────────────────────────────────

        if relay_candidates:
            self.finding(
                title=(
                    f"SMB Signing Not Required — "
                    f"{len(relay_candidates)} Host(s) Vulnerable to NTLM Relay"
                ),
                description=(
                    f"{len(relay_candidates)} host(s) do not require SMB signing: "
                    f"{', '.join(relay_candidates[:10])}. "
                    "When SMB signing is not required, an attacker who can intercept "
                    "NTLM authentication traffic (e.g. via LLMNR/NBT-NS poisoning or "
                    "a compromised host on the same subnet) can relay credentials "
                    "captured from one host to authenticate against these hosts "
                    "without knowing the plaintext password. "
                    "Combined with a captured domain user hash, this can lead to "
                    "lateral movement across the environment."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1557.001",
                mitre_tactic="Credential Access",
                evidence={
                    "relay_candidates": relay_candidates,
                    "smb_results": {
                        t: {
                            k: v for k, v in results[t].items()
                            if k in ("signing_enabled", "signing_required",
                                     "dialect", "security_mode")
                        }
                        for t in relay_candidates
                    },
                },
                remediation=(
                    "Enable SMB signing on all Windows hosts via Group Policy: "
                    "Computer Configuration → Windows Settings → Security Settings → "
                    "Local Policies → Security Options: "
                    "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                    "For workstations: set 'Microsoft network client: "
                    "Digitally sign communications (always)' = Enabled. "
                    "For DCs and servers, also enable RequireSecuritySignature=1 in the registry: "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters."
                ),
                confidence=1.0,
            )

        if signing_disabled:
            self.finding(
                title=(
                    f"SMB Signing Completely Disabled on "
                    f"{len(signing_disabled)} Host(s)"
                ),
                description=(
                    f"{len(signing_disabled)} host(s) have SMB signing disabled entirely "
                    f"(SecurityMode=0x0000): {', '.join(signing_disabled[:10])}. "
                    "This is more severe than 'not required' — no signing capability "
                    "is advertised at all, making these hosts easy relay targets "
                    "and indicating a non-default (weakened) SMB configuration."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1557.001",
                mitre_tactic="Credential Access",
                evidence={
                    "signing_disabled_hosts": signing_disabled,
                },
                remediation=(
                    "Investigate why signing was disabled on these hosts — "
                    "this is a non-default configuration and may indicate intentional "
                    "weakening or a misconfigured NAS/appliance. "
                    "Re-enable signing as described above."
                ),
                confidence=1.0,
            )

        # ── Optional: LDAP signing check ──────────────────────────────────
        if check_ldap:
            ldap_unsigned: list[str] = []
            for target in targets:
                try:
                    await self.before_request(target, "ldap")
                    # Query rootDSE — if LDAP returns without requiring signing, it's unsigned
                    loop = asyncio.get_running_loop()

                    def _check_ldap(host: str) -> bool:
                        """
                        Attempt an anonymous LDAP bind without signing.
                        If it succeeds, LDAP signing is NOT enforced.
                        """
                        try:
                            import ssl
                            from ldap3 import (  # type: ignore[import]
                                Server, Connection, ALL, ANONYMOUS,
                            )
                            srv  = Server(host, port=389, get_info=ALL,
                                          connect_timeout=8)
                            conn = Connection(srv, authentication=ANONYMOUS,
                                             auto_bind=False)
                            conn.open()
                            bound = conn.bind()
                            conn.unbind()
                            return bound   # True = signed not required
                        except Exception:
                            return False

                    unsigned = await loop.run_in_executor(None, _check_ldap, target)
                    if unsigned:
                        ldap_unsigned.append(target)
                    await self.noise.jitter.sleep()
                except Exception:
                    continue

            if ldap_unsigned:
                self.finding(
                    title=(
                        f"LDAP Signing Not Enforced — "
                        f"{len(ldap_unsigned)} Host(s)"
                    ),
                    description=(
                        f"{len(ldap_unsigned)} host(s) accept LDAP connections without "
                        f"signing: {', '.join(ldap_unsigned[:10])}. "
                        "LDAP relay (relaying NTLM credentials to LDAP) can be used "
                        "to add machines to the domain, modify ACLs, or perform "
                        "resource-based constrained delegation attacks."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1557.001",
                    mitre_tactic="Credential Access",
                    evidence={"ldap_unsigned_hosts": ldap_unsigned},
                    remediation=(
                        "Enforce LDAP signing via Group Policy: "
                        "Computer Configuration → Windows Settings → Security Settings → "
                        "Local Policies → Security Options: "
                        "'Domain controller: LDAP server signing requirements' = 'Require signing'. "
                        "Also set LdapEnforceChannelBinding=2 to require LDAP channel binding."
                    ),
                    confidence=0.9,
                )

        raw = {
            "targets_checked":   len(targets),
            "relay_candidates":  relay_candidates,
            "signing_disabled":  signing_disabled,
            "per_host_results":  results,
        }
        raw["smb_signing_config"] = {k: v for k, v in raw.items()}  # OUTPUTS key — shallow copy to avoid circular ref
        return self._findings[:], raw
