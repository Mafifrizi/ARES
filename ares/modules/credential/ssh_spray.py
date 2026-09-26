"""
ARES SSH Credential Spray & Authentication Audit Module
Category: credential
MITRE: T1110.003 (Password Spraying), T1110.001 (Password Guessing), T1021.004 (SSH)

Low-and-slow authentication testing against SSH services.
Built-in lockout protection:
  - Configurable max attempts per target (default: 20)
  - Jittered delay between attempts (default: 0.5s)
  - LockoutCircuitBreaker with fail-closed safety
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.modules.params import SSHSprayParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    module_contract,
)
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.ssh_spray")


@module_contract(
    permissions=[
        NetworkPermission(ports=[22], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=SSHSprayParams,
)
class SSHSprayModule(BaseModule[SSHSprayParams, ModuleResult]):
    """
    credential.ssh_spray - SSH authentication audit and credential spray.

    OPSEC: MEDIUM
    MITRE: "T1110.003", "T1110.001", "T1021.004"
    OUTPUTS: ["valid_credentials", "compromised_hosts"]
    """

    MODULE_ID          = "credential.ssh_spray"
    MODULE_NAME        = "SSH Credential Spray & Authentication Audit"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = "Low-and-slow SSH authentication audit and password spray against Linux hosts."
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["valid_credentials", "compromised_hosts"]
    MITRE_TECHNIQUES   = ["T1110.003", "T1110.001", "T1021.004"]
    PARAMS_MODEL       = SSHSprayParams

    async def execute(self, ctx: Any) -> ModuleResult:
        """Execute SSH credential spray using ExecutionContext or dict params."""
        params = getattr(ctx, "params", {})
        if isinstance(params, SSHSprayParams):
            target = params.target
            port = params.port
            users = params.users
            passwords = params.passwords
            single_user = params.username
            single_pass = params.password.get_secret_value() if params.password else None
            delay_s = params.delay_s
            timeout_s = params.timeout_s
            max_attempts = params.max_attempts
        elif isinstance(params, dict):
            target = str(params.get("target") or params.get("host") or getattr(ctx, "target", "")).strip()
            port = int(params.get("port") or params.get("ssh_port") or 22)
            users = list(params.get("users") or ["root", "admin", "kali", "ubuntu", "user", "kraii"])
            passwords = list(params.get("passwords") or ["Password123!", "admin", "root", "toor", "ubuntu", "kali", "password", "123456"])
            single_user = params.get("username")
            raw_pass = params.get("password")
            single_pass = raw_pass.get_secret_value() if hasattr(raw_pass, "get_secret_value") else raw_pass
            delay_s = float(params.get("delay_s", 0.5))
            timeout_s = float(params.get("timeout_s", 5.0))
            max_attempts = int(params.get("max_attempts", 20))
        else:
            target = getattr(ctx, "target", "")
            port = 22
            users = ["root", "admin", "kali", "ubuntu", "kraii"]
            passwords = ["Password123!", "admin", "root"]
            single_user = None
            single_pass = None
            delay_s = 0.5
            timeout_s = 5.0
            max_attempts = 20

        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={
                    "dry_run": True,
                    "target": target,
                    "port": port,
                    "candidate_users": [single_user] if single_user else users[:5],
                    "candidate_passwords_count": 1 if single_pass else len(passwords),
                },
            )

        findings, raw = await self.run(
            target=target,
            port=port,
            users=[single_user] if single_user else users,
            passwords=[single_pass] if single_pass else passwords,
            delay_s=delay_s,
            timeout_s=timeout_s,
            max_attempts=max_attempts,
        )

        return ModuleResult(
            status="success" if raw.get("valid_credentials") else "partial" if findings or raw else "failed",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.ssh_spray")
    async def run(
        self,
        target: str,
        port: int = 22,
        users: list[str] | None = None,
        passwords: list[str] | None = None,
        delay_s: float = 0.5,
        timeout_s: float = 5.0,
        max_attempts: int = 20,
        **kwargs: Any,
    ) -> tuple[list[Finding], dict[str, Any]]:
        target_users = users or ["root", "admin", "kali", "ubuntu", "kraii"]
        target_passwords = passwords or ["Password123!", "admin", "root", "toor"]

        valid_credentials: list[dict[str, Any]] = []
        tested_pairs: list[dict[str, Any]] = []
        loot: list[dict[str, Any]] = []
        attempts = 0

        # Try asyncssh or fallback to paramiko
        has_asyncssh = False
        try:
            import asyncssh
            has_asyncssh = True
        except ImportError:
            pass

        has_paramiko = False
        try:
            import paramiko
            has_paramiko = True
        except ImportError:
            pass

        logger.info(
            "ssh_spray_starting",
            target=target,
            port=port,
            user_count=len(target_users),
            pass_count=len(target_passwords),
            engine="asyncssh" if has_asyncssh else "paramiko" if has_paramiko else "none",
        )

        # Pair generation: low-and-slow across users
        for password in target_passwords:
            for username in target_users:
                if attempts >= max_attempts:
                    logger.info("ssh_spray_max_attempts_reached", limit=max_attempts)
                    break

                # Scope enforcement + rate limiting + jitter per attempt (MOD-031)
                await self.before_request(target, "ssh")

                attempts += 1
                success = False

                if has_asyncssh:
                    try:
                        conn = await asyncio.wait_for(
                            asyncssh.connect(
                                host=target,
                                port=port,
                                username=username,
                                password=password,
                                known_hosts=None,
                            ),
                            timeout=timeout_s,
                        )
                        success = True
                        close_fn = getattr(conn, "close", None)
                        if callable(close_fn):
                            res = close_fn()
                            if asyncio.iscoroutine(res):
                                await res
                    except (asyncssh.PermissionDenied, asyncssh.KeyExchangeFailed, asyncssh.Error):
                        success = False
                    except (asyncio.TimeoutError, OSError) as exc:
                        logger.debug("ssh_spray_connection_error", target=target, user=username, error=str(exc))
                        success = False
                    except Exception as exc:
                        logger.debug("ssh_spray_attempt_failed", target=target, user=username, error=str(exc))
                        success = False
                elif has_paramiko:
                    try:
                        def _test_paramiko(t: str, p: int, u: str, pw: str, to: float) -> bool:
                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            try:
                                client.connect(t, port=p, username=u, password=pw, timeout=to, banner_timeout=to, look_for_keys=False)
                                client.close()
                                return True
                            except paramiko.AuthenticationException:
                                return False
                            except Exception:
                                return False

                        loop = asyncio.get_running_loop()
                        success = await loop.run_in_executor(None, _test_paramiko, target, port, username, password, timeout_s)
                    except Exception:
                        success = False

                tested_pairs.append({
                    "username": username,
                    "password_masked": "***",
                    "success": success,
                })

                if success:
                    logger.info("ssh_spray_valid_credential_found", target=target, user=username)
                    valid_credentials.append({
                        "username": username,
                        "password": password,
                        "target": target,
                        "port": int(port),
                        "method": "password",
                        "protocol": "ssh",
                        "privilege": "admin" if username in ("root", "admin", "system") else "user",
                        "domain": None,
                    })
                    # Emit finding immediately for discovered credential
                    self.finding(
                        title=f"Valid SSH Credentials Discovered: {username}@{target}:{port}",
                        description=(
                            f"Authentication audit succeeded against SSH service at {target}:{port}. "
                            f"Account '{username}' accepted the tested credentials, granting shell access."
                        ),
                        severity=Severity.CRITICAL if username in ("root", "admin", "system") else Severity.HIGH,
                        mitre_technique="T1110.003",
                        mitre_tactic="Initial Access",
                        evidence={
                            "username": username,
                            "service": "ssh",
                            "port": port,
                            "target": target,
                        },
                        remediation="Enforce public-key authentication, disable SSH password auth, and implement fail2ban.",
                        host=target,
                        confidence=1.0,
                    )

                if delay_s > 0:
                    await asyncio.sleep(delay_s)

            if attempts >= max_attempts:
                break

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis for SSH Spray
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect Linux SSH Credential Spray & Authentication Anomalies ({target}:{port})\n"
            f"Syslog\n"
            f"| where ProcessName =~ \"sshd\"\n"
            f"| where SyslogMessage has_any (\"Failed password\", \"Invalid user\", \"Connection closed by authenticating user\")\n"
            f"| where HostIP has \"{target}\" or Computer has \"{target}\"\n"
            f"| summarize FailedAttempts = count(), UniqueUsers = dcount(SyslogMessage) by HostIP, bin(TimeGenerated, 5m)\n"
            f"| where FailedAttempts >= 3\n"
        )
        sigma_rule = (
            f"title: Linux SSH Credential Spray & Brute Force Detection ({target})\n"
            f"id: 8f9a0b1c-ares-ssh-spray-{abs(hash(str(target) + str(port))) % 1000000:06d}\n"
            f"status: experimental\n"
            f"description: Detects repeated authentication failures indicating SSH credential spraying or brute force attacks targeting {target}.\n"
            f"logsource:\n"
            f"  product: linux\n"
            f"  service: auth\n"
            f"detection:\n"
            f"  selection:\n"
            f"    process: 'sshd'\n"
            f"    message|contains:\n"
            f"      - 'Failed password'\n"
            f"      - 'Invalid user'\n"
            f"  condition: selection\n"
            f"level: high\n"
            f"tags:\n"
            f"  - attack.credential_access\n"
            f"  - attack.t1110.003\n"
            f"  - attack.t1021.004\n"
        )
        loot.extend([
            {
                "name": f"Detection Rule (KQL): SSH Credential Spray ({target})",
                "loot_type": "detection_rule_kql",
                "description": f"Microsoft Sentinel KQL query for detecting SSH credential spraying on {target}",
                "content": {"kql": kql_query, "target": target, "port": port},
                "tags": ["detection", "kql", "sentinel", "linux", "ssh", "credential_spray"],
            },
            {
                "name": f"Detection Rule (Sigma): SSH Credential Spray ({target})",
                "loot_type": "detection_rule_sigma",
                "description": f"Sigma rule for detecting SSH authentication spraying on {target}",
                "content": {"sigma": sigma_rule, "target": target, "port": port},
                "tags": ["detection", "sigma", "linux", "auth", "ssh", "credential_spray"],
            },
        ])

        raw: dict[str, Any] = {
            "target": target,
            "port": port,
            "attempts": attempts,
            "tested_pairs_count": len(tested_pairs),
            "valid_credentials_count": len(valid_credentials),
            "valid_credentials": valid_credentials,
            "loot": loot,
            "compromised": len(valid_credentials) > 0,
            "foothold_granted": len(valid_credentials) > 0,
            "host": target,
        }

        return self._findings[:], raw
