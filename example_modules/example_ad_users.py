"""
ARES Example Module: AD User Enumeration
Demonstrates the full Module SDK pattern for community authors.

This module:
  - Uses @module_metadata decorator for clean metadata
  - Implements validate(ctx) for parameter checking
  - Implements execute(ctx) with dry_run support
  - Returns structured ModuleResult
  - Uses self.finding() helper for consistent finding creation
  - Handles errors properly with SDK error types

Copy this as a starting point for your own modules.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.modules.sdk import (
    BaseModule,
    ExecutionContext,
    ModuleResult,
    OpsecLevel,
    Severity,
    module_metadata,
    get_logger,
    AuthenticationFailed,
    HostUnreachable,
    ModuleValidationError,
    HostArtifact,
    UserArtifact,
)

logger = get_logger("example.ad_users")


@module_metadata(
    module_id   = "example.ad_users",
    name        = "Example AD User Enumeration",
    category    = "ad",
    description = "Example module: enumerates AD users via LDAP",
    author      = "ares-team@example.com",
    opsec       = OpsecLevel.LOW,
    requires    = ["domain_creds", "ldap_access"],
    outputs     = ["user_list"],
    mitre       = ["T1087.002"],
)
class ExampleADUserModule(BaseModule):
    """
    Example module demonstrating the ARES SDK.
    Performs LDAP user enumeration against an Active Directory domain.

    Parameters (in ctx.params):
        dc      — IP or hostname of a Domain Controller
        domain  — AD domain name (CORP.LOCAL)
        ldap_filter — optional custom LDAP filter (default: all users)
        max_results — max users to return (default: 1000)

    Outputs:
        Findings: one Finding per sensitive user found
        ModuleResult.new_credentials — cleared accounts (no pre-auth)
    """

    async def validate(self, ctx: ExecutionContext) -> None:
        """
        Validate context before execution.
        Raise ModuleValidationError for missing/invalid params.
        """
        # Require these context fields
        ctx.require("target", "domain")

        # Validate module-specific params
        dc = ctx.params.get("dc") or ctx.target
        if not dc:
            raise ModuleValidationError(
                "ExampleADUserModule requires 'dc' parameter (Domain Controller address)",
                module_id=self.MODULE_ID,
                field="dc",
            )

        max_results = ctx.params.get("max_results", 1000)
        if not isinstance(max_results, int) or max_results < 1:
            raise ModuleValidationError(
                "max_results must be a positive integer",
                module_id=self.MODULE_ID,
                field="max_results",
            )

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        """
        Execute the AD user enumeration.
        Returns ModuleResult with findings and discovered users.
        """
        dc          = ctx.params.get("dc") or ctx.target
        domain      = ctx.domain or ctx.params.get("domain", "")
        max_results = ctx.params.get("max_results", 1000)
        ldap_filter = ctx.params.get("ldap_filter", "(objectClass=user)")

        self._bind_log_context(target=dc)

        # ── Dry run mode: simulate without network ────────────────────────
        if ctx.dry_run:
            logger.info("dry_run_mode", module=self.MODULE_ID, dc=dc)
            # Simulate finding users
            simulated_users = [
                {"username": "svc_sql",   "domain": domain, "spns": ["MSSQLSvc/db01:1433"], "no_preauth": False},
                {"username": "jsmith",    "domain": domain, "spns": [],                      "no_preauth": False},
                {"username": "asrep_user","domain": domain, "spns": [],                      "no_preauth": True},
            ]
            return self._process_users(simulated_users, ctx, dc)

        # ── Real execution ────────────────────────────────────────────────
        await self.before_request(dc, action="ldap_query")

        try:
            # Production: use ldap3 to query
            # import ldap3
            # cred = ctx.best_credential()
            # server = ldap3.Server(dc, port=389, use_ssl=False, get_info=ldap3.ALL)
            # conn = ldap3.Connection(
            #     server,
            #     user=f"{domain}\\{cred.username}" if cred else None,
            #     password=cred.secret if cred else None,
            #     authentication=ldap3.NTLM if cred else ldap3.ANONYMOUS,
            # )
            # conn.bind()
            # conn.search(
            #     f"DC={domain.replace('.', ',DC=')}",
            #     ldap_filter,
            #     attributes=["sAMAccountName", "servicePrincipalName",
            #                 "userAccountControl", "memberOf"],
            #     size_limit=max_results,
            # )
            # users = [dict(e["attributes"]) for e in conn.entries]
            users: list[dict[str, Any]] = []   # stub
            return self._process_users(users, ctx, dc)

        except Exception as exc:
            # Map generic errors to SDK error types for engine handling
            err = str(exc).lower()
            if "unreachable" in err or "no route" in err:
                raise HostUnreachable(
                    f"DC {dc} unreachable: {exc}",
                    module_id=self.MODULE_ID, target=dc
                )
            if "invalid credentials" in err or "wrong password" in err:
                cred = ctx.best_credential()
                raise AuthenticationFailed(
                    f"LDAP auth failed on {dc}",
                    module_id=self.MODULE_ID, target=dc,
                    username=cred.username if cred else "",
                )
            raise

    def _process_users(
        self,
        users: list[dict[str, Any]],
        ctx:   ExecutionContext,
        dc:    str,
    ) -> ModuleResult:
        """Process raw user data into findings and artifacts."""
        findings         = []
        asrep_candidates = []

        for user in users:
            username  = user.get("username") or user.get("sAMAccountName", "")
            spns      = user.get("spns") or user.get("servicePrincipalName", [])
            no_preauth = user.get("no_preauth", False)
            if isinstance(spns, str):
                spns = [spns]

            # Finding: SPN account (kerberoastable)
            if spns:
                f = self.finding(
                    title       = f"Kerberoastable account: {username}@{ctx.domain}",
                    description = (
                        f"User {username} has {len(spns)} SPN(s) registered. "
                        f"All domain users can request a TGS ticket and crack it offline."
                    ),
                    severity        = Severity.HIGH,
                    mitre_technique = "T1558.003",
                    mitre_tactic    = "Credential Access",
                    host            = dc,
                    evidence        = {"username": username, "spns": spns},
                    remediation     = (
                        "Use Group Managed Service Accounts (gMSA) for service accounts. "
                        "Require AES-256 Kerberos encryption. "
                        "Use strong random passwords (25+ chars) if MSA not possible."
                    ),
                )
                findings.append(f)

            # Finding: AS-REP roastable
            if no_preauth:
                f = self.finding(
                    title       = f"AS-REP Roastable account: {username}@{ctx.domain}",
                    description = (
                        f"Account {username} has pre-authentication disabled. "
                        f"An attacker can request the AS-REP hash without any credentials."
                    ),
                    severity        = Severity.HIGH,
                    mitre_technique = "T1558.004",
                    host            = dc,
                    evidence        = {"username": username},
                    remediation     = "Enable Kerberos pre-authentication on this account.",
                )
                findings.append(f)
                asrep_candidates.append(username)

        logger.info(
            "user_enumeration_complete",
            total=len(users),
            spn_accounts=sum(1 for u in users if u.get("spns")),
            asrep_accounts=len(asrep_candidates),
        )

        return ModuleResult(
            status           = "success" if users else "no_results",
            findings         = findings,
            discovered_hosts = [dc],
            raw              = {
                "total_users":       len(users),
                "spn_accounts":      [u.get("username") for u in users if u.get("spns")],
                "asrep_candidates":  asrep_candidates,
                "domain":            ctx.domain,
            },
            module_id = self.MODULE_ID,
        )

    # Legacy interface — engine calls execute(ctx) but run(**kwargs) kept for compat
    async def run(self, **kwargs: Any):
        ctx = ExecutionContext.for_test(
            target    = kwargs.get("dc", ""),
            module_id = self.MODULE_ID,
            params    = kwargs,
            dry_run   = True,
        )
        result = await self.execute(ctx)
        return result.findings, result.raw
