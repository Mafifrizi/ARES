"""
Azure Recon & Attack Module — Production Implementation
AAD users, storage misconfig, RBAC over-permission, NSG rules.

Authentication (automatic priority order):
  1. ClientSecretCredential — if tenant_id + client_id + client_secret supplied
  2. DefaultAzureCredential — env vars / managed identity / Azure CLI / VS Code

Required optional extras:
    pip install ares-redteam[cloud]
    → azure-identity, azure-mgmt-authorization, azure-mgmt-storage,
      azure-mgmt-network, azure-mgmt-resource, requests
"""
from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.modules.cloud.azure")

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

_SENSITIVE_PORTS: set[int] = {22, 23, 3389, 5985, 5986, 1433, 3306, 5432,
                               6379, 9200, 27017, 445, 135, 2375, 2376}


def _get_credential(tenant_id=None, client_id=None, client_secret=None):
    from azure.identity import ClientSecretCredential, DefaultAzureCredential  # type: ignore[import]
    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id,
                                      client_secret=client_secret)
    return DefaultAzureCredential()


class AzureModule(BaseModule):
    """
    cloud.azure — AAD enum, storage misconfig, RBAC audit, NSG rules

    OPSEC: LOW
    MITRE: "T1526", "T1530", "T1580", "T1078.004"
    OUTPUTS:  "azure_findings"
    """
    MODULE_ID          = "cloud.azure"
    MODULE_NAME        = "Azure Recon & Attack"
    MODULE_CATEGORY    = "cloud"
    MODULE_DESCRIPTION = "AAD enum, storage misconfig, RBAC audit, NSG rules"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["azure_findings"]
    MITRE_TECHNIQUES   = ["T1526", "T1530", "T1580", "T1078.004"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        has_cred = bool(ctx.params.get("subscription_id") or
                        ctx.params.get("client_id") or
                        __import__("os").environ.get("AZURE_CLIENT_ID"))
        if not has_cred:
            raise ModuleValidationError(
                "cloud.azure requires Azure credentials — set subscription_id or "
                "AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID env vars.",
                module_id=self.MODULE_ID, field="subscription_id",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(status="success" if (findings or raw) else "partial",
                            findings=findings, raw=raw, module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""))

    @trace_module("cloud.azure")
    async def run(self, subscription_id: str, tenant_id: str | None = None,
                  client_id: str | None = None, client_secret: str | None = None,
                  **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        # Note: before_request() intentionally not called — cloud modules use
        # API credentials, not host IPs. Scope check (CIDR) does not apply to
        # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
        logger.info("azure_recon_start", subscription_id=subscription_id[:8] + "...")
        try:
            credential = _get_credential(tenant_id, client_id, client_secret)
        except ImportError as exc:
            raise ImportError(
                "azure-identity not installed. Run: pip install ares-redteam[cloud]"
            ) from exc

        loop = asyncio.get_running_loop()
        raw: dict[str, Any] = {"subscription_id": subscription_id}
        for label, fn in [
            ("aad_users", partial(self._enum_aad_users, credential)),
            ("storage",   partial(self._check_storage_accounts, credential, subscription_id)),
            ("rbac",      partial(self._check_rbac,             credential, subscription_id)),
            ("nsg",       partial(self._check_nsg_rules,        credential, subscription_id)),
        ]:
            await self.noise.rate_limiter.acquire("cloud_api")
            try:
                raw[label] = await loop.run_in_executor(None, fn)
            except Exception as exc:
                logger.warning(f"azure_{label}_failed", error=str(exc)[:150])
                raw[label] = {"error": str(exc)[:200]}
            await self.noise.jitter.sleep()
        logger.info("azure_recon_done", findings=len(self._findings))
        raw["azure_findings"] = self._findings  # matches OUTPUTS
        return self._findings, raw

    # ── AAD Users ─────────────────────────────────────────────────────────────

    def _enum_aad_users(self, credential: Any) -> dict[str, Any]:
        import requests  # type: ignore[import]
        token   = credential.get_token("https://graph.microsoft.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}
        session = requests.Session()
        session.headers.update(headers)

        guest_users: list[str] = []
        admin_users: list[str] = []
        disabled_admins: list[str] = []

        # Paginate users
        url: str | None = (
            "https://graph.microsoft.com/v1.0/users"
            "?$select=userPrincipalName,userType,accountEnabled&$top=999"
        )
        while url:
            data = session.get(url, timeout=20).json()
            for u in data.get("value", []):
                if u.get("userType") == "Guest":
                    guest_users.append(u.get("userPrincipalName", ""))
            url = data.get("@odata.nextLink")

        # Global Admins
        roles = session.get(
            "https://graph.microsoft.com/v1.0/directoryRoles"
            "?$filter=displayName eq 'Global Administrator'", timeout=20
        ).json()
        for role in roles.get("value", []):
            members = session.get(
                f"https://graph.microsoft.com/v1.0/directoryRoles/{role['id']}/members"
                "?$select=userPrincipalName,accountEnabled,id",
                timeout=20,
            ).json()
            for m in members.get("value", []):
                upn = m.get("userPrincipalName", m.get("id", ""))
                admin_users.append(upn)
                if not m.get("accountEnabled", True):
                    disabled_admins.append(upn)

        if len(admin_users) > 4:
            self.finding(
                title=f"Too Many Global Administrators ({len(admin_users)})",
                description=(
                    f"{len(admin_users)} accounts hold Global Administrator. "
                    "Best practice is ≤4 break-glass accounts. "
                    "Compromise of any grants full tenant control."
                ),
                severity=Severity.CRITICAL, mitre_technique="T1078.004",
                mitre_tactic="Initial Access",
                evidence={"admins": admin_users, "count": len(admin_users)},
                remediation=(
                    "Reduce to ≤4 break-glass accounts with hardware MFA (FIDO2). "
                    "Use PIM for just-in-time access. Enable Entra ID Protection."
                ),
            )
        elif admin_users:
            self.finding(
                title=f"Azure AD Global Administrator Accounts ({len(admin_users)})",
                description=(
                    f"{len(admin_users)} Global Administrator account(s) identified. "
                    "Compromise gives full Azure tenant access."
                ),
                severity=Severity.HIGH, mitre_technique="T1078.004",
                mitre_tactic="Initial Access",
                evidence={"admins": admin_users},
                remediation="Ensure hardware MFA on all GA accounts. Use PIM.",
            )

        if disabled_admins:
            self.finding(
                title=f"Disabled Accounts Retaining Global Administrator Role ({len(disabled_admins)})",
                description=(
                    f"{len(disabled_admins)} disabled account(s) still hold Global Administrator. "
                    "Re-enabling any gives instant tenant admin access."
                ),
                severity=Severity.MEDIUM, mitre_technique="T1078.004",
                mitre_tactic="Persistence",
                evidence={"disabled_admins": disabled_admins},
                remediation="Remove GA role from all disabled accounts.",
            )

        if len(guest_users) > 50:
            self.finding(
                title=f"Excessive Guest Users in Tenant ({len(guest_users)})",
                description=(
                    f"{len(guest_users)} external guest users. Over-scoped guests "
                    "increase lateral movement surface."
                ),
                severity=Severity.LOW, mitre_technique="T1078.004",
                mitre_tactic="Initial Access",
                evidence={"guest_count": len(guest_users), "sample": guest_users[:10]},
                remediation=(
                    "Review and remove stale guests. Enforce cross-tenant access policies. "
                    "Enable guest access reviews in Entra ID Governance."
                ),
            )

        return {"guest_users": guest_users, "admin_users": admin_users,
                "disabled_admins": disabled_admins}

    # ── Storage Accounts ──────────────────────────────────────────────────────

    def _check_storage_accounts(self, credential: Any,
                                  subscription_id: str) -> dict[str, Any]:
        from azure.mgmt.storage import StorageManagementClient  # type: ignore[import]
        client = StorageManagementClient(credential, subscription_id)
        public_containers: list[dict[str, Any]] = []
        http_allowed: list[str] = []

        for account in client.storage_accounts.list():
            name = account.name or ""
            rg   = ""
            if account.id and "/resourceGroups/" in account.id:
                rg = account.id.split("/resourceGroups/")[1].split("/")[0]

            allow_public = getattr(account, "allow_blob_public_access", None)
            if allow_public is True or allow_public is None:
                try:
                    for container in client.blob_containers.list(rg, name):
                        pa = getattr(container, "public_access", None)
                        if pa and str(pa).lower() not in ("none", "null", ""):
                            public_containers.append({
                                "storage_account": name,
                                "container":       container.name,
                                "access_level":    str(pa),
                                "resource_group":  rg,
                            })
                except Exception:
                    if allow_public is True:
                        public_containers.append({
                            "storage_account": name,
                            "container":       "(public access enabled at account level)",
                            "access_level":    "account-level",
                            "resource_group":  rg,
                        })

            if not getattr(account, "enable_https_traffic_only", True):
                http_allowed.append(name)

        if public_containers:
            self.finding(
                title=f"Publicly Accessible Azure Blob Containers ({len(public_containers)})",
                description=(
                    f"{len(public_containers)} blob container(s) accessible without "
                    "authentication. Data including backups and configs may be exposed."
                ),
                severity=Severity.CRITICAL, mitre_technique="T1530",
                mitre_tactic="Collection",
                evidence={"containers": public_containers[:20]},
                remediation=(
                    "Disable 'Allow Blob Public Access' at account level. "
                    "Apply Azure Policy: 'Storage accounts should disallow public blob access'. "
                    "Use SAS tokens with expiry for external sharing."
                ),
            )

        if http_allowed:
            self.finding(
                title=f"Storage Accounts Without HTTPS-Only Enforcement ({len(http_allowed)})",
                description=(
                    f"{len(http_allowed)} storage account(s) allow unencrypted HTTP. "
                    "Data in transit can be intercepted."
                ),
                severity=Severity.HIGH, mitre_technique="T1040",
                mitre_tactic="Collection",
                evidence={"accounts": http_allowed},
                remediation="Enable 'Secure transfer required' on all storage accounts.",
            )

        return {"public_containers": public_containers, "http_allowed": http_allowed}

    # ── RBAC ──────────────────────────────────────────────────────────────────

    def _check_rbac(self, credential: Any, subscription_id: str) -> dict[str, Any]:
        from azure.mgmt.authorization import AuthorizationManagementClient  # type: ignore[import]
        client    = AuthorizationManagementClient(credential, subscription_id)
        sub_scope = f"/subscriptions/{subscription_id}"
        _OWNER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        _CONTRIB  = "b24988ac-6180-42a0-ab88-20f7382dd24c"

        owner_assignments:       list[dict[str, Any]] = []
        contributor_assignments: list[dict[str, Any]] = []
        classic_admins:          list[str] = []

        try:
            for assign in client.role_assignments.list_for_scope(sub_scope):
                role_def_id = (assign.role_definition_id or "").split("/")[-1]
                scope       = (assign.scope or "").rstrip("/")
                if scope != sub_scope.rstrip("/"):
                    continue
                entry = {"principal_id": assign.principal_id or "",
                         "role_definition": role_def_id, "scope": scope}
                if role_def_id == _OWNER_ID:
                    owner_assignments.append(entry)
                elif role_def_id == _CONTRIB:
                    contributor_assignments.append(entry)
        except Exception as exc:
            logger.warning("azure_rbac_list_failed", error=str(exc)[:150])

        try:
            for ca in client.classic_administrators.list():
                email_addr = getattr(ca, "email_address", "") or ""
                role_name  = getattr(ca, "role", "") or ""
                if email_addr and "CoAdministrator" in role_name:
                    classic_admins.append(email_addr)
        except Exception as exc:
            logger.debug("azure_classic_admin_skipped", reason=str(exc)[:80])

        if owner_assignments:
            self.finding(
                title=f"Owner Assignments at Subscription Scope ({len(owner_assignments)})",
                description=(
                    f"{len(owner_assignments)} principal(s) hold Owner at subscription scope. "
                    "Owners can modify all resources and manage access."
                ),
                severity=Severity.CRITICAL, mitre_technique="T1078.004",
                mitre_tactic="Privilege Escalation",
                evidence={"owner_assignments": owner_assignments},
                remediation=(
                    "Scope Owner to resource groups. Use PIM for just-in-time access. "
                    "Keep ≤2 break-glass Owner accounts with hardware MFA."
                ),
            )

        if len(contributor_assignments) > 10:
            self.finding(
                title=f"Excessive Contributor Assignments at Subscription Scope ({len(contributor_assignments)})",
                description=(
                    f"{len(contributor_assignments)} principals have Contributor at subscription scope. "
                    "Contributor can create/delete resources and exfiltrate data."
                ),
                severity=Severity.HIGH, mitre_technique="T1078.004",
                mitre_tactic="Privilege Escalation",
                evidence={"count": len(contributor_assignments),
                           "sample": contributor_assignments[:10]},
                remediation=(
                    "Scope Contributor to resource groups. "
                    "Use custom roles with minimum permissions."
                ),
            )

        if classic_admins:
            self.finding(
                title=f"Legacy Classic Co-Administrators Found ({len(classic_admins)})",
                description=(
                    f"{len(classic_admins)} account(s) have Classic Co-Admin access. "
                    "These bypass Azure RBAC, MFA, and Conditional Access."
                ),
                severity=Severity.HIGH, mitre_technique="T1078.004",
                mitre_tactic="Persistence",
                evidence={"co_admins": classic_admins},
                remediation=(
                    "Remove all Classic Co-Admins. "
                    "Migrate to Azure RBAC Owner with PIM and MFA."
                ),
            )

        return {"owner_assignments": owner_assignments,
                "contributor_assignments": contributor_assignments,
                "classic_admins": classic_admins}

    # ── NSG Rules ─────────────────────────────────────────────────────────────

    def _check_nsg_rules(self, credential: Any, subscription_id: str) -> dict[str, Any]:
        from azure.mgmt.network import NetworkManagementClient  # type: ignore[import]
        net_client = NetworkManagementClient(credential, subscription_id)
        open_rules:         list[dict[str, Any]] = []
        wildcard_any_rules: list[dict[str, Any]] = []

        for nsg in net_client.network_security_groups.list_all():
            nsg_name = nsg.name or ""
            rg = ""
            if nsg.id and "/resourceGroups/" in nsg.id:
                rg = nsg.id.split("/resourceGroups/")[1].split("/")[0]

            for rule in (nsg.security_rules or []):
                direction = (getattr(rule, "direction", "") or "").lower()
                access    = (getattr(rule, "access", "") or "").lower()
                if direction != "inbound" or access != "allow":
                    continue

                src = (getattr(rule, "source_address_prefix", "") or "").strip()
                if src not in ("*", "0.0.0.0/0", "Internet", "Any"):
                    continue

                dest_port  = (getattr(rule, "destination_port_range", "") or "").strip()
                dest_ports = list(getattr(rule, "destination_port_ranges", []) or [])
                if dest_port:
                    dest_ports.append(dest_port)

                entry = {
                    "nsg":               nsg_name,
                    "rule_name":         rule.name or "",
                    "priority":          getattr(rule, "priority", 0),
                    "source":            src,
                    "destination_ports": dest_ports,
                    "resource_group":    rg,
                }

                is_wildcard = any(p in ("*", "Any") for p in dest_ports)
                if is_wildcard:
                    wildcard_any_rules.append(entry)
                    continue

                ports_hit: list[int] = []
                for port_spec in dest_ports:
                    if "-" in str(port_spec):
                        try:
                            lo, hi = str(port_spec).split("-")
                            ports_hit += [p for p in range(int(lo), int(hi) + 1)
                                          if p in _SENSITIVE_PORTS]
                        except ValueError:
                            pass
                    else:
                        try:
                            p = int(port_spec)
                            if p in _SENSITIVE_PORTS:
                                ports_hit.append(p)
                        except ValueError:
                            pass

                if ports_hit:
                    entry["sensitive_ports"] = ports_hit
                    open_rules.append(entry)

        if wildcard_any_rules:
            self.finding(
                title=f"NSG Rules Allow ALL Ports from Internet ({len(wildcard_any_rules)})",
                description=(
                    f"{len(wildcard_any_rules)} NSG rule(s) allow any port (*) from the internet. "
                    "All services on associated resources are fully exposed."
                ),
                severity=Severity.CRITICAL, mitre_technique="T1190",
                mitre_tactic="Initial Access",
                evidence={"rules": wildcard_any_rules[:10]},
                remediation=(
                    "Remove all wildcard inbound rules from internet-facing NSGs. "
                    "Use Azure Firewall or Application Gateway. Apply zero-trust segmentation."
                ),
            )

        if open_rules:
            port_names = {22:"SSH", 3389:"RDP", 5985:"WinRM-HTTP", 5986:"WinRM-HTTPS",
                          1433:"MSSQL", 3306:"MySQL", 5432:"PostgreSQL", 6379:"Redis",
                          9200:"Elasticsearch", 27017:"MongoDB", 445:"SMB",
                          23:"Telnet", 2375:"Docker-HTTP", 2376:"Docker-TLS"}
            by_port: dict[str, list[str]] = {}
            for r in open_rules:
                for p in r.get("sensitive_ports", []):
                    by_port.setdefault(port_names.get(p, str(p)), []).append(r["nsg"])

            self.finding(
                title=f"NSG Rules Expose Sensitive Services to Internet ({len(open_rules)} rules)",
                description=(
                    f"{len(open_rules)} NSG rule(s) expose sensitive service ports to 0.0.0.0/0. "
                    f"Services exposed: {', '.join(by_port.keys())}."
                ),
                severity=Severity.HIGH, mitre_technique="T1190",
                mitre_tactic="Initial Access",
                evidence={"exposed_services": by_port, "rules": open_rules[:20]},
                remediation=(
                    "Restrict inbound rules to specific source IP ranges or VPN gateway. "
                    "Use Azure Bastion for RDP/SSH. "
                    "Use Private Endpoints for PaaS services. "
                    "Enable Microsoft Defender for Cloud network recommendations."
                ),
            )

        return {"open_rules": open_rules, "wildcard_any_rules": wildcard_any_rules,
                "total_issues": len(open_rules) + len(wildcard_any_rules)}
