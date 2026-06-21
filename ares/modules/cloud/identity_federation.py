"""
cloud.identity_federation_abuse — Cross-Cloud Identity Federation Abuse

Enumerates and abuses federated identity trust relationships between
cloud providers and on-premises Active Directory.

Attack scenarios:
  1. Golden SAML — forge SAML assertion after AD krbtgt/ADFS private key compromise
  2. Azure AD → AWS via federated identity (SAML assertion abuse)
  3. Google Workspace → GCP service accounts (OIDC token forging)
  4. Cross-tenant OAuth2 token abuse (Business Email Compromise chain)
  5. Over-privileged SAML/OIDC trust enumeration

Requires: AD or cloud credentials obtained from prior compromise.
Best used after: ad.dcsync, cloud.azure, cloud.aws

MITRE:
  T1606.002 — SAML Tokens (Golden SAML)
  T1528     — Steal Application Access Token
  T1550.001 — Use Alternate Authentication Material: Application Access Token
  T1484.002 — Domain Trust Modification: Trust Modification

OPSEC: MEDIUM — queries Azure/AWS APIs (low noise) but SAML forgery is high risk
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, TYPE_CHECKING

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel, ModuleResult
from ares.core.tracing import trace_module
from ares.core.security import sanitize_hostname

if TYPE_CHECKING:
    pass

logger = get_logger("ares.modules.cloud.identity_federation")


class CloudIdentityFederationModule(BaseModule):
    """
    cloud.identity_federation_abuse — Cross-cloud identity federation enumeration and abuse.

    OPSEC: MEDIUM
    MITRE: T1606.002, T1528, T1550.001, T1484.002
    REQUIRES: cloud_credentials (Azure/AWS) or domain_admin_creds
    OUTPUTS:  federation_trusts, golden_saml_paths, oauth_tokens, pivot_paths
    """
    MODULE_ID          = "cloud.identity_federation_abuse"
    MODULE_NAME        = "Cloud Identity Federation Abuse"
    MODULE_CATEGORY    = "cloud"
    MODULE_DESCRIPTION = "Enumerate and abuse SAML/OIDC federation trusts across Azure, AWS, and GCP. Includes Golden SAML path after AD compromise."
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["federation_trusts", "golden_saml_paths", "oauth_tokens", "pivot_paths"]
    MITRE_TECHNIQUES   = ["T1606.002", "T1528", "T1550.001", "T1484.002"]
    MODULE_TIMEOUT_SECONDS: int | None = 300

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight: need at least one cloud or AD credential."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        has_azure  = bool(ctx.params.get("tenant_id") or ctx.params.get("client_id"))
        has_aws    = bool(ctx.params.get("access_key") or
                         __import__("os").environ.get("AWS_ACCESS_KEY_ID"))
        has_ad     = bool(ctx.params.get("adfs_url") or ctx.params.get("krbtgt_hash"))
        has_google = bool(ctx.params.get("project_id") or ctx.params.get("credentials_file"))
        if not any([has_azure, has_aws, has_ad, has_google]):
            raise ModuleValidationError(
                "cloud.identity_federation_abuse requires at least one credential: "
                "Azure (tenant_id), AWS (access_key), AD (adfs_url or krbtgt_hash), "
                "or GCP (project_id).",
                module_id=self.MODULE_ID, field="credentials",
            )

    async def execute(self, ctx: "Any") -> ModuleResult:
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "mode": ctx.params.get("mode", "enumerate")},
            )
        findings, raw = await self.run(
            tenant_id=ctx.params.get("tenant_id", ""),
            client_id=ctx.params.get("client_id", ""),
            client_secret=ctx.params.get("client_secret", ""),
            access_key=ctx.params.get("access_key", ""),
            secret_key=ctx.params.get("secret_key", ""),
            adfs_url=ctx.params.get("adfs_url", ""),
            krbtgt_hash=ctx.params.get("krbtgt_hash", ""),
            domain=ctx.params.get("domain", ""),
            mode=ctx.params.get("mode", "enumerate"),
            **ctx.params,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("cloud.identity_federation_abuse")
    async def run(
        self,
        tenant_id:     str = "",
        client_id:     str = "",
        client_secret: str = "",
        access_key:    str = "",
        secret_key:    str = "",
        adfs_url:      str = "",
        krbtgt_hash:   str = "",
        domain:        str = "",
        mode:          str = "enumerate",  # enumerate|golden_saml|oauth_abuse
        **kwargs: Any,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """
        Note: before_request() not called — cloud modules use API creds, not host IPs.
        Scope/jitter checks do not apply to cloud API endpoints.
        """
        audit("cloud_federation_abuse", actor="operator",
              technique="T1606.002", source="operator", target="cloud_federation",
              detail=f"mode={mode} tenant={tenant_id[:8] + '...' if tenant_id else 'none'}")

        logger.info("federation_abuse_start", mode=mode, has_azure=bool(tenant_id),
                    has_aws=bool(access_key), has_ad=bool(adfs_url or krbtgt_hash))

        loop = asyncio.get_running_loop()
        results: dict[str, Any] = {}

        # ── Phase 1: Azure AD Federation Enumeration ─────────────────────────
        if tenant_id or client_id:
            azure_result = await loop.run_in_executor(
                None, lambda: self._enumerate_azure_federation(tenant_id, client_id, client_secret)
            )
            results["azure_federation"] = azure_result

        # ── Phase 2: AWS SAML Provider Enumeration ───────────────────────────
        if access_key:
            aws_result = await loop.run_in_executor(
                None, lambda: self._enumerate_aws_saml_providers(access_key, secret_key)
            )
            results["aws_federation"] = aws_result

        # ── Phase 3: ADFS Discovery and Golden SAML Path ─────────────────────
        if adfs_url or domain:
            adfs_result = await loop.run_in_executor(
                None, lambda: self._enumerate_adfs(adfs_url, domain)
            )
            results["adfs_federation"] = adfs_result

        # ── Phase 4: Token lifetime + B2B (when Graph token available) ─────────
        _graph_token = ""
        if results.get("azure_federation", {}).get("graph_token_obtained"):
            # Re-acquire token for subsequent calls
            try:
                import httpx as _hx
                with _hx.Client(follow_redirects=False, timeout=15) as _cl:
                    _tr = _cl.post(
                        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                        data={"grant_type": "client_credentials", "client_id": client_id,
                              "client_secret": client_secret,
                              "scope": "https://graph.microsoft.com/.default"},
                    )
                    if _tr.status_code == 200:
                        _graph_token = _tr.json().get("access_token", "")
            except Exception:
                pass

        if _graph_token:
            token_result = await self._enumerate_token_lifetime_policies(tenant_id, _graph_token)
            b2b_result   = await self._enumerate_b2b_cross_tenant(_graph_token)
            results["token_lifetime"]   = token_result
            results["b2b_cross_tenant"] = b2b_result
            # Azure Managed Identity enumeration
            subscription_id = kwargs.get("subscription_id", "")
            if subscription_id:
                mi_result = await self._enumerate_managed_identities(
                    _graph_token, subscription_id
                )
                results["managed_identities"] = mi_result

        # GCP Workload Identity Federation enumeration
        project_id_raw = kwargs.get("project_id", "")
        gcp_token      = kwargs.get("gcp_access_token", "")
        if project_id_raw:
            gcp_wif = await self._enumerate_gcp_workload_identity(
                project_id_raw, gcp_token
            )
            results["gcp_wif"] = gcp_wif

        # ── Phase 5: Cross-cloud pivot path analysis ──────────────────────────
        pivot_paths = self._analyze_pivot_paths(results)
        results["pivot_paths"] = pivot_paths

        # ── Generate findings ─────────────────────────────────────────────────
        self._generate_findings(results, krbtgt_hash, domain)

        await self.noise.jitter.sleep()

        raw = {
            "azure_federation":  results.get("azure_federation", {}),
            "aws_federation":    results.get("aws_federation", {}),
            "adfs_federation":   results.get("adfs_federation", {}),
            "token_lifetime":    results.get("token_lifetime", {}),
            "b2b_cross_tenant":  results.get("b2b_cross_tenant", {}),
            "managed_identities": results.get("managed_identities", {}),
            "gcp_wif":           results.get("gcp_wif", {}),
            "pivot_paths":       pivot_paths,
            "federation_trusts": self._extract_trust_list(results),
            "golden_saml_paths": self._extract_golden_saml_paths(results, krbtgt_hash),
            "oauth_tokens":      [],  # populated by oauth_abuse mode
        }
        return self._findings[:], raw

    def _enumerate_azure_federation(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> dict:
        """Enumerate Azure AD federation settings, trusted domains, and SAML providers."""
        result: dict[str, Any] = {"error": None, "federated_domains": [], "saml_providers": [],
                                   "app_registrations": [], "service_principals": []}
        try:
            import httpx
            # Enumerate federated domains via Azure AD OpenID configuration
            headers = {"Accept": "application/json"}

            if tenant_id:
                # Check federation metadata
                meta_url = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
                try:
                    with httpx.Client(follow_redirects=False, timeout=15) as client:
                        resp = client.get(meta_url, headers=headers)
                        if resp.status_code == 200:
                            result["adfs_federation_metadata"] = True
                            # Parse entity ID from federation metadata
                            if "EntityID" in resp.text or "entityID" in resp.text:
                                result["has_adfs"] = True
                except Exception as e:
                    result["federation_metadata_error"] = str(e)[:100]

                # Get tenant info (no auth needed)
                try:
                    with httpx.Client(follow_redirects=False, timeout=10) as client:
                        tenant_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
                        resp = client.get(tenant_url)
                        if resp.status_code == 200:
                            oidc_config = resp.json()
                            result["tenant_region"] = oidc_config.get("tenant_region_scope", "")
                            result["issuer"] = oidc_config.get("issuer", "")
                except Exception:
                    pass

            # If we have app creds, enumerate more
            if client_id and client_secret and tenant_id:
                try:
                    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
                    with httpx.Client(follow_redirects=False, timeout=15) as client:
                        token_resp = client.post(token_url, data={
                            "grant_type":    "client_credentials",
                            "client_id":     client_id,
                            "client_secret": client_secret,
                            "scope":         "https://graph.microsoft.com/.default",
                        })
                        if token_resp.status_code == 200:
                            token = token_resp.json().get("access_token", "")
                            if token:
                                result["graph_token_obtained"] = True
                                graph_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
                                # Enum domains
                                dom_resp = client.get("https://graph.microsoft.com/v1.0/domains",
                                                       headers=graph_headers, timeout=15)
                                if dom_resp.status_code == 200:
                                    domains = dom_resp.json().get("value", [])
                                    result["federated_domains"] = [
                                        {"id": d.get("id"), "authenticated": d.get("isVerified"),
                                         "federated": d.get("authenticationType") == "Federated"}
                                        for d in domains
                                    ]
                                # Enum service principals with SAML config
                                sp_resp = client.get(
                                    "https://graph.microsoft.com/v1.0/servicePrincipals"
                                    "?$filter=preferredSingleSignOnMode eq 'saml'"
                                    "&$select=displayName,appId,preferredSingleSignOnMode",
                                    headers=graph_headers, timeout=15)
                                if sp_resp.status_code == 200:
                                    result["saml_service_principals"] = [
                                        {"name": sp.get("displayName"), "app_id": sp.get("appId")}
                                        for sp in sp_resp.json().get("value", [])[:20]
                                    ]
                        else:
                            result["auth_error"] = token_resp.json().get("error_description", "")[:200]
                except Exception as e:
                    result["graph_enum_error"] = str(e)[:150]

        except ImportError:
            result["error"] = "httpx not installed — pip install httpx"
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def _enumerate_aws_saml_providers(self, access_key: str, secret_key: str) -> dict:
        """Enumerate AWS SAML identity providers and federated roles."""
        result: dict[str, Any] = {"error": None, "saml_providers": [], "oidc_providers": [],
                                   "federated_roles": []}
        try:
            import boto3  # type: ignore[import]
            from botocore.config import Config  # type: ignore[import]

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            iam = session.client("iam", config=Config(connect_timeout=10, read_timeout=10))

            # List SAML providers
            try:
                saml_resp = iam.list_saml_providers()
                result["saml_providers"] = [
                    {"arn": p["Arn"], "valid_until": str(p.get("ValidUntil", ""))}
                    for p in saml_resp.get("SAMLProviderList", [])
                ]
            except Exception as e:
                result["saml_error"] = str(e)[:100]

            # List OIDC providers
            try:
                oidc_resp = iam.list_open_id_connect_providers()
                result["oidc_providers"] = [
                    {"arn": p["Arn"]} for p in oidc_resp.get("OpenIDConnectProviderList", [])
                ]
            except Exception as e:
                result["oidc_error"] = str(e)[:100]

            # Find roles that trust SAML providers (federation targets)
            try:
                paginator = iam.get_paginator("list_roles")
                federated_roles = []
                for page in paginator.paginate():
                    for role in page["Roles"]:
                        trust = json.dumps(role.get("AssumeRolePolicyDocument", {}))
                        if "saml-provider" in trust or "Federated" in trust:
                            federated_roles.append({
                                "role_name": role["RoleName"],
                                "role_arn":  role["Arn"],
                                "trust_has_saml": "saml-provider" in trust,
                            })
                result["federated_roles"] = federated_roles[:25]
            except Exception as e:
                result["roles_error"] = str(e)[:100]

        except ImportError:
            result["error"] = "boto3 not installed — pip install ares-redteam[cloud]"
        except Exception as e:
            result["error"] = str(e)[:200]

        return result

    def _enumerate_adfs(self, adfs_url: str, domain: str) -> dict:
        """Enumerate ADFS configuration and federation metadata."""
        result: dict[str, Any] = {"error": None, "adfs_url": adfs_url, "endpoints": [],
                                   "relying_parties": []}
        if not adfs_url and domain:
            adfs_url = f"https://adfs.{sanitize_hostname(domain)}"

        if not adfs_url:
            return result

        try:
            import httpx
            with httpx.Client(follow_redirects=False, timeout=15, verify=False) as client:
                # Try ADFS federation metadata
                endpoints_to_try = [
                    f"{adfs_url}/FederationMetadata/2007-06/FederationMetadata.xml",
                    f"{adfs_url}/adfs/fs/federationserverservice.asmx",
                    f"{adfs_url}/adfs/oauth2/authorize",
                ]
                for endpoint in endpoints_to_try:
                    try:
                        resp = client.get(endpoint, timeout=8)
                        result["endpoints"].append({
                            "url":    endpoint,
                            "status": resp.status_code,
                            "active": resp.status_code in (200, 302, 401),
                        })
                        if resp.status_code == 200 and "EntityDescriptor" in resp.text:
                            result["federation_metadata_found"] = True
                            # Try to extract relying party identifiers
                            import re
                            rps = re.findall(r'entityID="([^"]+)"', resp.text)
                            result["relying_parties"] = rps[:20]
                    except Exception:
                        pass

        except ImportError:
            result["error"] = "httpx not installed"
        except Exception as e:
            result["error"] = str(e)[:150]

        return result


    async def _enumerate_token_lifetime_policies(
        self, tenant_id: str, token: str
    ) -> dict:
        """
        Enumerate Azure AD token lifetime policies.
        Checks: CAE status, legacy auth, default lifetimes, refresh token expiry.
        """
        result: dict = {"error": None, "policies": [], "risks": []}
        try:
            import httpx
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            with httpx.Client(follow_redirects=False, timeout=15) as client:
                # Check token lifetime policies
                pol_resp = client.get(
                    "https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies",
                    headers=headers, timeout=15
                )
                if pol_resp.status_code == 200:
                    policies = pol_resp.json().get("value", [])
                    result["policies"] = [
                        {
                            "id":           p.get("id"),
                            "displayName":  p.get("displayName"),
                            "isOrganizationDefault": p.get("isOrganizationDefault"),
                            "definition":   p.get("definition", []),
                        }
                        for p in policies
                    ]
                    # No custom policy = using Azure defaults (1h access, 90d refresh)
                    if not policies:
                        result["risks"].append({
                            "risk":   "Default token lifetime in use",
                            "detail": "Access tokens valid 1h, refresh tokens 90 days. "
                                      "Stolen refresh token can be used for up to 90 days "
                                      "without triggering new authentication.",
                            "severity": "HIGH",
                        })

                # Check Continuous Access Evaluation (CAE) policy
                cae_resp = client.get(
                    "https://graph.microsoft.com/v1.0/policies/continuousAccessEvaluationPolicy",
                    headers=headers, timeout=15
                )
                if cae_resp.status_code == 200:
                    cae = cae_resp.json()
                    cae_enabled = cae.get("isEnabled", False)
                    result["cae_enabled"] = cae_enabled
                    if not cae_enabled:
                        result["risks"].append({
                            "risk":   "Continuous Access Evaluation (CAE) disabled",
                            "detail": "Without CAE, revoked access tokens remain valid until "
                                      "expiry (up to 1 hour). Token revocation does NOT "
                                      "immediately block attacker access.",
                            "severity": "CRITICAL",
                        })

                # Check for legacy authentication policies
                auth_policy_resp = client.get(
                    "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
                    headers=headers, timeout=15
                )
                if auth_policy_resp.status_code == 200:
                    auth_pol = auth_policy_resp.json()
                    # Legacy auth exemptions
                    if auth_pol.get("allowEmailVerifiedUsersToJoinOrganization", False):
                        result["risks"].append({
                            "risk":   "Email-verified users can join organization",
                            "detail": "AllowEmailVerifiedUsersToJoinOrganization is enabled. "
                                      "External users with verified email can access tenant resources.",
                            "severity": "MEDIUM",
                        })

        except ImportError:
            result["error"] = "httpx not installed"
        except Exception as e:
            result["error"] = str(e)[:150]
        return result

    async def _enumerate_b2b_cross_tenant(
        self, token: str
    ) -> dict:
        """
        Enumerate Azure B2B guest access and cross-tenant pivot opportunities.
        Finds external tenants this account has guest access to, and
        guest users in our tenant (potential pivot targets).

        Based on Midnight Blizzard TTPs: pivot via vendor/partner B2B trust.
        """
        result: dict = {
            "error": None,
            "guest_accounts_in_tenant": [],
            "external_tenant_access":   [],
            "b2b_risks":                [],
        }
        try:
            import httpx
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            with httpx.Client(follow_redirects=False, timeout=15) as client:
                # Enumerate guest users in OUR tenant (attacker's pivot targets)
                guest_resp = client.get(
                    "https://graph.microsoft.com/v1.0/users"
                    "?$filter=userType eq 'Guest'"
                    "&$select=displayName,mail,createdDateTime,userPrincipalName"
                    "&$top=50",
                    headers=headers, timeout=15,
                )
                if guest_resp.status_code == 200:
                    guests = guest_resp.json().get("value", [])
                    result["guest_accounts_in_tenant"] = [
                        {
                            "name":       g.get("displayName"),
                            "email":      g.get("mail", ""),
                            "upn":        g.get("userPrincipalName", ""),
                            "created":    g.get("createdDateTime", ""),
                            "ext_tenant": g.get("mail", "").split("#")[0].split("_")[-1]
                                          if "#EXT#" in g.get("userPrincipalName", "") else "",
                        }
                        for g in guests
                    ]
                    if len(guests) > 10:
                        result["b2b_risks"].append({
                            "risk":     f"Large guest user population ({len(guests)})",
                            "detail":   "High number of B2B guests increases attack surface. "
                                        "Each guest represents a potential pivot to their home tenant.",
                            "severity": "MEDIUM",
                        })

                # Check cross-tenant access settings (what external tenants we trust)
                xta_resp = client.get(
                    "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners",
                    headers=headers, timeout=15,
                )
                if xta_resp.status_code == 200:
                    partners = xta_resp.json().get("value", [])
                    result["external_tenant_access"] = [
                        {
                            "tenant_id":     p.get("tenantId"),
                            "inbound":       p.get("inboundTrust", {}),
                            "outbound":      p.get("automaticUserConsentSettings", {}),
                        }
                        for p in partners[:20]
                    ]
                    if partners:
                        result["b2b_risks"].append({
                            "risk":   f"Cross-tenant access configured with {len(partners)} external tenants",
                            "detail": "Compromised account in any of these tenants could pivot to ours. "
                                      "Review each partner's inbound trust settings.",
                            "severity": "HIGH",
                        })

                # Check our own guest memberships in external groups
                my_groups = client.get(
                    "https://graph.microsoft.com/v1.0/me/memberOf"
                    "?$select=displayName,id,groupTypes",
                    headers=headers, timeout=15,
                )
                if my_groups.status_code == 200:
                    ext_groups = [
                        g for g in my_groups.json().get("value", [])
                        if "unified" in [gt.lower() for gt in g.get("groupTypes", [])]
                    ]
                    if ext_groups:
                        result["external_tenant_access"].append({
                            "type":   "group_membership",
                            "groups": [g.get("displayName") for g in ext_groups[:10]],
                        })

        except ImportError:
            result["error"] = "httpx not installed"
        except Exception as e:
            result["error"] = str(e)[:150]
        return result


    async def _enumerate_managed_identities(
        self, token: str, subscription_id: str
    ) -> dict:
        """
        Enumerate Azure resources with Managed Identities.
        Zero-credential attack path: VM with MI can access Key Vault,
        Storage, and other resources without any password.
        """
        result: dict = {
            "system_assigned":  [],
            "user_assigned":    [],
            "high_value_paths": [],
            "error":            None,
        }
        _HIGH_VALUE_ROLES = {
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
            "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
        }
        try:
            import httpx
            auth_hdr = {"Authorization": f"Bearer {token}"}
            with httpx.Client(follow_redirects=False, timeout=20) as client:
                # Find resources with managed identity
                url = (
                    f"https://management.azure.com/subscriptions/{subscription_id}"
                    "/resources?$filter=identity/type+ne+null&api-version=2021-04-01"
                )
                resp = client.get(url, headers=auth_hdr)
                resources = resp.json().get("value", []) if resp.status_code == 200 else []
                for res in resources[:50]:
                    identity = res.get("identity", {})
                    id_type  = identity.get("type", "")
                    entry = {
                        "name":     res.get("name", ""),
                        "type":     res.get("type", ""),
                        "location": res.get("location", ""),
                        "id_type":  id_type,
                    }
                    if "SystemAssigned" in id_type:
                        result["system_assigned"].append(entry)
                    if "UserAssigned" in id_type:
                        result["user_assigned"].append(entry)

                # Check high-value role assignments
                ra_url = (
                    f"https://management.azure.com/subscriptions/{subscription_id}"
                    "/providers/Microsoft.Authorization/roleAssignments"
                    "?api-version=2022-04-01"
                )
                ra_resp = client.get(ra_url, headers=auth_hdr)
                if ra_resp.status_code == 200:
                    # Build principal→resource map from enumerated MIs
                    mi_principals: dict = {}
                    for res in result["system_assigned"] + result["user_assigned"]:
                        # Resource name used as principal proxy
                        mi_principals[res.get("name", "")] = res
                    for assignment in ra_resp.json().get("value", []):
                        props   = assignment.get("properties", {})
                        role_id = props.get("roleDefinitionId", "").split("/")[-1]
                        scope   = props.get("scope", "")
                        if role_id in _HIGH_VALUE_ROLES:
                            # Try to match scope to a specific resource
                            matched_resource = next(
                                (r for r in result["system_assigned"] + result["user_assigned"]
                                 if r.get("name", "") in scope),
                                None
                            )
                            result["high_value_paths"].append({
                                "role":              _HIGH_VALUE_ROLES[role_id],
                                "scope":             scope,
                                "principal_id":      props.get("principalId", ""),
                                "matched_resource":  matched_resource.get("name") if matched_resource else "unknown",
                                "resource_type":     matched_resource.get("type", "") if matched_resource else "",
                                "attack": (
                                    f"{matched_resource.get('type','Resource') if matched_resource else 'Resource'} "
                                    f"with Managed Identity + {_HIGH_VALUE_ROLES[role_id]} role = "
                                    "zero-credential access path (no password needed)"
                                ),
                            })
        except ImportError:
            result["error"] = "httpx not installed"
        except Exception as exc:
            result["error"] = str(exc)[:150]
        return result

    async def _enumerate_gcp_workload_identity(
        self, project_id: str, access_token: str = ""
    ) -> dict:
        """
        Enumerate GCP Workload Identity Federation pools and providers.
        GitHub Actions → GCP is the most common breach vector 2025-2026.
        Unrestricted GitHub OIDC WIF pool = any public repo can impersonate SA.
        """
        result: dict = {
            "wif_pools":       [],
            "providers":       [],
            "high_risk_paths": [],
            "error":           None,
        }
        _DANGEROUS_ISSUERS = {
            "https://token.actions.githubusercontent.com": "GitHub Actions",
            "https://sts.amazonaws.com":                   "AWS Cross-Account",
            "https://accounts.google.com":                 "Google Account (external)",
        }
        try:
            import httpx
            headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
            with httpx.Client(follow_redirects=False, timeout=20) as client:
                pools_url = (
                    "https://iam.googleapis.com/v1/"
                    f"projects/{project_id}/locations/global/workloadIdentityPools"
                )
                resp = client.get(pools_url, headers=headers)
                pools = resp.json().get("workloadIdentityPools", []) if resp.status_code == 200 else []

                for pool in pools:
                    pool_name = pool.get("name", "")
                    pool_id   = pool_name.split("/")[-1]
                    result["wif_pools"].append({
                        "id":    pool_id,
                        "state": pool.get("state", ""),
                    })
                    # List providers
                    prov_resp = client.get(
                        f"https://iam.googleapis.com/v1/{pool_name}/providers",
                        headers=headers,
                    )
                    if prov_resp.status_code != 200:
                        continue
                    for prov in prov_resp.json().get("workloadIdentityPoolProviders", []):
                        issuer = prov.get("oidc", {}).get("issuerUri", "")
                        cond   = prov.get("attributeCondition", "")
                        is_unrestricted = not cond
                        if issuer in _DANGEROUS_ISSUERS:
                            risk_label = "CRITICAL" if is_unrestricted else "HIGH"
                            result["high_risk_paths"].append({
                                "pool":         pool_id,
                                "provider":     _DANGEROUS_ISSUERS[issuer],
                                "issuer":       issuer,
                                "unrestricted": is_unrestricted,
                                "condition":    cond or "(none — unrestricted)",
                                "attack": (
                                    f"{_DANGEROUS_ISSUERS[issuer]} can impersonate "
                                    f"service accounts in project {project_id}"
                                    + (" — NO repo/org filter!" if is_unrestricted else "")
                                ),
                                "risk": risk_label,
                            })

            # Enumerate service accounts that WIF pools can impersonate
            sa_url = (
                f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
            )
            sa_resp = client.get(sa_url, headers=headers)
            if sa_resp.status_code == 200:
                sas = sa_resp.json().get("accounts", [])
                # Mark which SAs have WIF bindings
                impersonatable = []
                for sa in sas[:50]:
                    email = sa.get("email", "")
                    # Check IAM policy for workloadIdentityUser bindings
                    iam_url = (
                        f"https://iam.googleapis.com/v1/projects/{project_id}"
                        f"/serviceAccounts/{email}:getIamPolicy"
                    )
                    iam_resp = client.post(iam_url, headers=headers, json={})
                    if iam_resp.status_code == 200:
                        for binding in iam_resp.json().get("bindings", []):
                            if binding.get("role") == "roles/iam.workloadIdentityUser":
                                impersonatable.append({
                                    "email":   email,
                                    "members": binding.get("members", [])[:5],
                                })
                if impersonatable:
                    result["impersonatable_service_accounts"] = impersonatable
                    # Enrich high_risk_paths with SA info
                    for path in result["high_risk_paths"]:
                        path["impersonatable_sas"] = [s["email"] for s in impersonatable[:5]]

        except ImportError:
            result["error"] = "httpx not installed"
        except Exception as exc:
            result["error"] = str(exc)[:150]
        return result

    def _analyze_pivot_paths(self, results: dict) -> list[dict]:
        """Identify cross-cloud pivot paths based on enumerated trusts."""
        paths = []

        azure = results.get("azure_federation", {})
        aws   = results.get("aws_federation", {})
        adfs  = results.get("adfs_federation", {})

        # Azure → AWS pivot via federated identity
        if (azure.get("federated_domains") and aws.get("saml_providers")):
            paths.append({
                "path":        "Azure AD → AWS via SAML Federation",
                "technique":   "T1606.002",
                "description": "Azure AD acts as SAML IdP for AWS. "
                               "Compromised Azure AD allows forging SAML assertions to assume AWS roles.",
                "prereq":      "Azure AD Global Admin or ADFS private key",
                "impact":      "Lateral movement to AWS without AWS credentials",
                "viable":      True,
            })

        # ADFS → Cloud pivot (Golden SAML path)
        if adfs.get("federation_metadata_found"):
            paths.append({
                "path":        "AD → Any Cloud via Golden SAML (ADFS compromise)",
                "technique":   "T1606.002",
                "description": "ADFS token signing certificate allows forging SAML for any relying party. "
                               "After AD compromise, extract ADFS private key to forge assertions.",
                "prereq":      "Domain Admin + ADFS server access",
                "impact":      "Access to ALL cloud services trusting this ADFS",
                "relying_parties": adfs.get("relying_parties", [])[:5],
                "viable":      True,
            })

        # AWS → Azure pivot via OIDC
        if aws.get("oidc_providers") and azure.get("tenant_region"):
            paths.append({
                "path":        "AWS Workload → Azure via OIDC Federation",
                "technique":   "T1528",
                "description": "AWS OIDC providers may trust Azure AD tokens. "
                               "Compromised Azure access token can assume AWS roles.",
                "prereq":      "Valid Azure access token",
                "impact":      "AWS role assumption without AWS credentials",
                "viable":      bool(aws.get("oidc_providers")),
            })

        return paths

    def _extract_trust_list(self, results: dict) -> list[str]:
        trusts = []
        azure = results.get("azure_federation", {})
        aws   = results.get("aws_federation", {})
        adfs  = results.get("adfs_federation", {})

        for d in azure.get("federated_domains", []):
            if d.get("federated"):
                trusts.append(f"Azure federated domain: {d.get('id', 'unknown')}")
        for p in aws.get("saml_providers", []):
            trusts.append(f"AWS SAML provider: {p.get('arn', 'unknown')}")
        for rp in adfs.get("relying_parties", [])[:5]:
            trusts.append(f"ADFS relying party: {rp}")
        return trusts

    def _extract_golden_saml_paths(self, results: dict, krbtgt_hash: str) -> list[dict]:
        paths = []
        adfs = results.get("adfs_federation", {})
        if adfs.get("federation_metadata_found"):
            paths.append({
                "attack":      "Golden SAML",
                "technique":   "T1606.002",
                "status":      "viable" if krbtgt_hash else "requires_adfs_key",
                "next_steps":  [
                    "Extract ADFS token signing certificate from ADFS server",
                    "Use ADFSDump or AADInternals to export the certificate",
                    "Forge SAML assertion for any relying party",
                    "Use forged assertion to obtain cloud tokens",
                ],
                "relying_parties": adfs.get("relying_parties", [])[:10],
            })
        return paths

    def _generate_findings(self, results: dict, krbtgt_hash: str, domain: str) -> None:
        """Generate ARES findings from federation enumeration results."""
        adfs  = results.get("adfs_federation", {})
        aws   = results.get("aws_federation", {})
        azure = results.get("azure_federation", {})
        pivot = results.get("pivot_paths", [])

        # Golden SAML finding
        if adfs.get("federation_metadata_found"):
            rps = adfs.get("relying_parties", [])
            self.finding(
                title=f"ADFS Federation Metadata Found — {len(rps)} Relying Parties",
                description=(
                    f"Active ADFS deployment detected at {adfs.get('adfs_url', 'unknown')}. "
                    f"Federation metadata accessible with {len(rps)} relying parties. "
                    "Golden SAML attack is viable after obtaining the ADFS token signing certificate. "
                    "This allows forging SAML assertions for any federated service "
                    "without knowing user passwords — and does NOT trigger AD authentication logs."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1606.002",
                mitre_tactic="Credential Access",
                evidence={
                    "adfs_url":       adfs.get("adfs_url"),
                    "relying_parties": rps[:10],
                    "endpoints_found": [e for e in adfs.get("endpoints", []) if e.get("active")],
                },
                remediation=(
                    "1. Restrict access to ADFS server — only Domain Controllers should reach it. "
                    "2. Enable ADFS Extranet Lockout. "
                    "3. Monitor for ADFS token signing certificate export. "
                    "4. Consider migrating to Azure AD Managed domains (no ADFS)."
                ),
                host=adfs.get("adfs_url", domain),
                confidence=0.95,
            )

        # Azure SAML service principals
        saml_sps = azure.get("saml_service_principals", [])
        if saml_sps:
            self.finding(
                title=f"Azure AD SAML Applications — {len(saml_sps)} Apps with SSO",
                description=(
                    f"Found {len(saml_sps)} Azure AD applications configured with SAML SSO. "
                    "A compromised Global Admin or Application Admin can modify SAML configurations "
                    "to add malicious certificate for SAML response signing, enabling persistent access."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1484.002",
                mitre_tactic="Defense Evasion",
                evidence={"saml_applications": saml_sps[:10]},
                remediation=(
                    "Audit SAML application configurations regularly. "
                    "Enable Conditional Access for all SAML applications. "
                    "Use Certificate-Based Authentication where possible."
                ),
                host="azure_ad",
                confidence=0.85,
            )

        # AWS federated roles
        fed_roles = aws.get("federated_roles", [])
        if fed_roles:
            self.finding(
                title=f"AWS SAML Federated Roles — {len(fed_roles)} Roles Assuming via Federation",
                description=(
                    f"Found {len(fed_roles)} AWS IAM roles that trust SAML federation. "
                    "If the SAML identity provider is compromised, an attacker can assume "
                    "any of these roles without AWS credentials."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1606.002",
                mitre_tactic="Credential Access",
                evidence={"federated_roles": [r["role_name"] for r in fed_roles[:15]]},
                remediation=(
                    "Review trust policies for all federated roles. "
                    "Apply least-privilege — federated roles should not have Admin permissions. "
                    "Enable AWS CloudTrail and alert on AssumeRoleWithSAML events."
                ),
                host="aws",
                confidence=0.90,
            )

        # Token lifetime risks
        for risk in results.get("token_lifetime", {}).get("risks", []):
            sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
            self.finding(
                title=f"Azure Token Policy Risk: {risk['risk']}",
                description=risk["detail"],
                severity=sev_map.get(risk["severity"], Severity.MEDIUM),
                mitre_technique="T1528",
                mitre_tactic="Credential Access",
                evidence=risk,
                remediation=(
                    "Enable Continuous Access Evaluation. "
                    "Configure token lifetime policies. "
                    "Block legacy authentication via Conditional Access."
                ),
                host="azure_ad",
                confidence=0.90,
            )

        # B2B cross-tenant risks
        b2b = results.get("b2b_cross_tenant", {})
        guests = b2b.get("guest_accounts_in_tenant", [])
        if len(guests) > 5:
            self.finding(
                title=f"B2B Cross-Tenant Attack Surface: {len(guests)} Guest Accounts",
                description=(
                    f"Found {len(guests)} B2B guest accounts in this tenant. "
                    "Each guest represents a potential pivot point — if their home tenant "
                    "is compromised, an attacker can use their guest credentials to access "
                    "this tenant's resources. This is the Midnight Blizzard attack vector "
                    "(Microsoft breach 2024)."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1199",
                mitre_tactic="Initial Access",
                evidence={
                    "guest_count":   len(guests),
                    "sample_guests": [g["email"] for g in guests[:5]],
                    "b2b_risks":     b2b.get("b2b_risks", []),
                },
                remediation=(
                    "Audit all B2B guest access regularly. "
                    "Apply Conditional Access policies to guest accounts. "
                    "Enable cross-tenant access settings with least-privilege. "
                    "Review Microsoft Entra External Identities access reviews."
                ),
                host="azure_ad",
                confidence=0.80,
            )

        # Azure Managed Identity high-value paths
        mi_data = results.get("managed_identities", {})
        hvp = mi_data.get("high_value_paths", [])
        if hvp:
            self.finding(
                title=f"Azure Managed Identity High-Value Paths: {len(hvp)} Roles",
                description=(
                    f"{len(mi_data.get('system_assigned',[]))} system-assigned and "
                    f"{len(mi_data.get('user_assigned',[]))} user-assigned Managed Identities found. "
                    f"{len(hvp)} with high-privilege roles (Owner/Contributor/Key Vault). "
                    "This is a zero-credential attack path — no password needed. "
                    "A compromised VM with MI can directly access Key Vault secrets, "
                    "Storage blobs, or perform administrative actions."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1078.004",
                mitre_tactic="Privilege Escalation",
                evidence={"high_value_paths": hvp[:5]},
                remediation=(
                    "Apply least-privilege to Managed Identity role assignments. "
                    "Remove Owner/Contributor from MI where not needed. "
                    "Enable Azure Policy to audit MI permissions."
                ),
                host="azure_managed_identity",
                confidence=0.95,
            )

        # GCP Workload Identity Federation high-risk paths
        wif_data = results.get("gcp_wif", {})
        for path in wif_data.get("high_risk_paths", []):
            self.finding(
                title=f"GCP WIF: {path['provider']} can impersonate SA ({path['risk']})",
                description=path["attack"],
                severity=Severity.CRITICAL if path["risk"] == "CRITICAL" else Severity.HIGH,
                mitre_technique="T1528",
                mitre_tactic="Credential Access",
                evidence=path,
                remediation=(
                    "Add attributeCondition to WIF provider to restrict to specific repos/orgs. "
                    "Example: attribute.repository == 'org/repo'. "
                    "Audit all WIF pool providers for unrestricted access."
                ),
                host=f"gcp/{path.get('pool', 'unknown')}",
                confidence=0.95,
            )

        # Cross-cloud pivot paths
        for path in pivot:
            if path.get("viable"):
                self.finding(
                    title=f"Cross-Cloud Pivot Path: {path['path']}",
                    description=path["description"],
                    severity=Severity.CRITICAL,
                    mitre_technique=path.get("technique", "T1606.002"),
                    mitre_tactic="Lateral Movement",
                    evidence={
                        "prereq":  path.get("prereq"),
                        "impact":  path.get("impact"),
                    },
                    remediation=(
                        "Review all cross-cloud federation trust relationships. "
                        "Implement Just-In-Time access for federated roles. "
                        "Alert on SAML assertion usage from unexpected IPs."
                    ),
                    host="multi_cloud",
                    confidence=0.80,
                )
