"""
Azure AD / Entra ID Identity Attacks — cloud.azure_ad
MITRE: T1528 — Steal Application Access Token
       T1606 — Forge Web Credentials

Azure AD identity attack techniques not covered by cloud.azure (resource enum):
  1. Device code flow phishing — request device code, poll for user auth
  2. Service principal credential exposure — SP secrets visible to overprivileged apps
  3. Guest account enumeration — external identities that may have excessive access
  4. Seamless SSO silver ticket — Kerberos ticket for AZUREADSSOACC$ machine account
  5. PRT (Primary Refresh Token) detection paths

cloud.azure (existing) handles resource enumeration.
cloud.azure_ad handles identity-specific attacks.

OPSEC: LOW to MEDIUM — token-based auth, not credential spray.
       Device code flow: legitimate OAuth2 flow, not blocked by CA policies.
       Does not trigger sign-in risk if using valid PRT.

Prerequisites: Azure AD tenant ID. Optional: client credentials or existing access token.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.cloud.azure_ad")

# Well-known Azure AD OAuth2 endpoints and client IDs
_GRAPH_ENDPOINT   = "https://graph.microsoft.com"
_LOGIN_ENDPOINT   = "https://login.microsoftonline.com"
_DEVICE_CODE_URL  = "{tenant}/oauth2/v2.0/devicecode"
_TOKEN_URL        = "{tenant}/oauth2/v2.0/token"

# Microsoft Graph API scopes for enumeration
_ENUM_SCOPES = [
    "User.Read.All",
    "Group.Read.All",
    "Application.Read.All",
    "Directory.Read.All",
]


class AzureADModule(BaseModule):
    """
    cloud.azure_ad — Azure AD / Entra ID identity attack techniques: device code flow, service principal exposure.

    OPSEC: LOW
    MITRE: "T1528", "T1606"
    OUTPUTS:  "access_tokens", "azure_ad_findings"
    """
    MODULE_ID          = "cloud.azure_ad"
    MODULE_NAME        = "Azure AD Identity Attacks"
    MODULE_CATEGORY    = "cloud"
    MODULE_DESCRIPTION = (
        "Azure AD / Entra ID identity attack techniques: "
        "device code flow, service principal exposure, "
        "guest account enum, seamless SSO detection."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["access_tokens", "azure_ad_findings"]
    MITRE_TECHNIQUES   = ["T1528", "T1606"]

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        tenant_id = ctx.params.get("tenant_id", "")
        if not tenant_id:
            raise ModuleValidationError(
                "cloud.azure_ad requires 'tenant_id' — Azure AD tenant ID (UUID). "
                "Find via: az account show --query tenantId",
                module_id=self.MODULE_ID, field="tenant_id",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})

        tenant_id      = ctx.params.get("tenant_id", "")
        client_id      = ctx.params.get("client_id", "")
        client_secret  = ctx.params.get("client_secret", "")
        access_token   = ctx.params.get("access_token", "")
        technique      = ctx.params.get("technique", "enumerate")   # enumerate|device_code|sp_audit

        findings, raw = await self.run(
            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret,
            access_token=access_token, technique=technique,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("cloud.azure_ad")
    async def run(self, tenant_id: str, client_id: str = "", client_secret: str = "",
                  access_token: str = "", technique: str = "enumerate", **kwargs: Any):
        # Note: before_request() intentionally not called — cloud modules use
        # API credentials, not host IPs. Scope check (CIDR) does not apply to
        # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
        logger.info("azure_ad_start", tenant=tenant_id[:8] + "...", technique=technique)
        audit("azure_ad_attack", actor="operator", technique="T1528",
              source="operator", target=f"tenant:{tenant_id[:8]}")

        loop = asyncio.get_running_loop()

        # Acquire access token if not provided
        token = access_token
        if not token and client_id and client_secret:
            token = await loop.run_in_executor(
                None,
                lambda: self._get_token_client_credentials(
                    tenant_id, client_id, client_secret
                ),
            )

        if technique == "device_code":
            # Generate device code for operator to use in phishing scenario
            dc_info = await loop.run_in_executor(
                None,
                lambda: self._request_device_code(tenant_id, client_id or "d3590ed6-52b3-4102-aeff-aad2292ab01c"),
            )
            raw = {"technique": "device_code", "tenant_id": tenant_id, **dc_info}
            if dc_info.get("user_code"):
                self.finding(
                    title       = "Azure AD Device Code Generated",
                    description = (
                        f"Device authentication code: {dc_info['user_code']}. "
                        f"User visits: {dc_info.get('verification_uri', 'https://microsoft.com/devicelogin')}. "
                        "When user authenticates, access token will be captured. "
                        "Token grants access to Microsoft 365, Azure, and all consented resources."
                    ),
                    severity    = Severity.HIGH,
                    mitre_technique = "T1528",
                    mitre_tactic    = "Credential Access",
                    evidence    = {
                        "user_code":          dc_info.get("user_code"),
                        "verification_uri":   dc_info.get("verification_uri"),
                        "expires_in":         dc_info.get("expires_in"),
                        "poll_interval":      dc_info.get("interval"),
                    },
                    remediation = (
                        "Enable Conditional Access policy to block device code flow. "
                        "Restrict device code to managed devices only. "
                        "Monitor for device code authentication events in Sign-in logs."
                    ),
                )
            await self.noise.jitter.sleep()
            raw["access_tokens"] = raw.get("access_token", "")  # OUTPUTS key
        raw["azure_ad_findings"] = self._findings  # OUTPUTS key
        return self._findings[:], raw

        # Enumeration with Graph API
        if not token:
            return [], {
                "error": "No access token available. Provide client_id+client_secret or access_token.",
                "hint": "Or use technique=device_code to initiate device code flow.",
            }

        # Enumerate users, guests, service principals
        results = await loop.run_in_executor(
            None,
            lambda: self._enumerate_tenant(token, tenant_id),
        )

        # Findings
        guests     = results.get("guests", [])
        sps        = results.get("service_principals", [])
        priv_users = results.get("privileged_users", [])

        if guests:
            self.finding(
                title       = f"Azure AD Guest Accounts: {len(guests)} External Identities",
                description = (
                    f"{len(guests)} guest (B2B) accounts in the tenant. "
                    "External identities may have excessive permissions, "
                    "especially if invited before RBAC was tightened."
                ),
                severity    = Severity.MEDIUM,
                mitre_technique = "T1528",
                mitre_tactic    = "Discovery",
                evidence    = {
                    "guest_count": len(guests),
                    "guests":      [g.get("userPrincipalName", "") for g in guests[:15]],
                },
                remediation = (
                    "Audit guest account permissions. Enable Guest access restrictions. "
                    "Enable Microsoft Entra External ID review cycles."
                ),
            )

        if sps:
            expired_sps = [s for s in sps if s.get("has_expired_secret")]
            high_priv   = [s for s in sps if s.get("privileged")]
            if high_priv:
                self.finding(
                    title       = f"Privileged Service Principals: {len(high_priv)} Apps with High Privilege",
                    description = (
                        f"{len(high_priv)} service principal(s) have privileged roles "
                        "(Global Admin, Application Admin, or privileged MS Graph API permissions). "
                        "Compromising these app registrations gives tenant-wide access."
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1528",
                    mitre_tactic    = "Privilege Escalation",
                    evidence    = {
                        "count":    len(high_priv),
                        "apps":     [s.get("displayName", "") for s in high_priv[:10]],
                    },
                    remediation = (
                        "Apply least privilege to app registrations. "
                        "Remove unused high-privilege API permissions. "
                        "Enable Workload Identity conditional access. "
                        "Rotate all service principal secrets."
                    ),
                )

        raw = {
            "tenant_id":          tenant_id,
            "technique":          technique,
            "user_count":         results.get("user_count", 0),
            "guest_count":        len(guests),
            "sp_count":           len(sps),
            "privileged_users":   [u.get("userPrincipalName", "") for u in priv_users[:10]],
            "high_priv_sps":      [s.get("displayName", "") for s in
                                   [s for s in sps if s.get("privileged")][:10]],
        }
        await self.noise.jitter.sleep()
        return self._findings[:], raw

    def _get_token_client_credentials(self, tenant_id: str, client_id: str,
                                       client_secret: str) -> str:
        """Acquire access token via client credentials flow."""
        try:
            import msal  # type: ignore[import]
            app = msal.ConfidentialClientApplication(
                client_id,
                authority=f"{_LOGIN_ENDPOINT}/{tenant_id}",
                client_credential=client_secret,
            )
            result = app.acquire_token_for_client(
                scopes=[f"{_GRAPH_ENDPOINT}/.default"]
            )
            return result.get("access_token", "")
        except ImportError:
            logger.warning("msal_not_installed",
                           hint="pip install ares-redteam[cloud] (includes msal)")
            return ""
        except Exception as exc:
            raise self._classify_error(exc, target="azure_ad") from exc

    def _request_device_code(self, tenant_id: str, client_id: str) -> dict:
        """Request a device code for phishing-style auth capture."""
        try:
            import msal  # type: ignore[import]
            app = msal.PublicClientApplication(
                client_id,
                authority=f"{_LOGIN_ENDPOINT}/{tenant_id}",
            )
            flow = app.initiate_device_flow(
                scopes=["User.Read", "openid", "profile", "offline_access"]
            )
            return {
                "user_code":        flow.get("user_code"),
                "device_code":      flow.get("device_code"),
                "verification_uri": flow.get("verification_uri"),
                "expires_in":       flow.get("expires_in"),
                "interval":         flow.get("interval"),
                "message":          flow.get("message"),
            }
        except ImportError:
            return {"error": "msal not installed — pip install ares-redteam[cloud]"}
        except Exception as exc:
            return {"error": str(exc)[:150]}

    def _enumerate_tenant(self, access_token: str, tenant_id: str) -> dict:
        """Enumerate users, guests, service principals via Microsoft Graph."""
        try:
            import httpx
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type":  "application/json",
            }

            results: dict = {
                "user_count": 0,
                "guests":     [],
                "service_principals": [],
                "privileged_users":   [],
            }

            with httpx.Client(follow_redirects=True, timeout=20) as client:
                # Count total users
                r = client.get(
                    f"{_GRAPH_ENDPOINT}/v1.0/users/$count",
                    headers={**headers, "ConsistencyLevel": "eventual"},
                )
                if r.is_success:
                    results["user_count"] = int(r.text)

                # Guest accounts
                r = client.get(
                    f"{_GRAPH_ENDPOINT}/v1.0/users"
                    "?$filter=userType eq 'Guest'"
                    "&$select=userPrincipalName,displayName,mail,createdDateTime"
                    "&$top=50",
                    headers={**headers, "ConsistencyLevel": "eventual"},
                )
                if r.is_success:
                    results["guests"] = r.json().get("value", [])

                # Service principals with high-priv app roles
                r = client.get(
                    f"{_GRAPH_ENDPOINT}/v1.0/servicePrincipals"
                    "?$select=displayName,appId,createdDateTime,keyCredentials,passwordCredentials"
                    "&$top=50",
                    headers=headers,
                )
                if r.is_success:
                    sps = r.json().get("value", [])
                    for sp in sps:
                        # Flag SP with secrets/certs (potential exposure)
                        has_secret = bool(sp.get("passwordCredentials"))
                        sp["has_secret"]  = has_secret
                        sp["privileged"]  = False  # would need role check via /directoryRoles
                    results["service_principals"] = sps

            return results

        except Exception as exc:
            logger.warning("azure_ad_enum_failed", error=str(exc)[:100])
            return {}
