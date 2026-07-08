"""
GCP Recon & Attack Module — Production Implementation
IAM bindings, GCS buckets, service account keys, metadata server.

Authentication (automatic priority order):
  1. Service account key file — if credentials_file supplied
  2. Application Default Credentials (ADC) — env GOOGLE_APPLICATION_CREDENTIALS,
     gcloud auth, Workload Identity, or Compute Engine metadata server

Required API permissions (read-only):
  roles/viewer OR the following individual roles:
    resourcemanager.projects.getIamPolicy
    storage.buckets.list + storage.buckets.getIamPolicy
    iam.serviceAccountKeys.list
    compute.instances.list (for metadata server check)

Required optional extras:
    pip install ares-redteam[cloud]
    → google-cloud-resource-manager, google-cloud-iam, google-auth, httpx
"""
from __future__ import annotations

import asyncio
import datetime
from functools import partial
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.modules.cloud.gcp")

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

_SA_KEY_MAX_AGE_DAYS = 90   # Keys older than this are flagged
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


def _get_gcp_credentials(credentials_file: str | None = None) -> "Any":
    """Return Google credentials — file or ADC."""
    if credentials_file:
        from google.oauth2 import service_account  # type: ignore[import]
        return service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
    import google.auth  # type: ignore[import]
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
    )
    return credentials


class GCPModule(BaseModule):
    """
    cloud.gcp — IAM bindings, GCS misconfig, SA key audit, metadata server

    OPSEC: LOW
    MITRE: "T1526", "T1530", "T1552.005", "T1580"
    OUTPUTS:  "gcp_findings"
    """
    MODULE_ID          = "cloud.gcp"
    MODULE_NAME        = "GCP Recon & Attack"
    MODULE_CATEGORY    = "cloud"
    MODULE_DESCRIPTION = "IAM bindings, GCS misconfig, SA key audit, metadata server"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["gcp_findings"]
    MITRE_TECHNIQUES   = ["T1526", "T1530", "T1552.005", "T1580"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        has_cred = bool(ctx.params.get("project_id") or
                        ctx.params.get("credentials_file") or
                        __import__("os").environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
        if not has_cred:
            raise ModuleValidationError(
                "cloud.gcp requires GCP credentials — set project_id param or "
                "GOOGLE_APPLICATION_CREDENTIALS environment variable.",
                module_id=self.MODULE_ID, field="project_id",
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

    @trace_module("cloud.gcp")
    async def run(self, project_id: str, credentials_file: str | None = None,
                  **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        # Note: before_request() intentionally not called — cloud modules use
        # API credentials, not host IPs. Scope check (CIDR) does not apply to
        # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
        logger.info("gcp_recon_start", project_id=project_id)
        try:
            credentials = _get_gcp_credentials(credentials_file)
        except ImportError as exc:
            raise ImportError(
                "google-auth not installed. Run: pip install ares-redteam[cloud]"
            ) from exc

        loop = asyncio.get_running_loop()
        raw: dict[str, Any] = {"project_id": project_id}

        for label, fn in [
            ("iam",              partial(self._check_iam_bindings,       credentials, project_id)),
            ("gcs",              partial(self._check_gcs_buckets,        credentials, project_id)),
            ("service_accounts", partial(self._check_sa_keys,            credentials, project_id)),
            ("metadata",         self._check_metadata_server),
        ]:
            await self.noise.rate_limiter.acquire("cloud_api")
            try:
                if label == "metadata":
                    raw[label] = await loop.run_in_executor(None, fn)
                else:
                    raw[label] = await loop.run_in_executor(None, fn)
            except Exception as exc:
                logger.warning(f"gcp_{label}_failed", error=str(exc)[:150])
                raw[label] = {"error": str(exc)[:200]}
            await self.noise.jitter.sleep()

        logger.info("gcp_recon_done", findings=len(self._findings))
        raw["gcp_findings"] = self._findings  # matches OUTPUTS
        return self._findings, raw

    # ── IAM Bindings ──────────────────────────────────────────────────────────

    def _check_iam_bindings(self, credentials: Any, project_id: str) -> dict[str, Any]:
        """
        Get project IAM policy via Google Cloud Resource Manager SDK.
        Fixed: was using requests.post directly — replaced with SDK that handles
        auth refresh automatically and is the supported stable API.
        """
        try:
            from google.cloud import resourcemanager_v3  # type: ignore[import]
            from google.oauth2 import credentials as _creds_module
            import google.auth.transport.requests as _garequests

            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            request = resourcemanager_v3.GetIamPolicyRequest(
                resource=f"projects/{project_id}"
            )
            policy = client.get_iam_policy(request=request)

            public_bindings: list[str] = []
            owner_bindings:  list[str] = []

            for binding in policy.bindings:
                role    = binding.role
                members = list(binding.members)
                for member in members:
                    if member in _PUBLIC_MEMBERS:
                        public_bindings.append(f"{member} → {role}")
                if role in ("roles/owner", "roles/editor"):
                    owner_bindings.extend(
                        m for m in members if m not in _PUBLIC_MEMBERS
                    )

        except ImportError:
            # Fallback to requests if google-cloud-resource-manager not installed
            import requests
            import google.auth.transport.requests as _garequests

            auth_req = _garequests.Request()
            credentials.refresh(auth_req)
            resp = requests.post(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy",
                headers={"Authorization": f"Bearer {credentials.token}"},
                json={}, timeout=20,
            )
            resp.raise_for_status()
            raw_policy = resp.json()

            public_bindings = []
            owner_bindings  = []
            for binding in raw_policy.get("bindings", []):
                role    = binding.get("role", "")
                members = binding.get("members", [])
                for member in members:
                    if member in _PUBLIC_MEMBERS:
                        public_bindings.append(f"{member} → {role}")
                if role in ("roles/owner", "roles/editor"):
                    owner_bindings.extend(m for m in members if m not in _PUBLIC_MEMBERS)

        if public_bindings:
            self.finding(
                title="GCP Project IAM Grants Access to allUsers/allAuthenticatedUsers",
                description=(
                    "The project IAM policy has bindings for 'allUsers' or "
                    "'allAuthenticatedUsers'. This grants unauthenticated or "
                    "any Google-authenticated access globally."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1078.004",
                mitre_tactic="Initial Access",
                evidence={"public_bindings": public_bindings},
                remediation=(
                    "Remove allUsers and allAuthenticatedUsers from all IAM bindings. "
                    "Apply org policy: constraints/iam.allowedPolicyMemberDomains. "
                    "Enable Cloud Asset Inventory to monitor IAM drift."
                ),
            )

        if owner_bindings:
            self.finding(
                title=f"Multiple Project Owner/Editor Bindings ({len(owner_bindings)})",
                description=(
                    f"{len(owner_bindings)} identities have roles/owner or roles/editor "
                    "on this project. These roles allow full resource control and IAM modification."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1078.004",
                mitre_tactic="Initial Access",
                evidence={"owners": owner_bindings},
                remediation=(
                    "Replace roles/owner with custom least-privilege roles. "
                    "Limit owners to ≤2 break-glass accounts. "
                    "Use Org Policy to enforce owner restrictions."
                ),
            )

        return {"public_bindings": public_bindings, "owner_bindings": owner_bindings,
                "total_bindings": len(policy.get("bindings", []))}

    # ── GCS Buckets ───────────────────────────────────────────────────────────

    def _check_gcs_buckets(self, credentials: Any, project_id: str) -> dict[str, Any]:
        """
        List all GCS buckets and check their IAM policies for public access.
        Also checks uniform bucket-level access and versioning.
        """
        import requests  # type: ignore[import]
        import google.auth.transport.requests  # type: ignore[import]

        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        headers  = {"Authorization": f"Bearer {credentials.token}"}
        session  = requests.Session()
        session.headers.update(headers)

        public_buckets:          list[dict[str, Any]] = []
        uniform_access_disabled: list[str]            = []
        versioning_disabled:     list[str]            = []

        # List all buckets in project
        resp = session.get(
            "https://storage.googleapis.com/storage/v1/b",
            params={"project": project_id, "maxResults": 1000},
            timeout=20,
        )
        resp.raise_for_status()
        buckets = resp.json().get("items", [])

        for bucket in buckets:
            bucket_name = bucket.get("name", "")

            # ── IAM policy ─────────────────────────────────────────────────
            try:
                iam_resp = session.get(
                    f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/iam",
                    timeout=15,
                )
                iam_resp.raise_for_status()
                for binding in iam_resp.json().get("bindings", []):
                    role    = binding.get("role", "")
                    members = binding.get("members", [])
                    for member in members:
                        if member in _PUBLIC_MEMBERS:
                            public_buckets.append({
                                "bucket":    bucket_name,
                                "member":    member,
                                "role":      role,
                                "project_id": project_id,
                            })
            except Exception as exc:
                logger.debug("gcs_iam_check_skipped",
                             bucket=bucket_name, reason=str(exc)[:80])

            # ── Uniform bucket-level access ────────────────────────────────
            iamConfig = bucket.get("iamConfiguration", {})
            uba = iamConfig.get("uniformBucketLevelAccess", {})
            if not uba.get("enabled", True):
                uniform_access_disabled.append(bucket_name)

            # ── Object versioning ─────────────────────────────────────────
            versioning = bucket.get("versioning", {})
            if not versioning.get("enabled", False):
                versioning_disabled.append(bucket_name)

        if public_buckets:
            self.finding(
                title=f"Publicly Accessible GCS Buckets ({len(public_buckets)})",
                description=(
                    f"{len(public_buckets)} GCS bucket IAM binding(s) grant access to "
                    "allUsers or allAuthenticatedUsers. Data is readable without credentials."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1530",
                mitre_tactic="Collection",
                evidence={"buckets": public_buckets[:20]},
                remediation=(
                    "Remove allUsers and allAuthenticatedUsers from all bucket IAM policies. "
                    "Apply org policy: constraints/storage.publicAccessPrevention. "
                    "Enable uniform bucket-level access to prevent ACL overrides."
                ),
            )

        if uniform_access_disabled:
            self.finding(
                title=f"GCS Buckets Without Uniform Bucket-Level Access ({len(uniform_access_disabled)})",
                description=(
                    f"{len(uniform_access_disabled)} bucket(s) have per-object ACLs enabled. "
                    "Object-level ACLs can inadvertently expose individual objects publicly."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1530",
                mitre_tactic="Collection",
                evidence={"buckets": uniform_access_disabled[:20]},
                remediation=(
                    "Enable Uniform Bucket-Level Access on all buckets. "
                    "Migrate from per-object ACLs to bucket IAM policies."
                ),
            )

        return {
            "public_buckets":          public_buckets,
            "uniform_access_disabled": uniform_access_disabled,
            "versioning_disabled":     versioning_disabled,
            "total_buckets":           len(buckets),
        }

    # ── Service Account Keys ──────────────────────────────────────────────────

    def _check_sa_keys(self, credentials: Any, project_id: str) -> dict[str, Any]:
        """
        List all service accounts and their user-managed keys.
        Flag keys older than _SA_KEY_MAX_AGE_DAYS days.
        Also flags service accounts with owner/editor bindings.
        """
        import requests  # type: ignore[import]
        import google.auth.transport.requests  # type: ignore[import]

        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        headers = {"Authorization": f"Bearer {credentials.token}"}
        session = requests.Session()
        session.headers.update(headers)

        old_keys:  list[dict[str, Any]] = []
        many_keys: list[dict[str, Any]] = []   # SAs with >2 active keys

        # List ALL service accounts — paginate until nextPageToken is absent
        service_accounts: list[dict] = []
        page_token: str | None = None
        while True:
            params: dict = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            sa_resp = session.get(
                f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts",
                params=params,
                timeout=20,
            )
            sa_resp.raise_for_status()
            body = sa_resp.json()
            service_accounts.extend(body.get("accounts", []))
            page_token = body.get("nextPageToken")
            if not page_token:
                break

        cutoff = datetime.datetime.now(datetime.timezone.utc) - \
                 datetime.timedelta(days=_SA_KEY_MAX_AGE_DAYS)

        for sa in service_accounts:
            sa_email = sa.get("email", "")
            sa_name  = sa.get("name", "")

            # List keys — only USER_MANAGED type (system-managed keys auto-rotate)
            try:
                keys_resp = session.get(
                    f"https://iam.googleapis.com/v1/{sa_name}/keys",
                    params={"keyTypes": "USER_MANAGED"},
                    timeout=15,
                )
                keys_resp.raise_for_status()
                keys = keys_resp.json().get("keys", [])
            except Exception:
                continue

            active_keys = [k for k in keys
                           if k.get("keyType") == "USER_MANAGED"
                           and not k.get("disabled", False)]

            if len(active_keys) > 2:
                many_keys.append({
                    "service_account": sa_email,
                    "active_key_count": len(active_keys),
                })

            for key in active_keys:
                created_str = key.get("validAfterTime", "")
                if not created_str:
                    continue
                try:
                    created = datetime.datetime.fromisoformat(
                        created_str.replace("Z", "+00:00")
                    )
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days
                    if age_days > _SA_KEY_MAX_AGE_DAYS:
                        old_keys.append({
                            "service_account": sa_email,
                            "key_id":          key.get("name", "").split("/")[-1],
                            "age_days":        age_days,
                            "created":         created_str,
                        })
                except (ValueError, TypeError):
                    pass

        if old_keys:
            self.finding(
                title=f"Stale Service Account Keys Found ({len(old_keys)})",
                description=(
                    f"{len(old_keys)} user-managed service account key(s) are over "
                    f"{_SA_KEY_MAX_AGE_DAYS} days old. Long-lived keys are prime targets "
                    "for theft via repository leaks, config file exposure, or insider threats."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1552.001",
                mitre_tactic="Credential Access",
                evidence={"old_keys": old_keys[:20]},
                remediation=(
                    f"Rotate or delete SA keys older than {_SA_KEY_MAX_AGE_DAYS} days. "
                    "Prefer Workload Identity Federation over SA keys. "
                    "Scan repos with truffleHog/gitleaks for leaked keys. "
                    "Set org policy: constraints/iam.disableServiceAccountKeyCreation."
                ),
            )

        if many_keys:
            self.finding(
                title=f"Service Accounts with Excessive Active Keys ({len(many_keys)})",
                description=(
                    f"{len(many_keys)} service account(s) have more than 2 active user-managed keys. "
                    "Each extra key is an additional credential that can be stolen."
                ),
                severity=Severity.LOW,
                mitre_technique="T1552.001",
                mitre_tactic="Credential Access",
                evidence={"service_accounts": many_keys},
                remediation=(
                    "Delete unused SA keys. Keep only 1 active key per SA (2 during rotation). "
                    "Automate key rotation with Secret Manager."
                ),
            )

        return {
            "old_keys":          old_keys,
            "many_keys":         many_keys,
            "total_accounts":    len(service_accounts),
        }

    # ── GCE Metadata Server ───────────────────────────────────────────────────

    def _check_metadata_server(self) -> dict[str, Any]:
        """
        Check if the GCE metadata server is reachable from this execution context.
        Accessible metadata server = SSRF → credential theft risk.
        Uses httpx (already in deps) instead of requests for consistency.
        """
        import httpx  # type: ignore[import]

        metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/"
        try:
            with httpx.Client(follow_redirects=False, timeout=2) as client:
                resp = client.get(
                    metadata_url,
                    headers={"Metadata-Flavor": "Google"},
                )
            if resp.status_code == 200:
                # Try to list SA credentials exposed
                try:
                    with httpx.Client(follow_redirects=False, timeout=2) as client2:
                        sa_resp = client2.get(
                            "http://metadata.google.internal/computeMetadata/v1"
                            "/instance/service-accounts/",
                            headers={"Metadata-Flavor": "Google"},
                        )
                    sa_list = sa_resp.text.strip().splitlines() if sa_resp.is_success else []
                except Exception:
                    sa_list = []

                self.finding(
                    title="GCE Metadata Server Accessible — SSRF → Credential Theft",
                    description=(
                        "The GCE metadata server (169.254.169.254) is reachable from this context. "
                        "SSRF vulnerabilities in any application running here can steal service "
                        "account tokens and escalate to GCP project-level access. "
                        f"Service accounts exposed: {', '.join(sa_list) or 'unknown'}."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1552.005",
                    mitre_tactic="Credential Access",
                    evidence={
                        "metadata_url": metadata_url,
                        "service_accounts": sa_list,
                        "status_code": resp.status_code,
                    },
                    remediation=(
                        "Require IMDSv2-equivalent: enable metadata server with SA scopes only. "
                        "Enforce Workload Identity instead of SA bound to VM. "
                        "Limit SA permissions with minimal IAM roles. "
                        "Enable VPC Service Controls to restrict metadata access. "
                        "Use WAF / SSRF protection on all internet-facing applications."
                    ),
                )
                return {"accessible": True, "service_accounts": sa_list}
        except httpx.ConnectError:
            # Expected — not running on GCE or metadata blocked
            pass
        except Exception as exc:
            logger.debug("gcp_metadata_check_failed", error=str(exc)[:80])
        return {"accessible": False}
