# ARES Security Audit Report: Batch 11 — Cloud Asset & Infrastructure Discovery

> **Audit Date**: 26 September 2026  
> **Auditor**: Antigravity Autonomous Security Engineer  
> **Scope**: 4 Tier-2 Cloud Discovery Modules  
>   - [`ares/modules/cloud/aws.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/aws.py) (`cloud.aws`)  
>   - [`ares/modules/cloud/azure.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure.py) (`cloud.azure`)  
>   - [`ares/modules/cloud/azure_ad.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure_ad.py) (`cloud.azure_ad`)  
>   - [`ares/modules/cloud/gcp.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/gcp.py) (`cloud.gcp`)  
> **Governing Standards**: `AGENTS.md` (Rules 1–5), Gate 6 (Vault Protection), Anti-Hype Policy  

---

## 1. Executive Summary & Batch Metrics

Batch 11 inspects the read-only discovery and attack surface enumeration modules for the three primary public cloud providers (Amazon Web Services, Microsoft Azure / Entra ID, and Google Cloud Platform).

All four modules rely on cloud provider SDKs or REST APIs (`boto3`, `azure-identity`, `azure-mgmt-*`, `msal`, `google-auth`, `google.cloud.resourcemanager`, and `httpx`/`requests`). While none of the modules violate Gate 6 (no unauthorized writes to `AresVault._store`), the audit identified **6 significant architectural, operational, and pipeline defects** (`MOD-063` through `MOD-068`), including a **CRITICAL control-flow bug with `UnboundLocalError` that renders Microsoft Graph enumeration 100% unreachable dead code** (`MOD-067`), **SSRF probing of the operator workstation's own link-local metadata service** (`MOD-064`), **unscoped cloud tenant/account execution** (`MOD-063`), and **100% normalizer telemetry data loss** (`MOD-066`, `MOD-068`).

### Summary of Batch 11 Audit Findings

| Finding ID | Module(s) Affected | Severity | Audit Category | Description |
|---|---|:---:|---|---|
| **MOD-063** | `cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp` | **HIGH** | Grup D: Scope Bypass | Unscoped cloud account/subscription/project execution via ambient credentials |
| **MOD-064** | `cloud.aws`, `cloud.gcp` | **HIGH** | Grup D / E: Operator Egress | Operator workstation link-local metadata probe (`169.254.169.254` / `metadata.google.internal`) leaking operator credentials |
| **MOD-065** | `cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp` | **MEDIUM** | Grup E: Robustness | Missing pre-flight SDK dependency validation in `validate()` |
| **MOD-066** | `cloud.azure`, `cloud.azure_ad` | **HIGH** | Grup A: Normalizer Data Loss | 100% telemetry data loss on `azure_findings`, `azure_ad_findings`, and `access_tokens` |
| **MOD-067** | `cloud.azure_ad` | **CRITICAL** | Grup E: Flow / Dead Code | Indentation defect causing `UnboundLocalError` on default technique and 100% unreachable Graph API code |
| **MOD-068** | `cloud.gcp` | **HIGH** | Grup A: Normalizer Data Loss | 100% telemetry data loss on `gcp_findings` into `ArtifactStore` |

---

## 2. Detailed Module-by-Module Audit (Checklists B1–B6)

### 2.1. `cloud.aws` (`ares/modules/cloud/aws.py`)

#### B1: Scope Enforcement & Target Isolation
- **Scope Bypass on Cloud Account ID (`MOD-063`)**:
  Lines 190–192 contain the comment:
  ```python
  # Note: before_request() intentionally not called - cloud modules use
  # API credentials, not host IPs. Scope check (CIDR) does not apply to
  # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
  ```
  While CIDR checking does not apply to AWS global endpoints, STS caller identity (`get_caller_identity()["Account"]`) is queried without checking whether the resulting account ID matches the authorized campaign scope. If the operator runs ARES with ambient `~/.aws/credentials` or default AWS profile, ARES can enumerate an unauthorized AWS production account.
- **Operator Host Link-Local IMDSv1 SSRF Probe (`MOD-064`)**:
  Lines 302–310 implement `_check_imds`:
  ```python
  def _check_imds(self) -> dict:
      import urllib.request, urllib.error
      r: dict = {"imdsv1_available": False}
      try:
          req = urllib.request.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
          with urllib.request.urlopen(req, timeout=3) as resp:
              r["imdsv1_available"] = True; r["credential_roles"] = resp.read().decode().strip().splitlines()
      except Exception: pass
      return r
  ```
  This is executed from the **operator machine**. If ARES is running inside an EC2 instance, ECS container, or bastion host, this probe reaches the **operator's own metadata service**, extracts the operator's IAM roles, and issues a HIGH finding attributing this vulnerability to the remote engagement target!

#### B2: Teardown & Guaranteed Cleanup
- Clean. The module is purely read-only (IAM account summary, S3 bucket ACLs, Security Group ingress rules). No resources or persistence artifacts are created.

#### B3: Cryptographic & Vault Integrity
- The module does not attempt direct vault writes (`_vault.store` is not called). Gate 6 is satisfied.
- No raw credential hashes or unmasked access keys are emitted in findings.

#### B4: Technical Honesty & Real vs Mock
- Real API calls are used via `boto3`.
- **Pre-flight SDK check omitted (`MOD-065`)**: `validate()` checks for parameter existence but does not verify `import boto3`. If `boto3` is not installed, the module fails during `execute()` rather than pre-flight admission.

#### B5: Contract & Normalizer Alignment
- `OUTPUTS = ["aws_findings"]`.
- `ArtifactNormalizer.handlers["aws_findings"]` calls `_normalize_cloud`.
- `_normalize_cloud` only extracts `s3` public buckets into `CloudResourceArtifact`. It completely drops IAM findings (root MFA disabled, users without MFA, stale access keys) and Security Group findings (open ports to internet).

---

### 2.2. `cloud.azure` (`ares/modules/cloud/azure.py`)

#### B1: Scope Enforcement & Target Isolation
- **Unscoped Subscription Execution (`MOD-063`)**:
  `subscription_id` is passed as a string parameter, but `validate()` does not verify whether `subscription_id` or `tenant_id` belongs to the campaign's authorized scope.
  In `_get_credential()`, if `client_id` is not passed, it instantiates `DefaultAzureCredential()`, which can pick up ambient developer tokens (`az login`, Azure CLI token, VS Code Azure credentials).

#### B2: Teardown & Guaranteed Cleanup
- Read-only queries against Azure Resource Graph, Azure Storage, and Azure RBAC. No persistent infrastructure or role assignments are generated.

#### B3: Cryptographic & Vault Integrity
- Complies with Gate 6: no direct vault injection.
- Detection rule synthesis generates KQL and Sigma rules in `raw["loot"]`.

#### B4: Technical Honesty & Real vs Mock
- Real API calls via `azure.mgmt.*` and Microsoft Graph.
- `validate()` does not perform pre-flight verification of Azure SDK imports (`azure.identity`, `azure.mgmt.storage`, `azure.mgmt.authorization`, `azure.mgmt.network`).

#### B5: Contract & Normalizer Alignment
- **100% Data Loss (`MOD-066`)**:
  `OUTPUTS = ["azure_findings"]`.
  `ArtifactNormalizer` has NO handler for `"azure_findings"`!
  All discovered blob containers, Global Admins, RBAC Owner/Contributor roles, and internet-exposed NSG rules evaporate completely from `ArtifactStore`.

---

### 2.3. `cloud.azure_ad` (`ares/modules/cloud/azure_ad.py`)

#### B1: Scope Enforcement & Target Isolation
- `tenant_id` is unvalidated against campaign scope (`MOD-063`).

#### B2: Teardown & Guaranteed Cleanup
- Read-only enumeration. The device code flow generates a verification URI and code, but does not alter cloud state.

#### B3: Cryptographic & Vault Integrity
- No direct vault writes. `raw["access_tokens"]` stores acquired tokens.

#### B4: Technical Honesty & Control-Flow Flaw (`MOD-067`)
- **CRITICAL Control Flow Defect & UnboundLocalError**:
  In `run()` (lines 282–285):
  ```python
  280:                 )
  281:             await self.noise.jitter.sleep()
  282:             raw["access_tokens"] = raw.get("access_token", "")  # OUTPUTS key
  283:         raw["azure_ad_findings"] = self._findings  # OUTPUTS key
  284:         return self._findings[:], raw
  285: 
  286:         # Enumeration with Graph API
  287:         if not token:
  288:             return [], {
  ...
  296:             lambda: self._enumerate_tenant(token, tenant_id),
  ```
  Lines 283–284 are unindented!
  1. When running with the default `technique="enumerate"`, `raw` was never assigned inside `if technique == "device_code":`. Executing line 283 throws `UnboundLocalError: local variable 'raw' referenced before assignment`.
  2. Because line 284 returns unconditionally, lines 286–363 (the entire Microsoft Graph tenant enumeration logic for guest users, users without MFA, and high-privilege service principals) are **100% unreachable dead code**!
- `msal` is imported dynamically inside `_request_device_code` and `_get_token_client_credentials` without pre-flight validation in `validate()` (`MOD-065`).

#### B5: Contract & Normalizer Alignment
- **100% Data Loss (`MOD-066`)**:
  `OUTPUTS = ["azure_ad_findings", "access_tokens"]`.
  Neither capability has a handler in `ArtifactNormalizer`. Discovered Entra ID users and tokens are not ingested into `ArtifactStore`.

---

### 2.4. `cloud.gcp` (`ares/modules/cloud/gcp.py`)

#### B1: Scope Enforcement & Target Isolation
- **Unscoped Project Execution (`MOD-063`)**:
  `project_id` is not validated against authorized campaign scope.
- **Operator Host GCE Metadata Probe (`MOD-064`)**:
  Lines 590–648 (`_check_metadata_server`):
  Sends an HTTP request with `{"Metadata-Flavor": "Google"}` to `http://metadata.google.internal/computeMetadata/v1/instance/`. If ARES is running inside a GCP VM or Cloud Shell, this probes the operator workstation's own service account, stealing tokens and reporting a false finding on the engagement target.

#### B2: Teardown & Guaranteed Cleanup
- Read-only queries against Google Cloud Resource Manager, IAM, and GCS. Clean teardown.

#### B3: Cryptographic & Vault Integrity
- Complies with Gate 6: no direct vault bypass.

#### B4: Technical Honesty & Real vs Mock
- Real API calls via Google Cloud Client Libraries and REST endpoints.
- `validate()` checks `project_id` parameter or `GOOGLE_APPLICATION_CREDENTIALS` existence, but does not check SDK imports (`MOD-065`).

#### B5: Contract & Normalizer Alignment
- **100% Data Loss (`MOD-068`)**:
  `OUTPUTS = ["gcp_findings"]`.
  `ArtifactNormalizer` has NO handler for `"gcp_findings"`. All discovered GCP findings evaporate completely from `ArtifactStore`.

---

## 3. Findings Catalog: `MOD-063` through `MOD-068`

### [MOD-063] Unscoped Cloud Account/Tenant Execution across Cloud Discovery Modules
- **Severity**: **HIGH**
- **Affected Modules**: `cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp`
- **Category**: **Grup D (Scope Bypass / Unscoped Target)**
- **Technical Description**:
  All four cloud discovery modules explicitly bypass `before_request()` because "cloud modules use API credentials, not host IPs". However, none of the modules validate resolved cloud scope identifiers (`Account` from STS `get_caller_identity()`, `subscription_id`, `tenant_id`, `project_id`) against `campaign.scope`. If an operator runs ARES with ambient developer credentials, ARES will enumerate unauthorized personal or non-target cloud subscriptions without any boundary protection.
- **Remediation Plan**:
  Introduce a `validate_cloud_scope(target_identifier, provider)` check against `campaign.scope` in `validate()` / `run()`.

---

### [MOD-064] Operator Workstation Link-Local Metadata Server SSRF Probing & Token Leak
- **Severity**: **HIGH**
- **Affected Modules**: `cloud.aws` (`_check_imds`), `cloud.gcp` (`_check_metadata_server`)
- **Category**: **Grup D / E (Operator Egress & Attribution Risk)**
- **Technical Description**:
  Both modules initiate direct HTTP requests from the operator machine to link-local metadata endpoints (`http://169.254.169.254` and `http://metadata.google.internal`). When ARES is hosted in an EC2 instance, GCP VM, or cloud runner, it probes and leaks the operator's own instance profile and service account tokens, falsely generating findings attributed to the target.
- **Remediation Plan**:
  Remove local IMDS probes from remote discovery modules. IMDS probing belongs strictly to post-exploitation privilege escalation modules executed *on target* via remote command runners.

---

### [MOD-065] Missing Pre-Flight SDK Dependency Validation in `validate()`
- **Severity**: **MEDIUM**
- **Affected Modules**: `cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp`
- **Category**: **Grup E (Robustness & Fail-Fast Pre-Flight)**
- **Technical Description**:
  Modules fail at runtime inside `execute()` or `run()` if required SDKs (`boto3`, `azure-identity`, `azure-mgmt-*`, `msal`, `google-cloud-resourcemanager`) are not installed, rather than failing fast in `validate()` during campaign planning.
- **Remediation Plan**:
  Add structured `importlib.util.find_spec` verification in `validate()` raising `ModuleValidationError` with clear installation hints (`pip install ares-redteam[cloud]`).

---

### [MOD-066] 100% Normalizer Data Loss on `azure_findings`, `azure_ad_findings`, and `access_tokens`
- **Severity**: **HIGH**
- **Affected Modules**: `cloud.azure`, `cloud.azure_ad`
- **Category**: **Grup A (Normalizer Handlers Missing)**
- **Technical Description**:
  `ArtifactNormalizer` has no handlers for `azure_findings`, `azure_ad_findings`, or `access_tokens`. Discovered storage accounts, RBAC owner bindings, NSG security rules, and Entra ID guest users evaporate upon module completion.
- **Remediation Plan**:
  Implement `_normalize_azure` and `_normalize_azure_ad` handlers in `ares/normalize/artifacts.py` producing `CloudResourceArtifact` and `PermissionArtifact`.

---

### [MOD-067] Indentation Defect Causing `UnboundLocalError` & 100% Unreachable Graph API Dead Code
- **Severity**: **CRITICAL**
- **Affected Modules**: `cloud.azure_ad` (`ares/modules/cloud/azure_ad.py:283-294`)
- **Category**: **Grup E (Control Flow & Dead Code)**
- **Technical Description**:
  Lines 283–284 in `cloud.azure_ad.py` are indented at the method root immediately following `if technique == "device_code":`. When `technique="enumerate"` (the default!), `raw` is referenced before assignment, crashing with `UnboundLocalError`. Furthermore, line 284 returns unconditionally, making lines 286–363 (the entire Microsoft Graph user, guest, and service principal enumeration) completely unreachable dead code.
- **Remediation Plan**:
  Correct indentation of lines 282–284 so they are contained within `if technique == "device_code":`, initialize `raw = {"tenant_id": tenant_id}` at the beginning of `run()`, and allow enumeration execution to proceed when `technique != "device_code"`.

---

### [MOD-068] 100% Normalizer Data Loss on `gcp_findings`
- **Severity**: **HIGH**
- **Affected Modules**: `cloud.gcp` (`ares/modules/cloud/gcp.py`)
- **Category**: **Grup A (Normalizer Handlers Missing)**
- **Technical Description**:
  `cloud.gcp` declares `OUTPUTS = ["gcp_findings"]`. `ArtifactNormalizer.handlers` does not have an entry for `gcp_findings`. All public GCS buckets, project IAM owner bindings, and service account keys are dropped from `ArtifactStore`.
- **Remediation Plan**:
  Implement `_normalize_gcp` handler in `ares/normalize/artifacts.py` generating `CloudResourceArtifact` and `PermissionArtifact`.

---

## 4. Verification & Status Recommendation

In accordance with user instructions:
- **Zero code changes were applied to cloud modules** during this audit turn.
- Findings `MOD-063` through `MOD-068` are marked **DEFERRED** and consolidated into `MASTER_FIX_PLAN.md` for the unified batch remediation phase.
