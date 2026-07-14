# ARES Modules Guide

ARES ships with 60+ built-in modules. The modules are not meant to be random
buttons. They are building blocks for an authorized engagement: create a
campaign, define scope, run safe validation first, collect findings, then
generate a report.

The core workflow is universal across module families: create a campaign,
define targets and scope CIDRs, select a module from the backend catalog, fill
the generated parameters, dry-run where supported, execute only inside
authorized scope, review findings, and generate a report. AD/Kerberos, cloud,
network, credential, Windows, Linux, and other modules differ only in optional
extras/tools and parameter values.

## Safety Model

Only run ARES in systems you own or have written permission to test.

Every serious workflow should start with:

1. Create a campaign with an explicit scope.
2. Keep `dry_run` enabled until the module parameters look correct.
3. Use low-noise enumeration before medium or high-noise modules.
4. Treat high-noise modules as approval-only actions.
5. Generate a report and keep evidence inside the campaign.

The dashboard and API enforce authentication, RBAC, scope validation, parameter
validation, rate limits, and token revocation. The frontend is a convenience
layer; the backend remains the enforcement boundary.

## How Modules Are Used

### Dashboard Flow

1. For local development, run `ares dashboard dev --no-reload` from the
   repository root and open `http://127.0.0.1:5173/dashboard/`. On Windows,
   use `.\.venv\Scripts\ares.exe dashboard dev --no-reload`. In
   production/static mode, FastAPI serves the built dashboard at `/dashboard`
   after frontend assets are built.
2. Log in as an authorized operator.
3. Go to `Campaigns`.
4. Create or select a campaign.
5. Go to `Modules`.
6. Select a campaign and a module.
7. Fill the generated parameter form.
8. Run in `dry_run` first.
9. Review the result, then run only if the engagement allows it.
10. Generate a report from `Reports`.

The module form is generated from backend metadata. That means new or updated
modules can expose their own parameters without hardcoding fields in React.
The dashboard catalog uses the backend loader output for built-in module IDs,
names, categories, OPSEC labels, and parameter schemas. High-noise or sensitive
modules remain guarded by RBAC, scope checks, and explicit confirmation. Do not
run destructive, credential theft, lateral movement, exfiltration,
persistence, EDR bypass, or other noisy workflows without written
authorization and a scoped campaign.

### API Flow

```powershell
$token = (Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/auth/token `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin&password=YOUR_PASSWORD").access_token

$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod `
  -Method Get `
  -Uri http://127.0.0.1:8080/modules `
  -Headers $headers
```

Run a module in dry-run mode:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/modules/recon.fingerprint/run `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{
    "campaign_id": "CAMPAIGN_ID",
    "target": "127.0.0.1",
    "params": {},
    "dry_run": true
  }'
```

Optional extras and native tools depend on the module family. The base
dashboard/reporting workflow uses the `dev,pdf` baseline; install `.[ad]`,
`.[cloud]`, `.[windows]`, or `.[full]` only when those modules are needed.
For AD modules, `.[ad]` is the normal full install. If `ares doctor` already
shows Impacket as importable from a source/local install, use `.[ad-support]`
to install the direct AD support libraries (`pyasn1`, `pyasn1_modules`,
`ldap3`, and `httpx_ntlm`) without forcing another Impacket wheel install.
On Windows, if `.[ad]` fails while importing Impacket example scripts such as
`GetNPUsers.py`, restore the known-good source/local Impacket checkout and use
`.[ad-support]` for the direct support libraries. For dashboard module
parameters, prefer UPN usernames such as `alice@lab.local`; use `LAB\alice`
only when NTLM/MD4 support is known to work in the active Python/OpenSSL
environment.

## Module Categories

| Category | Purpose | Typical Use |
| --- | --- | --- |
| `recon` | Target/environment fingerprinting | Start here to understand a host or domain. |
| `network` | DNS, HTTP, service and port discovery | Build basic target context. |
| `ad` | Active Directory enumeration and abuse checks | Domain assessment, Kerberos, ACLs, ADCS, SCCM. |
| `credential` | Credential testing, vault use, cracking workflows | Offline validation and authorized credential checks. |
| `lateral` | Lateral movement validation | Medium/high-noise actions; use with care. |
| `windows` | Windows host checks and local privilege paths | Endpoint-focused validation. |
| `linux` | Linux privilege and container checks | Linux/container assessment. |
| `cloud` | AWS, Azure, GCP posture and identity paths | Cloud control-plane review. |
| `edr` | EDR/OPSEC decision support | Adaptive bypass planning and telemetry. |
| `opsec` | Detection-risk modeling | Coverage prediction before running noisy actions. |
| `ai` | Autonomous planning | Suggest chains and next steps from current state. |
| `exfil` | Authorized data exposure checks | Secrets and share exposure validation. |
| `persistence` | Persistence exposure checks | Scheduled task, WMI, registry run-key review. |

## Built-In Catalog

This is the operator-facing catalog. Exact availability depends on installed
optional dependencies such as AD, cloud, container, Windows, and PDF extras.

### Active Directory

| Module | Use |
| --- | --- |
| `ad.enum_users` | Enumerate domain users, dormant accounts, and password policy. |
| `ad.enum_spn` | Find service principal accounts that may be Kerberoast candidates. |
| `ad.enum_computers` | Enumerate computers, OS versions, stale accounts, and DCs. |
| `ad.enum_acl` | Find ACL paths such as WriteDACL, GenericAll, and DCSync rights. |
| `ad.kerberoast` | Request service tickets for authorized Kerberoast validation. |
| `ad.asreproast` | Check accounts without Kerberos pre-authentication. |
| `ad.adcs` | Assess ADCS template and enrollment misconfigurations. |
| `ad.delegation_abuse` | Review unconstrained, constrained, and resource-based delegation paths. |
| `ad.laps_enum` | Enumerate LAPS-managed local admin password exposure. |
| `ad.sccm` | Review SCCM/MECM abuse paths. |
| `ad.coerce` | High-noise coercion validation; use only with approval. |
| `ad.dcsync` | High-noise replication-rights validation; requires explicit authorization. |

### Credential

| Module | Use |
| --- | --- |
| `credential.crack` | Offline hash cracking workflow from campaign artifacts. |
| `credential.pass_spray` | Password-spray validation with rate-limit awareness. |
| `credential.golden_ticket` | Golden ticket validation in approved lab/engagement contexts. |
| `credential.pass_the_hash` | Authorized NTLM hash reuse validation. |
| `credential.reuse` | Credential reuse checks across discovered services. |

### Lateral Movement

| Module | Use |
| --- | --- |
| `lateral.smb_relay` | SMB signing and relay-prerequisite audit. |
| `lateral.ntlm_relay` | High-noise NTLM relay automation path. |
| `lateral.mssql` | MSSQL linked-server and command execution path review. |
| `lateral.dcom` | DCOM lateral movement validation. |
| `lateral.wmiexec` | WMI process creation validation. |
| `lateral.winrm` | PowerShell Remoting validation. |
| `lateral.ssh_pivot` | SSH pivot and SOCKS/forwarding workflow. |
| `lateral.psexec` | High-noise service-control validation. |
| `lateral.rdp` | RDP access validation. |

### Windows

| Module | Use |
| --- | --- |
| `windows.registry_enum` | Registry credential and configuration review. |
| `windows.scheduled_tasks_enum` | Scheduled task enumeration and exposure review. |
| `windows.uac_bypass` | UAC configuration audit. |
| `windows.token_impersonation` | Token impersonation exposure validation. |
| `windows.lsass_dump` | LSASS exposure validation in approved contexts. |
| `windows.dpapi` | DPAPI artifact review. |
| `windows.applocker_bypass` | AppLocker bypass posture review. |
| `windows.lsa_secrets` | LSA secrets exposure review. |

### Linux and Containers

| Module | Use |
| --- | --- |
| `linux.kernel_suggester` | Kernel version and known local privilege path review. |
| `linux.container` | Docker/Kubernetes/container escape posture checks. |
| `linux.privesc` | Linux privilege escalation posture review. |
| `linux.ld_preload` | LD_PRELOAD misconfiguration validation. |
| `linux.service_hijack` | Service hijack exposure review. |
| `linux.nfs_escape` | NFS/container escape path review. |

### Cloud

| Module | Use |
| --- | --- |
| `cloud.aws` | AWS IAM, S3, IMDS, and security group review. |
| `cloud.aws_privesc` | AWS IAM privilege escalation path analysis. |
| `cloud.azure` | Azure resource, storage, RBAC, and Key Vault review. |
| `cloud.azure_ad` | Azure AD service principal, device code, and guest review. |
| `cloud.gcp` | GCP IAM, GCS, and service account review. |
| `cloud.identity_federation_abuse` | SAML/OIDC and cross-cloud identity path review. |

### Network, Recon, Exfil, Persistence, OPSEC, AI

| Module | Use |
| --- | --- |
| `recon.fingerprint` | Target OS, role, and EDR/environment fingerprinting. |
| `network.dns_enum` | DNS enumeration. |
| `network.http_fingerprint` | HTTP service fingerprinting. |
| `network.port_scan` | Port discovery inside campaign scope. |
| `network.service_detect` | Service identification. |
| `network.snmp_enum` | SNMP exposure review. |
| `network.pivot` | Pivot path modeling. |
| `exfil.secrets_scan` | Secrets and sensitive-file exposure review. |
| `exfil.smb_shares` | SMB share exposure review. |
| `exfil.staged_collection` | Authorized staged collection workflow. |
| `persistence.scheduled_task` | Scheduled task persistence exposure. |
| `persistence.wmi_subscription` | WMI subscription persistence exposure. |
| `persistence.registry_run` | Registry run-key persistence exposure. |
| `edr.bypass_adaptive` | EDR vendor-aware OPSEC recommendations and outcome tracking. |
| `opsec.coverage_predictor` | Predict detection probability and recommended wait windows. |
| `ai.autonomous_planner` | Plan an engagement chain from campaign state and goals. |

### AI Planner Module

`ai.autonomous_planner` is the LLM-backed planning module. It is different from
template planning and from the internal module scorer:

| Planner surface | LLM required? | Primary use |
| --- | --- | --- |
| `Templates` dashboard page | No | Produce predictable template-based plans for review. |
| `ai.autonomous_planner` module | Yes, unless using local Ollama | Ask Claude, OpenAI, or Ollama to propose a plan from campaign context. |
| `Strategy` dashboard page | Usually yes | Start a background goal-based engagement loop with strategy events. |
| Internal `AttackPlanner` scorer | No | Rank possible next modules using local state and scoring weights. |

Parameters:

| Parameter | Values | Meaning |
| --- | --- | --- |
| `goal` | `domain_admin`, `enterprise_admin`, `cloud_admin`, `data_exfil`, `persistence`, `full_compromise` | The desired high-level outcome for the proposed plan. |
| `llm_backend` | `claude`, `openai`, `local` | Which planner backend to use. |
| `llm_model` | Optional string | Overrides the backend default model. |
| `auto_approve` | `false` recommended | When `false`, ARES returns a proposed plan for operator review. |

Provider setup:

- `llm_backend=claude` requires `ANTHROPIC_API_KEY`.
- `llm_backend=openai` requires `OPENAI_API_KEY`.
- `llm_backend=local` expects Ollama at `http://localhost:11434`.

Expected output:

- `execution_plan`: proposed stages and module IDs.
- `ai_reasoning`: why the planner selected the path.
- `confidence_score`: confidence from the planner response.
- `warnings`: OPSEC or safety notes to review before execution.

The module is OPSEC `LOCAL`: the planning call goes to the selected LLM backend
and does not contact the target network by itself. Treat the result as a plan
proposal, not as automatic authorization to execute it.

## Recommended Workflows

### Local Validation

Use this after a code or UI change:

```powershell
$env:ARES_LAB_PASSWORD="your-current-admin-password"
.\scripts\run_validation_lab.ps1
```

The validation lab logs in, checks auth, creates a local campaign, validates
input handling, generates a report, creates/deletes an API key, and deletes the
temporary campaign when done.

### Safe First Campaign

1. Create a campaign with one loopback or lab target.
2. Run `recon.fingerprint` in dry-run.
3. Run `network.http_fingerprint` or `network.dns_enum` in dry-run.
4. Generate an HTML report.
5. Confirm the report and dashboard views behave correctly.

### Active Directory Review

1. Start with `ad.enum_users`, `ad.enum_computers`, and `ad.enum_spn`.
2. Review findings and scope.
3. Use `ad.kerberoast` only when explicitly authorized.
4. Use `credential.crack` for offline analysis.
5. Keep high-noise modules such as `ad.dcsync`, `ad.coerce`, and
   `lateral.psexec` approval-gated.

### OPSEC Review

1. Run or review `recon.fingerprint`.
2. Use `edr.bypass_adaptive` to understand defensive product assumptions.
3. Use `opsec.coverage_predictor` before noisy chains.
4. Prefer low-noise enumeration when uncertainty is high.
