# ARES Module Development Guide

**Version:** 1.0.0

---

## Quick Start

Generate a module scaffold using the CLI:

```bash
ares module create ad.my_attack \
    --author alice@corp.com \
    --category ad \
    --description "Find something interesting"
```

This creates two files:
- `my_attack.py` — module implementation
- `test_my_attack.py` — test scaffold

---

## Module Anatomy

Every ARES module is a Python class that inherits from `BaseModule`:

```python
from ares.modules.sdk import (
    BaseModule, ExecutionContext, ModuleResult,
    OpsecLevel, Severity, module_metadata,
)

@module_metadata(
    module_id   = "ad.my_attack",      # unique dot-notation ID
    name        = "My Attack",
    category    = "ad",                # ad | linux | cloud | lateral | exfil | credential
    description = "Does something",
    author      = "alice@corp.com",
    opsec       = OpsecLevel.LOW,      # silent | low | medium | high_noise
    requires    = ["domain_creds"],    # capabilities this module needs
    outputs     = ["credential_list"], # capabilities this module produces
    mitre       = ["T1558.003"],       # MITRE ATT&CK technique IDs
)
class MyAttackModule(BaseModule):

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target", "domain")   # raises if missing

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        if ctx.dry_run:
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID)

        target = ctx.params["target"]
        await self.before_request(target, "ldap")   # scope + noise check

        # ... attack work ...

        self.finding(
            title           = "Kerberoastable account found",
            description     = "Service account has SPN set",
            severity        = Severity.HIGH,
            mitre_technique = "T1558.003",
            host            = target,
            evidence        = {"spn": "MSSQLSvc/db01"},
            remediation     = "Use gMSA instead",
        )

        return ModuleResult(
            status    = "success",
            findings  = self._findings,
            module_id = self.MODULE_ID,
            raw       = {"spns": [...]},
        )

    async def run(self, **kwargs):
        """Required: legacy interface called by engine."""
        ctx = ExecutionContext.for_test(**kwargs)
        r   = await self.execute(ctx)
        return r.findings, r.raw
```

---

## REQUIRES and OUTPUTS

These are the two most important metadata fields for the capability-based planner.

| Field | Type | Purpose |
|-------|------|---------|
| `REQUIRES` | `list[str]` | Capabilities this module needs to run |
| `OUTPUTS` | `list[str]` | Capabilities this module produces on success |

The `CapabilityGraph` uses these to automatically determine execution order when running a goal. If you set them correctly, your module will be discovered and used automatically by the planner.

**Standard capability names:**

| Capability | Description |
|------------|-------------|
| `domain_creds` | Any valid domain user credential |
| `domain_admin_creds` | Domain Admin credential |
| `local_admin_cred` | Local admin on a specific host |
| `user_list` | List of domain users |
| `spn_list` | List of SPN accounts |
| `kerberos_hashes` | Kerberos TGS/AS-REP hashes |
| `ntlm_hashes` | NTLM hashes from DCSync |
| `acl_findings` | Dangerous ACL grants |
| `computer_list` | Domain computers |
| `lateral_session` | Active session on remote host |
| `persistence_established` | Persistence mechanism in place |
| `file_share_list` | Accessible SMB shares |
| `credential_list` | List of credentials |
| `sensitive_data_found` | Sensitive data located |

---

## OpsecLevel

Controls whether the planner includes your module in stealth profiles:

| Level | Description | Example |
|-------|-------------|---------|
| `OpsecLevel.SILENT` | No network noise, read-only | Reading local files |
| `OpsecLevel.LOW` | Minimal network, no auth events | LDAP anonymous query |
| `OpsecLevel.MEDIUM` | Some auth events expected | Kerberoast (normal TGS) |
| `OpsecLevel.HIGH_NOISE` | Very noisy, creates many events | DCSync, brute force |

---

## Finding Severity

```python
from ares.modules.sdk import Severity

Severity.CRITICAL   # CVSS 9.0–10.0
Severity.HIGH       # CVSS 7.0–8.9
Severity.MEDIUM     # CVSS 4.0–6.9
Severity.LOW        # CVSS 0.1–3.9
Severity.INFO       # Informational
```

---

## Testing Your Module

The scaffold generates a test file with two baseline tests. Add more:

```python
@pytest.mark.asyncio
async def test_finds_kerberoastable_user(module):
    """When SPN accounts exist, module should find them."""
    with patch("impacket.examples.GetUserSPNs.GetUserSPNs") as mock:
        mock.return_value.run.return_value = None
        # mock file output...
        findings, raw = await module.run(
            dc="10.0.0.1", domain="CORP",
            username="user", password="pass",
        )
    assert len(findings) > 0
    assert findings[0].severity.value == "high"

@pytest.mark.asyncio
async def test_no_spns_no_finding(module):
    """When no SPN accounts, module should return empty findings."""
    # ...
    assert findings == []
```

Run tests:
```bash
pytest test_my_attack.py -v
```

---

## Installing Your Module

```bash
# Sign the module (required for non-builtin)
ares signing generate-key --author alice@corp.com
ares signing sign my_attack.py

# Install from local file
ares module install ./my_attack.py

# Verify it loaded
ares module list | grep my_attack
ares module info ad.my_attack
```

---

## Module Categories

| Category | Purpose | Examples |
|----------|---------|---------|
| `ad` | Active Directory attacks | kerberoast, dcsync, enum_users |
| `linux` | Linux/Unix attacks | privesc, container escape |
| `cloud` | Cloud provider attacks | aws, azure, gcp |
| `lateral` | Lateral movement | psexec, wmiexec, winrm, ssh |
| `exfil` | Data exfiltration | smb_shares, secrets_scan |
| `credential` | Credential operations | reuse, cracking |
| `persistence` | Persistence mechanisms | scheduled_task, registry_run |
| `reporting` | Report generation | report_gen |
