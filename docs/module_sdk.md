# ARES Module SDK

**Version:** 1.0.0 | **Status:** Active

> Complete guide for ARES module authors.
> Everything needed to build, test, sign, and publish an ARES module.

`ares.sdk` is the preferred public import path for new modules. The older
`ares.modules.sdk` path remains available for existing modules.

---

## Quick Start

```python
# my_module.py
from ares.sdk import (
    BaseModule, ExecutionContext, ModuleResult,
    OpsecLevel, Severity, Finding,
    module_metadata, get_logger,
    AuthenticationFailed, HostUnreachable,
)
from ares.core.capabilities import Capability

logger = get_logger("myorg.my_module")

@module_metadata(
    module_id   = "myorg.my_attack",
    name        = "My Attack Module",
    category    = "ad",
    description = "Does something interesting against AD",
    author      = "alice@myorg.com",
    opsec       = OpsecLevel.LOW,
    requires    = ["domain_creds"],
    outputs     = ["user_list"],
    mitre       = ["T1087.002"],
)
class MyModule(BaseModule):
    CAPABILITIES = {Capability.CAP_NET, Capability.CAP_DB}

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target", "domain")
        if not ctx.params.get("dc"):
            from ares.core.errors import ModuleValidationError
            raise ModuleValidationError("Missing 'dc' param", field="dc")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        if ctx.dry_run:
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID)

        await self.before_request(ctx.target)   # scope + rate limit + jitter

        # ... do work ...
        finding = self.finding(
            title           = "Something found",
            description     = "Details here",
            severity        = Severity.HIGH,
            mitre_technique = "T1087.002",
            host            = ctx.target,
        )
        return ModuleResult(
            status    = "success",
            findings  = [finding],
            module_id = self.MODULE_ID,
        )

    async def run(self, **kwargs):
        # Legacy interface — engine calls execute(ctx) instead
        ctx = ExecutionContext.for_test(**kwargs)
        result = await self.execute(ctx)
        return result.findings, result.raw
```

---

## Module Contract (v1.0.0)

Every module must implement 3 methods:

### `validate(ctx: ExecutionContext) → None`

Called **before** execution. Check that all required params and context fields are present.
Raise `ModuleValidationError` if context is insufficient — engine aborts immediately.

```python
async def validate(self, ctx: ExecutionContext) -> None:
    # Assert required context fields
    ctx.require("target", "domain")

    # Validate module params
    dc = ctx.params.get("dc")
    if not dc:
        raise ModuleValidationError("Missing 'dc'", module_id=self.MODULE_ID, field="dc")

    # Check opsec profile allows this module
    if ctx.opsec_profile == "stealth" and self.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE:
        raise ModuleValidationError("Module blocked in stealth profile")
```

### `execute(ctx: ExecutionContext) → ModuleResult`

Main execution. Receives typed context, returns structured result.

```python
async def execute(self, ctx: ExecutionContext) -> ModuleResult:
    if ctx.dry_run:
        # Always support dry_run — no real network calls
        return ModuleResult(status="dry_run", module_id=self.MODULE_ID)

    # Use before_request hook (scope check + rate limit + opsec jitter)
    await self.before_request(ctx.target, action="ldap_query")

    try:
        # ... network operations ...
        findings = [self.finding(...)]
        return ModuleResult(
            status           = "success",
            findings         = findings,
            new_credentials  = [],            # Credential objects if harvested
            discovered_hosts = ["10.0.0.5"],  # IPs if lateral discovery
            raw              = {"count": 3},  # free-form extra data
            module_id        = self.MODULE_ID,
        )
    except HostUnreachable as e:
        raise   # let engine handle (will skip target)
    except AuthenticationFailed as e:
        raise   # let engine try next credential
```

### `report(result: ModuleResult) → dict`

Format result for the report engine. Default implementation works fine for most modules.
Override to add custom narrative, MITRE context, or remediation text.

```python
def report(self, result: ModuleResult) -> dict:
    base = super().report(result)
    base["narrative"] = (
        f"The {self.MODULE_NAME} found {len(result.findings)} "
        f"exploitable accounts. Immediate remediation required."
    )
    return base
```

---

## Required Metadata

```python
MODULE_ID          = "myorg.my_attack"     # dotted: category.name (REQUIRED)
MODULE_NAME        = "My Attack Module"    # human name (REQUIRED)
MODULE_CATEGORY    = "ad"                  # ad | linux | cloud | reporting (REQUIRED)
MODULE_DESCRIPTION = "Does X against Y"   # one-liner (REQUIRED)
MODULE_AUTHOR      = "alice@myorg.com"     # optional but recommended
```

**MODULE_ID rules:**
- Must use dotted format: `category.name` or `org.category.name`
- Lowercase, alphanumeric + `.` + `_` only
- Must be globally unique — prefix with your org name

---

## Optional Metadata

```python
OPSEC_LEVEL       = OpsecLevel.LOW       # silent | low | medium | high_noise
REQUIRES          = ["domain_creds"]     # what the module needs as input
OUTPUTS           = ["spn_list"]         # what the module produces
MITRE_TECHNIQUES  = ["T1558.003"]        # ATT&CK technique IDs
MIN_NOISE_PROFILE = "normal"             # "stealth" | "normal" | "aggressive"
CAPABILITIES      = {Capability.CAP_NET} # resource access declaration
```

**REQUIRES / OUTPUTS** wire into the GoalEngine's dependency resolver and AttackPlanner's scoring:

```python
# Example: your module needs kerberoastable accounts (produced by ad.enum_spn)
# and produces cracked credentials
REQUIRES = ["spn_list"]
OUTPUTS  = ["credential"]

# The engine will automatically:
# 1. Run ad.enum_spn first (produces spn_list)
# 2. Then run your module (needs spn_list, produces credential)
```

---

## Capability Declaration

Declare exactly what system resources your module needs:

```python
from ares.core.capabilities import Capability

class MyModule(BaseModule):
    # Network-only module (most AD/cloud modules)
    CAPABILITIES = {Capability.CAP_NET, Capability.CAP_DB}

    # Module that spawns subprocesses (lateral movement)
    CAPABILITIES = {Capability.CAP_NET, Capability.CAP_EXEC, Capability.CAP_DB}

    # Module that reads/writes local files (reporting, evidence)
    CAPABILITIES = {Capability.CAP_DB, Capability.CAP_FS}
```

**Community module limits:**
- `CAP_NET`, `CAP_DB`, `CAP_FS` — allowed
- `CAP_EXEC`, `CAP_PROCESS`, `CAP_UNSAFE` — **not allowed for community modules**
- If you declare forbidden caps, module is rejected at load time

---

## Error Handling

Always raise typed SDK errors — engine uses the type to decide retry/fallback/abort:

```python
from ares.sdk import (
    AuthenticationFailed,   # try next credential
    AccountLocked,          # ABORT all auth attempts
    HostUnreachable,        # skip this target
    ConnectionRefused,      # fallback to alternative module
    DetectionSignal,        # pause + escalate opsec
    HoneypotDetected,       # abort campaign
    InsufficientPrivilege,  # suggest privesc
)

async def execute(self, ctx):
    try:
        result = ldap_connect(ctx.target, ctx.best_credential())
    except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
        raise AuthenticationFailed(
            f"LDAP auth failed on {ctx.target}",
            username=ctx.best_credential().username if ctx.best_credential() else "",
            module_id=self.MODULE_ID, target=ctx.target,
        )
    except ConnectionError as e:
        if "refused" in str(e).lower():
            raise ConnectionRefused(f"Port 389 refused on {ctx.target}", port=389)
        raise HostUnreachable(f"{ctx.target} unreachable: {e}")
```

---

## Using ExecutionContext

```python
# Access target and params
dc     = ctx.params.get("dc") or ctx.target
domain = ctx.domain or ctx.params.get("domain", "")

# Get best available credential
cred = ctx.best_credential()
if cred:
    username = cred.username
    password = cred.secret   # plaintext if cracked, else hash

# Check opsec profile
if ctx.opsec_profile == "stealth":
    # Use more cautious technique
    use_ldaps = True

# Dry run mode (simulation)
if ctx.dry_run:
    return ModuleResult(status="dry_run", ...)

# Check optional fields
if ctx.has("session"):
    host_state = ctx.host_state()
    if host_state and host_state.is_dc:
        logger.info("Target is a DC — running full enumeration")
```

---

## Creating Findings

```python
finding = self.finding(
    title           = "Kerberoastable SPN account: svc_sql",
    description     = (
        "Account svc_sql has SPN MSSQLSvc/db01:1433 registered. "
        "Any domain user can request a TGS ticket and attempt offline cracking."
    ),
    severity        = Severity.HIGH,           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    mitre_technique = "T1558.003",             # Kerberoasting
    mitre_tactic    = "Credential Access",
    host            = ctx.target,
    confidence      = 0.95,                    # 0.0–1.0
    evidence        = {
        "username": "svc_sql",
        "spns":     ["MSSQLSvc/db01:1433"],
        "domain":   ctx.domain,
    },
    remediation     = (
        "Use Group Managed Service Accounts (gMSA) for service accounts. "
        "Require AES-256 Kerberos encryption."
    ),
)
```

**Severity guidelines:**

| Severity | Examples                                          |
|----------|---------------------------------------------------|
| CRITICAL | DA credential harvested, DCSync successful        |
| HIGH     | Kerberoastable SPN, AS-REP roastable, ACL abuse  |
| MEDIUM   | Misconfigured SMB shares, weak password policy   |
| LOW      | Information disclosure, non-critical misconfigs  |
| INFO     | Enumeration results (user list, host discovery)  |

---

## Testing Your Module

Use `ModuleTestHelper` from the SDK:

```python
# tests/test_my_module.py
import pytest
from ares.sdk import ModuleTestHelper
from my_module import MyModule

class TestMyModule:
    @pytest.fixture
    def helper(self):
        return ModuleTestHelper(MyModule)

    def test_metadata_valid(self, helper):
        errors = helper.validate_class()
        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_dry_run(self, helper):
        result = await helper.run_full(
            target="10.0.0.1",
            domain="CORP",
            params={"dc": "10.0.0.1"},
            dry_run=True,
        )
        assert result.status == "dry_run"

    @pytest.mark.asyncio
    async def test_validate_missing_dc(self, helper):
        from ares.core.errors import ModuleValidationError
        ctx = helper.make_context(target="10.0.0.1", domain="CORP", params={})
        with pytest.raises(ModuleValidationError):
            await helper.validate(ctx)

    def test_report_structure(self, helper):
        from ares.sdk import ModuleResult
        result = ModuleResult(status="success", module_id="myorg.my_attack")
        report = helper.report(result)
        assert "module_id" in report
        assert "findings" in report
```

Run: `pytest tests/ -v`

---

## Signing Your Module

Before publishing:

```bash
# 1. Generate key pair (once per author)
ares signing generate-key --author alice@myorg.com --out ~/.ares/keys/

# 2. Sign your module
ares signing sign my_module.py \
    --key ~/.ares/keys/<key_id>.key \
    --author alice@myorg.com \
    --module-id myorg.my_attack \
    --version 1.0.0

# 3. Verify signature
ares signing verify my_module.py
# ✓ my_module.py: COMMUNITY (author: 'alice@myorg.com')

# 4. Publish public key to ARES registry
ares signing add-key <key_id> ~/.ares/keys/<key_id>.pub \
    --author alice@myorg.com
```

Include both `my_module.py` and `my_module.py.sig` in your release.

---

## Publishing

**Option 1: pip package**

```toml
# pyproject.toml
[project.entry-points."ares.modules"]
myorg_my_attack = "myorg_ares_modules.my_module:MyModule"
```

Users install with: `pip install myorg-ares-modules`

**Option 2: Drop-in file**

Copy `my_module.py` + `my_module.py.sig` to `~/.ares/plugins/`.
ARES auto-discovers on next startup.

---

## Checklist

Before submitting a module to the ARES marketplace:

- [ ] All required metadata set (`MODULE_ID`, `MODULE_NAME`, `MODULE_CATEGORY`, `MODULE_DESCRIPTION`)
- [ ] `validate(ctx)` checks all required params
- [ ] `execute(ctx)` supports `dry_run=True`
- [ ] Typed errors raised (never bare `Exception`)
- [ ] `CAPABILITIES` declared (no undeclared `CAP_EXEC`/`CAP_PROCESS`)
- [ ] `MITRE_TECHNIQUES` set
- [ ] `OPSEC_LEVEL` set accurately
- [ ] Unit tests with `ModuleTestHelper`
- [ ] `@module_metadata` decorator validates clean (no errors)
- [ ] Module signed with Ed25519 key
