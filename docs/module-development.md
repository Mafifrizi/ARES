# ARES Module Development Guide

Writing your first ARES module in 10 minutes.

---

## Quick Start

```python
# mymodule/mssql_enum.py
from ares.modules.base import BaseModule, ModuleResult, OpsecLevel
from ares.core.campaign import Finding, Severity
from ares.core.context import ExecutionContext
from ares.core.errors import NetworkError, ConnectionRefused


class MssqlEnumModule(BaseModule):
    """Enumerate MSSQL instances and check for weak authentication."""

    # ── Required metadata ───────────────────────────────────────────────
    MODULE_ID          = "db.mssql_enum"
    MODULE_NAME        = "MSSQL Enumeration"
    MODULE_CATEGORY    = "db"
    MODULE_DESCRIPTION = "Enumerate MSSQL instances, check SA password, xp_cmdshell"

    # ── Optional metadata ───────────────────────────────────────────────
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]           # needs a credential
    OUTPUTS            = ["mssql_instances"]        # produces this for downstream
    MITRE_TECHNIQUES   = ["T1505.001"]
    MODULE_AUTHOR      = "Your Name <you@example.com>"

    # ── v0.9.0 SDK contract ─────────────────────────────────────────────

    async def validate(self, ctx: ExecutionContext) -> None:
        """Check that context has everything we need before executing."""
        ctx.require("target")           # target IP/hostname
        if not ctx.params.get("port"):
            ctx.params["port"] = 1433   # default MSSQL port (set if missing)

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        """Run the enumeration. Network calls go here."""
        target = ctx.target
        port   = ctx.params.get("port", 1433)
        result = ModuleResult(module_id=self.MODULE_ID, execution_id=ctx.execution_id)

        # Always call before_request to enforce scope + rate limiting
        await self.before_request(target, action="mssql_enum")

        if ctx.dry_run:
            # Simulation mode — return dummy data
            result.status = "success"
            result.raw    = {"simulated": True}
            return result

        try:
            # Real implementation: connect to MSSQL and enumerate
            # import aioodbc / pymssql / etc.
            instances = await self._enumerate(target, port, ctx)
            for inst in instances:
                f = self.finding(
                    title       = f"MSSQL instance on {target}:{port}",
                    description = f"MSSQL {inst['version']} with {inst['auth_method']} auth",
                    severity    = Severity.MEDIUM,
                    mitre_technique = "T1505.001",
                    host        = target,
                    evidence    = inst,
                )
                result.findings.append(f)
            result.status    = "success"
            result.artifacts = {"instances": instances}
        except ConnectionRefusedError:
            raise ConnectionRefused(
                f"MSSQL port {port} not open on {target}",
                module_id=self.MODULE_ID, target=target, port=port,
            )
        return result

    def report(self, result: ModuleResult) -> dict:
        """Return module-specific report section."""
        base = super().report(result)   # get default structure
        base["narrative"] = (
            f"MSSQL enumeration found {len(result.findings)} instance(s) on "
            f"the target network. Review for xp_cmdshell exposure and weak SA passwords."
        )
        return base

    # ── Private helpers ─────────────────────────────────────────────────

    async def _enumerate(self, target: str, port: int, ctx: ExecutionContext) -> list[dict]:
        # Stub — real implementation uses pymssql or aioodbc
        return []
```

---

## Module Metadata Reference

### Required Attributes

| Attribute | Type | Example | Description |
|-----------|------|---------|-------------|
| `MODULE_ID` | `str` | `"ad.kerberoast"` | Unique dotted ID. Must contain exactly one dot. |
| `MODULE_NAME` | `str` | `"Kerberoasting"` | Human-readable name shown in CLI. |
| `MODULE_CATEGORY` | `str` | `"ad"` | Category prefix (must match MODULE_ID prefix). |
| `MODULE_DESCRIPTION` | `str` | `"Request Kerberos TGS tickets..."` | One-liner for `ares module list`. |

### Optional Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `OPSEC_LEVEL` | `OpsecLevel` | `LOW` | `SILENT \| LOW \| MEDIUM \| HIGH_NOISE` |
| `REQUIRES` | `list[str]` | `[]` | Capabilities needed (outputs of upstream modules) |
| `OUTPUTS` | `list[str]` | `[]` | What this module produces (feeds downstream modules) |
| `MITRE_TECHNIQUES` | `list[str]` | `[]` | ATT&CK technique IDs (`["T1558.003"]`) |
| `MODULE_AUTHOR` | `str` | `"ARES Team"` | Author name and email |
| `MIN_NOISE_PROFILE` | `str \| None` | `None` | Minimum profile: `"stealth" \| "normal" \| "aggressive"` |

### OpsecLevel Guidelines

| Level | Use when | Examples |
|-------|----------|---------|
| `SILENT` | No network calls, local only | File parsing, local enumeration |
| `LOW` | Read-only, passive queries | LDAP read, DNS lookup |
| `MEDIUM` | Active queries, Kerberos | Kerberoasting, SMB enumeration |
| `HIGH_NOISE` | Triggers event logs heavily | DCSync, PsExec, brute force |

---

## The SDK Contract (v0.9.0)

### `validate(ctx)` — Called before execution

```python
async def validate(self, ctx: ExecutionContext) -> None:
    # Check required context fields
    ctx.require("target", "domain")

    # Check module-specific params
    if not ctx.params.get("wordlist"):
        ctx.params["wordlist"] = "/usr/share/wordlists/rockyou.txt"

    # Custom validation
    if ctx.opsec_profile == "stealth" and self.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE:
        from ares.core.errors import ModuleValidationError
        raise ModuleValidationError(
            f"Module {self.MODULE_ID} blocked in stealth profile",
            module_id=self.MODULE_ID,
        )
```

### `execute(ctx)` — The attack logic

```python
async def execute(self, ctx: ExecutionContext) -> ModuleResult:
    result = ModuleResult(module_id=self.MODULE_ID, execution_id=ctx.execution_id)

    # Always enforce scope + rate limiting
    await self.before_request(ctx.target)

    # Don't make real calls in dry_run / simulation mode
    if ctx.dry_run:
        result.status = "success"
        return result

    try:
        # Your attack/enumeration logic here
        data = await self._do_attack(ctx.target, ctx.best_credential())

        # Create findings
        for item in data:
            f = self.finding(title=..., description=..., severity=Severity.HIGH)
            result.findings.append(f)

        # Report new credentials discovered
        result.new_credentials = [{"username": ..., "hash": ...}]

        # Report new hosts found (triggers service_intel automatically)
        result.discovered_hosts = ["10.0.0.5", "10.0.0.6"]

        result.status = "success"

    except AuthenticationFailed as e:
        # Engine will try next credential in vault
        raise

    except AccountLocked as e:
        # Engine will STOP all attempts for this account
        raise

    return result
```

### `report(result)` — Report formatting

```python
def report(self, result: ModuleResult) -> dict:
    base = super().report(result)   # get standard structure
    base["narrative"] = "Your narrative here..."
    base["recommendations"] = [
        "Enable AES-only Kerberos encryption",
        "Audit service accounts with SPNs",
    ]
    return base
```

---

## ExecutionContext Fields

```python
ctx.target               # str: IP or hostname
ctx.domain               # str: AD domain (CORP.LOCAL)
ctx.port                 # int: target port if relevant
ctx.params               # dict: module-specific params (from CLI/API)
ctx.credentials          # list[Credential]: sorted by score (best first)
ctx.best_credential()    # Credential | None: highest-scored credential
ctx.session              # OperatorSession: shared campaign state
ctx.vault                # CredentialVault: full credential store
ctx.campaign_id          # str: campaign UUID
ctx.operator             # str: operator username
ctx.opsec_profile        # str: "stealth" | "normal" | "aggressive"
ctx.dry_run              # bool: True = simulation, no real network calls
ctx.execution_id         # str: unique per-execution UUID
ctx.require(*fields)     # raise InvalidContext if field missing
ctx.has(*fields)         # bool: check if optional fields present
ctx.host_state()         # HostState | None: from operator session
ctx.record_metric(m, v)  # record to telemetry
```

---

## Standard Error Handling

Always raise ARES errors (not generic exceptions):

```python
from ares.core.errors import (
    ModuleValidationError,    # bad config / bad context
    ConnectionRefused,        # TCP refused
    ConnectionTimeout,        # TCP timeout
    HostUnreachable,          # no route
    AuthenticationFailed,     # bad creds
    AccountLocked,            # lockout — CRITICAL
    InsufficientPrivilege,    # need higher priv
    ScopeError,               # out of scope
    SandboxError,             # module crashed
)

# Engine behavior:
#   ModuleValidationError → abort module, don't retry
#   ConnectionRefused     → try fallback protocol/port
#   AuthenticationFailed  → try next credential
#   AccountLocked         → STOP immediately, never retry this account
#   ScopeError            → abort campaign operation
```

---

## ModuleResult Fields

```python
result = ModuleResult(
    status           = "success",      # "success"|"failure"|"partial"|"skipped"
    findings         = [f1, f2],       # list[Finding]
    artifacts        = {"key": data},  # raw artifacts for evidence
    new_credentials  = [{"username": "svc", "hash": "aad3..."}],
    discovered_hosts = ["10.0.0.5"],   # engine auto-scans these
    raw              = {"debug": ...}, # unstructured output
    error            = "",             # error message if not success
)
```

---

## Testing Your Module

```python
import pytest
from ares.core.context import ExecutionContext
from mymodule.mssql_enum import MssqlEnumModule

@pytest.mark.asyncio
async def test_mssql_enum_validate():
    ctx = ExecutionContext.for_test(target="10.0.0.10")
    module = MssqlEnumModule.__new__(MssqlEnumModule)
    await module.validate(ctx)   # should not raise

@pytest.mark.asyncio
async def test_mssql_enum_dry_run():
    from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
    from ares.core.config import AresSettings
    from ares.core.noise import NoiseController

    campaign = Campaign(name="test", scope=[ScopeEntry(cidr="10.0.0.0/8")],
                        noise_profile=NoiseProfile.NORMAL)
    module = MssqlEnumModule(
        settings=AresSettings(), campaign=campaign,
        noise=NoiseController(campaign),
    )
    ctx = ExecutionContext.for_test(target="10.0.0.10", dry_run=True)
    result = await module.execute(ctx)
    assert result.status == "success"
    assert result.module_id == "db.mssql_enum"

def test_module_metadata():
    from ares.modules.base import validate_module_class
    errors = validate_module_class(MssqlEnumModule)
    assert errors == [], f"Module metadata errors: {errors}"
```

---

## Packaging & Publishing

### Module manifest (`manifest.json`)

```json
{
  "module_id":   "db.mssql_enum",
  "name":        "MSSQL Enumeration",
  "version":     "1.0.0",
  "author":      "Your Name",
  "description": "Enumerate MSSQL instances",
  "requires":    ["pymssql"],
  "ares_min":    "0.9.0",
  "signature":   "sha256:abc123..."
}
```

### Install

```bash
ares module install db/mssql_enum@1.0.0
# or from local path:
ares module install ./mymodule/
```

### Guidelines for accepted modules

- ✅ Must have all 4 required metadata attributes
- ✅ Must implement `validate()` — check context completeness
- ✅ Must respect `ctx.dry_run` — no network calls when True
- ✅ Must raise ARES errors, not generic exceptions
- ✅ Must have unit tests covering validate + execute + dry_run
- ✅ Must have MITRE technique mapping
- ❌ Must NOT access filesystem outside campaign working directory
- ❌ Must NOT make outbound calls to non-target hosts without operator config
- ❌ Must NOT store credentials in plaintext (use vault)
