# ARES Module Development Guide

Writing your first ARES module in 10 minutes.

---

## Phase 5C.1 Boundary

Phase 5C.1 introduces `ares.modules.descriptors`, an immutable audit-only
sidecar containing explicit contracts for the 62 first-party module IDs. It
does not change module execution, parsing, plugin loading, or any execution
ingress. In particular, it is not the canonical pre-side-effect gateway; that
enforcement work is deferred to Phase 5C.2.

Descriptor completeness and future-gateway eligibility are separate states.
A first-party module may have every descriptor field recorded and still be
ineligible because its current cancellation, output, destination, credential,
or adapter contract is unsafe or unproven. Existing Phase 5C.0 P0/P1 execution
defects remain unfixed in this metadata phase.

The descriptor records sensitive defaults only as fixed semantic states; no
sensitive value or value-derived hash is retained. Current lifecycle metadata
is intentionally conservative: prior-attempt settlement, compensation, and
timeout settlement remain unproven across the inventory, while the external
LLM planner is explicitly billable, nondeterministic, and not automatically
retryable. Dry-run support is source-bound rather than inferred from the base
flag: 56 modules have native guard provenance and six lateral modules bind to
the shared lateral adapter guard. These classifications are audit evidence,
not live enforcement.

The sidecar is trusted first-party repository data, not metadata inferred from
class names, categories, defaults, or plugins. External plugin metadata remains
untrusted catalog data and receives neither a fallback first-party descriptor
nor future-gateway eligibility. Adding normal SDK class attributes is therefore
not sufficient to make a plugin eligible for the future gateway. Phase 5C.1
made no schema change. The later revision `0010` is additive test-only
persistence and does not make a module eligible or change any live ingress.

The examples below describe the modern v2 SDK surface with full backward
compatibility for existing v1 modules. They are not proof that all current
ingresses apply the same policy, that dry-run is universally side-effect-free,
or that current outcomes and retries are authoritative.

---

## Quick Start (v2 Modern Standard)

The modern ARES SDK (`ares.sdk`) introduces type-safe parameter schemas with Pydantic v2, generic `BaseModule[P, R]`, fluent execution helpers, and isolated simulation testing.

### Option A: Modern Class-Based Module (Recommended)

```python
# mymodule/mssql_enum.py
from ares.sdk import (
    BaseModule, ExecutionContext, ModuleResult,
    ModuleParams, param, SecretParam,
    OpsecLevel, Severity,
)
from ares.core.errors import NetworkError, ConnectionRefused


# 1. Strictly validated parameter schema (Pydantic v2)
class MssqlEnumParams(ModuleParams):
    target: str = param("Target IP address or hostname", min_length=1)
    port: int = param("MSSQL service port", default=1433, ge=1, le=65535)
    sa_password: SecretParam = param("Known or candidate SA password", secret=True, required=False)


# 2. Inherit from generic BaseModule[Params, Result]
class MssqlEnumModule(BaseModule[MssqlEnumParams, ModuleResult]):
    """Enumerate MSSQL instances and check for weak authentication."""

    # ── Required metadata ───────────────────────────────────────────────
    MODULE_ID          = "db.mssql_enum"
    MODULE_NAME        = "MSSQL Enumeration"
    MODULE_CATEGORY    = "db"
    MODULE_DESCRIPTION = "Enumerate MSSQL instances, check SA password, xp_cmdshell"
    PARAMS_MODEL       = MssqlEnumParams

    # ── Optional metadata ───────────────────────────────────────────────
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]           # needs a credential
    OUTPUTS            = ["mssql_instances"]        # produces this for downstream
    MITRE_TECHNIQUES   = ["T1505.001"]
    MODULE_AUTHOR      = "Your Name <you@example.com>"

    # ── ARES SDK contract ─────────────────────────────────────────────

    async def execute(self, ctx: ExecutionContext[MssqlEnumParams]) -> ModuleResult:
        """Run the enumeration. Network calls go here."""
        # ctx.params provides full static typing and runtime validation!
        target = ctx.params.target
        port   = ctx.params.port

        if ctx.dry_run:
            # Simulation mode — return dry-run result
            return ModuleResult.ok(
                f"Dry-run validated: {target}:{port} inside approved scope.",
                module_id=self.MODULE_ID,
            )

        # Existing SDK hook; Phase 5C.2 defines the canonical gateway order.
        await self.before_request(target, action="mssql_enum")

        try:
            instances = await self._enumerate(target, port, ctx)
            for inst in instances:
                # Emit findings using fluent context helper
                ctx.emit_finding(
                    title       = f"MSSQL instance on {target}:{port}",
                    description = f"MSSQL {inst['version']} with {inst['auth_method']} auth",
                    severity    = Severity.MEDIUM,
                    mitre_technique = "T1505.001",
                    host        = target,
                    evidence    = inst,
                )
            
            ctx.store_artifact("instances", instances)
            return ModuleResult(
                status="success",
                findings=ctx.findings,
                artifacts=ctx.artifacts,
                module_id=self.MODULE_ID,
            )
        except ConnectionRefusedError:
            raise ConnectionRefused(
                f"MSSQL port {port} not open on {target}",
                module_id=self.MODULE_ID, target=target, port=port,
            )

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
        # Stub — real implementation connects to MSSQL service
        return [{"version": "MSSQL 2019", "auth_method": "SQL_AND_WINDOWS"}]
```

### Option B: Declarative Functional Module (`@ares_module`)

For single-action modules, reconnaissance scripts, or quick extensions:

```python
from ares.sdk import ares_module, ExecutionContext, ModuleResult, Severity

@ares_module(
    id="db.mssql_quick_check",
    name="MSSQL Quick Check",
    category="db",
    params_model=MssqlEnumParams,
    mitre="T1505.001",
)
async def mssql_quick_check(ctx: ExecutionContext[MssqlEnumParams]) -> ModuleResult:
    ctx.emit_finding(
        title=f"MSSQL Port Active on {ctx.params.target}:{ctx.params.port}",
        severity=Severity.INFO,
        mitre_technique="T1505.001",
    )
    return ModuleResult(status="success", findings=ctx.findings, module_id="db.mssql_quick_check")
```

---

## Module Metadata Reference

### Required Attributes

| Attribute | Type | Example | Description |
|-----------|------|---------|-------------|
| `MODULE_ID` | `str` | `"ad.kerberoast"` | Unique dotted ID. Must contain exactly one dot. |
| `MODULE_NAME` | `str` | `"Kerberoasting"` | Human-readable name shown in CLI and UI. |
| `MODULE_CATEGORY` | `str` | `"ad"` | Category prefix (must match MODULE_ID prefix). |
| `MODULE_DESCRIPTION` | `str` | `"Request Kerberos TGS tickets..."` | One-liner for `ares module list` and catalog cards. |

### Optional Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `PARAMS_MODEL` | `type[ModuleParams]` | `None` | Pydantic v2 model for parameter validation and UI form generation |
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

## The ARES SDK Contract

### Parameter Validation

When `PARAMS_MODEL` is declared on your module, `BaseModule.validate(ctx)` automatically validates types, defaults, required parameters, and string constraints. You only need to override `validate()` if you have additional cross-field or dynamic business logic:

```python
async def validate(self, ctx: ExecutionContext) -> None:
    # 1. Base auto-validates against PARAMS_MODEL
    await super().validate(ctx)

    # 2. Add any custom operational guardrails:
    if ctx.opsec_profile == "stealth" and self.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE:
        from ares.core.errors import ModuleValidationError
        raise ModuleValidationError(
            f"Module {self.MODULE_ID} blocked in stealth profile",
            module_id=self.MODULE_ID,
        )
```

### `execute(ctx)` — The attack logic

```python
async def execute(self, ctx: ExecutionContext[MssqlEnumParams]) -> ModuleResult:
    result = ModuleResult(module_id=self.MODULE_ID, execution_id=ctx.execution_id)

    # Don't make real calls in dry_run / simulation mode
    if ctx.dry_run:
        result.status = "success"
        return result

    # Existing SDK hook; Phase 5C.2 defines the canonical gateway order.
    await self.before_request(ctx.params.target)

    try:
        # Attack/enumeration logic
        data = await self._do_attack(ctx.params.target, ctx.best_credential())

        # Create findings using fluent context helper
        for item in data:
            ctx.emit_finding(
                title=f"Vulnerability on {ctx.params.target}",
                description=item["summary"],
                severity=Severity.HIGH,
                mitre_technique="T1505.001",
                evidence=item,
            )

        # Store artifacts and discovered credentials
        ctx.store_artifact("raw_data", data)
        ctx.record_credential(username="sa", secret="P@ssw0rd123!", cred_type="db_password")

        result.status = "success"
        result.findings = ctx.findings
        result.artifacts = ctx.artifacts
        result.new_credentials = ctx.vault.export_new() if hasattr(ctx.vault, "export_new") else []

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

## ExecutionContext Reference

The `ExecutionContext` object represents the execution runtime environment for a module run:

```python
# Typed Parameters
ctx.params               # P (when ExecutionContext[P] is used) or dict
ctx.typed_params(Model)  # Parses and returns an instance of Model

# Fluent Helpers (v2 Standard)
ctx.emit_finding(title, severity, ...)      # Appends to ctx.findings and returns Finding
ctx.store_artifact(key, value)              # Stores to ctx.artifacts
ctx.record_credential(username, secret, ..) # Stores to vault and tracks new credential

# Context Metadata
ctx.target               # str: IP or hostname
ctx.domain               # str: AD domain (e.g. CORP.LOCAL)
ctx.port                 # int: target port if relevant
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
    ModuleValidationError,    # bad config / bad context / invalid parameter
    ConnectionRefused,        # TCP refused
    ConnectionTimeout,        # TCP timeout
    HostUnreachable,          # no route
    AuthenticationFailed,     # bad creds
    AccountLocked,            # lockout — CRITICAL
    InsufficientPrivilege,    # need higher priv
    ScopeError,               # out of scope
    SandboxError,             # module crashed
)
```

---

## Testing Your Module

### 1. Isolated Simulation with `ModuleTestHarness` (Recommended)

The v2 SDK includes `ModuleTestHarness`, enabling zero-mock unit testing with simulated scope guards, credential vaults, and fluent assertions:

```python
import pytest
from ares.sdk import ModuleTestHarness, Severity
from mymodule.mssql_enum import MssqlEnumModule, MssqlEnumParams

@pytest.mark.asyncio
async def test_mssql_enum_simulation():
    # Instantiate the harness
    harness = ModuleTestHarness(MssqlEnumModule)

    # Run the module hermetically
    result = await harness.simulate(
        target="10.0.0.10",
        params={"target": "10.0.0.10", "port": 1433},
        dry_run=True,
    )

    # Fluent assertions
    result.assert_success()
    result.assert_no_errors()
    assert result.duration_ms >= 0

@pytest.mark.asyncio
async def test_mssql_enum_finding_emission():
    harness = ModuleTestHarness(MssqlEnumModule)
    result = await harness.simulate(
        target="10.0.0.10",
        params={"target": "10.0.0.10", "port": 1433},
        dry_run=False,
    )
    result.assert_success()
    finding = result.assert_finding(severity=Severity.MEDIUM, mitre="T1505.001")
    assert "MSSQL instance" in finding.title
```

### 2. Legacy `ExecutionContext.for_test()` (v1 Standard)

Legacy test cases using direct `ExecutionContext.for_test()` continue to function seamlessly:

```python
@pytest.mark.asyncio
async def test_legacy_style():
    ctx = ExecutionContext.for_test(target="10.0.0.10", params={"port": 1433})
    module = MssqlEnumModule.__new__(MssqlEnumModule)
    await module.validate(ctx)
```

---

## Programmatic Automation (`AresClient`)

Automate engagements, module runs, and telemetry streams from Python scripts or CI/CD pipelines:

```python
from ares.sdk import AresClient

async def main():
    async with AresClient(base_url="http://127.0.0.1:8000", api_key="ares_key_...") as ares:
        # Create campaign with approved scope
        campaign = await ares.campaigns.create(
            name="Op-Nightshade",
            scope=["10.0.0.0/24"],
        )

        # Dispatch module asynchronously
        job = await ares.modules.run(
            module_id="db.mssql_enum",
            target="10.0.0.15",
            campaign_id=campaign["id"],
            params={"port": 1433},
        )
        print(f"Execution dispatched: {job['execution_id']}")

        # Retrieve campaign findings
        findings = await ares.campaigns.findings(campaign["id"])
        print(f"Captured {len(findings)} findings")
```

---

## Packaging & Publishing

### Module manifest (`manifest.json`)

```json
{
  "module_id":   "db.mssql_enum",
  "name":        "MSSQL Enumeration",
  "version":     "2.0.0",
  "author":      "Your Name",
  "description": "Enumerate MSSQL instances and weak authentication",
  "requires":    ["pymssql"],
  "ares_min":    "6.0.0",
  "signature":   "sha256:abc123..."
}
```

### Install

```bash
ares module install db/mssql_enum@2.0.0
# or from local path:
ares module install ./mymodule/
```

### Quality & Safety Guidelines

-  Must define all required metadata (`MODULE_ID`, `MODULE_NAME`, `MODULE_CATEGORY`, `MODULE_DESCRIPTION`).
-  Must declare `PARAMS_MODEL` for robust type validation and clean UI parameter rendering.
-  Must respect `ctx.dry_run` — zero unauthorized side-effects or network traffic when True.
-  Must call `await self.before_request(target)` before network interactions.
-  Must raise standard ARES exceptions rather than raw socket or OS exceptions.
-  Must include unit tests using `ModuleTestHarness`.
-  Must NOT access the filesystem outside the campaign workspace.
-  Must NOT store credentials in plaintext (use `ctx.vault` or `ctx.record_credential`).
