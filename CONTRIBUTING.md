# Contributing to ARES

Thank you for contributing to ARES. This guide covers everything you need
to get started — from dev environment setup to submitting a pull request.

---

## Table of Contents

1. [Development Environment](#development-environment)
2. [Branching Strategy](#branching-strategy)
3. [Commit Conventions](#commit-conventions)
4. [Writing a New Module](#writing-a-new-module)
5. [Testing Requirements](#testing-requirements)
6. [Pull Request Process](#pull-request-process)
7. [Code Standards](#code-standards)

---

## Development Environment

```bash
# 1. Fork and clone
git clone https://github.com/<your-fork>/ares && cd ares

# 2. Create virtual environment
python -m venv venv && source venv/bin/activate

# 3. Install in dev mode with all extras
pip install -e ".[full,dev]"

# 4. Install pre-commit hooks
pip install pre-commit && pre-commit install

# 5. Copy and configure .env
cp .env.example .env
# Edit .env — set ARES_SECRET_KEY and ARES_ENCRYPTION_KEY
# Generate: openssl rand -hex 32

# 6. Verify setup
ares doctor
pytest tests/unit/ -v
```

---

## Branching Strategy

ARES uses Git Flow:

| Branch | Purpose |
|--------|---------|
| `main` | Production — protected, requires PR + review |
| `develop` | Integration branch — PRs target here |
| `feature/<name>` | New features and modules |
| `fix/<name>` | Bug fixes |
| `hotfix/<name>` | Critical fixes that go directly to main |
| `security/<name>` | Security fixes — keep private until patched |

```bash
# Start a new module
git checkout develop
git pull origin develop
git checkout -b feature/ad-my-new-module

# When done
git push origin feature/ad-my-new-module
# Open PR targeting develop
```

---

## Commit Conventions

ARES uses [Conventional Commits](https://www.conventionalcommits.org/).
Pre-commit will enforce this on `git commit`.

```
<type>: <short description>

[optional body]
[optional footer: BREAKING CHANGE / Closes #issue]
```

| Type | Use for |
|------|---------|
| `feat:` | New module, new feature |
| `fix:` | Bug fix |
| `security:` | Security fix or hardening |
| `docs:` | Documentation only |
| `test:` | Tests only |
| `refactor:` | Code change, no behavior change |
| `ci:` | CI/CD pipeline changes |
| `chore:` | Dependency updates, tooling |

Examples:
```bash
git commit -m "feat: add ad.delegation_abuse with RBCD support"
git commit -m "fix: laps_enum vault.store() not called after LDAP query"
git commit -m "security: narrow DataEncryptor exception catch-all"
```

---

## Writing a New Module

Every ARES module is a class that extends `BaseModule` in `ares/modules/base.py`.

### Minimal module skeleton

```python
"""
My Module — category.module_name
MITRE: T1234 — Technique Name

One paragraph: what this module does, what it needs, what it produces.
"""
from __future__ import annotations
from typing import Any
from ares.core.campaign import Severity
from ares.core.logger import audit, get_logger
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.category.module_name")


class MyModule(BaseModule):
    MODULE_ID          = "category.module_name"
    MODULE_NAME        = "Human Readable Name"
    MODULE_CATEGORY    = "category"   # ad|credential|lateral|windows|linux|cloud|network|recon|exfil|persistence
    MODULE_DESCRIPTION = "One line description for ares module list"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []           # e.g. ["domain_creds"]
    OUTPUTS            = []           # e.g. ["spn_list"]
    MITRE_TECHNIQUES   = ["T1234"]
    MODULE_TIMEOUT_SECONDS: int | None = None   # override if slow (e.g. 300 for dump)

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight checks — runs before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        # Add module-specific checks here
        if not ctx.params.get("required_param"):
            raise ModuleValidationError(
                "category.module_name requires 'required_param'.",
                module_id=self.MODULE_ID, field="required_param",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={})
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        findings, raw = await self.run(target=target, **ctx.params)
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
        )

    @trace_module("category.module_name")
    async def run(self, target: str, **kwargs: Any):
        import asyncio
        await self.before_request(target, "default")
        logger.info("my_module_start", target=target)
        audit("my_module", actor="operator", technique="T1234",
              source="operator", target=target)

        loop = asyncio.get_running_loop()

        # All blocking I/O must go in a sync function run via executor
        result = await loop.run_in_executor(None, lambda: self._do_work_sync(target))

        if result:
            self.finding(
                title=f"Finding title on {target}",
                description="What was found and why it matters.",
                severity=Severity.HIGH,
                mitre_technique="T1234",
                mitre_tactic="Tactic Name",
                evidence={"key": "value"},
                remediation="How to fix this.",
                host=target, confidence=0.9,
            )

        await self.noise.jitter.sleep()
        return self._findings[:], {"target": target, "result": result}

    def _do_work_sync(self, target: str) -> bool:
        """Blocking work. Called via run_in_executor — no await here."""
        return True
```

### Required patterns

| Pattern | Rule |
|---------|------|
| Blocking I/O | Always `loop.run_in_executor(None, self._sync_fn)` |
| Connection cleanup | `conn = None` → `try:` → `finally: if conn: conn.close()` |
| Pagination | `while cookie:` loop with `1.2.840.113556.1.4.319` OID for LDAP |
| STEALTH block | HIGH_NOISE modules must raise `ModuleValidationError` in STEALTH |
| dry_run | Always check `ctx.dry_run` first in `execute()` |
| `validate()` | All modules override; cloud/reporting skip super target check |
| Error classification | Classify errors: `AuthenticationFailed` / `HostUnreachable` / `NetworkError` |

### File location

```
ares/modules/<category>/<module_name>.py
```

Add your module to the `__init__.py` or ensure `PluginLoader` picks it up
(it auto-discovers via `inspect.getmembers` for all `BaseModule` subclasses).

---

## Testing Requirements

Every new module needs at minimum:

```python
class TestMyModule:
    def test_validate_requires_param(self):
        """validate() must raise ModuleValidationError if required param missing."""

    def test_dry_run(self):
        """execute() with dry_run=True must return ModuleResult(status='dry_run')."""

    def test_module_id_and_opsec(self):
        """MODULE_ID and OPSEC_LEVEL must match declaration."""

    def test_error_classification(self):
        """Auth failures must raise AuthenticationFailed, not generic Exception."""
```

Run tests:
```bash
pytest tests/unit/ -v                    # all unit tests
pytest tests/unit/ -k "MyModule" -v     # just your module
pytest tests/unit/ --cov=ares --cov-fail-under=82 -v  # with coverage
```

---

## Pull Request Process

1. All pre-commit hooks pass (`pre-commit run --all-files`)
2. Tests pass with `pytest tests/unit/ --cov=ares --cov-fail-under=82`
3. PR description includes: what changed, why, MITRE reference (for modules)
4. Update `CHANGELOG.md` — add entry under `[Unreleased]` section
5. At least one maintainer review required before merge to `develop`
6. Squash merge to `develop` — no merge commits

---

## Code Standards

- **Python 3.10+** — use `match`, `|` union types, `TypeAlias` where appropriate
- **Pydantic v2** for all settings and data models
- **structlog** for all logging — never `print()` or stdlib `logging` directly
- **asyncio** throughout — no blocking calls on the event loop
- **type annotations** on all public functions — mypy strict enabled
- **ruff** for linting (replaces flake8, isort, pyupgrade)
- **No hardcoded secrets** — everything via `.env` or env vars

Questions? Open an issue or ping `@ares-framework/maintainers` on GitHub.
