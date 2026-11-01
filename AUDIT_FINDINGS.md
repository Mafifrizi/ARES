# ARES — Comprehensive Audit Findings (v6.0.0)

**Date:** 2026-11-01
**Branch:** `claude/ares-comprehensive-audit-6fad2e`
**Auditor:** Claude (Opus) — engineering quality / security / UX review

## Method & coverage (honest scope statement)

This is **not** a line-by-line read of all ~130K LOC. It combines:
1. **Objective tooling** run locally and verified: `pytest`, `ruff`, `bandit`, frontend `tsc`/`eslint`/`vitest`/`vite build`.
2. **Targeted deep review** of the highest-risk paths: API auth (`ares/api/server.py`), scope firewall (`ares/core/scope_firewall.py`), crypto/config (`ares/core/config.py`, `ares/credential/vault.py`), and the DB query layer (`ares/db/*`).
3. **UI review** of the dashboard login (rendered in a real browser).

Every finding below is **reproducible** via the command or file:line reference given. Areas reviewed and found **sound** are listed in §E so coverage is explicit.

Severity: 🔴 High (crash/security/false-claim) · 🟠 Medium · 🟡 Low/hygiene · ✅ reviewed-sound

---

## Patch log

- **2026-11-01 — C1 complete (ruff GREEN) + B2 complete (ruff & bandit gated in CI).** `ruff check ares tests` → **All checks passed**; `bandit -c pyproject.toml -r ares` → **0 issues**. Added a `lint` job to CI running both. The cleanup surfaced 2 more real bugs (F811 duplicate definitions), both reviewed as intentional-but-messy (not active breakage) and noqa'd:
  - `core/errors.py`: a distinct `class ScopeViolationError(ScopeError)` (line 369) is overwritten by a backward-compat alias `ScopeViolationError = ScopeError` (line 551); a 3rd definition exists in `core/noise.py`. The alias deliberately collapses the name to the base class so every raise/except/isinstance path across modules stays compatible — verified by the passing suite. Restructuring is high-risk → documented + noqa'd as debt.
  - `normalize/artifacts.py`: `ArtifactNormalizer = ArtifactStore` alias (445) shadowed by the real `class ArtifactNormalizer` (450) — dead alias, runtime unaffected. noqa'd.
  - **Tail handling:** F841 (54) & B904 (45) marked `# noqa` at each existing site (kept ENFORCED for new code, NOT globally ignored); F841 deliberately NOT auto-removed (ruff's unsafe fix deletes side-effecting calls like `await db.upsert_host()`). Safe refactors applied (C4 comprehensions, I001, whitespace). Stylistic/test rules (B007/B027/B024/B905, A00x, N80x, PT*/E721/B017) relaxed in config with documented reasons.
  - **Bandit** adopted with a documented `[tool.bandit]` skip-list for intrinsic-offensive categories (subprocess, ssh-no-hostkey, weak crypto incl. VNC DES-ECB recovery, parameterized-SQL B608, try-except-pass, password-heuristic FPs) — see §D; fails CI only on NEW non-intrinsic findings.
- **2026-11-01 — Full unit suite after cleanup: 4,465 passed / 22 failed / 1 skipped.** 20 failures are known Windows-env artifacts (19× `[WinError 10013]` loopback-socket-bind in `validation_lab`/`browser_cookie_security`; 1× impacket `[Errno 22]` path). **2 were real regressions from the ruff auto-fix — both fixed & re-verified (33 tests green):**
  - **F401 stripped 3 optional-dep import *probes*** (bare `import X` used only to detect a dependency). The doctor's `pypykatz` and `httpx-ntlm` checks and `updater.py`'s core-platform health check each had their `import` deleted, so the `try` could never fail → they silently reported missing deps as "ready"/"PASS". Restored all three with `# noqa: F401` (+ `# type: ignore[import]`). Audited every net-removed import: `requests`/`urllib`/`dns.*` were still present & used (reorder only), so these 3 were the complete set. **Lesson:** F401 is unsafe against import-for-detection; probes must carry `# noqa: F401`.
  - **B023 bind-default on `engine.py` broke a source-pinned meta-test** (`test_hardening` greps for the literal `proc.wait(timeout=`). Reverted that one lambda to the original form + `# noqa: B023` (it is awaited in-iteration, so `proc` is stable anyway). The other B023 bind-default hardenings (pivot/snmp/attack_graph) kept — no test pins them.
- **2026-11-01 — C1 pragmatic ruff cleanup + 6 real bugs surfaced (A6, B005, B006, B023×7, B026, B033).** Safe auto-fixes (import sort `I001`, unused imports `F401`, f-strings `F541`, `datetime.UTC`, comprehensions `C4`, whitespace) brought ruff from **5,881 → ~300** findings (ares+tests). The cleanup surfaced genuine logic bugs, each fixed and cross-checked (compile + import smoke + full unit run):
  - **A6 (MEDIUM):** `ares/technique` package public API was 100% broken — `__init__.py` re-exported phantom names `TechniqueRecord`/`MITRETactic`, the combined import failed entirely, and `except ImportError: pass` hid it. Fixed to re-export the real surface (`Technique`, `TechniqueLibrary`, `TechniqueMapper`, `CoverageReport`); smoke-verified.
  - **B005** (`modules/ai/autonomous_planner.py:859-860`): `.lstrip("```json").rstrip("```")` misused `str.strip` (char-set, not substring) to strip a markdown fence — fragile/wrong. Replaced with a correct `_strip_md_fence()` helper mirroring the module's own canonical logic.
  - **B026** (`core/scope_firewall.py:456`): `*args` unpacked *after* `host=`/`port=` kwargs in the connection-interception hook → `TypeError: multiple values` if a caller passed host/port positionally. Fixed to positional `host, port` before `*args`.
  - **B006** (`api/server.py:4398`): mutable default `body={}` in `plan_from_template_endpoint` (read-only today, cross-request-leak footgun). Fixed to `None` + `body = body or {}`.
  - **B023×7** (`core/engine.py`, `graph/attack_graph.py`, `modules/network/{pivot,snmp_enum}.py`): closures over loop vars (`proc`, `community`, `item`/`target_node`), all consumed in-iteration (functionally correct) — hardened with bind-default params to kill the late-binding hazard.
  - **B033** (`strategy/enforcer.py:34`): `"windows.lsass_dump"` duplicated in the `ALWAYS_REQUIRE_AUTH` frozenset. Removed the redundant entry (no behavior change).
  - **Config** (`pyproject.toml`): migrated to `[tool.ruff.lint]`; relaxed only verified cosmetic/intentional rules (`E501, E402, E701/2, E741, UP037, UP042, N806/803/815/818`); added FastAPI + Typer + this project's RBAC DI factories to `flake8-bugbear.extend-immutable-calls` (proper B008 fix, not a blanket ignore); `S` (flake8-bandit) intentionally **not** selected — every current `S` finding was reviewed as intrinsic-offensive or a verified false positive (status strings, OAuth URL templates, parameterized SQL with whitelisted identifiers), and security scanning is owned by bandit (B2) with a justified baseline. Remaining ~300 findings are quality/cosmetic (`F841` unused vars, `B904` raise-without-from, `F401`, `F821` forward-ref FPs, pytest `PT*`) — the focused tail for gating ruff in CI (B2).
- **2026-11-01 — A4 found & fixed (HIGH, surfaced by `ruff F821`): SSO config-save endpoint was 500-broken.** `ares/api/server.py` `save_sso_configuration` (`POST /auth/sso/config/{org_slug}`) called `json.dumps(...)` at line 1868, but the module only imports `json as _json` (locally, in other functions) — bare `json` was undefined, so the endpoint raised `NameError` on every call. Fixed: added `import json as _json` in the handler and used `_json.dumps`. **Coverage gap:** existing SSO tests call the DB method `save_sso_config` directly; nothing exercises the HTTP route — recommend an endpoint regression test (follow-up F-items).
- **2026-11-01 — A5 found & fixed (MEDIUM latent, `ruff F821`): CLI logging fallback would `NameError`.** `ares/cli/typer_main.py:89` used `logging.basicConfig(...)` in an `except` fallback, but the file never imported `logging` — if `setup_logger` ever failed, the fallback itself raised `NameError`, masking the real error. Fixed: added `import logging`. (The other 27 `F821` were verified as forward-ref annotation false positives — `-> "AresDatabase"`, `-> "FeasibilityReport"`, `"asyncio.Lock"`, etc. — not bugs.)
- **2026-11-01 — A1 + A2 fixed (hooks hoisted) + C2 done (all 45 ESLint errors → 0) + B1 done.** Hoisted `useMemo` above early returns in `TacticalInspectorDrawer.tsx` and `StructuredJsonViewer.tsx`; removed dead code across 7 files (`GraphPage`, `CobaltSessionDock`, `CobaltStrikeNodes`, `LoginPage`, `SecurityMeshCanvas`, `NotificationPersistence.test`). Verified: ESLint **0 errors**, `tsc` clean, **206** vitest tests pass, `vite build` ok, graph inspector works live. CI frontend job now runs `lint` + `test` before `build` (B1).
- **2026-11-01 — A3 + B3 fixed (Python floor raised to 3.11).** Files changed: `pyproject.toml` (`requires-python >=3.11`, `ruff target py311`, `mypy python_version 3.11`), `ares/cli/typer_main.py` (`PYTHON_MIN_VERSION=(3,11)` + 3 doctor messages), `tests/unit/test_cli_doctor.py` (2 assertions), `docs/dashboard-guide.md`, `docs/research/linux-active-directory-tradecraft.md`, `CONTRIBUTING.md`, `README.md` (badge), `.github/workflows/ci.yml` (backend now a `["3.11","3.12"]` matrix). Verified: `test_cli_doctor.py` → 29 passed on 3.12; **API boots live on Python 3.11.9** (`/health` → `{"status":"ok","db":"connected"}`, log `ARES API v6.0.0 started`) at the exact spot 3.10 crashed. 3.10 now refused by `requires-python`.

## A. Confirmed runtime bugs

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| A1 | 🟡 | **React rules-of-hooks violation (latent, does NOT crash at runtime)** in `TacticalInspectorDrawer`: `useMemo` (line 51) is after `if (!selection) return null` (line 29). **Correction after live test:** the parent mounts it conditionally — `{selection && <TacticalInspectorDrawer/>}` at `GraphPage.tsx:662` — so the drawer only ever mounts with `selection` already non-null, making the early return dead code and the hook count stable (3). **Verified live:** opening the inspector on a host node works, no React error. Still a real ESLint error + fragile (breaks if ever mounted unconditionally); worth fixing by moving the hook above the return. My earlier "🔴 crashes" rating was wrong. | `frontend/src/features/graph/TacticalInspectorDrawer.tsx:29,51`; `GraphPage.tsx:662`; verified in browser | ✅ FIXED |
| A2 | 🟡 | **React rules-of-hooks violation (latent)** in `StructuredJsonViewer`: `useMemo` (447) after a conditional leaf-node `return` (~434). Would only crash if a single node instance's value flips leaf↔container across renders while mounted at the same position. **Observed live:** rendered the 16-key host-attributes object in the inspector — no crash. Real ESLint error + fragile; fix by hoisting the hook. | `frontend/src/components/common/StructuredJsonViewer.tsx:434,447`; rendered in browser | ✅ FIXED |
| **A6** | 🟠 | **`ares.technique` package public API 100% non-functional** (latent). `__init__.py` advertised `TechniqueRecord` & `MITRETactic` in its import + `__all__`, but neither name exists anywhere in the repo, so the combined `from ares.technique.library import (...)` raised `ImportError` — swallowed by `except ImportError: pass` — and even the valid `TechniqueLibrary` failed to re-export. Hidden because every internal consumer imports from the submodule `ares.technique.library` directly. Surfaced by the import cleanup + a re-export smoke test. **✅ FIXED** — now re-exports the real surface; `import ares.technique` + `hasattr` on all `__all__` passes. | `ares/technique/__init__.py`; `py -c "import ares.technique"` smoke | ✅ FIXED |
| **A3** | 🔴 | **The backend does not start on Python 3.10** (a *declared-supported* version). `ares/db/database.py:455,463,476` call `asyncio.Task.cancelling()`, which is **Python 3.11+**. On 3.10 the DB layer raises `AttributeError` during `connect()` → uvicorn logs `Application startup failed. Exiting.` This is **production code**, not a test. Found by actually running `uvicorn ares.api.server:app` on 3.10. **✅ FIXED** — raised the floor to 3.11 (3.10 is EOL as of Oct 2026; the cancellation logic is deliberately 3.11+ and a 3.10 fallback would silently degrade correctness). | reproduce: run the API under Python 3.10 → `AttributeError: '_asyncio.Task' object has no attribute 'cancelling'` | ✅ FIXED |

## B. Supported-version & CI gating gaps (process bugs that let real bugs ship)

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| B1 | 🔴 | **Frontend CI never runs `lint` or `test`** — only `npm run build`. `tsc --noEmit` does not catch rules-of-hooks or dead code, so A1/A2 and 45 eslint errors pass CI. The vitest suite (which *does* pass) is also not gated. | `.github/workflows/ci.yml` (frontend job) vs `frontend/package.json` scripts | TODO |
| B2 | 🟠 | **Backend CI never ran `ruff`/`bandit`** (now FIXED — a `lint` job gates both; `mypy` still not gated → C3) despite all three being configured in `pyproject.toml` and installed via `[dev]`. 4,160 ruff errors + mypy-strict + bandit findings never gate. Only `pytest tests/unit` runs (integration/simulation suites, except postgres, are not run). | `.github/workflows/ci.yml` | TODO |
| B3 | 🟠 | **Declared Python support is broader than tested.** `pyproject.toml` declares `requires-python = ">=3.10,<3.13"` but CI only tests **3.12**. On 3.10, `tests/unit/test_cli_doctor.py` fails to import (`import tomllib`, stdlib 3.11+). Either raise the floor to 3.11 or add a 3.10/3.11 CI matrix + `tomli` fallback. (Prod `ares/` code does **not** import `tomllib` — test-only, but the support claim is still false.) | `pyproject.toml`; `tests/unit/test_cli_doctor.py:6`; local 3.10 run errors at collection | ✅ FIXED (same change as A3; CI now runs a 3.11+3.12 matrix) |

## C. Lint / type / hygiene debt

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| C1 | 🟡 | **Ruff: was 5,881 errors** (ares+tests). **✅ largely fixed** — safe auto-fixes + verified-cosmetic rule relaxation brought it to ~300, and surfaced 6 real bugs (A6, B005/B006/B023/B026/B033). Remaining ~300 are quality/cosmetic (`F841`, `B904`, `F401`, `F821` forward-ref FPs, pytest `PT*`); gating in CI tracked under B2. | `python -m ruff check ares tests` | 🟡 MOSTLY FIXED (tail → B2) |
| C2 | 🟡 | **ESLint: 45 errors / 50 warnings.** Beyond A1/A2: dead code (unused imports/vars across `CobaltStrikeNodes.tsx`, `GraphPage.tsx`, `dashboardComponents.tsx`, etc.), `prefer-const`, `no-empty` (`GraphPage.tsx:649`), `no-unused-expressions` (`SecurityMeshCanvas.tsx:134` — functional ternary, cosmetic). Warnings: `react-hooks/exhaustive-deps`, `react-refresh/only-export-components`. | `cd frontend && npx eslint .` | TODO |
| C3 | 🟡 | **mypy strict** configured but not run in CI; error count to be measured. | `pyproject.toml [tool.mypy] strict=true` | TODO |

## D. Security scan — honest assessment (mostly intrinsic to an offensive tool)

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| D1 | 🟡 | **Bandit: 11 High / 194 Medium / 332 Low**, but the 11 High are **intrinsic to red-team function, not vulns in ARES's own trust boundary**: Paramiko `AutoAddPolicy` ×7 (SSH spray/lateral movement to arbitrary hosts), `verify=False` ×2 (recon scanners), MD4 (NTLM), SHA1 (git-blob hashing in `updater.py`). Recommend documenting/annotating with `# nosec` + justification rather than "fixing." No exploitable self-vuln found. | `python -m bandit -r ares` | REVIEW |
| D2 | 🟡 | `verify=False` TLS in `cloud/identity_federation.py:542` & `network/http_fingerprint.py:253` — expected for recon, but should be an explicit, documented option. | file:line | REVIEW |

## E. Reviewed and SOUND (no action — documents coverage)

- **Auth** (`ares/api/server.py`): per-IP **and** per-username login rate-limit; bcrypt DoS guard (128-char cap); refresh-token rotation with family revocation; SSO users blocked from password login; strong password policy (12+ chars, complexity, 72-byte bcrypt cap); CSRF bootstrap endpoint; `Cache-Control: no-store` on auth responses. **Sound.**
- **SQL layer** (`ares/db/database.py`, `execution_lifecycle.py`): values are `?`-parameterized; dynamic identifiers are whitelisted (e.g. `_scalar_campaign_value` rejects columns outside `{scope_json, targets_json}`) or internal constants. **No SQL injection found.**
- **Secrets/config** (`ares/core/config.py`): `ares_secret_key` / `ares_encryption_key` are required, `min_length=32`, **no defaults** (fail-closed); error messages redact these fields. **Sound.**
- **Scope firewall** (`ares/core/scope_firewall.py`): default-deny (`return False` on unmatched paths); DNS resolve-and-pin to prevent rebinding TOCTOU; socket-level `assert_allowed_address` raises on deny; hooks on `socket.connect/connect_ex/sendto/sendmsg` + `asyncio.create_connection`. **Fail-closed by design.**
- **CORS**: `allow_credentials=False` with canonicalized non-credentialed origins. **Sound.**
- **Credential vault crypto** (`ares/credential/vault.py`): AES-256-GCM with a **fresh `os.urandom(12)` nonce per record** (no nonce reuse — the classic GCM footgun is avoided), PBKDF2-HMAC-SHA256 600k iterations, per-record random 16-byte salt embedded with the ciphertext, legacy Fernet paths are decrypt-only. **Cryptographically sound.**

## F. UI / UX (dashboard)

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| F1 | 🟡 | **Login page is well-designed** (dark theme, crimson accent, dragon mascot, SSO option, password reveal toggle). Minor **responsive** issue: around ~800px viewport width the right mascot panel collapses to an empty black half (looks broken at mid widths). | rendered at 1440px (good) vs 800px (empty right half) | TODO |
| F2 | ✅ | **Authenticated dashboard reviewed live (backend on 3.12 + seeded admin).** Exercised end-to-end and all work: login → Overview empty state → **create campaign** (structured scope/target badges) → **Graph** (Cobalt-Strike-style attack map, node inspector opens cleanly — this is where A1 was *disproved*) → **Modules** (66, MITRE IDs, noise badges, filters) → **Security** (Account/API Keys/Audit/Users, RBAC-gated) → **Reports** (generated an HTML artifact, 200 OK, appears in Library with Download/Delete). Production-quality UI. | browser walkthrough, `127.0.0.1:5173` | ✅ |
| F3 | 🟡 | **Horizontal page scroll at narrow widths** (~800px): data tables (e.g. Reports Library) and some panels overflow the viewport, clipping the `ACTIONS` column and forcing a horizontal scrollbar. Dashboard appears designed for ≥1024px; add responsive handling / `overflow-x` containment for smaller windows. | Reports Library at ~800px | TODO |
| F4 | ℹ️ | Benign (not bugs, verified): a `POST /auth/refresh → 401` on first load (expected: no session yet, app falls back to login) and `GET /auth/csrf` `ERR_ABORTED ×3` (dev-mode React StrictMode double-fetch). Neither occurs as an error to the user. | console + network trace | NOTE |

## G. Test suite status

| ID | Sev | Finding | Evidence | Status |
|----|-----|---------|----------|--------|
| G1 | — | Frontend: `tsc` ✅, `vitest` ✅ (all suites pass), `vite build` ✅. | `npm run typecheck/test/build` | ✅ |
| G2 | — | Backend `tests/unit`: **4,459 tests collected, exactly 1 collection error** — `test_cli_doctor.py` (`tomllib`, 3.10). Sampled files run in isolation **pass** (e.g. `test_adaptive_opsec.py` → 37 passed). CI runs this green on 3.12. | `pytest tests/unit --collect-only` (with CI env) | ✅ (1 err = B3) |
| G3 | — | **Correction / transparency:** an earlier whole-suite run showed scattered `E`/`F`, but those were **artifacts of running two pytest processes concurrently** (SQLite/temp-file contention), **not code defects** — confirmed by clean isolation re-runs. Not reported as findings. | — | NOTE |
| G4 | — | **Authoritative `tests/unit` run on 3.12: 4,467 passed, 20 failed, 1 skipped.** All 20 failures classified as **Windows-only environment artifacts, NOT code bugs** (verified by isolation re-run): 19 in `test_browser_cookie_security.py` fail with `[WinError 10013] socket access forbidden` → "Validation-lab loopback listener was unavailable" (the tests bind a real loopback listener; Windows denies the bind on this host — passes on CI Ubuntu); 1 (`test_secrets_scan_uses_smb_protocol`) fails with `[Errno 22] Invalid argument` on a Windows path to `impacket`. Not reported as product defects. | `pytest tests/unit` on 3.12 (21 min); isolation re-run reproduces the same WinError | NOTE |
| G5 | 🟡 | Minor doc-accuracy note (optional): `docs/dashboard-guide.md` says the unit suite is "designed to run on Windows", but ~20 loopback/impacket-path tests can't run on a stock Windows host without socket-bind permissions. Worth a caveat in that doc. | §G4 evidence | TODO |

---

### Proposed remediation order (each patched individually, cross-checked for regressions)
1. **A1, A2** — fix the two hook violations (move hooks above early returns). Low-risk, high-value.
2. **B1, B2** — add `lint`+`test` to frontend CI and `ruff`+`bandit` to backend CI (gate future regressions).
3. **B3** — decide Python floor (recommend raising to 3.11, or add `tomli` fallback + matrix).
4. **C1, C2** — `ruff --fix` + eslint autofix for the safe, mechanical dead-code removals (reviewed, not blind).
5. **D1, D2** — annotate intentional `# nosec` with justifications.
6. **F1** — login responsive fix; then **F2** authenticated dashboard review.
