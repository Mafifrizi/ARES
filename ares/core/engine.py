"""
ARES Async Engine
Full async orchestration with parallel module execution.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

from ares.core.logger import get_logger

from pydantic import BaseModel
from ares.core.campaign import Campaign, Finding
from ares.core.config import AresSettings, get_settings
from ares.core.context import ExecutionContext
from ares.core.errors import AresError
from ares.core.logger import audit, setup_logger
from ares.core.noise import NoiseController
from ares.core.notifier import build_notifier_from_settings
from ares.core.plugin.loader import ModuleRegistry, PluginLoader
from ares.core.validator import FindingValidator, ValidationResult, build_default_validator
logger = get_logger("ares.engine")



class ModuleStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE    = "done"
    FAILED  = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class EngineModuleResult(BaseModel):
    module_id:          str
    status:             ModuleStatus = ModuleStatus.DONE
    findings:           list[Finding] = []
    validation_results: list[ValidationResult] = []
    raw_output:         dict[str, Any] = {}
    error:              str | None = None
    duration_ms:        float = 0.0

    @property
    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.validated and not f.false_positive]


@dataclass
class ExecutionPlan:
    """
    Stages run sequentially.
    Modules WITHIN each stage run in PARALLEL.

    Example:
        plan = (ExecutionPlan()
            .add_stage("recon",  ["ad.enum_users", "ad.enum_spn", "ad.enum_computers"])
            .add_stage("attack", ["ad.kerberoast", "ad.asreproast"])
            .add_stage("cloud",  ["cloud.aws", "cloud.azure", "cloud.gcp"])
        )
    """
    stages: list[dict[str, Any]] = field(default_factory=list)

    def add_stage(
        self,
        name:       str,
        module_ids: list[str],
        params:     dict[str, dict[str, Any]] | None = None,
    ) -> "ExecutionPlan":
        self.stages.append({"name": name, "modules": module_ids, "params": params or {}})
        return self

    def all_module_ids(self) -> list[str]:
        return [mid for s in self.stages for mid in s["modules"]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionPlan":
        plan = cls()
        for s in data.get("stages", []):
            plan.add_stage(s["name"], s["modules"], s.get("params", {}))
        return plan


@dataclass
class ProgressEvent:
    stage:         str
    module_id:     str
    status:        ModuleStatus
    finding_count: int = 0
    error:         str | None = None
    duration_ms:   float = 0.0


ProgressCallback = Callable[[ProgressEvent], Coroutine[Any, Any, None]]



def _estimate_stage_duration(module_count: int) -> str:
    """Rough wall-clock estimate for a stage in dry-run preview.

    Modules run in parallel so the floor is ~30s (avg slowest module).
    Each additional module adds ~5s to account for scheduling overhead
    and the increasing likelihood of a slower outlier.
    """
    if module_count == 0:
        return "0s"
    secs = max(30, 30 + 5 * (module_count - 1))
    return f"~{secs // 60}m {secs % 60}s" if secs >= 60 else f"~{secs}s"



def _fire_and_log(coro, label: str = "background_task") -> None:
    """Schedule a fire-and-forget coroutine that logs exceptions instead of silently dropping them."""
    import asyncio as _aio
    async def _wrapper() -> None:
        try:
            await coro
        except Exception as _exc:
            logger.warning("background_task_error", task=label, error=str(_exc)[:120])
    _aio.create_task(_wrapper())

class AresEngine:
    """
    ARES Async Engine.

    Single module:  await engine.run_module(module_id, campaign, params)
    Full plan:      await engine.run_plan(plan, campaign)
                    → modules in same stage run CONCURRENTLY
    """

    def __init__(
        self,
        settings:     AresSettings | None = None,
        validator:    FindingValidator | None = None,
        db:           Any | None = None,
        max_parallel: int = 5,
    ) -> None:
        self.settings     = settings  or get_settings()
        self.validator    = validator or build_default_validator()
        self.db           = db
        self.max_parallel = max_parallel
        self._registry:   ModuleRegistry | None = None
        self._semaphore:  asyncio.Semaphore | None = None
        self.notifier     = build_notifier_from_settings(self.settings)
        setup_logger(self.settings.ares_log_level, self.settings.ares_log_file)

    # ── Loading ────────────────────────────────────────────────────────────

    def load_modules(self, external_dir: str | None = None) -> int:
        loader = PluginLoader()
        self._registry = loader.load_all(external_dir=external_dir)
        if loader.errors:
            logger.warning("engine_modules_failed_to_load")
        logger.info("engine_loaded_modules")
        return len(self._registry)

    @property
    def registry(self) -> ModuleRegistry:
        if self._registry is None:
            self.load_modules()
        if self._registry is None:
            raise RuntimeError(
                "ModuleRegistry not initialised — call load_modules() before accessing registry"
            )
        return self._registry

    def list_modules(self) -> list[dict[str, Any]]:
        return self.registry.list_metadata()

    # ── Single module ──────────────────────────────────────────────────────

    async def run_module(
        self,
        module_id:       str,
        campaign:        Campaign,
        params:          dict[str, Any],
        skip_validation: bool = False,
        timeout_seconds: int  = 120,
        actor_role:      str  = "operator",
    ) -> EngineModuleResult:

        if module_id not in self.registry:
            return EngineModuleResult(
                module_id=module_id,
                status=ModuleStatus.FAILED,
                error=f"Module '{module_id}' not found. Run: ares module list",
            )

        # ── RBAC check — role must be allowed to run this module ──────────
        from ares.collab.manager import can_role_run_module
        if not can_role_run_module(actor_role, module_id, self.registry):
            audit("module_rbac_denied", actor=campaign.operator,
                  detail=f"role={actor_role} module={module_id}")
            return EngineModuleResult(
                module_id=module_id,
                status=ModuleStatus.FAILED,
                error=(f"Role '{actor_role}' is not permitted to run "
                       f"'{module_id}'. Check ROLE_PERMISSIONS in collab/manager.py."),
            )

        # ── Scope pre-check — enforce before any module code runs ────────
        # Cloud/reporting modules use API credentials, not host IPs — skip scope check
        _NO_SCOPE_CATEGORIES = {"cloud", "reporting", "recon"}
        _target = params.get("target", "") or params.get("dc", "") or params.get("host", "")
        _module_category = (self.registry.get(module_id) or type("", (), {"MODULE_CATEGORY": ""})).MODULE_CATEGORY
        if _target and _module_category not in _NO_SCOPE_CATEGORIES:
            if not campaign.is_in_scope(_target):
                from ares.core.errors import ScopeError
                audit("module_scope_violation", actor=campaign.operator,
                      detail=f"module={module_id} target={_target!r} not in scope")
                return EngineModuleResult(
                    module_id=module_id,
                    status=ModuleStatus.FAILED,
                    error=f"Target {_target!r} is not in campaign scope {[s.cidr for s in campaign.scope]}. "
                          "Add the target CIDR to scope or use a different target.",
                )

        cls      = self.registry.get(module_id)
        noise    = NoiseController(campaign)
        instance = cls(settings=self.settings, campaign=campaign, noise=noise)  # type: ignore[misc]

        audit("module_run_start", actor=campaign.operator,
              detail=f"module={module_id} campaign={campaign.id[:8]}")
        t0 = time.monotonic()

        try:
            # Build ExecutionContext — new v0.9.0+ interface
            ctx = ExecutionContext.build(
                campaign   = campaign,
                target     = params.get("dc") or params.get("host") or params.get("target", ""),
                module_id  = module_id,
                domain     = params.get("domain", ""),
                params     = params,
                operator   = campaign.operator,
                settings   = self.settings,
                noise      = noise,
            )


            # ── validate() before execute() ───────────────────────────
            # Always call validate() first — lets modules fail fast with
            # informative errors before any network activity happens.
            # skip_validation=True is an escape hatch for tests / retries.
            if not skip_validation:
                try:
                    await asyncio.wait_for(
                        instance.validate(ctx),
                        timeout=10,
                    )
                except asyncio.TimeoutError:
                    duration_ms = round((time.monotonic() - t0) * 1000, 2)
                    audit("module_validation_failed", actor=campaign.operator,
                          detail=f"module={module_id} reason=timeout")
                    return EngineModuleResult(
                        module_id   = module_id,
                        status      = ModuleStatus.FAILED,
                        error       = f"Module '{module_id}' validate() timed out (>10s)",
                        duration_ms = duration_ms,
                    )
                except Exception as val_exc:
                    duration_ms = round((time.monotonic() - t0) * 1000, 2)
                    err_msg = str(val_exc)
                    logger.warning("engine_module_validation_failed",
                                   module_id=module_id, error=err_msg[:200])
                    audit("module_validation_failed", actor=campaign.operator,
                          detail=f"module={module_id} error={err_msg[:100]}")
                    return EngineModuleResult(
                        module_id   = module_id,
                        status      = ModuleStatus.FAILED,
                        error       = f"Validation failed: {err_msg[:300]}",
                        duration_ms = duration_ms,
                    )
            # ── end validate ───────────────────────────────────────────

            # Call execute(ctx) — preferred interface.
            # Falls back to run(**ctx.params) via BaseModule.execute() default
            # for modules that haven't migrated yet.
            execute_coro = instance.execute(ctx)
            # Respect per-module timeout if declared (MODULE_TIMEOUT_SECONDS)
            effective_timeout = (
                getattr(instance.__class__, "MODULE_TIMEOUT_SECONDS", None)
                or timeout_seconds
            )
            if effective_timeout != timeout_seconds:
                logger.debug("engine_using_module_timeout",
                             module_id=module_id,
                             timeout=effective_timeout)
            module_result = await asyncio.wait_for(
                execute_coro, timeout=effective_timeout
            )
            findings = module_result.findings
            raw      = module_result.raw
        except asyncio.TimeoutError:
            logger.error("engine_timed_out_s", module_id=module_id, timeout_seconds=timeout_seconds)
            _last_exc: Exception = asyncio.TimeoutError(f"Timed out after {timeout_seconds}s")
            _action = AresError.RETRY
        except AresError as exc:
            logger.warning("engine_areserror", module_id=module_id, action=exc.action, exc=exc)
            _last_exc = exc
            _action = exc.action
        except Exception as exc:
            logger.error("engine_crashed", module_id=module_id, exc=exc, exc_info=True)
            _last_exc = exc
            _action = AresError.SKIP
        else:
            _last_exc = None
            _action = None

        # ── Retry logic ───────────────────────────────────────────────────
        # Track whether the *original* failure was a timeout — if retries also
        # fail (possibly with a different exception), we still report TIMEOUT
        # so callers can distinguish "module timed out repeatedly" from "module crashed".
        _was_timeout = isinstance(_last_exc, asyncio.TimeoutError)
        if _last_exc is not None and _action == AresError.RETRY:
            MAX_RETRIES = 2
            for attempt in range(1, MAX_RETRIES + 1):
                wait = 2 ** attempt   # 2s, 4s
                logger.info("engine_retry_in_s", module_id=module_id, attempt=attempt, MAX_RETRIES=MAX_RETRIES, wait=wait)
                await asyncio.sleep(wait)
                try:
                    # Re-instantiate module fresh — previous coroutine is exhausted/timed-out
                    module2 = cls(
                        settings=self.settings,
                        campaign=campaign,
                        noise=noise,
                    )
                    # Rebuild ctx — same as initial attempt, use execute() not run()
                    ctx2 = ExecutionContext.build(
                        campaign   = campaign,
                        target     = params.get("dc") or params.get("host") or params.get("target", ""),
                        module_id  = module_id,
                        domain     = params.get("domain", ""),
                        params     = params,
                        operator   = campaign.operator,
                        settings   = self.settings,
                        noise      = noise,
                    )
                    module_result2 = await asyncio.wait_for(
                        module2.execute(ctx2), timeout=timeout_seconds
                    )
                    findings = module_result2.findings
                    raw      = module_result2.raw
                    _last_exc = None
                    break
                except asyncio.TimeoutError as te:
                    _last_exc = te
                    _was_timeout = True
                    logger.warning("engine_retry_timed_out", module_id=module_id, attempt=attempt)
                except Exception as re:
                    _last_exc = re
                    logger.warning("engine_retry_failed", module_id=module_id, attempt=attempt, re=re)

        if _last_exc is not None:
            status = (ModuleStatus.TIMEOUT if _was_timeout
                      else ModuleStatus.FAILED)
            return EngineModuleResult(
                module_id=module_id, status=status,
                error=str(_last_exc)[:300],
                duration_ms=round((time.monotonic() - t0) * 1000, 2),
            )

        duration_ms = round((time.monotonic() - t0) * 1000, 2)

        # Validate
        validation_results: list[ValidationResult] = []
        if not skip_validation:
            # Run all validations in parallel too
            validation_results = list(await asyncio.gather(
                *[self.validator.validate(f, raw) for f in findings]
            ))

        # Persist confirmed findings
        confirmed: list[Finding] = []
        for f in findings:
            if not f.false_positive:
                campaign.add_finding(f)
                confirmed.append(f)
                if self.db:
                    try:
                        await self.db.save_finding(campaign.id, f, module_id)
                    except Exception as e:
                        logger.warning("engine_db_save_failed_for_finding", e=e)
                # Webhook alert for qualifying findings
                if self.notifier and self.notifier.should_notify(f.severity):
                    asyncio.create_task(
                        self.notifier.notify_finding(f, campaign)
                    )
                # Dashboard live feed — non-blocking broadcast
                try:
                    from ares.api.dashboard.app import broadcast_finding as _dash_broadcast
                    _fire_and_log(_dash_broadcast({
                        "event":      "finding_discovered",
                        "campaign_id": campaign.id,
                        "title":      f.title,
                        "severity":   f.severity.value,
                        "confidence": f.confidence,
                        "mitre_technique": f.mitre_technique,
                        "host":       f.host,
                        "module_id":  f.module_id,
                        "timestamp":  f.discovered_at.isoformat()
                                      if hasattr(f, "discovered_at") and f.discovered_at
                                      else None,
                    }))
                except Exception:
                    pass   # dashboard not loaded — silently skip

        fp_count = len(findings) - len(confirmed)
        audit("module_run_complete", actor=campaign.operator,
              detail=(f"module={module_id} ms={duration_ms} "
                      f"confirmed={len(confirmed)} fp={fp_count}"))

        # ── Persist vault credentials to DB ───────────────────────────────
        if self.db and getattr(campaign, "_vault", None) is not None:
            try:
                await self._persist_vault_credentials(campaign)
            except Exception as _ve:
                logger.warning("engine_vault_persist_failed",
                               module_id=module_id, error=str(_ve)[:100])

        # ── Auto-normalize raw output into ArtifactStore ──────────────────
        artifact_count = 0
        try:
            from ares.normalize.artifacts import ArtifactNormalizer
            cls_ref = self.registry.get(module_id)
            outputs = getattr(cls_ref, "OUTPUTS", []) if cls_ref else []
            if outputs and raw:
                # Retrieve or create campaign artifact store
                if not hasattr(campaign, "_artifact_store"):
                    from ares.normalize.artifacts import ArtifactStore
                    campaign._artifact_store = ArtifactStore()  # type: ignore[attr-defined]
                normalizer = ArtifactNormalizer()
                artifact_count = normalizer.normalize(
                    module_id=module_id,
                    outputs=outputs,
                    raw=raw,
                    store=campaign._artifact_store,  # type: ignore[attr-defined]
                )
                if artifact_count > 0:
                    logger.debug(
                        "artifacts_normalized",
                        module=module_id,
                        count=artifact_count,
                    )
        except Exception as _norm_exc:
            logger.debug("artifact_normalization_skipped", error=str(_norm_exc)[:80])

        return EngineModuleResult(
            module_id=module_id, status=ModuleStatus.DONE,
            findings=confirmed,
            validation_results=validation_results,
            raw_output=raw, duration_ms=duration_ms,
        )

    # ── Parallel plan ──────────────────────────────────────────────────────

    async def run_plan(
        self,
        plan:               ExecutionPlan,
        campaign:           Campaign,
        global_params:      dict[str, Any] | None = None,
        skip_validation:    bool = False,
        timeout_per_module: int  = 120,
        on_progress:        ProgressCallback | None = None,
        actor_role:         str = "operator",
    ) -> dict[str, EngineModuleResult]:
        """
        Run all stages.
        Within each stage: modules execute CONCURRENTLY (bounded by max_parallel semaphore).
        Between stages: sequential (later stages can depend on earlier recon).
        """
        self._semaphore = asyncio.Semaphore(self.max_parallel)
        results: dict[str, EngineModuleResult] = {}
        gp = global_params or {}

        total_mods = len(plan.all_module_ids())
        logger.info("engine_plan_start_stages_modules", total_mods=total_mods)

        for stage in plan.stages:
            name       = stage["name"]
            module_ids = stage["modules"]
            sp         = stage.get("params", {})

            logger.info("engine_stage_modules_parallel", name=name)

            coros = [
                self._guarded_run(
                    module_id=mid,
                    campaign=campaign,
                    params={**gp, **sp.get(mid, {})},
                    skip_validation=skip_validation,
                    timeout_seconds=timeout_per_module,
                    stage_name=name,
                    on_progress=on_progress,
                    actor_role=actor_role,
                )
                for mid in module_ids
            ]

            raw_results = await asyncio.gather(*coros, return_exceptions=True)
            stage_results: list[EngineModuleResult] = []
            for mid, res in zip(module_ids, raw_results):
                if isinstance(res, Exception):
                    logger.error("engine_raised_unhandled_exception", mid=mid, res=res, exc_info=res)
                    stage_results.append(EngineModuleResult(
                        module_id=mid, status=ModuleStatus.FAILED,
                        error=f"Unhandled: {res!s}"[:200],
                    ))
                else:
                    stage_results.append(res)
            for mid, res in zip(module_ids, stage_results):
                results[mid] = res

        confirmed_total = sum(len(r.confirmed_findings) for r in results.values())
        logger.info("engine_plan_complete_confirmed_findings", confirmed_total=confirmed_total)

        # Teardown: close any active pivot tunnels established during this plan
        if "network.pivot" in results and results["network.pivot"].status == ModuleStatus.DONE:
            try:
                from ares.modules.network.pivot import _PIVOT_MANAGERS
                campaign_id = campaign.id
                if campaign_id in _PIVOT_MANAGERS:
                    pm = _PIVOT_MANAGERS[campaign_id]
                    for tunnel in pm.all_tunnels():
                        try:
                            if tunnel._conn:
                                tunnel._conn.close()
                            elif tunnel._proc:
                                tunnel._proc.terminate()
                                try:
                                    tunnel._proc.wait(timeout=5)
                                except Exception:
                                    tunnel._proc.kill()  # force kill if terminate hangs
                        except Exception:
                            pass
                    _PIVOT_MANAGERS.pop(campaign_id, None)
                    logger.info("engine_pivot_teardown", campaign_id=campaign_id[:8])
            except Exception as teardown_exc:
                logger.warning("engine_pivot_teardown_failed",
                               error=str(teardown_exc)[:80])

        # ALWAYS clean up credential artifacts — regardless of which modules ran.
        # This runs unconditionally to prevent accumulation in 24/7 operation.
        try:
            from ares.core.security import cleanup_credential_artifacts
            cleaned = cleanup_credential_artifacts(campaign.id)
            # Also clean global-scope artifacts (created outside campaign context)
            cleaned += cleanup_credential_artifacts()
            if cleaned:
                logger.info("engine_credential_artifacts_cleaned",
                            count=cleaned, campaign_id=campaign.id[:8])
        except Exception:
            pass

        return results

    def check_plan_dependencies(self, plan: "ExecutionPlan") -> list[dict[str, Any]]:
        """
        Validate each module's REQUIRES are satisfied by earlier stages.
        Returns list of warning dicts with module_id, missing_requirement, suggested_provider.
        Called automatically in run_plan — warnings logged, never blocking.
        """
        warnings_out: list[dict[str, Any]] = []
        available_outputs: set[str] = set()

        # reverse map: capability → module_id that provides it
        provider_map: dict[str, str] = {}
        for cls in self.registry.all():
            for out in getattr(cls, "OUTPUTS", []):
                provider_map[out] = getattr(cls, "MODULE_ID", cls.__name__)

        for stage in plan.stages:
            for mid in stage.get("modules", []):
                cls = self.registry.get(mid)
                if not cls:
                    continue
                for req in getattr(cls, "REQUIRES", []):
                    if req not in available_outputs:
                        suggested = provider_map.get(req, "unknown")
                        warnings_out.append({
                            "module_id":           mid,
                            "missing_requirement": req,
                            "suggested_provider":  suggested,
                            "message": (
                                f"'{mid}' requires '{req}' — "
                                f"add '{suggested}' to an earlier stage first"
                            ),
                        })
            for mid in stage.get("modules", []):
                cls = self.registry.get(mid)
                if cls:
                    available_outputs.update(getattr(cls, "OUTPUTS", []))

        return warnings_out

    def dry_run_plan(
        self,
        plan:          "ExecutionPlan",
        global_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Validate a plan without executing — pre-flight check.

        Returns:
            dry_run:          True
            plan[]:           stages with module details, opsec level, missing params
            param_validation: ok flag + per-field errors
            dependency_check: ok flag + missing REQUIRES warnings
            summary:          total stages/modules, ready_to_run bool

        Usage:
            POST /campaigns/{id}/run  {"dry_run": true}
            ares module run-plan --plan plan.json --dry-run
        """
        gp           = global_params or {}
        dep_warnings = self.check_plan_dependencies(plan)
        stages_out:  list[dict[str, Any]] = []
        param_errors: list[dict[str, str]] = []

        for stage in plan.stages:
            name  = stage.get("name", "unnamed")
            mids  = stage.get("modules", [])
            sp    = stage.get("params", {})

            stage_info: dict[str, Any] = {
                "stage":              name,
                "modules":            [],
                "estimated_duration": _estimate_stage_duration(len(mids)),
            }

            for mid in mids:
                cls = self.registry.get(mid)
                if not cls:
                    param_errors.append({"module_id": mid, "field": "(module)",
                                         "error": f"Module '{mid}' not found in registry"})
                    stage_info["modules"].append({"module_id": mid, "status": "not_found"})
                    continue

                merged = {**gp, **sp.get(mid, {})}
                mod_errors: list[str] = []
                try:
                    from ares.modules.params import MODULE_PARAMS
                    model_cls = MODULE_PARAMS.get(mid)
                    if model_cls:
                        for fname, field_info in model_cls.model_fields.items():
                            if field_info.is_required() and fname not in merged:
                                mod_errors.append(fname)
                                param_errors.append({
                                    "module_id": mid,
                                    "field":     fname,
                                    "error":     f"Required param '{fname}' not provided",
                                })
                except ImportError:
                    pass

                opsec = getattr(cls, "OPSEC_LEVEL", "?")
                stage_info["modules"].append({
                    "module_id":      mid,
                    "opsec_level":    opsec.value if hasattr(opsec, "value") else str(opsec),
                    "requires":       getattr(cls, "REQUIRES", []),
                    "outputs":        getattr(cls, "OUTPUTS",  []),
                    "mitre":          getattr(cls, "MITRE_TECHNIQUES", []),
                    "missing_params": mod_errors,
                    "status":         "error" if mod_errors else "ready",
                })

            stages_out.append(stage_info)

        return {
            "dry_run": True,
            "plan":    stages_out,
            "param_validation": {
                "ok":     len(param_errors) == 0,
                "errors": param_errors,
            },
            "dependency_check": {
                "ok":       len(dep_warnings) == 0,
                "warnings": dep_warnings,
            },
            "summary": {
                "total_stages":  len(plan.stages),
                "total_modules": len(plan.all_module_ids()),
                "ready_to_run":  len(param_errors) == 0,
            },
        }

    async def _persist_vault_credentials(self, campaign: "Campaign") -> int:
        """
        Sync in-memory CredentialVault to the DB after each module run.
        Uses save_credential_preencrypted() to avoid double-encrypting secrets
        that are already Fernet-encrypted by the vault.

        Returns: number of credentials saved/updated.
        """
        vault = getattr(campaign, "_vault", None)
        if not vault or not hasattr(vault, "_store") or not vault._store:
            return 0

        from ares.db.database import DBCredential
        saved = 0
        for cred_id, cred in vault._store.items():
            try:
                secret_enc = ""
                if hasattr(cred, "secret_enc") and cred.secret_enc:
                    secret_enc = (
                        cred.secret_enc.decode("utf-8", errors="replace")
                        if isinstance(cred.secret_enc, bytes)
                        else str(cred.secret_enc)
                    )
                db_cred = DBCredential(
                    id            = cred.id,
                    campaign_id   = campaign.id,
                    host_id       = getattr(cred, "source_host", None) or None,
                    username      = cred.username,
                    cred_type     = (
                        cred.cred_type.value
                        if hasattr(cred.cred_type, "value")
                        else str(cred.cred_type)
                    ),
                    secret        = secret_enc,
                    domain        = getattr(cred, "domain", ""),
                    source_module = getattr(cred, "source_module", ""),
                    notes         = getattr(cred, "notes", ""),
                )
                await self.db.save_credential_preencrypted(db_cred)
                saved += 1
            except Exception as exc:
                logger.debug("vault_persist_cred_failed",
                             cred_id=cred_id[:8], error=str(exc)[:80])
        if saved:
            logger.debug("vault_persisted",
                         campaign=campaign.id[:8], count=saved)
        return saved

    async def _guarded_run(
        self,
        module_id:       str,
        campaign:        Campaign,
        params:          dict[str, Any],
        skip_validation: bool,
        timeout_seconds: int,
        stage_name:      str,
        on_progress:     ProgressCallback | None,
        actor_role:      str,
    ) -> EngineModuleResult:
        if self._semaphore is None:
            raise RuntimeError(
                "Engine semaphore not initialised — engine was not started correctly"
            )
        async with self._semaphore:
            if on_progress:
                await on_progress(ProgressEvent(
                    stage=stage_name, module_id=module_id,
                    status=ModuleStatus.RUNNING,
                ))
            result = await self.run_module(
                module_id,
                campaign,
                params,
                skip_validation,
                timeout_seconds,
                actor_role=actor_role,
            )
            if on_progress:
                await on_progress(ProgressEvent(
                    stage=stage_name, module_id=module_id,
                    status=result.status,
                    finding_count=len(result.confirmed_findings),
                    error=result.error,
                    duration_ms=result.duration_ms,
                ))
            return result

# Backward-compat alias
ModuleResult = EngineModuleResult  # noqa


# ── Campaign Templates ───────────────────────────────────────────────────────

CAMPAIGN_TEMPLATES: dict[str, dict] = {
    "internal_pentest": {
        "description": "Standard internal network penetration test",
        "stages": [
            {"name": "recon", "modules": [
                "network.port_scan", "network.service_detect",
                "recon.fingerprint", "network.dns_enum",
            ]},
            {"name": "ad_enum", "modules": [
                "ad.enum_users", "ad.enum_spn", "ad.enum_computers",
                "ad.enum_acl",
            ]},
            {"name": "credential_attack", "modules": [
                "ad.kerberoast", "ad.asreproast",
            ]},
            {"name": "credential_crack", "modules": [
                "credential.crack",
            ]},
            {"name": "lateral_movement", "modules": [
                "credential.reuse", "lateral.smb_relay",
                "lateral.ntlm_relay",
            ]},
        ],
    },
    "ad_full_compromise": {
        "description": "Full Active Directory compromise — recon to domain admin",
        "stages": [
            {"name": "recon", "modules": [
                "recon.fingerprint", "ad.enum_users", "ad.enum_spn",
                "ad.enum_computers", "ad.enum_acl",
            ]},
            {"name": "credential_harvest", "modules": [
                "ad.kerberoast", "ad.asreproast", "ad.laps_enum",
            ]},
            {"name": "crack_and_reuse", "modules": [
                "credential.crack", "credential.reuse",
                "credential.pass_the_hash",
            ]},
            {"name": "escalation", "modules": [
                "ad.delegation_abuse", "ad.adcs", "ad.sccm",
            ]},
            {"name": "domain_admin", "modules": [
                "ad.dcsync", "credential.golden_ticket",
            ]},
        ],
    },
    "cloud_assessment": {
        "description": "Multi-cloud security assessment — AWS, Azure, GCP",
        "stages": [
            {"name": "cloud_enum", "modules": [
                "cloud.aws", "cloud.azure", "cloud.gcp", "cloud.azure_ad",
            ]},
            {"name": "cloud_privesc", "modules": [
                "cloud.aws_privesc",
            ]},
            {"name": "federation", "modules": [
                "cloud.identity_federation_abuse",
            ]},
        ],
    },
    "assumed_breach": {
        "description": "Assumed breach — start with valid creds, test lateral + escalation",
        "stages": [
            {"name": "situational_awareness", "modules": [
                "recon.fingerprint", "ad.enum_users", "ad.enum_computers",
                "ad.enum_acl",
            ]},
            {"name": "escalation", "modules": [
                "ad.kerberoast", "ad.adcs", "ad.delegation_abuse",
                "ad.sccm",
            ]},
            {"name": "lateral", "modules": [
                "lateral.smb_relay", "lateral.ntlm_relay",
                "credential.reuse",
                "lateral.wmiexec", "lateral.dcom",
            ]},
            {"name": "post_exploit", "modules": [
                "windows.lsass_dump", "windows.dpapi",
                "exfil.smb_shares", "exfil.secrets_scan",
            ]},
        ],
    },
    "linux_pentest": {
        "description": "Linux infrastructure penetration test",
        "stages": [
            {"name": "recon", "modules": [
                "network.port_scan", "network.service_detect",
                "recon.fingerprint",
            ]},
            {"name": "privesc", "modules": [
                "linux.privesc", "linux.kernel_suggester",
                "linux.service_hijack", "linux.ld_preload",
            ]},
            {"name": "post_exploit", "modules": [
                "linux.container", "linux.nfs_escape",
                "exfil.secrets_scan",
            ]},
        ],
    },
}


def get_campaign_template(name: str) -> dict | None:
    """Return a campaign template by name, or None if not found."""
    return CAMPAIGN_TEMPLATES.get(name)


def list_campaign_templates() -> list[dict]:
    """Return list of available campaign templates with descriptions."""
    return [
        {"name": k, "description": v["description"],
         "stages": len(v["stages"]),
         "modules": sum(len(s["modules"]) for s in v["stages"])}
        for k, v in CAMPAIGN_TEMPLATES.items()
    ]


def plan_from_template(name: str, custom_params: dict | None = None) -> "ExecutionPlan":
    """
    Build an ExecutionPlan from a named template.

    Usage:
        plan = plan_from_template("internal_pentest", {"dc": "10.0.0.5", "domain": "corp.local"})
        results = await engine.run_plan(plan, campaign, global_params)
    """
    template = CAMPAIGN_TEMPLATES.get(name)
    if not template:
        raise ValueError(
            f"Unknown template '{name}'. Available: {list(CAMPAIGN_TEMPLATES.keys())}"
        )
    plan = ExecutionPlan()
    for stage in template["stages"]:
        plan.add_stage(
            name=stage["name"],
            module_ids=stage["modules"],
            params=custom_params or {},
        )
    return plan
