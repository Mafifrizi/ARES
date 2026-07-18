"""
ARES Validator Engine
Multi-stage validation + confidence scoring.
Prevents false positives before anything hits the report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

from ares.core.logger import get_logger

logger = get_logger("ares.core.validator")

from ares.core.campaign import Finding


class ValidationStage(str, Enum):
    EXISTENCE   = "existence"    # Does the condition actually exist?
    EXPLOITABLE = "exploitable"  # Can it be exploited (PoC-level)?
    IMPACTFUL   = "impactful"    # Does it have real-world impact?


@dataclass
class ValidationCheck:
    stage: ValidationStage
    name: str
    check: Callable[..., Awaitable[tuple[bool, float, str]]]
    weight: float = 1.0   # Contribution to confidence score


@dataclass
class ValidationResult:
    finding_id: str
    passed: bool
    confidence: float
    stage_results: dict[str, tuple[bool, float, str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def should_report(self) -> bool:
        """Only report if passed validation AND confidence is meaningful."""
        return self.passed and self.confidence >= 0.4


class FindingValidator:
    """
    Validates a finding through multiple stages.
    Each stage adjusts the confidence score.

    Confidence scale:
        1.0 = Confirmed, fully exploitable, high impact
        0.7 = Confirmed existence, likely exploitable
        0.4 = Possible, needs manual verification
        0.0 = Likely false positive
    """

    def __init__(self) -> None:
        self._registry: dict[str, list[ValidationCheck]] = {}

    def register(self, finding_type: str, checks: list[ValidationCheck]) -> None:
        """Register validation checks for a finding type."""
        self._registry[finding_type] = checks

    async def validate(self, finding: Finding, context: dict[str, Any]) -> ValidationResult:
        """Run all registered checks for this finding type."""
        checks = self._registry.get(finding.module_id, [])

        if not checks:
            # No validators registered → assume valid but low confidence
            logger.debug("validator_no_checks_for_defaulting_06", module_id=finding.module_id)
            finding.confidence = 0.6
            finding.validated = True
            return ValidationResult(
                finding_id=finding.id,
                passed=True,
                confidence=0.6,
                notes=["No validators registered — manual review recommended"],
            )

        stage_results: dict[str, tuple[bool, float, str]] = {}
        total_weight = sum(c.weight for c in checks)
        weighted_confidence = 0.0

        for chk in checks:
            try:
                passed, score, note = await chk.check(finding=finding, context=context)
                stage_results[chk.name] = (passed, score, note)
                weighted_confidence += score * chk.weight
                logger.debug("validator_passed_score", name=chk.name, passed=passed, score=round(score, 2), note=note)
            except Exception as e:
                logger.warning("validator_check_threw", name=chk.name, e=e)
                stage_results[chk.name] = (False, 0.0, f"error: {e}")

        final_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        result = ValidationResult(
            finding_id=finding.id,
            passed=final_confidence >= 0.4,
            confidence=round(final_confidence, 3),
            stage_results=stage_results,
        )

        # Update the finding
        finding.confidence = result.confidence
        finding.validated = True
        if not result.passed:
            finding.mark_false_positive(f"Confidence too low: {final_confidence:.2f}")

        logger.info(
            f"[validator] Finding '{finding.title}' -> "
            f"confidence={result.confidence:.2f} passed={result.passed}"
        )
        return result


# ── Built-in validators ───────────────────────────────────────────────────────

async def _check_kerberoastable_active(
    finding: Finding, context: dict[str, Any]
) -> tuple[bool, float, str]:
    """Check that the SPN account is actually enabled and not a honeypot."""
    spns: list[dict[str, Any]] = context.get("spns", [])
    active = [s for s in spns if s.get("enabled") and not s.get("decoy")]
    if not active:
        return False, 0.0, "No active, non-decoy SPN accounts"
    return True, 1.0, f"{len(active)} active SPN accounts confirmed"


async def _check_kerberoastable_privileged(
    finding: Finding, context: dict[str, Any]
) -> tuple[bool, float, str]:
    """Higher confidence if SPN account has elevated privileges."""
    spns = context.get("spns", [])
    privileged = [s for s in spns if s.get("is_admin") or "svc" in s.get("name", "").lower()]
    if privileged:
        return True, 1.0, f"{len(privileged)} privileged SPN accounts"
    return True, 0.6, "SPN accounts found but not obviously privileged"


async def _check_s3_actually_public(
    finding: Finding, context: dict[str, Any]
) -> tuple[bool, float, str]:
    """Re-verify S3 bucket is publicly accessible via unauthenticated HTTP."""
    import httpx
    buckets: list[str] = context.get("public_buckets", [])
    confirmed = []
    async with httpx.AsyncClient(timeout=5) as client:
        for bucket in buckets[:5]:  # Limit checks
            try:
                url = f"https://{bucket}.s3.amazonaws.com/"
                r = await client.get(url)
                if r.status_code in (200, 301):
                    confirmed.append(bucket)
            except (OSError, ConnectionError, TimeoutError):
                pass
    if confirmed:
        return True, 1.0, f"Confirmed public access: {confirmed}"
    return False, 0.1, "Buckets appear public in API but HTTP check failed"


async def _check_docker_socket_exploitable(
    finding: Finding, context: dict[str, Any]
) -> tuple[bool, float, str]:
    """Verify Docker socket is actually writable, not just readable."""
    import os
    socket_path = "/var/run/docker.sock"
    if not os.path.exists(socket_path):
        return False, 0.0, "Socket not found"
    readable = os.access(socket_path, os.R_OK)
    writable = os.access(socket_path, os.W_OK)
    if writable:
        return True, 1.0, "Docker socket is read+write — full container escape possible"
    if readable:
        return True, 0.6, "Docker socket readable — limited exploitation"
    return False, 0.1, "Docker socket exists but not accessible"


async def _check_ad_finding_evidence(
    finding: Finding, context: dict[str, Any]
) -> tuple[bool, float, str]:
    """Score AD findings from the evidence produced by the module itself."""
    evidence = finding.evidence
    module_id = finding.module_id

    if module_id in {"ad.asreproast", "ad.kerberoast"}:
        hash_count = int(evidence.get("hash_count", 0) or 0)
        if hash_count > 0:
            return True, 0.95, f"{hash_count} captured hash result(s)"
        return False, 0.0, "No captured hash evidence"

    if module_id == "ad.enum_spn":
        candidate_count = int(
            evidence.get("total_spns", 0)
            or len(evidence.get("accounts", []))
        )
        if candidate_count > 0:
            return True, 0.6, f"{candidate_count} SPN candidate account(s) enumerated"
        return False, 0.0, "No SPN candidate evidence"

    return False, 0.0, "Unsupported AD finding type"


# ── Default validator registry ────────────────────────────────────────────────

def build_default_validator() -> FindingValidator:
    v = FindingValidator()

    v.register("ad.attacks", [
        ValidationCheck(
            stage=ValidationStage.EXISTENCE,
            name="kerberoastable_active",
            check=_check_kerberoastable_active,
            weight=1.5,
        ),
        ValidationCheck(
            stage=ValidationStage.IMPACTFUL,
            name="kerberoastable_privileged",
            check=_check_kerberoastable_privileged,
            weight=1.0,
        ),
    ])

    v.register("cloud.aws", [
        ValidationCheck(
            stage=ValidationStage.EXPLOITABLE,
            name="s3_http_verify",
            check=_check_s3_actually_public,
            weight=2.0,
        ),
    ])

    v.register("linux.container", [
        ValidationCheck(
            stage=ValidationStage.EXPLOITABLE,
            name="docker_socket_writable",
            check=_check_docker_socket_exploitable,
            weight=2.0,
        ),
    ])

    for module_id in ("ad.asreproast", "ad.enum_spn", "ad.kerberoast"):
        v.register(module_id, [
            ValidationCheck(
                stage=ValidationStage.EXISTENCE,
                name="module_evidence_confidence",
                check=_check_ad_finding_evidence,
            ),
        ])

    return v
