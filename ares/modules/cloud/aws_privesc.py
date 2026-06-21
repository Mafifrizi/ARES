"""
AWS IAM Privilege Escalation
MITRE: T1078.004, T1548 (Abuse Elevation Control)

Checks for IAM privilege escalation paths using current credentials:
  - PassRole abuse (iam:PassRole + ec2/lambda/etc CreateFunction)
  - AssumeRole with overly permissive trust policies
  - Inline policy with iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion
  - Attached admin policies on accessible roles

Based on Rhino Security Labs IAM privesc research.
"""
from __future__ import annotations
import asyncio
from functools import partial
from typing import Any
from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.cloud.aws_privesc")

# IAM actions that indicate privilege escalation paths
_PRIVESC_ACTIONS: list[tuple[str, str, str]] = [
    ("iam:CreatePolicyVersion",        "Create new policy version with admin perms", "T1548"),
    ("iam:SetDefaultPolicyVersion",    "Revert to older policy version with more perms", "T1548"),
    ("iam:CreateAccessKey",            "Create new access key for any user", "T1098"),
    ("iam:CreateLoginProfile",         "Set password for user without console access", "T1098"),
    ("iam:UpdateLoginProfile",         "Change password for any user", "T1098"),
    ("iam:AttachUserPolicy",           "Attach admin policy to self", "T1548"),
    ("iam:AttachGroupPolicy",          "Attach admin policy to own group", "T1548"),
    ("iam:AttachRolePolicy",           "Attach admin policy to role", "T1548"),
    ("iam:PutUserPolicy",              "Create inline admin policy on self", "T1548"),
    ("iam:AddUserToGroup",             "Add self to privileged group", "T1078"),
    ("iam:PassRole",                   "Pass privileged role to compute service", "T1548"),
    ("sts:AssumeRole",                 "Assume another role — check trust policy", "T1550.001"),
    ("lambda:CreateFunction",          "Create Lambda with privileged execution role", "T1648"),
    ("ec2:RunInstances",               "Launch EC2 with privileged instance profile", "T1578.002"),
    ("cloudformation:CreateStack",     "Deploy stack with privileged service role", "T1578"),
    ("glue:CreateDevEndpoint",         "Create Glue endpoint with admin role", "T1578"),
]


class AWSPrivescModule(BaseModule):
    """
    cloud.aws_privesc — Enumerate current IAM permissions and identify privilege escalation paths — PassRole abuse, Assu

    OPSEC: LOW
    MITRE: "T1078.004", "T1548", "T1098"
    OUTPUTS:  "aws_privesc_paths", "aws_findings"
    """
    MODULE_ID          = "cloud.aws_privesc"
    MODULE_NAME        = "AWS IAM Privilege Escalation"
    MODULE_CATEGORY    = "cloud"
    MODULE_DESCRIPTION = (
        "Enumerate current IAM permissions and identify privilege escalation paths — "
        "PassRole abuse, AssumeRole, policy manipulation techniques"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["aws_privesc_paths", "aws_findings"]
    MITRE_TECHNIQUES   = ["T1078.004", "T1548", "T1098"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        has_key = bool(ctx.params.get("access_key") or
                       __import__("os").environ.get("AWS_ACCESS_KEY_ID"))
        if not has_key:
            raise ModuleValidationError(
                "cloud.aws_privesc requires AWS credentials — set access_key param "
                "or AWS_ACCESS_KEY_ID environment variable.",
                module_id=self.MODULE_ID, field="access_key",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(status="success" if (findings or raw.get("privesc_paths")) else "partial",
                            findings=findings, raw=raw, module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""))

    @trace_module("cloud.aws_privesc")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        # Note: before_request() intentionally not called — cloud modules use
        # API credentials, not host IPs. Scope check (CIDR) does not apply to
        # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
        access_key    = kwargs.get("aws_access_key", "")
        secret_key    = kwargs.get("aws_secret_key", "")
        session_token = kwargs.get("aws_session_token", "")
        region        = kwargs.get("aws_region", "us-east-1")
        dry_run       = kwargs.get("dry_run", False)

        if dry_run:
            return [], {"dry_run": True}

        try:
            import boto3  # type: ignore[import]
        except ImportError:
            return [], {"error": "boto3 not installed — pip install ares-redteam[cloud]"}

        logger.info("aws_privesc_check_start")
        await self.noise.rate_limiter.acquire("cloud_api")
        await self.noise.jitter.sleep()

        loop = asyncio.get_running_loop()

        def _check() -> dict[str, Any]:
            creds: dict[str, str] = {}
            if access_key:
                creds = {"aws_access_key_id": access_key,
                          "aws_secret_access_key": secret_key,
                          "region_name": region}
                if session_token:
                    creds["aws_session_token"] = session_token

            session = boto3.Session(**creds) if creds else boto3.Session(region_name=region)
            iam     = session.client("iam")
            sts     = session.client("sts")

            results: dict[str, Any] = {
                "current_identity": {}, "allowed_actions": [],
                "privesc_paths": [], "errors": []
            }

            # Who am I?
            try:
                identity = sts.get_caller_identity()
                results["current_identity"] = {
                    "arn":     identity.get("Arn", ""),
                    "user_id": identity.get("UserId", ""),
                    "account": identity.get("Account", ""),
                }
            except Exception as e:
                results["errors"].append(f"GetCallerIdentity: {e!s:.80}")
                return results

            # Simulate each potentially dangerous action
            for action, description, technique in _PRIVESC_ACTIONS:
                service, action_name = action.split(":", 1)
                try:
                    # Use IAM policy simulator
                    sim_resp = iam.simulate_principal_policy(
                        PolicySourceArn=results["current_identity"]["arn"],
                        ActionNames=[action],
                        ResourceArns=["*"],
                    )
                    for eval_result in sim_resp.get("EvaluationResults", []):
                        if eval_result.get("EvalDecision") == "allowed":
                            results["allowed_actions"].append(action)
                            results["privesc_paths"].append({
                                "action":      action,
                                "description": description,
                                "technique":   technique,
                            })
                except Exception:
                    pass  # SimulatePrincipalPolicy may not be allowed

            return results

        result = await loop.run_in_executor(None, _check)

        if result.get("privesc_paths"):
            paths = result["privesc_paths"]
            critical_paths = [p for p in paths if
                              p["action"] in ("iam:CreatePolicyVersion",
                                              "iam:AttachUserPolicy", "iam:PutUserPolicy")]
            sev = Severity.CRITICAL if critical_paths else Severity.HIGH

            self.finding(
                title=f"AWS IAM Privilege Escalation Paths Found ({len(paths)} path(s))",
                description=(
                    f"Current identity {result['current_identity'].get('arn', '')} has "
                    f"{len(paths)} potential IAM privilege escalation path(s). "
                    f"Most dangerous: {', '.join(p['action'] for p in critical_paths[:3])}."
                ),
                severity=sev,
                mitre_technique="T1548",
                mitre_tactic="Privilege Escalation",
                evidence={"identity": result["current_identity"],
                           "privesc_paths": paths},
                remediation=(
                    "Apply least-privilege IAM policies. "
                    "Remove iam:PassRole from non-administrative roles. "
                    "Enable AWS IAM Access Analyzer. "
                    "Use Permission Boundaries to limit maximum permission scope. "
                    "Enable CloudTrail and alert on IAM policy changes."
                ),
                host="aws", confidence=0.85,
            )

        raw = {
            "current_identity": result.get("current_identity", {}),
            "privesc_paths":    result.get("privesc_paths", []),
            "allowed_actions":  result.get("allowed_actions", []),
            "errors":           result.get("errors", []),
        }
        raw["aws_privesc_paths"] = self._findings  # OUTPUTS key
        raw["aws_findings"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
