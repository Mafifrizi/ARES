"""AWS Recon — boto3 implementation. IAM, S3, Security Groups, IMDS. MITRE: T1526, T1530, T1552.005, T1580"""
from __future__ import annotations
import asyncio
from functools import partial
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.cloud.aws")
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.modules.params import AWSParams
from ares.sdk import (
    CircuitBreaker,
    EvidenceRecord,
    ExecutionContext,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

SENSITIVE_PORTS = {22:"SSH",23:"Telnet",3389:"RDP",1433:"MSSQL",3306:"MySQL",
                   5432:"PostgreSQL",27017:"MongoDB",6379:"Redis",9200:"Elasticsearch"}

@module_contract(
    permissions=[
        NetworkPermission(ports=[443], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=CircuitBreaker(name="cloud.aws", failure_threshold=5),
    params_model=AWSParams,
)
class AWSEnumModule(BaseModule):
    """
    cloud.aws — IAM enum, S3 misconfig, IMDS check, Security Group audit

    OPSEC: LOW
    MITRE: "T1526","T1530","T1552.005","T1580"
    OUTPUTS:  "aws_findings"
    """
    MODULE_ID="cloud.aws"; MODULE_NAME="AWS Recon & Attack"; MODULE_CATEGORY="cloud"
    MODULE_DESCRIPTION="IAM enum, S3 misconfig, IMDS check, Security Group audit"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL=OpsecLevel.LOW; REQUIRES=[]; OUTPUTS=["aws_findings"]
    MITRE_TECHNIQUES=["T1526","T1530","T1552.005","T1580"]
    PARAMS_MODEL       = AWSParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        params = getattr(ctx, "params", {})
        if isinstance(params, AWSParams):
            pdict = params.model_dump()
        elif isinstance(params, dict):
            pdict = dict(params)
        else:
            pdict = {}
        # Cloud modules need AWS credentials — check at least one method available
        has_key = bool(pdict.get("access_key") or pdict.get("profile") or pdict.get("aws_profile"))
        has_env = bool(__import__("os").environ.get("AWS_ACCESS_KEY_ID"))
        if not has_key and not has_env:
            raise ModuleValidationError(
                "cloud.aws requires AWS credentials — set access_key/aws_profile params "
                "or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY environment variables.",
                module_id=self.MODULE_ID, field="access_key",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})

        params = getattr(ctx, "params", {})
        if isinstance(params, AWSParams):
            pdict = params.model_dump()
        elif isinstance(params, dict):
            pdict = dict(params)
        else:
            pdict = {}

        raw_sec = pdict.get("secret_key")
        if hasattr(raw_sec, "get_secret_value"):
            secret_key = raw_sec.get_secret_value()
        elif raw_sec is not None:
            secret_key = str(raw_sec)
        else:
            secret_key = None

        raw_tok = pdict.get("session_token")
        if hasattr(raw_tok, "get_secret_value"):
            session_token = raw_tok.get_secret_value()
        elif raw_tok is not None:
            session_token = str(raw_tok)
        else:
            session_token = None

        findings, raw = await self.run(
            profile=pdict.get("profile"),
            access_key=pdict.get("access_key"),
            secret_key=secret_key,
            session_token=session_token,
            region=pdict.get("region") or "us-east-1",
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"aws-{pdict.get('region', 'us-east-1')}-{finding.mitre_technique}",
                source_target=f"aws:{pdict.get('region', 'us-east-1')}",
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "severity": str(finding.severity),
                    "technique": finding.mitre_technique,
                },
                tags=["cloud", "aws", "recon"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("cloud.aws")
    async def run(self, profile=None, access_key=None, secret_key=None,
                  session_token=None, region="us-east-1", **kwargs):
        # Note: before_request() intentionally not called — cloud modules use
        # API credentials, not host IPs. Scope check (CIDR) does not apply to
        # cloud API endpoints. Rate limiting and jitter are handled at the API call level.
        logger.info("aws_recon_start", region=region)
        try:
            session = self._make_session(profile, access_key, secret_key, session_token)
        except Exception as exc:
            from ares.core.errors import AuthenticationFailed
            raise AuthenticationFailed(f"AWS auth failed: {exc}", username="aws_key", module_id=self.MODULE_ID, target="aws") from exc
        loop = asyncio.get_running_loop()
        raw = {"region": region}
        for label, fn in [
            ("identity",        partial(self._get_caller_identity, session)),
            ("iam",             partial(self._enum_iam, session)),
            ("s3",              partial(self._enum_s3, session, region)),
            ("security_groups", partial(self._enum_security_groups, session, region)),
            ("imds",            self._check_imds),
        ]:
            try:
                raw[label] = await loop.run_in_executor(None, fn)
            except Exception as exc:
                logger.warning("aws_check_failed", check=label, error=str(exc)[:100])
                raw[label] = {"error": str(exc)[:150]}
        self._analyze(raw)
        logger.info("aws_recon_done", findings=len(self._findings))
        raw["aws_findings"] = self._findings  # matches OUTPUTS
        return self._findings, raw

    def _make_session(self, profile, access_key, secret_key, session_token):
        import boto3
        kw = {}
        if profile: kw["profile_name"] = profile
        elif access_key:
            kw.update(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            if session_token: kw["aws_session_token"] = session_token
        return boto3.Session(**kw)

    def _get_caller_identity(self, session):
        return session.client("sts").get_caller_identity()

    def _enum_iam(self, session) -> dict:
        import datetime
        iam = session.client("iam")
        r: dict = {}
        try:
            pp = iam.get_account_password_policy()["PasswordPolicy"]
            r["password_policy"] = {"min_length":pp.get("MinimumPasswordLength",0),
                                     "max_age":pp.get("MaxPasswordAge",0),
                                     "lockout_threshold":pp.get("HardExpiry",False)}
        except (KeyError, ValueError, AttributeError):
            r["password_policy"] = {"error":"no_policy"}
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            r["root_mfa_enabled"] = bool(summary.get("AccountMFAEnabled",0))
        except Exception: pass
        try:
            users_no_mfa = []
            for page in iam.get_paginator("list_users").paginate():
                for user in page["Users"]:
                    if not iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]:
                        users_no_mfa.append(user["UserName"])
            r["users_without_mfa"] = users_no_mfa[:20]
        except Exception: pass
        try:
            stale = []
            for page in iam.get_paginator("list_users").paginate():
                for user in page["Users"]:
                    for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                        age = (datetime.datetime.now(datetime.timezone.utc)-key["CreateDate"]).days
                        if age > 90 and key["Status"] == "Active":
                            stale.append({"user":user["UserName"],"age_days":age})
            r["stale_access_keys"] = stale[:20]
        except Exception: pass
        return r

    def _enum_s3(self, session, region) -> dict:
        s3 = session.client("s3", region_name=region)
        r: dict = {"public_buckets":[],"no_encryption":[]}
        try:
            for b in s3.list_buckets().get("Buckets",[]):
                name = b["Name"]
                try:
                    for grant in s3.get_bucket_acl(Bucket=name).get("Grants",[]):
                        uri = grant.get("Grantee",{}).get("URI","")
                        if uri.endswith(("AllUsers","AuthenticatedUsers")):
                            r["public_buckets"].append({"name":name,"access":grant["Permission"]})
                except Exception: pass
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except Exception as e:
                    if "NoSuchEncryption" in str(e) or "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                        r["no_encryption"].append(name)
        except Exception: pass
        return r

    def _enum_security_groups(self, session, region) -> dict:
        ec2 = session.client("ec2", region_name=region)
        r: dict = {"open_to_internet":[]}
        try:
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for sg in page["SecurityGroups"]:
                    for perm in sg.get("IpPermissions",[]):
                        fp,tp = perm.get("FromPort",0),perm.get("ToPort",65535)
                        for cidr in perm.get("IpRanges",[]):
                            if cidr.get("CidrIp") == "0.0.0.0/0":
                                for port in range(max(0,fp), min(65535,tp)+1):
                                    if port in SENSITIVE_PORTS:
                                        r["open_to_internet"].append({"sg_id":sg["GroupId"],"port":port,"service":SENSITIVE_PORTS[port]})
        except Exception as e:
            r["error"] = str(e)[:100]
        return r

    def _check_imds(self) -> dict:
        import urllib.request, urllib.error
        r: dict = {"imdsv1_available": False}
        try:
            req = urllib.request.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
            with urllib.request.urlopen(req, timeout=3) as resp:
                r["imdsv1_available"] = True; r["credential_roles"] = resp.read().decode().strip().splitlines()
        except Exception: pass
        return r

    def _analyze(self, raw):
        iam,s3,sgs,imds = raw.get("iam",{}),raw.get("s3",{}),raw.get("security_groups",{}),raw.get("imds",{})
        if not iam.get("root_mfa_enabled"):
            self.finding(title="Root Account MFA Disabled",description="AWS root account lacks MFA. Unrestricted access risk.",
                severity=Severity.CRITICAL,mitre_technique="T1078.004",mitre_tactic="Persistence",
                evidence={"root_mfa":False},remediation="Enable hardware MFA on root. Never use root access keys.")
        no_mfa = iam.get("users_without_mfa",[])
        if no_mfa:
            self.finding(title=f"IAM Users Without MFA ({len(no_mfa)})",description=f"{len(no_mfa)} IAM users have no MFA device.",
                severity=Severity.HIGH,mitre_technique="T1078.004",mitre_tactic="Initial Access",
                evidence={"users":no_mfa[:10]},remediation="Enforce MFA for all human IAM users.")
        stale = iam.get("stale_access_keys",[])
        if stale:
            self.finding(title=f"Stale IAM Access Keys ({len(stale)})",description=f"{len(stale)} active keys older than 90 days.",
                severity=Severity.MEDIUM,mitre_technique="T1552.004",mitre_tactic="Credential Access",
                evidence={"keys":stale[:10]},remediation="Rotate or disable keys older than 90 days.")
        public = s3.get("public_buckets",[])
        if public:
            self.finding(title=f"Public S3 Buckets ({len(public)})",description=f"{len(public)} buckets publicly accessible.",
                severity=Severity.CRITICAL,mitre_technique="T1530",mitre_tactic="Collection",
                evidence={"buckets":public[:10]},remediation="Block public access at account level.")
        open_sgs = sgs.get("open_to_internet",[])
        if open_sgs:
            self.finding(title=f"Security Groups Open to Internet ({len(open_sgs)} sensitive ports)",
                description=f"{len(open_sgs)} rules expose sensitive ports to 0.0.0.0/0.",
                severity=Severity.HIGH,mitre_technique="T1046",mitre_tactic="Discovery",
                evidence={"rules":open_sgs[:10]},remediation="Restrict ingress. Use VPN or SSM Session Manager.")
        if imds.get("imdsv1_available"):
            self.finding(title="IMDSv1 Available — SSRF → Credential Theft",
                description="EC2 IMDSv1 accessible without token. SSRF can extract IAM credentials.",
                severity=Severity.HIGH,mitre_technique="T1552.005",mitre_tactic="Credential Access",
                evidence={"roles":imds.get("credential_roles",[])},
                remediation="Require IMDSv2: aws ec2 modify-instance-metadata-options --http-tokens required.")

# Backward-compat alias — was AWSModule before v3.0.1
AWSModule = AWSEnumModule  # noqa
