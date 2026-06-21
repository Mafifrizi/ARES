"""
ARES Module Parameter Validation — Pydantic-based

Replaces the weak dict-based PARAM_SCHEMA with a proper Pydantic model
that enforces types, lengths, patterns, and secret handling.

Usage in modules:

    from ares.modules.params import param, SecretParam, ModuleParams

    class KerberoastParams(ModuleParams):
        dc:          str = param(description="DC IP or FQDN", min_length=3)
        domain:      str = param(description="e.g. CORP.LOCAL", min_length=3),
        username:    str = param(description="Authenticating username")
        password:    SecretParam = param(description="Password", secret=True)
        target_user: str = param(description="Target specific user", required=False, default="")

    class KerberoastModule(BaseModule):
        PARAMS = KerberoastParams

        async def run(self, **kwargs):
            p = KerberoastParams.model_validate(kwargs)  # raises ValidationError on bad input
            # Use p.dc, p.domain, etc.

Integrates with API:
    POST /modules/{id}/run validates body.params against module's PARAMS model.
    Returns 422 with field-level error detail on validation failure.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

# ── Type aliases ──────────────────────────────────────────────────────────────

SecretParam = SecretStr


def param(
    description: str = "",
    required: bool = True,
    default: Any = None,
    min_length: int | None = None,
    max_length: int | None = None,
    ge: float | None = None,
    le: float | None = None,
    pattern: str | None = None,
    secret: bool = False,
) -> Any:
    """
    Factory for module parameter field definitions.
    Wraps pydantic Field() with ARES-specific metadata.

    Example:
        dc:       str = param("DC IP or FQDN", min_length=7),
        password: SecretStr  = param("Password", secret=True)
        timeout:  int        = param("Timeout seconds", required=False, default=30, ge=1, le=300)
    """
    kwargs: dict[str, Any] = {
        "description": description,
        "json_schema_extra": {"secret": secret, "required": required},
    }
    if not required and default is not None:
        kwargs["default"] = default
    elif not required:
        kwargs["default"] = None
    # else: required=True, no default → pydantic marks as required

    if min_length is not None:
        kwargs["min_length"] = min_length
    if max_length is not None:
        kwargs["max_length"] = max_length
    if ge is not None:
        kwargs["ge"] = ge
    if le is not None:
        kwargs["le"] = le
    if pattern is not None:
        kwargs["pattern"] = pattern

    return Field(**kwargs)


# ── Base class for all module params ─────────────────────────────────────────


class ModuleParams(BaseModel):
    """
    Base class for module parameter models.
    Subclass this in each module to define typed, validated params.

    Example:
        class DCParams(ModuleParams):
            dc:       str = param("DC IP or FQDN", min_length=3)
            username: str = param("Username")
            password: SecretParam = param("Password", secret=True)
            domain:   str = param("FQDN domain, e.g. CORP.LOCAL")
    """

    model_config = ConfigDict(
        extra="allow",  # Allow extra params (ignore unknown keys)
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    @classmethod
    def validate_dict(cls, data: dict[str, Any]) -> ModuleParams:
        """
        Validate a raw param dict and return a populated model.
        Raises pydantic.ValidationError with field-level errors on failure.
        """
        return cls.model_validate(data)

    @classmethod
    def schema_for_api(cls) -> dict[str, Any]:
        """Return a simplified schema dict for API documentation."""
        schema = cls.model_json_schema()
        result: dict[str, Any] = {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        for name, field_schema in props.items():
            result[name] = {
                "type": field_schema.get("type", "string"),
                "description": field_schema.get("description", ""),
                "required": name in required,
                "secret": field_schema.get(
                    "secret",
                    field_schema.get("json_schema_extra", {}).get("secret", False),
                ),
            }
            if "minimum" in field_schema:
                result[name]["min"] = field_schema["minimum"]
            if "maximum" in field_schema:
                result[name]["max"] = field_schema["maximum"]
            if "minLength" in field_schema:
                result[name]["min_len"] = field_schema["minLength"]
            if "maxLength" in field_schema:
                result[name]["max_len"] = field_schema["maxLength"]
            if "pattern" in field_schema:
                result[name]["pattern"] = field_schema["pattern"]
        return result

    def safe_dict(self) -> dict[str, Any]:
        """Export params dict, replacing SecretStr values with '***'."""
        result = {}
        for name, field_info in self.model_fields.items():
            val = getattr(self, name, None)
            if isinstance(val, SecretStr):
                result[name] = "***"
            else:
                result[name] = val
        return result


# ── Common reusable parameter models ─────────────────────────────────────────

_HOST_PATTERN = r"^[\w.-]+$"
_DOMAIN_PATTERN = r"^[\w.-]+$"
_USER_PATTERN = r"^[\w.\\@-]+$"
_CIDR_PATTERN = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"


class DomainAuthParams(ModuleParams):
    """Shared params for AD modules requiring DC + credentials."""

    dc: str = param("DC IP or FQDN", min_length=3, pattern=_HOST_PATTERN)
    domain: str = param(
        "FQDN domain (CORP.LOCAL)", min_length=3, pattern=_DOMAIN_PATTERN
    )
    username: str = param(
        "Authenticating username", min_length=1, pattern=_USER_PATTERN
    )
    password: SecretParam = param("Password", secret=True)
    use_ldaps: bool = param("Use LDAPS (port 636)", required=False, default=True)


class KerberoastParams(DomainAuthParams):
    target_user: str = param(
        "Target specific user (default: all SPN accounts)",
        required=False,
        default="",
        max_length=256,
    )


class ASREPRoastParams(ModuleParams):
    dc: str = param("DC IP or FQDN", min_length=3, pattern=_HOST_PATTERN)
    domain: str = param("Domain FQDN", min_length=3, pattern=_DOMAIN_PATTERN)
    username: str | None = param(
        "Authenticated username for LDAP discovery", required=False, default=None
    )
    password: SecretParam | None = param(
        "Password (for authenticated mode)", required=False, default=None, secret=True
    )
    userfile: str | None = param(
        "Path to username wordlist (unauthenticated mode)",
        required=False,
        default=None,
        max_length=512,
    )

    @model_validator(mode="after")
    def require_auth_or_wordlist(self) -> ASREPRoastParams:
        if not self.username and not self.userfile:
            raise ValueError(
                "Either 'username' (authenticated LDAP) or 'userfile' (wordlist mode) is required"
            )
        return self


class DCSyncParams(DomainAuthParams):
    target_user: str = param(
        "Target user (default: krbtgt)",
        required=False,
        default="krbtgt",
        max_length=256,
    )


class AWSParams(ModuleParams):
    profile: str | None = param("AWS named profile", required=False, default=None)
    access_key: str | None = param(
        "AWS Access Key ID", required=False, default=None, min_length=16, max_length=128
    )
    secret_key: SecretParam | None = param(
        "AWS Secret Key", required=False, default=None, secret=True
    )
    session_token: SecretParam | None = param(
        "Session token", required=False, default=None, secret=True
    )
    region: str = param(
        "AWS region",
        required=False,
        default="us-east-1",
        pattern=r"^[a-z]{2}-[a-z]+-\d$",
    )


class LinuxPrivescParams(ModuleParams):
    host: str = param(
        "Target host (localhost for local)", required=False, default="localhost"
    )
    ssh_user: str | None = param(
        "SSH username (remote mode)", required=False, default=None
    )
    ssh_key: str | None = param("Path to SSH private key", required=False, default=None)
    ssh_pass: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    ssh_port: int = param("SSH port", required=False, default=22, ge=1, le=65535)


# ── AD modules ────────────────────────────────────────────────────────────────


class ADCSParams(DomainAuthParams):
    """ad.adcs — ADCS ESC1-ESC8 enumeration and exploitation."""

    ca_server: str = param(
        "CA server hostname or IP", required=False, default="", max_length=253
    )
    mode: str = param(
        "Mode: enumerate|exploit",
        required=False,
        default="enumerate",
        pattern=r"^(enumerate|exploit)$",
    )
    template: str = param(
        "Target certificate template (exploit mode)",
        required=False,
        default="",
        max_length=256,
    )


class CoerceParams(DomainAuthParams):
    """ad.coerce — PetitPotam/PrinterBug/DFSCoerce NTLM coercion."""

    listener_ip: str = param(
        "Attacker IP to receive NTLM auth", min_length=7, max_length=45
    )
    method: str = param(
        "Method: auto|petitpotam|printerbug|dfscoerce",
        required=False,
        default="auto",
        pattern=r"^(auto|petitpotam|printerbug|dfscoerce)$",
    )


class SCCMParams(DomainAuthParams):
    """ad.sccm — SCCM/MECM enumeration and credential extraction."""

    sccm_server: str = param(
        "SCCM site server hostname (auto-discover if empty)",
        required=False,
        default="",
        max_length=253,
    )
    target: str = param(
        "Target SCCM client for NAA extraction (requires local admin)",
        required=False,
        default="",
        max_length=253,
    )


class NTLMRelayParams(DomainAuthParams):
    """lateral.ntlm_relay — Full NTLM relay attack chain."""

    targets: list[str] = param(
        "Target hosts to check for relay (auto-discover if empty)",
        required=False,
        default=[],
    )
    coerce_source: str = param(
        "Host to coerce authentication from (default: DC)",
        required=False,
        default="",
        max_length=253,
    )
    target_user: str = param(
        "User to impersonate via RBCD (default: administrator)",
        required=False,
        default="administrator",
        max_length=256,
    )
    mode: str = param(
        "Mode: discover|coerce|full",
        required=False,
        default="full",
        pattern=r"^(discover|coerce|full)$",
    )


class DelegationAbuseParams(DomainAuthParams):
    """ad.delegation_abuse — Unconstrained/constrained/RBCD delegation abuse."""

    mode: str = param(
        "Mode: enumerate|unconstrained|constrained|rbcd",
        required=False,
        default="enumerate",
        pattern=r"^(enumerate|unconstrained|constrained|rbcd)$",
    )
    target_host: str = param(
        "Target computer for delegation abuse",
        required=False,
        default="",
        max_length=253,
    )


class LAPSEnumParams(DomainAuthParams):
    """ad.laps_enum — LAPS v1/v2 password retrieval."""

    computer_filter: str = param(
        "LDAP filter for target computers", required=False, default="", max_length=512
    )


# ── Cloud modules ─────────────────────────────────────────────────────────────


class AWSPrivescParams(ModuleParams):
    """cloud.aws_privesc — AWS IAM privilege escalation."""

    access_key: str | None = param(
        "AWS Access Key ID", required=False, default=None, min_length=16, max_length=128
    )
    secret_key: SecretParam | None = param(
        "AWS Secret Key", required=False, default=None, secret=True
    )
    session_token: SecretParam | None = param(
        "Session token", required=False, default=None, secret=True
    )
    region: str = param(
        "AWS region",
        required=False,
        default="us-east-1",
        pattern=r"^[a-z]{2}-[a-z]+-\d+$",
    )


class AzureParams(ModuleParams):
    """cloud.azure — Azure resource enumeration."""

    subscription_id: str | None = param(
        "Azure subscription ID", required=False, default=None
    )
    tenant_id: str | None = param("Azure tenant ID", required=False, default=None)
    client_id: str | None = param(
        "Service principal client ID", required=False, default=None
    )
    client_secret: SecretParam | None = param(
        "Service principal secret", required=False, default=None, secret=True
    )


class AzureADParams(ModuleParams):
    """cloud.azure_ad — Azure AD enumeration via Graph API."""

    tenant_id: str | None = param("Azure tenant ID", required=False, default=None)
    client_id: str | None = param("App client ID", required=False, default=None)
    mode: str = param(
        "Auth mode: device_code|client_credentials",
        required=False,
        default="device_code",
        pattern=r"^(device_code|client_credentials)$",
    )


class GCPParams(ModuleParams):
    """cloud.gcp — GCP resource enumeration."""

    project_id: str | None = param(
        "GCP project ID (lowercase letters, digits, hyphens)",
        required=False,
        default=None,
        max_length=30,
        pattern=r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$",
    )
    credentials_file: str | None = param(
        "Path to service account JSON", required=False, default=None, max_length=512
    )


# ── Credential modules ────────────────────────────────────────────────────────


class CredentialCrackParams(ModuleParams):
    """credential.crack — Offline hash cracking via hashcat/john."""

    hashcat_path: str = param(
        "Path to hashcat binary", required=False, default="hashcat", max_length=512
    )
    wordlist: str = param(
        "Path to wordlist", required=False, default="", max_length=512
    )
    rules: str = param(
        "Hashcat rules file", required=False, default="best64.rule", max_length=256
    )


class GoldenTicketParams(ModuleParams):
    """credential.golden_ticket — Kerberos golden ticket forging."""

    domain: str = param("Target domain FQDN", min_length=3, pattern=r"^[\w.-]+$")
    domain_sid: str = param(
        "Domain SID (S-1-5-21-...)", pattern=r"^S-1-5-21-\d+-\d+-\d+$"
    )
    krbtgt_hash: SecretParam = param(
        "krbtgt NT hash (32 hex chars)", secret=True, min_length=32, max_length=32
    )
    username: str = param(
        "Identity to forge", required=False, default="Administrator", max_length=256
    )
    target: str = param("Target host", required=False, default="", max_length=253)


class PassSprayParams(ModuleParams):
    """credential.pass_spray — Password spraying against LDAP/SMB."""

    target: str = param("DC or target IP/hostname", min_length=3, max_length=253)
    domain: str = param("Domain FQDN", required=False, default="", max_length=253)
    users: list[str] = param("List of usernames to spray")
    passwords: list[str] = param("List of passwords to spray")
    delay_s: float = param(
        "Delay between attempts (seconds)", required=False, default=1.0, ge=0.0, le=60.0
    )
    max_per_user: int = param(
        "Max attempts per user (lockout protection)",
        required=False,
        default=1,
        ge=1,
        le=5,
    )


class PassTheHashParams(ModuleParams):
    """credential.pass_the_hash — SMB pass-the-hash authentication."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("Username", min_length=1, max_length=256)
    nt_hash: SecretParam = param(
        "NT hash (32 hex chars)", secret=True, min_length=32, max_length=32
    )
    lm_hash: str = param(
        "LM hash",
        required=False,
        default="aad3b435b51404eeaad3b435b51404ee",
        min_length=32,
        max_length=32,
    )
    domain: str = param("Domain", required=False, default="", max_length=253)
    command: str = param(
        "Verification command", required=False, default="whoami", max_length=500
    )


class CredentialReuseParams(ModuleParams):
    """credential.reuse — Test captured credentials against a target."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    protocol: str = param(
        "Protocol: smb|winrm|ssh|ldap",
        required=False,
        default="smb",
        pattern=r"^(smb|winrm|ssh|ldap)$",
    )


# ── Exfil modules ─────────────────────────────────────────────────────────────


class SecretsScanParams(ModuleParams):
    """exfil.secrets_scan — SSH remote scan for credential patterns."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("SSH username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    key_path: str | None = param(
        "SSH private key path", required=False, default=None, max_length=512
    )
    platform: str = param(
        "Target OS: linux|windows",
        required=False,
        default="linux",
        pattern=r"^(linux|windows)$",
    )


class SmbSharesParams(ModuleParams):
    """exfil.smb_shares — Enumerate SMB shares and search for sensitive files."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("Username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "Password", required=False, default=None, secret=True
    )
    domain: str = param("Domain", required=False, default="", max_length=253)
    max_depth: int = param(
        "Max directory traversal depth", required=False, default=3, ge=1, le=10
    )


class StagedCollectionParams(ModuleParams):
    """exfil.staged_collection — Collect files matching patterns via SSH."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("SSH username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    destination: str = param("Staging destination path or share", max_length=512)
    platform: str = param(
        "Target OS: linux|windows",
        required=False,
        default="linux",
        pattern=r"^(linux|windows)$",
    )
    max_files: int = param(
        "Max files to collect", required=False, default=200, ge=1, le=1000
    )


# ── Lateral movement modules ──────────────────────────────────────────────────


class LateralBaseParams(ModuleParams):
    """Shared params for lateral movement modules (remote execution — command runs on target)."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("Username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "Password", required=False, default=None, secret=True
    )
    domain: str = param("Domain", required=False, default="", max_length=253)
    command: str = param(
        "Command to execute on remote target",
        required=False,
        default="whoami /all",
        max_length=2048,
    )


class DCOMParams(LateralBaseParams):
    """lateral.dcom — DCOM lateral movement via MMC20/ShellWindows."""

    method: str = param(
        "DCOM method: auto|mmc20|shellwindows|shellbrowserwindow",
        required=False,
        default="auto",
        pattern=r"^(auto|mmc20|shellwindows|shellbrowserwindow)$",
    )


class PsExecParams(LateralBaseParams):
    """lateral.psexec — PsExec-style lateral movement via SMB + SCM."""

    service_name: str = param(
        "Temporary service name", required=False, default="", max_length=256
    )


class WmiExecParams(LateralBaseParams):
    """lateral.wmiexec — WMI remote execution."""

    pass


class WinRMParams(LateralBaseParams):
    """lateral.winrm — WinRM PowerShell remote execution."""

    pass


class RDPLateralParams(LateralBaseParams):
    """lateral.rdp — RDP lateral movement (HIGH_NOISE)."""

    pass


class SSHPivotParams(ModuleParams):
    """lateral.ssh_pivot — SSH tunnel SOCKS5 pivot."""

    target: str = param("SSH server IP or hostname", min_length=3, max_length=253)
    username: str = param("SSH username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    key_path: str | None = param(
        "SSH private key path", required=False, default=None, max_length=512
    )
    ssh_port: int = param("SSH port", required=False, default=22, ge=1, le=65535)
    socks_port: int = param(
        "Local SOCKS5 port", required=False, default=1080, ge=1024, le=65535
    )


class SMBRelayParams(ModuleParams):
    """lateral.smb_relay — SMB signing audit and relay candidate detection."""

    target: str | None = param(
        "Single target to check", required=False, default=None, max_length=253
    )
    targets: list[str] = param("List of targets to audit", required=False, default=[])
    check_ldap: bool = param("Also check LDAP signing", required=False, default=False)


# ── Linux modules ─────────────────────────────────────────────────────────────


class LinuxSSHParams(ModuleParams):
    """Shared SSH params for Linux post-exploitation modules."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("SSH username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    key_path: str | None = param(
        "SSH private key path", required=False, default=None, max_length=512
    )
    ssh_port: int = param("SSH port", required=False, default=22, ge=1, le=65535)


class ContainerEscapeParams(LinuxSSHParams):
    """linux.container — Docker/K8s container escape techniques."""

    pass


class KernelSuggesterParams(LinuxSSHParams):
    """linux.kernel_suggester — Kernel exploit suggester via uname."""

    pass


class LDPreloadParams(LinuxSSHParams):
    """linux.ld_preload — LD_PRELOAD privilege escalation."""

    pass


class NFSEscapeParams(LinuxSSHParams):
    """linux.nfs_escape — NFS no_root_squash escape."""

    pass


class ServiceHijackParams(LinuxSSHParams):
    """linux.service_hijack — Writable systemd service hijack."""

    pass


# ── Network modules ───────────────────────────────────────────────────────────


class PortScanParams(ModuleParams):
    """network.port_scan — TCP port scan."""

    target: str = param("Target IP, hostname, or CIDR", min_length=3, max_length=253)
    ports: str = param(
        "Port spec: top1000|all|22,80,443,8080-8090",
        required=False,
        default="top1000",
        max_length=512,
    )
    timeout: float = param(
        "Per-port timeout (seconds)", required=False, default=1.0, ge=0.1, le=10.0
    )
    threads: int = param(
        "Concurrent scan threads", required=False, default=100, ge=1, le=500
    )


class DNSEnumParams(ModuleParams):
    """network.dns_enum — DNS enumeration and zone transfer attempt."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    domain: str = param(
        "Domain to enumerate", required=False, default="", max_length=253
    )
    brute: bool = param("Brute-force subdomains", required=False, default=True)


class HTTPFingerprintParams(ModuleParams):
    """network.http_fingerprint — HTTP service and tech fingerprinting."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    ports: list[int] = param(
        "Ports to fingerprint", required=False, default=[80, 443, 8080, 8443]
    )
    timeout: float = param(
        "HTTP timeout (seconds)", required=False, default=5.0, ge=0.5, le=30.0
    )


class SNMPEnumParams(ModuleParams):
    """network.snmp_enum — SNMP community brute-force and OID walk."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    port: int = param("SNMP UDP port", required=False, default=161, ge=1, le=65535)
    communities: list[str] = param(
        "Community strings to try",
        required=False,
        default=["public", "private", "manager"],
    )


class ServiceDetectParams(ModuleParams):
    """network.service_detect — Banner-grab service version detection."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    ports: list[int] = param("Ports to check", required=False, default=[])
    timeout: float = param(
        "Per-port timeout (seconds)", required=False, default=3.0, ge=0.5, le=30.0
    )


class PivotParams(ModuleParams):
    """network.pivot — SSH tunnel SOCKS5 pivot infrastructure."""

    target: str = param("Pivot host IP or hostname", min_length=3, max_length=253)
    username: str = param("SSH username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "SSH password", required=False, default=None, secret=True
    )
    key_path: str | None = param(
        "SSH private key path", required=False, default=None, max_length=512
    )
    local_port: int = param(
        "Local SOCKS5 port", required=False, default=1080, ge=1024, le=65535
    )


# ── Persistence modules ───────────────────────────────────────────────────────


class PersistenceBaseParams(ModuleParams):
    """Shared params for persistence modules."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param(
        "Username with local admin rights", min_length=1, max_length=256
    )
    password: SecretParam | None = param(
        "Password", required=False, default=None, secret=True
    )
    domain: str = param("Domain", required=False, default="", max_length=253)


class ScheduledTaskParams(PersistenceBaseParams):
    """persistence.scheduled_task — Windows scheduled task persistence."""

    task_name: str = param(
        "Scheduled task name",
        required=False,
        default="AresUpdater",
        max_length=256,
        pattern=r"^[\w\s\-.]+$",
    )
    command: str = param(
        "Command to persist (runs as SYSTEM)",
        required=False,
        max_length=2048,
        default="powershell.exe -NoP -W Hidden -Enc BASE64",
    )


class RegistryRunParams(PersistenceBaseParams):
    """persistence.registry_run — Registry Run key persistence."""

    key_name: str = param(
        "Run key value name",
        required=False,
        default="AresUpdate",
        max_length=256,
        pattern=r"^[\w\s\-.]+$",
    )
    command: str = param(
        "Command to persist",
        required=False,
        max_length=2048,
        default="powershell.exe -NoP -W Hidden -Enc BASE64",
    )


class WMISubscriptionParams(PersistenceBaseParams):
    """persistence.wmi_subscription — WMI event subscription persistence."""

    subscription_name: str = param(
        "WMI subscription name",
        required=False,
        default="AresMonitor",
        max_length=256,
        pattern=r"^[\w\s\-.]+$",
    )
    command: str = param(
        "Command to persist",
        required=False,
        max_length=2048,
        default="powershell.exe -NoP -W Hidden -Enc BASE64",
    )


# ── Recon modules ─────────────────────────────────────────────────────────────


class FingerprintParams(ModuleParams):
    """recon.fingerprint — Environment fingerprinting (EDR, OS, domain)."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    timeout: float = param(
        "Timeout per check (seconds)", required=False, default=5.0, ge=0.5, le=30.0
    )


# ── Windows post-exploitation modules ────────────────────────────────────────


class WindowsBaseParams(ModuleParams):
    """Shared params for Windows post-exploitation modules."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param(
        "Username with local admin rights", min_length=1, max_length=256
    )
    password: SecretParam | None = param(
        "Password", required=False, default=None, secret=True
    )
    nt_hash: SecretParam | None = param(
        "NT hash for PTH (32 hex chars)",
        required=False,
        default=None,
        secret=True,
        min_length=32,
        max_length=32,
    )
    domain: str = param("Domain", required=False, default="", max_length=253)


class AppLockerBypassParams(WindowsBaseParams):
    """windows.applocker_bypass — AppLocker policy enumeration and bypass."""

    command: str = param(
        "Command to execute if bypass found",
        required=False,
        default="whoami /all",
        max_length=2048,
    )


class DPAPIParams(WindowsBaseParams):
    """windows.dpapi — DPAPI credential and browser password decryption."""

    targets: list[str] = param(
        "DPAPI target types: chrome|wifi|rdp|credentials",
        required=False,
        default=["chrome", "wifi", "credentials"],
    )


class LSASecretsParams(WindowsBaseParams):
    """windows.lsa_secrets — LSA secrets and cached credential extraction."""

    pass


class LsassDumpParams(WindowsBaseParams):
    """windows.lsass_dump — LSASS process memory dump and parsing."""

    technique: str = param(
        "Dump technique: comsvcs|secretsdump",
        required=False,
        default="comsvcs",
        pattern=r"^(comsvcs|secretsdump)$",
    )


class RegistryEnumParams(WindowsBaseParams):
    """windows.registry_enum — Registry credential hunting."""

    pass


class ScheduledTasksEnumParams(WindowsBaseParams):
    """windows.scheduled_tasks_enum — Scheduled task enumeration for privesc."""

    pass


class TokenImpersonationParams(ModuleParams):
    """windows.token_impersonation — Token impersonation via named pipe."""

    target: str = param("Target IP or hostname", min_length=3, max_length=253)
    username: str = param("Username", min_length=1, max_length=256)
    password: SecretParam | None = param(
        "Password", required=False, default=None, secret=True
    )
    domain: str = param("Domain", required=False, default="", max_length=253)


class UACBypassParams(WindowsBaseParams):
    """windows.uac_bypass — UAC configuration check and bypass."""

    technique: str = param(
        "Bypass technique: auto|fodhelper|eventvwr",
        required=False,
        default="auto",
        pattern=r"^(auto|fodhelper|eventvwr)$",
    )


class CoveragePredictorParams(ModuleParams):
    """opsec.coverage_predictor — Detection probability scoring."""

    noise_profile: str = param(
        "Campaign noise profile for scoring",
        required=False,
        default="normal",
        pattern=r"^(stealth|normal|aggressive)$",
    )


class CloudFederationParams(ModuleParams):
    """cloud.identity_federation_abuse — Cross-cloud SAML/OIDC federation abuse."""

    tenant_id: str | None = param("Azure tenant ID", required=False, default=None)
    client_id: str | None = param("Azure client ID", required=False, default=None)
    client_secret: SecretParam | None = param(
        "Azure client secret", required=False, default=None, secret=True
    )
    access_key: str | None = param("AWS Access Key ID", required=False, default=None)
    secret_key: SecretParam | None = param(
        "AWS Secret Key", required=False, default=None, secret=True
    )
    adfs_url: str | None = param(
        "ADFS base URL", required=False, default=None, max_length=512
    )
    krbtgt_hash: SecretParam | None = param(
        "krbtgt NT hash (for Golden SAML path check)",
        required=False,
        default=None,
        secret=True,
        min_length=32,
        max_length=32,
    )
    domain: str = param("Target domain", required=False, default="", max_length=253)
    mode: str = param(
        "Mode: enumerate|golden_saml|oauth_abuse",
        required=False,
        default="enumerate",
        pattern=r"^(enumerate|golden_saml|oauth_abuse)$",
    )


class EDRBypassParams(ModuleParams):
    """edr.bypass_adaptive — Adaptive EDR evasion."""

    edr_vendor: str = param(
        "EDR vendor: crowdstrike|sentinelone|defender_atp|defender_av|carbon_black|cylance|unknown",
        required=False,
        default="unknown",
        pattern=r"^(crowdstrike|sentinelone|defender_atp|defender_av|carbon_black|cylance|unknown)$",
    )
    target: str = param("Target host", required=False, default="", max_length=253)
    os_version: str = param(
        "Target OS version", required=False, default="", max_length=256
    )


class AIPlannerParams(ModuleParams):
    """ai.autonomous_planner — LLM-powered attack chain planning."""

    goal: str = param(
        "Attack goal: domain_admin|cloud_admin|data_exfil|persistence|full_compromise",
        required=False,
        default="domain_admin",
        pattern=r"^(domain_admin|enterprise_admin|cloud_admin|data_exfil|persistence|full_compromise)$",
    )
    llm_backend: str = param(
        "LLM backend: claude|openai|local",
        required=False,
        default="claude",
        pattern=r"^(claude|openai|local)$",
    )
    llm_model: str = param(
        "Specific LLM model (optional, uses default if empty)",
        required=False,
        default="",
        max_length=128,
    )
    auto_approve: bool = param(
        "Skip operator review and execute plan automatically (use with caution)",
        required=False,
        default=False,
    )


# ── Module → Params class registry ───────────────────────────────────────────


class MSSQLParams(ModuleParams):
    """Parameters for lateral.mssql — validated before execution."""

    target: str = Field(
        ..., min_length=1, max_length=253, description="MSSQL server IP or hostname"
    )
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(default="", max_length=256)
    port: int = Field(default=1433, ge=1, le=65535)
    technique: str = Field(
        default="xp_cmdshell", pattern=r"^(xp_cmdshell|linked|unc_coerce)$"
    )
    command: str = Field(
        default="whoami",
        max_length=500,
        # Allow alphanumeric, spaces, and common cmd chars — block quotes and semicolons
        pattern=r"^[a-zA-Z0-9 /\.\-_=@:,\(\)\[\]\*\?]+$",
        description="OS command to execute (no quotes or semicolons)",
    )
    linked: str = Field(
        default="",
        max_length=128,
        pattern=r"^[a-zA-Z0-9\.\-_]*$",
        description="Linked server name (alphanumeric only)",
    )
    listener: str = Field(
        default="",
        max_length=253,
        pattern=r"^[a-zA-Z0-9.\-:]*$",
        description="Attacker IP/hostname for NTLM capture (no special chars)",
    )


MODULE_PARAMS: dict[str, type[ModuleParams]] = {
    # ── Active Directory ──────────────────────────────────────────────────────
    "ad.enum_users": DomainAuthParams,
    "ad.enum_spn": DomainAuthParams,
    "ad.enum_acl": DomainAuthParams,
    "ad.enum_computers": DomainAuthParams,
    "ad.kerberoast": KerberoastParams,
    "ad.asreproast": ASREPRoastParams,
    "ad.dcsync": DCSyncParams,
    "ad.adcs": ADCSParams,
    "ad.coerce": CoerceParams,
    "ad.delegation_abuse": DelegationAbuseParams,
    "ad.laps_enum": LAPSEnumParams,
    "ad.sccm": SCCMParams,
    # ── Cloud ─────────────────────────────────────────────────────────────────
    "cloud.aws": AWSParams,
    "cloud.aws_privesc": AWSPrivescParams,
    "cloud.azure": AzureParams,
    "cloud.azure_ad": AzureADParams,
    "cloud.gcp": GCPParams,
    # ── Credential ────────────────────────────────────────────────────────────
    "credential.crack": CredentialCrackParams,
    "credential.golden_ticket": GoldenTicketParams,
    "credential.pass_spray": PassSprayParams,
    "credential.pass_the_hash": PassTheHashParams,
    "credential.reuse": CredentialReuseParams,
    # ── Exfil ─────────────────────────────────────────────────────────────────
    "exfil.secrets_scan": SecretsScanParams,
    "exfil.smb_shares": SmbSharesParams,
    "exfil.staged_collection": StagedCollectionParams,
    # ── Lateral ───────────────────────────────────────────────────────────────
    "lateral.dcom": DCOMParams,
    "lateral.psexec": PsExecParams,
    "lateral.wmiexec": WmiExecParams,
    "lateral.winrm": WinRMParams,
    "lateral.rdp": RDPLateralParams,
    "lateral.ssh_pivot": SSHPivotParams,
    "lateral.smb_relay": SMBRelayParams,
    "lateral.ntlm_relay": NTLMRelayParams,
    "lateral.mssql": MSSQLParams,
    # ── Linux ─────────────────────────────────────────────────────────────────
    "linux.privesc": LinuxPrivescParams,
    "linux.container": ContainerEscapeParams,
    "linux.kernel_suggester": KernelSuggesterParams,
    "linux.ld_preload": LDPreloadParams,
    "linux.nfs_escape": NFSEscapeParams,
    "linux.service_hijack": ServiceHijackParams,
    # ── Network ───────────────────────────────────────────────────────────────
    "network.port_scan": PortScanParams,
    "network.dns_enum": DNSEnumParams,
    "network.http_fingerprint": HTTPFingerprintParams,
    "network.snmp_enum": SNMPEnumParams,
    "network.service_detect": ServiceDetectParams,
    "network.pivot": PivotParams,
    # ── Persistence ───────────────────────────────────────────────────────────
    "persistence.scheduled_task": ScheduledTaskParams,
    "persistence.registry_run": RegistryRunParams,
    "persistence.wmi_subscription": WMISubscriptionParams,
    # ── Recon ─────────────────────────────────────────────────────────────────
    "recon.fingerprint": FingerprintParams,
    # ── OPSEC ─────────────────────────────────────────────────────────────────
    "opsec.coverage_predictor": CoveragePredictorParams,
    # ── EDR ───────────────────────────────────────────────────────────────────
    "edr.bypass_adaptive": EDRBypassParams,
    # ── AI ────────────────────────────────────────────────────────────────────
    "ai.autonomous_planner": AIPlannerParams,
    # ── Cloud (new) ───────────────────────────────────────────────────────────
    "cloud.identity_federation_abuse": CloudFederationParams,
    # ── Windows ───────────────────────────────────────────────────────────────
    "windows.applocker_bypass": AppLockerBypassParams,
    "windows.dpapi": DPAPIParams,
    "windows.lsa_secrets": LSASecretsParams,
    "windows.lsass_dump": LsassDumpParams,
    "windows.registry_enum": RegistryEnumParams,
    "windows.scheduled_tasks_enum": ScheduledTasksEnumParams,
    "windows.token_impersonation": TokenImpersonationParams,
    "windows.uac_bypass": UACBypassParams,
}


def validate_module_params(
    module_id: str, raw_params: dict[str, Any]
) -> dict[str, Any]:
    """
    Validate raw_params against the module's Pydantic schema.
    Returns validated dict (with SecretStr values accessible via .get_secret_value()).
    Raises pydantic.ValidationError with field-level errors on failure.
    Raises KeyError if module_id has no registered params model.
    """
    model_cls = MODULE_PARAMS.get(module_id)
    if not model_cls:
        return raw_params  # No schema registered → pass through

    validated = model_cls.validate_dict(raw_params)
    # Convert back to dict, keeping SecretStr objects intact for modules
    result: dict[str, Any] = {}
    for name in validated.model_fields:
        val = getattr(validated, name, None)
        if val is None and name not in (validated.model_fields_set or set()):
            continue
        result[name] = val
    # Include extra fields (allowed by model_config extra="allow")
    for name, val in (
        validated.__pydantic_extra__.items() if validated.__pydantic_extra__ else []
    ):
        result[name] = val
    return result
