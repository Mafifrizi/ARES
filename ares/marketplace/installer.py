"""
ARES Plugin Marketplace
Install modules from git repositories, URLs, or local paths.

Commands:
  ares module install recon/subfinder          # from ARES community registry
  ares module install github.com/user/module   # from GitHub
  ares module install ./my_module.py           # from local path
  ares module install https://...module.py     # from URL
  ares module uninstall subfinder
  ares module search kerberos
  ares module update --all

Module manifest format (module_name.ares.json):
{
  "id":          "recon.subfinder",
  "name":        "Subfinder Integration",
  "description": "DNS subdomain enumeration via subfinder",
  "author":      "community",
  "version":     "1.0.0",
  "opsec_level": "low",
  "requires":    ["domain_name"],
  "outputs":     ["hostname"],
  "mitre":       ["T1018"],
  "entry":       "subfinder_module.py",
  "deps":        []
}

Install directory: ~/.ares/plugins/
Manifest registry: ~/.ares/plugins/registry.json
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.marketplace")

PLUGINS_DIR   = Path.home() / ".ares" / "plugins"

INSTALLED_REGISTRY: "Path" = Path.home() / ".ares" / "marketplace" / "installed.json"
REGISTRY_FILE = Path.home() / ".ares" / "plugins" / "registry.json"

# Community module index
COMMUNITY_INDEX_URL = "https://raw.githubusercontent.com/ares-framework/modules/main/index.json"

# Bundled offline index — always available, no internet required.
# `ares module search` and CLI work fully offline using this index.
# Live fetch overlays additional community modules when ARES_MARKETPLACE_LIVE=true.
_BUNDLED_INDEX: "dict" = {
    "schema_version": "1.0",
    "source": "bundled",
    "modules": [
        {"id": "ad.kerberoast",      "name": "Kerberoasting",           "category": "ad",
         "description": "Request TGS tickets for SPN accounts — hashcat-ready hashes",
         "opsec": "medium", "requires": ["domain_creds"], "outputs": ["kerberos_hashes"],
         "mitre": ["T1558.003"], "builtin": True},
        {"id": "ad.asreproast",      "name": "ASREPRoasting",           "category": "ad",
         "description": "Capture AS-REP hashes from accounts without Kerberos pre-auth",
         "opsec": "low",    "requires": [],                "outputs": ["asrep_hashes"],
         "mitre": ["T1558.004"], "builtin": True},
        {"id": "ad.dcsync",          "name": "DCSync",                  "category": "ad",
         "description": "Replicate domain hashes via MS-DRSR (requires DA rights)",
         "opsec": "high_noise", "requires": ["domain_admin_creds"], "outputs": ["ntlm_hashes"],
         "mitre": ["T1003.006"], "builtin": True},
        {"id": "ad.enum_users",      "name": "AD User Enumeration",     "category": "ad",
         "description": "Enumerate domain users, attributes, dormant accounts, password policy",
         "opsec": "low",    "requires": [],                "outputs": ["user_list"],
         "mitre": ["T1087.002", "T1201"], "builtin": True},
        {"id": "ad.enum_spn",        "name": "AD SPN Enumeration",      "category": "ad",
         "description": "Find SPN accounts (Kerberoasting candidates)",
         "opsec": "low",    "requires": [],                "outputs": ["spn_list"],
         "mitre": ["T1558.003", "T1087.002"], "builtin": True},
        {"id": "ad.enum_computers",  "name": "AD Computer Enumeration", "category": "ad",
         "description": "Enumerate domain computers, OS versions, stale accounts, DCs",
         "opsec": "low",    "requires": [],                "outputs": ["computer_list"],
         "mitre": ["T1018", "T1087.002"], "builtin": True},
        {"id": "ad.enum_acl",        "name": "AD ACL Enumeration",      "category": "ad",
         "description": "Find WriteDACL, GenericAll, GenericWrite, DCSync delegation misconfigs",
         "opsec": "low",    "requires": [],                "outputs": ["acl_findings"],
         "mitre": ["T1222.001", "T1003.006"], "builtin": True},
        {"id": "cloud.aws",          "name": "AWS Recon & Attack",      "category": "cloud",
         "description": "IAM enum, S3 misconfig, IMDS check, Security Group audit",
         "opsec": "low",    "requires": [],                "outputs": ["aws_findings"],
         "mitre": ["T1526", "T1530", "T1552.005", "T1580"], "builtin": True},
        {"id": "cloud.azure",        "name": "Azure Recon & Attack",    "category": "cloud",
         "description": "AAD enum, storage misconfig, RBAC audit, NSG rules",
         "opsec": "low",    "requires": [],                "outputs": [],
         "mitre": ["T1526", "T1530", "T1580"], "builtin": True},
        {"id": "cloud.gcp",          "name": "GCP Recon & Attack",      "category": "cloud",
         "description": "IAM bindings, GCS misconfig, metadata server, SA key audit",
         "opsec": "low",    "requires": [],                "outputs": [],
         "mitre": ["T1526", "T1530", "T1552.005"], "builtin": True},
        {"id": "linux.privesc",      "name": "Linux Privilege Escalation","category": "linux",
         "description": "SUID, sudo, cron, capabilities, writable PATH — local or remote SSH",
         "opsec": "medium", "requires": [],                "outputs": ["privesc_vectors"],
         "mitre": ["T1548.001", "T1053.003", "T1574.006"], "builtin": True},
        {"id": "linux.container",    "name": "Container Escape",        "category": "linux",
         "description": "Docker socket abuse, privileged escape, K8s RBAC misconfigs",
         "opsec": "medium", "requires": [],                "outputs": [],
         "mitre": ["T1611", "T1552.007", "T1613"], "builtin": True},
        {"id": "lateral.psexec",     "name": "PsExec Lateral",          "category": "lateral",
         "description": "SMB lateral movement via Service Control Manager",
         "opsec": "high_noise", "requires": ["smb_access", "local_admin_creds"],
         "outputs": ["lateral_session"], "mitre": ["T1569.002"], "builtin": True},
        {"id": "lateral.wmiexec",    "name": "WmiExec Lateral",         "category": "lateral",
         "description": "WMI lateral movement via Win32_Process.Create",
         "opsec": "medium", "requires": ["wmi_access", "domain_creds"],
         "outputs": ["lateral_session"], "mitre": ["T1047"], "builtin": True},
        {"id": "lateral.winrm",      "name": "WinRM Lateral",           "category": "lateral",
         "description": "PowerShell Remoting / WinRM lateral movement",
         "opsec": "medium", "requires": ["winrm_access", "domain_creds"],
         "outputs": ["lateral_session"], "mitre": ["T1021.006"], "builtin": True},
        {"id": "lateral.ssh_pivot",  "name": "SSH Pivot",               "category": "lateral",
         "description": "SSH lateral movement and SOCKS5 proxy pivot",
         "opsec": "low",    "requires": ["ssh_access", "ssh_credentials"],
         "outputs": ["lateral_session", "socks5_proxy"], "mitre": ["T1021.004"], "builtin": True},
        {"id": "lateral.rdp",        "name": "RDP Lateral",             "category": "lateral",
         "description": "RDP lateral movement — high noise",
         "opsec": "high_noise", "requires": ["rdp_access", "domain_creds"],
         "outputs": ["lateral_session"], "mitre": ["T1021.001"], "builtin": True},
        {"id": "exfil.smb_shares",   "name": "SMB Share Enumeration",   "category": "exfil",
         "description": "Enumerate accessible SMB shares and scan for sensitive files",
         "opsec": "medium", "requires": ["target", "credential"],
         "outputs": ["file_share_list", "sensitive_file_paths"],
         "mitre": ["T1039", "T1021.002"], "builtin": True},
        {"id": "exfil.secrets_scan", "name": "Secrets Scanner",         "category": "exfil",
         "description": "Scan filesystem for hardcoded credentials and API keys",
         "opsec": "low",    "requires": ["target"],
         "outputs": ["credential_list", "sensitive_data_found"],
         "mitre": ["T1552", "T1552.001", "T1083"], "builtin": True},
        {"id": "credential.reuse",   "name": "Credential Reuse",        "category": "credential",
         "description": "Try captured credentials against target hosts",
         "opsec": "medium", "requires": ["target"],
         "outputs": ["valid_credentials", "owned_hosts"],
         "mitre": ["T1078", "T1550.002"], "builtin": True},
        {"id": "persistence.scheduled_task", "name": "Scheduled Task Persistence",
         "category": "persistence",
         "description": "Register a scheduled task via impacket tsch RPC",
         "opsec": "medium", "requires": ["target", "credential"],
         "outputs": ["persistence_established", "task_name"],
         "mitre": ["T1053.005"], "builtin": True},

        # ── Network modules ──
        {"id": "network.port_scan",     "name": "TCP Port Scanner",         "category": "network",
         "description": "Async TCP connect scan, maps open ports to services and attack modules",
         "opsec": "medium", "requires": [],             "outputs": ["open_ports", "service_map"],
         "mitre": ["T1046"], "builtin": True},
        {"id": "network.service_detect","name": "Service Detection",        "category": "network",
         "description": "Banner grabbing and version fingerprinting on open ports",
         "opsec": "low",    "requires": ["open_ports"],  "outputs": ["service_versions", "vulnerable_services"],
         "mitre": ["T1046", "T1590.004"], "builtin": True},
        {"id": "network.http_fingerprint","name": "HTTP Fingerprinting",    "category": "network",
         "description": "Detect web server, framework, CMS, and exposed admin interfaces",
         "opsec": "low",    "requires": [],             "outputs": ["web_fingerprint", "admin_interfaces"],
         "mitre": ["T1592.002", "T1046"], "builtin": True},
        {"id": "network.dns_enum",      "name": "DNS Enumeration",         "category": "network",
         "description": "Zone transfer attempt, subdomain brute, and DNS record enumeration",
         "opsec": "low",    "requires": [],             "outputs": ["dns_records", "subdomains"],
         "mitre": ["T1590.002"], "builtin": True},
        {"id": "network.snmp_enum",      "name": "SNMP Enumeration",         "category": "network",
         "description": "Test SNMP community strings and enumerate system info, interfaces, processes",
         "opsec": "low",    "requires": [],                "outputs": ["snmp_findings","system_info"],
         "mitre": ["T1046","T1590"], "builtin": True},
        # ── Windows modules ──
        {"id": "windows.token_impersonation","name": "Token Impersonation","category": "windows",
         "description": "Detect SeImpersonatePrivilege — prerequisite for Potato-family LPE",
         "opsec": "medium", "requires": ["lateral_session"], "outputs": ["privesc_vectors"],
         "mitre": ["T1134.001", "T1134.002"], "builtin": True},
        {"id": "windows.lsa_secrets",   "name": "LSA Secrets & SAM Dump", "category": "windows",
         "description": "Extract local account hashes (SAM) and LSA secrets via impacket secretsdump",
         "opsec": "high_noise", "requires": ["local_admin_creds"], "outputs": ["ntlm_hashes", "lsa_secrets"],
         "mitre": ["T1003.002", "T1003.004"], "builtin": True},
        # ── Linux extra modules ──
        {"id": "linux.kernel_suggester","name": "Kernel Exploit Suggester","category": "linux",
         "description": "Map kernel version to known LPE CVEs — detection only, no exploitation",
         "opsec": "low",    "requires": ["ssh_credentials"], "outputs": ["privesc_vectors"],
         "mitre": ["T1068", "T1082"], "builtin": True},
        # ── Credential extra modules ──
        {"id": "credential.golden_ticket","name": "Golden Ticket Forgery", "category": "credential",
         "description": "Forge Kerberos TGT using krbtgt hash — persistent domain access",
         "opsec": "medium", "requires": ["ntlm_hashes", "domain_admin_creds"], "outputs": ["golden_ticket"],
         "mitre": ["T1558.001"], "builtin": True},
        {"id": "credential.pass_the_hash","name": "Pass-the-Hash",        "category": "credential",
         "description": "Authenticate to target using NTLM hash without plaintext password",
         "opsec": "medium", "requires": ["ntlm_hashes"],    "outputs": ["valid_credentials", "owned_hosts"],
         "mitre": ["T1550.002"], "builtin": True},
        {"id": "credential.pass_spray", "name": "Password Spray",         "category": "credential",
         "description": "Low-and-slow password spray with built-in lockout protection",
         "opsec": "medium", "requires": ["user_list"],       "outputs": ["valid_credentials"],
         "mitre": ["T1110.003"], "builtin": True},
        # ── Persistence extra modules ──
        {"id": "persistence.wmi_subscription","name": "WMI Event Subscription","category": "persistence",
         "description": "Create WMI FilterToConsumerBinding for stealthy persistent execution",
         "opsec": "medium", "requires": ["local_admin_creds"], "outputs": ["persistence_established"],
         "mitre": ["T1546.003"], "builtin": True},
        # ── Exfil extra modules ──
        {"id": "exfil.staged_collection","name": "Staged File Collection",  "category": "exfil",
         "description": "Find and inventory sensitive files before exfiltration decision",
         "opsec": "medium", "requires": ["lateral_session"], "outputs": ["sensitive_file_paths", "collection_inventory"],
         "mitre": ["T1119", "T1039"], "builtin": True},
        # ── Cloud extra modules ──
        {"id": "cloud.aws_privesc",     "name": "AWS IAM Privilege Escalation","category": "cloud",
         "description": "Enumerate IAM permissions and identify privilege escalation paths",
         "opsec": "low",    "requires": [],             "outputs": ["aws_privesc_paths", "aws_findings"],
         "mitre": ["T1078.004", "T1548"], "builtin": True},
        {"id": "persistence.registry_run", "name": "Registry Run Key Persistence",
         "category": "persistence",
         "description": "Write a Run key via impacket rrp RPC",
         "opsec": "medium", "requires": ["target", "credential"],
         "outputs": ["persistence_established", "registry_key"],
         "mitre": ["T1547.001"], "builtin": True},
    ],
}

# Live community index — fetched from GitHub when ARES_MARKETPLACE_LIVE=true.
# Disabled by default: the public ares-framework/modules repo is not yet published.
# Enable: export ARES_MARKETPLACE_LIVE=true
import os as _os
_COMMUNITY_INDEX_AVAILABLE = _os.getenv("ARES_MARKETPLACE_LIVE", "").lower() in ("1", "true", "yes")


# ── Module manifest ───────────────────────────────────────────────────────────

@dataclass
class ModuleManifest:
    module_id:   str = ""   # primary identifier (used in tests)
    id:          str = ""   # legacy alias
    name:        str = ""
    description: str = ""
    version:     str      = "1.0.0"
    author:      str      = "unknown"
    opsec_level: str      = "medium"
    requires:    list[str] = field(default_factory=list)
    outputs:     list[str] = field(default_factory=list)
    mitre:       list[str] = field(default_factory=list)
    entry:       str      = ""       # main .py filename
    module_file: str      = ""       # alias for entry
    plugin_dir:  str      = ""       # directory where plugin files live
    deps:        list[str] = field(default_factory=list)  # pip deps
    source_url:  str      = ""
    installed_at: str     = ""
    verified:    bool     = False  # True if SHA-256 hash check passed
    sha256:      str      = ""     # expected hash (set in manifest.json for signed modules)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleManifest":
        fields = set(cls.__dataclass_fields__.keys())
        mapped = {k: v for k, v in data.items() if k in fields}
        # Handle module_id → id mapping
        if "module_id" in data and "id" not in mapped:
            mapped["id"] = data["module_id"]
        return cls(**mapped)

    def __post_init__(self) -> None:
        if self.module_id and not self.id:
            self.id = self.module_id
        elif self.id and not self.module_id:
            self.module_id = self.id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Local registry ────────────────────────────────────────────────────────────

class LocalRegistry:
    """Tracks installed plugins in ~/.ares/plugins/registry.json"""

    def __init__(self) -> None:
        try:
            PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        import ares.marketplace.installer as _self_module
        reg_path = getattr(_self_module, "INSTALLED_REGISTRY", REGISTRY_FILE)
        try:
            if reg_path.exists():
                return json.loads(reg_path.read_text())
        except (OSError, ValueError, AttributeError):
            pass
        return {"plugins": {}}

    def _save(self) -> None:
        import ares.marketplace.installer as _self_module
        reg_path = getattr(_self_module, "INSTALLED_REGISTRY", REGISTRY_FILE)
        try:
            reg_path.parent.mkdir(parents=True, exist_ok=True)
            reg_path.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def install(self, manifest: ModuleManifest, plugin_dir: Path) -> None:
        key = manifest.module_id or manifest.id
        self._data["plugins"][key] = {
            **manifest.to_dict(),
            "plugin_dir": str(plugin_dir),
        }
        self._save()

    def uninstall(self, module_id: str) -> None:
        self._data["plugins"].pop(module_id, None)
        self._save()

    def get(self, module_id: str) -> dict[str, Any] | None:
        return self._data["plugins"].get(module_id)

    def list_all(self) -> list[dict[str, Any]]:
        return list(self._data["plugins"].values())

    def is_installed(self, module_id: str) -> bool:
        return module_id in self._data["plugins"]


# ── Installer ─────────────────────────────────────────────────────────────────

class ModuleInstaller:
    """
    Install ARES modules from multiple sources.

    Source detection:
      "./path" or "/path"    → local file/directory
      "https://..."          → download URL
      "github.com/..."       → GitHub raw download
      "short/name"           → community registry lookup
    """

    def __init__(self) -> None:
        self.registry = LocalRegistry()

    # ── Main install entry ──────────────────────────────────────────────────

    def install(self, source: str, force: bool = False,
                verify_signature: bool = True) -> ModuleManifest:
        """
        Install a module from any source. Returns the manifest on success.
        Raises on failure.
        """
        source_type = self._detect_source(source)
        logger.info("marketplace_install_start", source=source, source_type=source_type)

        if source_type == "local":
            return self._install_local(Path(source), force)
        elif source_type == "url":
            return self._install_url(source, force, verify_signature=verify_signature)
        elif source_type == "github":
            return self._install_github(source, force, verify_signature=verify_signature)
        elif source_type == "community":
            return self._install_community(source, force)
        else:
            raise ValueError(f"Cannot determine install source for: {source}")

    def install_as_dict(
        self,
        source: str,
        force: bool = False,
        verify_signature: bool = True,
    ) -> dict[str, Any]:
        """
        Like install() but returns a CLI-friendly dict instead of raising.

        Returns:
            {"success": True, "version": "...", "path": "...", "verified": bool}
          or
            {"success": False, "error": "..."}
        """
        try:
            manifest = self.install(source, force=force,
                                    verify_signature=verify_signature)
            return {
                "success":  True,
                "version":  manifest.version,
                "path":     str(manifest.plugin_dir) if manifest.plugin_dir else "",
                "verified": verify_signature,
                "module_id": manifest.module_id,
                "name":     manifest.name,
            }
        except (FileNotFoundError, ValueError, OSError, RuntimeError) as exc:
            logger.warning("marketplace_install_failed", source=source, error=str(exc))
            return {"success": False, "error": str(exc)}

    def uninstall(self, module_id: str) -> bool:
        """Remove an installed module. Returns True if found and removed."""
        entry = self.registry.get(module_id)
        if not entry:
            logger.warning("marketplace_uninstall_not_found", module_id=module_id)
            return False

        plugin_dir = Path(entry.get("plugin_dir", ""))
        if plugin_dir.exists() and plugin_dir.parent == PLUGINS_DIR:
            shutil.rmtree(plugin_dir)

        self.registry.uninstall(module_id)
        logger.info("marketplace_uninstall_ok", module_id=module_id)
        return True

    def update(self, module_id: str) -> ModuleManifest:
        """Re-install from original source URL."""
        entry = self.registry.get(module_id)
        if not entry:
            raise ValueError(f"Module '{module_id}' is not installed")

        source_url = entry.get("source_url", "")
        if not source_url:
            raise ValueError(f"No source URL recorded for '{module_id}' — cannot auto-update")

        self.uninstall(module_id)
        return self.install(source_url, force=True)

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search the community index. Returns matching module entries."""
        index = self._fetch_community_index()
        if not index:
            return []
        q = query.lower()
        return [
            m for m in index.get("modules", [])
            if q in m.get("id", "").lower()
            or q in m.get("name", "").lower()
            or q in m.get("description", "").lower()
            or any(q in t.lower() for t in m.get("mitre", []))
        ]

    def list_installed(self) -> list[dict[str, Any]]:
        return self.registry.list_all()

    # ── Source handlers ─────────────────────────────────────────────────────

    def _install_local(self, path: Path, force: bool) -> ModuleManifest:
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if path.is_file() and path.suffix == ".py":
            return self._install_single_file(path, source_url=str(path), force=force)

        # Directory with manifest
        manifest_file = path / f"{path.name}.ares.json"
        if not manifest_file.exists():
            # Auto-generate minimal manifest from module class
            manifest = self._infer_manifest_from_file(
                next(path.glob("*.py"), None) or path, source_url=str(path)
            )
        else:
            manifest = ModuleManifest.from_dict(json.loads(manifest_file.read_text()))
            manifest.source_url = str(path)

        return self._finalize_install(path, manifest, force)

    def _read_manifest_from_file(self, path: "Path") -> dict | None:
        """
        Extract manifest metadata from a module .py file without installing it.
        Looks for a MODULE_MANIFEST dict or reads a sidecar manifest.json.
        Returns None if no manifest data found.
        """
        try:
            sidecar = path.parent / "manifest.json"
            if sidecar.exists():
                import json as _json
                return _json.loads(sidecar.read_text())
            # No sidecar — cannot extract sha256 from source alone
            return None
        except Exception:
            return None

    def _install_url(self, url: str, force: bool,
                     verify_signature: bool = True) -> ModuleManifest:
        if not verify_signature:
            logger.warning("marketplace_url_install_unverified",
                           url=url,
                           risk="Module downloaded without signature verification — supply chain risk")
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "module.py"
            try:
                # Use httpx for proper SSL verification and redirect control
                import httpx
                with httpx.Client(follow_redirects=False, timeout=30) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                    local.write_bytes(resp.content)
            except ImportError:
                # httpx always in deps — this is a safety net only
                urllib.request.urlretrieve(url, str(local))
            except Exception as e:
                raise ConnectionError(f"Failed to download {url}: {e}") from e
            # Verify BEFORE installing — if hash fails, file never touches plugin dir
            if verify_signature and local.exists():
                # Read manifest from tmp file to get sha256 without installing
                _tmp_manifest = self._read_manifest_from_file(local)
                if _tmp_manifest and _tmp_manifest.get("sha256"):
                    import hashlib
                    actual_hash = hashlib.sha256(local.read_bytes()).hexdigest()
                    expected    = _tmp_manifest["sha256"]
                    if actual_hash != expected:
                        raise ValueError(
                            f"Module from {url} failed integrity check BEFORE install: "
                            f"expected SHA-256 {expected[:16]}... "
                            f"got {actual_hash[:16]}... "
                            "File was NOT installed. Use verify_signature=False to override (not recommended)."
                        )
                else:
                    logger.warning(
                        "marketplace_no_signature: module has no sha256 in manifest "
                        "— cannot verify integrity. Set verify_signature=False to silence.",
                        url=url,
                    )
            manifest = self._install_single_file(local, source_url=url, force=force)
            # Post-install: set verified flag if hash matched above
            if verify_signature and manifest.sha256:
                manifest.verified = True
            return manifest

    def _install_github(self, spec: str, force: bool,
                        verify_signature: bool = True) -> ModuleManifest:
        """
        spec formats:
          github.com/user/repo
          github.com/user/repo/blob/main/module.py
        """
        spec = spec.replace("github.com/", "")
        parts = spec.split("/")

        if len(parts) >= 2:
            user, repo = parts[0], parts[1]
            file_path  = "/".join(parts[4:]) if len(parts) > 4 else f"{repo}.py"
            raw_url    = f"https://raw.githubusercontent.com/{user}/{repo}/main/{file_path}"
        else:
            raise ValueError(f"Invalid GitHub spec: {spec}")

        logger.info("marketplace_github_install", url=raw_url)
        return self._install_url(raw_url, force, verify_signature=verify_signature)

    def _install_community(self, short_name: str, force: bool) -> ModuleManifest:
        """Install by short name from community index (e.g. 'recon/subfinder')."""
        index = self._fetch_community_index()
        if not index:
            raise ConnectionError("Could not reach community module index")

        modules = {m["id"]: m for m in index.get("modules", [])}
        if short_name not in modules:
            raise ValueError(f"Module '{short_name}' not found in community index")

        entry = modules[short_name]
        download_url = entry.get("download_url", "")
        if not download_url:
            raise ValueError(f"No download URL for module '{short_name}'")

        return self._install_url(download_url, force)

    # ── Common install path ─────────────────────────────────────────────────

    def _install_single_file(self, file_path: Path, source_url: str, force: bool) -> ModuleManifest:
        manifest = self._infer_manifest_from_file(file_path, source_url)
        dest_dir = PLUGINS_DIR / manifest.id.replace(".", "_")
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, dest_dir / file_path.name)
        return self._finalize_install(dest_dir, manifest, force)

    def _finalize_install(self, plugin_dir: Path, manifest: ModuleManifest, force: bool) -> ModuleManifest:
        import datetime
        if self.registry.is_installed(manifest.id) and not force:
            raise FileExistsError(
                f"Module '{manifest.id}' already installed. Use force=True or ares module update."
            )

        # Install pip deps if any
        if manifest.deps:
            self._install_pip_deps(manifest.deps)

        manifest.installed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.registry.install(manifest, plugin_dir)
        logger.info("marketplace_install_ok", module_id=manifest.id, version=manifest.version)
        return manifest

    def _install_pip_deps(self, deps: list[str]) -> None:
        if not deps:
            return

        # Allowlist regex — rejects pip flags (--index-url, etc.) and shell injection
        import re
        _DEP_RE = re.compile(
            r"^[a-zA-Z0-9]"               # must start with alphanumeric
            r"[a-zA-Z0-9._-]*"            # package name chars
            r"(\[[\w,\s]+\])?"            # optional extras e.g. [security,async]
            r"(==|>=|<=|~=|!=|>|<)?"      # optional version operator
            r"[\w.*]*$"                    # optional version value
        )
        invalid = [d for d in deps if not _DEP_RE.match(d)]
        if invalid:
            raise ValueError(
                f"Dependency validation failed — rejected unsafe dep string(s): {invalid}. "
                "Only PEP 508 package specifiers are allowed (no flags, no URLs, no shell)."
            )

        logger.info("marketplace_installing_deps", deps=deps)
        import subprocess
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--break-system-packages", *deps],
            check=True,
            timeout=300,  # 5 minutes max — prevents hang on network issues
        )

    def _infer_manifest_from_file(self, path: Path, source_url: str = "") -> ModuleManifest:
        """Auto-generate manifest by reading module class attributes."""
        import importlib.util, inspect

        spec = importlib.util.spec_from_file_location("_ares_inspect", path)
        if not spec or not spec.loader:
            return ModuleManifest(id=path.stem, name=path.stem, description="", source_url=source_url)

        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        except (ImportError, AttributeError, OSError):
            return ModuleManifest(id=path.stem, name=path.stem, description="", source_url=source_url)

        from ares.modules.base import BaseModule
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            if issubclass(cls, BaseModule) and cls is not BaseModule and cls.MODULE_ID:
                return ModuleManifest(
                    id          = cls.MODULE_ID,
                    name        = cls.MODULE_NAME or cls.MODULE_ID,
                    description = cls.MODULE_DESCRIPTION,
                    opsec_level = cls.OPSEC_LEVEL.value if hasattr(cls.OPSEC_LEVEL, "value") else str(cls.OPSEC_LEVEL),
                    requires    = list(cls.REQUIRES),
                    outputs     = list(cls.OUTPUTS),
                    mitre       = list(cls.MITRE_TECHNIQUES),
                    entry       = path.name,
                    source_url  = source_url,
                )

        return ModuleManifest(id=path.stem, name=path.stem, description="external module",
                              entry=path.name, source_url=source_url)

    @staticmethod
    def _detect_source(source: str) -> str:
        if source.startswith(("./", "/", "../")) or Path(source).exists():
            return "local"
        if source.startswith("https://"):   # http:// rejected — MITM risk
            return "url"
        if source.startswith("github.com/"):
            return "github"
        return "community"

    @staticmethod
    def _fetch_community_index() -> dict[str, Any]:
        """
        Return the module index to search against.

        Priority:
          1. Live GitHub index (only when ARES_MARKETPLACE_LIVE=true)
          2. Bundled offline index (always available — shipped with ARES)

        The bundled index contains all 22 built-in modules so `ares module search`
        and `ares module list` work fully offline without any internet access.
        """
        if _COMMUNITY_INDEX_AVAILABLE:
            try:
                import httpx
                with httpx.Client(follow_redirects=False, timeout=10) as client:
                    resp = client.get(COMMUNITY_INDEX_URL)
                    resp.raise_for_status()
                    live = resp.json()
                # Merge: live modules overlay bundled, dedup by id
                merged_mods: dict[str, Any] = {
                    m["id"]: m for m in _BUNDLED_INDEX.get("modules", [])
                }
                for m in live.get("modules", []):
                    merged_mods[m["id"]] = m
                return {"schema_version": "1.0", "source": "live",
                        "modules": list(merged_mods.values())}
            except Exception as exc:
                logger.warning("marketplace_live_index_failed", error=str(exc)[:100],
                               fallback="bundled_index")
        # Offline fallback — always works
        return _BUNDLED_INDEX
