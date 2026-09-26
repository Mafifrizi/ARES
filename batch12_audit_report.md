# ARES Security Audit Report: Batch 12 — Host Configuration, Binary Parsing & Secrets Reconnaissance (FINAL BATCH)

> **Audit Date**: 26 September 2026  
> **Auditor**: Antigravity Autonomous Security Engineer  
> **Scope**: 6 Final Tier-2 Modules & Binary Parsing Engines  
>   - [`ares/modules/windows/registry_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/registry_enum.py) (`windows.registry_enum`)  
>   - [`ares/modules/windows/scheduled_tasks_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/scheduled_tasks_enum.py) (`windows.scheduled_tasks_enum`)  
>   - [`ares/modules/linux/kernel_suggester.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/kernel_suggester.py) (`linux.kernel_suggester`)  
>   - [`ares/modules/linux/_parsers.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/_parsers.py) (Binary parsing library: ccache, keytab, kirbi, TDB)  
>   - [`ares/modules/exfil/secrets_scan.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/secrets_scan.py) (`exfil.secrets_scan`)  
>   - [`ares/modules/exfil/smb_shares.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/smb_shares.py) (`exfil.smb_shares`)  
> **Governing Standards**: `AGENTS.md` (Rules 1–5), Gate 6 (Vault Protection), Anti-Hype Policy, B1–B7 Checklist Framework  

---

## 1. Executive Summary & Batch Metrics

Batch 12 concludes the 12-batch offensive module security audit across the entire ARES codebase. This batch covers host configuration inspection (Windows Registry and Scheduled Tasks via SMB/RPC), Linux kernel vulnerability estimation, low-level binary Kerberos/TDB parser engines, and credential/sensitive file reconnaissance (secrets scanner and SMB share traversal).

The audit identified **6 new security, architectural, and data loss findings** (`MOD-069` through `MOD-074`):
1. **Input Validation Asymmetry (`MOD-069`)**: `validate()` checks only `target`, ignoring required credentials (`username`), leading to silent execution aborts instead of pre-flight admission errors.
2. **Raw Output Normalizer Gap & Domain Object Bleed (`MOD-070`)**: Raw output keys (`cleartext_credentials`, `credential_hints`, `scheduled_tasks`, `privesc_vectors`) receive un-serialized `Finding` objects that have zero handlers in `ArtifactNormalizerPipeline`.
3. **Flawed Heuristic & Userspace CVE False Positives (`MOD-071`)**: Linux kernel suggester matches userspace CVEs (PwnKit CVE-2021-4034, Baron Samedit CVE-2021-3156) against generic kernel regexes (`[345]\.[0-9]+`), yielding 100% false positive findings across modern Linux distributions.
4. **Pseudo-Parser in `KirbiASN1Codec.decode_kirbi()` (`MOD-072`)**: Does not parse ASN.1 KRB-CRED structures, hardcodes session keys to 32 zero bytes (`"00" * 32`), and naively guesses client principal names, corrupting all converted tickets.
5. **Scope Guard Protocol Defaulting and Incomplete Pre-Flight Validation (`MOD-073`)**: `exfil.secrets_scan` and `exfil.smb_shares` pass protocol string `"default"` to `before_request()`, bypassing protocol-specific port and noise profiles, while omitting username validation in `validate()`.
6. **Exfil Raw Output Keys Missing from Normalizer Contract (`MOD-074`)**: Telemetry keys `credential_list`, `discovered_secrets`, `sensitive_data_found`, `file_share_list`, and `sensitive_file_paths` are completely dropped by `ArtifactNormalizerPipeline`.

### Summary of Batch 12 Audit Findings

| Finding ID | Module(s) Affected | Severity | Audit Category | Description |
|---|---|:---:|---|---|
| **MOD-069** | `windows.registry_enum`, `windows.scheduled_tasks_enum` | **MEDIUM** | Grup E: Validation & Schema | Pre-flight validation asymmetry: `validate()` passes without required `username`, causing silent aborts in `run()` |
| **MOD-070** | `windows.registry_enum`, `windows.scheduled_tasks_enum`, `linux.kernel_suggester` | **MEDIUM** | Grup A: Normalizer Data Loss | Domain `Finding` object bleed into raw output keys (`cleartext_credentials`, `credential_hints`, `scheduled_tasks`, `privesc_vectors`) with zero normalizer handlers |
| **MOD-071** | `linux.kernel_suggester` | **MEDIUM** | Grup E: Heuristic Precision | Userspace CVEs (Polkit PwnKit, Sudo Baron Samedit) attributed to kernel versions via overbroad regexes `r"[345]\.[0-9]+"` |
| **MOD-072** | `linux._parsers.py` | **HIGH** | Grup E: Cryptographic Robustness | Pseudo-parser in `KirbiASN1Codec.decode_kirbi()` returns zeroed session keys (`0000...`) and synthetic principals, corrupting tickets |
| **MOD-073** | `exfil.secrets_scan`, `exfil.smb_shares` | **LOW** | Grup E: Validation & Schema | Protocol defaulting to `"default"` in `before_request()` and missing `username` validation in `validate()` |
| **MOD-074** | `exfil.secrets_scan`, `exfil.smb_shares` | **MEDIUM** | Grup A: Normalizer Data Loss | 100% data loss on exfiltration findings (`credential_list`, `discovered_secrets`, `file_share_list`, `sensitive_file_paths`) in `ArtifactNormalizer` |

---

## 2. Detailed Module-by-Module Audit (Checklists B1–B6 + B7)

### 2.1. `windows.registry_enum` (`ares/modules/windows/registry_enum.py`)

- **B1: Scope Enforcement & Boundary**:
  Calls `await self.before_request(target, "smb")` (line 383). Target host is properly validated against campaign scope before opening named pipe `\pipe\winreg`.
- **B2: Input Validation, Schema & Sanitization (`MOD-069`)**:
  In `validate()` (lines 220–242), `target` is checked, but `username` is not validated if `ctx.best_credential()` returns `None`. In `run()` (line 362), `if not target or not username:` returns `[], {"error": "target and username required"}`. This creates an validation asymmetry where invalid execution context passes pre-flight validation but silently aborts in execution.
- **B3: Execution Safety & Failure Modes**:
  All Impacket DCE/RPC calls are wrapped in `_read_registry()` and run on a thread executor with clean disconnect handlers in `finally: dce.disconnect(); smb.logoff()`. Handled properly.
- **B4: Normalizer Pipeline Compatibility (`MOD-070`)**:
  Lines 735–736 assign `raw["cleartext_credentials"] = self._findings` and `raw["credential_hints"] = self._findings`.
  1. It passes internal domain `Finding` model objects into the raw dictionary.
  2. `cleartext_credentials` and `credential_hints` have NO handlers in `ArtifactNormalizerPipeline`. All registry credential discoveries evaporate from the campaign artifact store.
- **B5: Logging, Telemetry & Operator Safety**:
  Audit logging is clean: `audit("registry_enum", technique="T1552.002")`. Synthesizes Microsoft Sentinel KQL and Sigma rules in `raw["loot"]`.
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Covered by `test_windows_resilience.py` and adapter tests.
- **B7: Completeness Check**:
  Shares the exact `self._findings` assignment pattern seen in `windows.services_enum` and `windows.user_hunter`.

---

### 2.2. `windows.scheduled_tasks_enum` (`ares/modules/windows/scheduled_tasks_enum.py`)

- **B1: Scope Enforcement & Boundary**:
  Calls `await self.before_request(target, "smb")` (line 333). Target host is strictly scope-checked before binding to `\pipe\atsvc`.
- **B2: Input Validation, Schema & Sanitization (`MOD-069`)**:
  Same asymmetry as `registry_enum`: `validate()` (lines 180–202) enforces `target` but fails to enforce `username`, whereas `run()` (line 315) fails if `username` is empty.
- **B3: Execution Safety & Failure Modes**:
  DCE/RPC task enumeration is wrapped in `_enum_tasks()` and executed via `run_in_executor()`. Task XML parsing uses `defusedxml` with fallback to `xml.etree.ElementTree` with stripped namespaces.
- **B4: Normalizer Pipeline Compatibility (`MOD-070`)**:
  Lines 521–522 assign `raw["scheduled_tasks"] = self._findings` and `raw["privesc_vectors"] = self._findings`.
  `ArtifactNormalizerPipeline` has zero handlers for `scheduled_tasks` or `privesc_vectors`. All writable binary paths and high-privilege scheduled tasks are dropped from the unified graph.
- **B5: Logging, Telemetry & Operator Safety**:
  Synthesizes Sentinel KQL and Sigma rules for Event ID 4698/4702 and `schtasks.exe` process creation.
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Verified in `test_module_execute_adapters.py`.
- **B7: Completeness Check**:
  Identical normalizer gap pattern to `windows.registry_enum`.

---

### 2.3. `linux.kernel_suggester` (`ares/modules/linux/kernel_suggester.py`)

- **B1: Scope Enforcement & Boundary**:
  Calls `await self.before_request(target, "ssh")` (line 223) and applies rate limiting/jitter.
- **B2: Input Validation, Schema & Sanitization**:
  `validate()` enforces both `target` and `username`.
- **B3: Execution Safety & Failure Modes**:
  Paramiko SSH connection handles missing host key policy warnings, runs `uname -r`, and gracefully closes.
- **B4: Normalizer Pipeline Compatibility (`MOD-070`)**:
  Line 306 sets `raw["privesc_vectors"] = self._findings`. `privesc_vectors` has no handler in `ArtifactNormalizerPipeline`.
- **B5: Logging, Telemetry & Heuristic Precision (`MOD-071`)**:
  Lines 33–42 define `_KERNEL_CVES`:
  - `(r"[345]\.[0-9]+", "CVE-2021-4034", "Polkit pkexec LPE (PwnKit)", "CRITICAL", "< 0.120-3")`
  - `(r"[345]\.[0-9]+", "CVE-2021-3156", "Sudo heap-overflow LPE (Baron Samedit)", "CRITICAL", "< 1.9.5p2")`
  PwnKit and Baron Samedit are userspace package vulnerabilities (polkit and sudo), not kernel vulnerabilities. Matching regex `r"[345]\.[0-9]+"` against kernel version generates CRITICAL false positive findings on 99% of Linux kernels regardless of package patch level.
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Tested in `test_module_execute_adapters.py` and `test_module_coverage.py`.
- **B7: Completeness Check**:
  Presents identical over-claiming pattern to `linux.container` (MOD-039).

---

### 2.4. `linux._parsers.py` (`ares/modules/linux/_parsers.py`)

- **B1: Scope Enforcement & Boundary**:
  Not a network module. Pure Python binary parser engine used by `sssd_harvest`, `samba_secrets`, `keytab_abuse`, `ccache_hunt`, and `ticket_converter`.
- **B2: Input Validation, Schema & Parsing Safety**:
  Bounds checks on buffer lengths before unpacking structs across `TDBParser`, `CcacheParser`, and `KeytabParser`.
- **B3: Execution Safety & Anti-Hype Compliance (`MOD-072`)**:
  `KirbiASN1Codec.decode_kirbi()` (lines 660–695) claims to be a:
  *"Pure Python ASN.1 DER serializer & deserializer for Kerberos KRB-CRED (RFC 4120). Enables lossless in-memory conversion between Linux ccache v4 and Windows .kirbi."*
  However, `decode_kirbi()` does NOT deserialize the ASN.1 tree:
  ```python
  ticket_info: dict[str, Any] = {
      "client": "Administrator@CORP.LOCAL",
      "server": "krbtgt/CORP.LOCAL@CORP.LOCAL",
      "keytype": 18,
      "keydata": "00" * 32,  # HARDCODED ALL-ZERO SESSION KEY
      ...
  }
  ```
  It hardcodes the session key to 32 zero bytes and naively searches for `@` in raw bytes to guess the domain. When `credential.ticket_converter` converts `.kirbi` into `ccache`, the resulting ticket has a corrupt session key (`00000000...`), making it completely unusable for authentication (breaking downstream Golden/Silver ticket tradecraft).
- **B4: Normalizer Pipeline Compatibility**:
  N/A (library module).
- **B5: Logging, Telemetry & Operator Safety**:
  Subprocess-free and C-extension free; clean pure-Python implementation of MD4 (`pure_md4`) for OpenSSL 3.0+ environments.
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Tested in `test_linux_ad_tradecraft.py`. Unit tests previously passed because they only asserted `assert principal` without verifying the decrypted session key value.
- **B7: Completeness Check**:
  Directly affects `credential.ticket_converter` (MOD-036).

---

### 2.5. `exfil.secrets_scan` (`ares/modules/exfil/secrets_scan.py`)

- **B1: Scope Enforcement & Boundary (`MOD-073`)**:
  Line 608 calls `await self.before_request(target, "default")` with `"default"` protocol instead of `"ssh"` or `"wmi"`, bypassing protocol-specific rate limits and port tagging.
- **B2: Input Validation, Schema & Sanitization (`MOD-073`)**:
  `validate()` (lines 406–419) only verifies `target`. In live runs (line 605), `if not username:` returns `[], {"error": "no_credential_username"}`.
- **B3: Execution Safety & Failure Modes**:
  Calculates real Shannon entropy (`calculate_shannon_entropy()`) and evaluates placeholder heuristics (`_is_placeholder_token()`).
- **B4: Normalizer Pipeline Compatibility (`MOD-074`)**:
  Outputs `OUTPUTS = ["credential_list", "sensitive_data_found"]`.
  Raw returns `credential_list`, `discovered_secrets`, `sensitive_data_found`, `hit_count`.
  `ArtifactNormalizerPipeline` does not define any handler for `credential_list` or `discovered_secrets`. All discovered API keys, passwords, and connection strings fail to enter `ArtifactStore`.
- **B5: Logging, Telemetry & Operator Safety**:
  Synthesizes Sentinel KQL and Sigma rules for file content searching (`Select-String`, `findstr`, `grep -r`).
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Thoroughly tested in `tests/unit/modules/test_secrets_scan.py` with mock SSH execution and entropy math tests.
- **B7: Completeness Check**:
  Similar normalizer gap to `ad.sccm` and `windows.lsa_secrets`.

---

### 2.6. `exfil.smb_shares` (`ares/modules/exfil/smb_shares.py`)

- **B1: Scope Enforcement & Boundary (`MOD-073`)**:
  Line 256 calls `await self.before_request(target, "default")` with `"default"` protocol string instead of `"smb"`.
- **B2: Input Validation, Schema & Sanitization (`MOD-073`)**:
  `validate()` verifies `target` but omits `username`.
- **B3: Execution Safety & Failure Modes**:
  Wraps all synchronous Impacket SMB operations in `_smb_enum_sync()` executed via `loop.run_in_executor(None, _smb_enum_sync)`. Clean `conn.logoff()` in `finally`.
- **B4: Normalizer Pipeline Compatibility (`MOD-074`)**:
  Outputs `OUTPUTS = ["file_share_list", "sensitive_file_paths"]`.
  Raw returns `file_share_list`, `sensitive_file_paths`, `sensitive_data_found`, `shares_scanned`, `files_found`.
  None of these keys have handlers in `ArtifactNormalizerPipeline`. All enumerated shares and sensitive file paths evaporate from the pipeline.
- **B5: Logging, Telemetry & Operator Safety**:
  Synthesizes Sentinel KQL and Sigma rules for Event ID 5140/5145 network share access.
- **B6: Anti-Mock Code Smells & Test Coverage**:
  Missing dedicated unit test suite (only tested via adapters).
- **B7: Completeness Check**:
  Identical exfil output evaporation pattern to `exfil.secrets_scan`.

---

## 3. Completeness & Cross-Batch Synthesis (Checklist B7)

1. **Sibling Pattern Analysis**:
   - The validation asymmetry (`validate()` checks target but misses username) is present across `windows.registry_enum`, `windows.scheduled_tasks_enum`, `exfil.secrets_scan`, and `exfil.smb_shares`.
   - The raw output domain object bleed (`raw["key"] = self._findings`) observed in `windows.registry_enum`, `windows.scheduled_tasks_enum`, and `linux.kernel_suggester` exactly matches the pattern fixed in `cloud.aws_privesc` (MOD-052) and `network.snmp_enum` (MOD-061).
2. **Normalizer Gaps**:
   - 9 new unhandled output keys identified in Batch 12: `cleartext_credentials`, `credential_hints`, `scheduled_tasks`, `privesc_vectors`, `credential_list`, `discovered_secrets`, `sensitive_data_found`, `file_share_list`, and `sensitive_file_paths`.
3. **Dependency Integrity**:
   - No Batch 12 modules depend on disabled modules (`ad.ghost_forge`, `windows.dpapi`, `windows.token_impersonation`, `cloud.phantom_token`).
   - `_parsers.py` is safely isolated from disabled modules, but requires real ASN.1 decoding to support `ticket_converter`.

---

## 4. Remediation Plan & Group Assignment

All Batch 12 findings are recorded as **DEFERRED** for the consolidated simultaneous remediation phase:
- **MOD-070, MOD-074** $\rightarrow$ **Grup A** (Normalizer Handlers Missing in `ares/normalize/artifacts.py`).
- **MOD-069, MOD-071, MOD-072, MOD-073** $\rightarrow$ **Grup E** (Technical Honesty, Validation Schema & Parsing Robustness).
