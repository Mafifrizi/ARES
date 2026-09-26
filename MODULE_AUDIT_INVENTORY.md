# ARES Security Architecture: Module Audit Inventory & Prioritization Matrix

> **Fase**: Pemetaan & Prioritas Pra-Audit (Inventory & Scoping)
> **Status**: Ready for Batch Security Audit
> **Total File Diperiksa**: 88 file Python di `ares/modules/`
> **Total Modul Konkret Terdaftar**: 70 modul

---

## 1. Ringkasan Eksekutif & Statistik Inventaris

Inventarisasi ini memetakan seluruh komponen modular dalam `ares/modules/` untuk menetapkan baseline pra-audit. Fokus fase ini adalah pengenalan batas arsitektur, pemetaan dependensi kontrak base class, klasifikasi tier risiko (Tier 1 Critical, Tier 2 High, Tier 3 Medium), dan pengelompokan batch audit terfokus tanpa memodifikasi kode atau menyimpulkan temuan prematur.

| Kategori Modul / File | Jumlah File | Total Baris Kode (Est.) | Persentase Kode | Status Test Coverage |
| :--- | :---: | :---: | :---: | :--- |
| **TIER 1 - CRITICAL** (Prioritas 1: Remote Exec, Creds, State Change) | 44 | 24,565 | 48.3% | 100% file memiliki test suite |
| **TIER 2 - HIGH** (Prioritas 2: Recon/Enum, Response/Binary Parsing) | 20 | 9,242 | 18.2% | 100% file memiliki test suite |
| **TIER 3 - MEDIUM** (Prioritas 3: Reporting, Local Utility, Core Base, Schema) | 24 | 17,031 | 33.5% | 9 file core teruji, 15 `__init__.py` modul |
| **TOTAL KESELURUHAN** | **88** | **50,838** | **100.0%** | **73 file teruji / 15 init files** |

---

### 1.1. Screening Awal Pola Fictitious / Stub Module (Pola MOD-005 `ghost_forge`)

Screening cepat berbasis AST, byte-level import inspection, dan trace call graph dilakukan terhadap seluruh 70 modul konkret untuk mendeteksi modul yang mengklaim eksploitasi aktif tetapi hanya menjalankan kalkulasi/hashing lokal tanpa transport protokol jaringan dan menginjeksi kredensial fiktif ke vault:

1. **[`ares/modules/cloud/phantom_token.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/phantom_token.py) (`cloud.phantom_token`)** — **TINGKAT KECURIGAAN: TINGGI (CRITICAL FAKE CANDIDATE)**
   - *Alasan*: Identik 1:1 dengan pola `ghost_forge`. File ini mengklaim teknik "Hybrid Entra ID PRT Hijack" / "Primary Refresh Token (PRT) Boundary Compromise". Modul tidak mengimpor library cloud/network apa pun (hanya `asyncio`, `hashlib`, `typing`), tidak memanggil `self.before_request()`, menghasilkan device ID sintetis lokal (`hashlib.sha256(tenant_id.encode()).hexdigest()[:12]`), memancarkan finding CRITICAL tanpa koneksi ke Azure AD / Microsoft Graph, dan menyuntikkan token palsu langsung ke vault: `ctx.record_credential(username=..., secret=f"PRT_ESTSAUTH_{simulated_device_id}", ...)`.
   - *Rekomendasi Prioritas*: Jadikan target audit mendalam nomor 1 pada **Batch 8 (Cloud Attacks)** untuk evaluasi deaktivasi/penghapusan.

2. **[`ares/modules/credential/ssh_spray.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ssh_spray.py) (`credential.ssh_spray`)** — **TINGKAT KECURIGAAN: SEDANG**
   - *Alasan*: Modul melakukan network I/O nyata via `asyncssh` / `paramiko`, tetapi sama sekali tidak memanggil `self.before_request(target)` sebelum memulai proses spraying kredensial ke host target. Memerlukan audit prioritas pada **Batch 5**.

3. **Modul-modul dengan status BENIGN / Bukan Fake Stub**:
   - [`ares/modules/credential/ticket_converter.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ticket_converter.py): Murni codec in-memory (ccache <-> kirbi), tidak melakukan network I/O secara by design (OPSEC SILENT utility).
   - [`ares/modules/linux/sssd_harvest.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/sssd_harvest.py), [`linux/ccache_hunt.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/ccache_hunt.py), [`linux/samba_secrets.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/samba_secrets.py), [`linux/keytab_abuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/keytab_abuse.py): Modul post-exploitation lokal yang membaca file filesystem Linux target (TDB, keytab, ccache) via file I/O lokal. Sah sebagai utility post-exploitation.

---

## 2. Arsitektur Plugin & Analisis Kontrak Base Class

Sistem modul ARES dibangun di atas arsitektur plugin terpadu dengan class pusat `BaseModule` di `ares/modules/base.py` (dan turunan spesialisasi `BaseLateralModule` di `ares/modules/lateral/modules.py`). Penemuan modul dilakukan secara dinamis oleh `PluginLoader` (`ares/core/plugin/loader.py`) melalui inspeksi kelas turunan `BaseModule`.

### 2.1. Hirarki Pewarisan (Inheritance Hierarchy)
```
BaseModule (ares/modules/base.py)
  ├── Concrete Standalone Modules (AD, Cloud, Credential, EDR, Exfil, Linux, Network, Persistence, Recon, Windows)
  └── BaseLateralModule (ares/modules/lateral/modules.py)
        ├── PsExecLateral (lateral.psexec)
        ├── WmiExecLateral (lateral.wmiexec)
        ├── WinRMLateral (lateral.winrm)
        ├── SSHPivot (lateral.ssh_pivot)
        ├── RDPLateral (lateral.rdp)
        └── DCOMLateral (lateral.dcom di lateral/dcom.py)
```

### 2.2. Kontrak Method Wajib (Abstract Contract)

Setiap modul konkret turunan `BaseModule` **wajib** mendefinisikan atribut dan meng-override method tertentu:

1. **Metadata Kelas Wajib**:
   - `MODULE_ID`: Identifikasi unik modul berformat dotted (`<category>.<name>`), contoh: `"ad.kerberoast"`, `"windows.lsass_dump"`.
   - `MODULE_NAME`: Nama deskriptif modul yang mudah dibaca operator.
   - `MODULE_CATEGORY`: Kategori modul (`ad`, `cloud`, `credential`, `edr`, `exfil`, `lateral`, `linux`, `network`, `opsec`, `persistence`, `recon`, `windows`, `reporting`).
   - `MODULE_DESCRIPTION`: Penjelasan singkat kapabilitas modul untuk CLI/API discovery.
2. **Method Eksekusi Wajib (`run()` atau `execute()`)**:
   - Legacy Interface: `async def run(self, **kwargs) -> tuple[list[Finding], dict[str, Any]]` — Default di `BaseModule` melempar `NotImplementedError`.
   - Modern SDK Interface (v0.9.0+ / v2): `async def execute(self, ctx: ExecutionContext) -> ModuleResult` — `BaseModule.execute()` mendelegasikan ke `run()` secara default jika tidak di-override langsung.
3. **Method Spesifik `BaseLateralModule`**:
   - `async def move(self, target: str, username: str, domain: str, secret: str, command: str, **kwargs) -> LateralResult` — Wajib di-override oleh seluruh modul lateral movement.

### 2.3. Fitur Default yang Disediakan Base Class (`BaseModule`)

Jika `BaseModule` bekerja dengan benar, modul turunan otomatis mewarisi perlindungan berikut:

1. **Validasi Parameter Deklaratif (`validate()`)**:
   - Memvalidasi schema parameter via `PARAMS_MODEL` (`validate_params()`).
   - Memastikan `ctx.target` terisi untuk modul non-cloud/recon/reporting.
   - Memverifikasi kapabilitas yang tercantum di `REQUIRES` (seperti `target`, `domain`, `vault`, `credentials`, `domain_creds`, `domain_admin_creds`) tersedia di context atau credential vault sebelum eksekusi dimulai.
2. **Evaluasi Kelayakan Pre-flight (`assess_feasibility()`)**:
   - Mengecek profil kebisingan (`noise_profile`) campaign terhadap `OPSEC_LEVEL` modul.
   - Memblokir eksekusi modul berlabel `high_noise` secara otomatis jika campaign berjalan dalam profil `stealth` (`score: 0.2`, `feasible: False`).
3. **Hook Pre-Request & Pembatasan Scope (`before_request()`)**:
   - **Scope Check (Layer 1)**: Memanggil `self.noise.scope_guard.assert_in_scope(target)` untuk memastikan target berada dalam scope yang diizinkan.
   - **Rate Limiting**: Memanggil `await self.noise.rate_limiter.acquire(action)` untuk mencegah flooding.
   - **OPSEC Jitter**: Memanggil `await self.noise.jitter.sleep()` untuk menghadirkan variasi timing antar request.
4. **Klasifikasi Error Seragam (`_classify_error()`)**:
   - Memetakan error transport/socket mentah ke tipe error standar ARES (`AuthenticationFailed`, `InsufficientPrivilege`, `ConnectionTimeout`, `HostUnreachable`, `RateLimited`, `NetworkError`) agar adaptive engine dapat mengambil keputusan fallback yang tepat.
5. **Registrasi Finding & Observabilitas (`finding()`)**:
   - Menginstansiasi objek `Finding`, mengikat UUID, severity, confidence, MITRE technique/tactic, dan evidence secara seragam.
   - Logging terstruktur dengan konteks otomatis (`_bind_log_context()`, `_clear_log_context()`).
6. **Parsing Strategi Otentikasi Lateral (`BaseLateralModule.resolve_auth_strategy()`)**:
   - Memilah otomatis antara otentikasi Kerberos (ticket/ccache), NTLM hash (`lmhash:nthash` atau 32-char NT hash), atau plaintext password.

### 2.4. Tanggung Jawab yang Wajib Diimplementasikan Modul Turunan (Child Responsibilities)

> [!CAUTION]
> **Peringatan Batas Arsitektural**: Base class menyediakan mekanisme proteksi, tetapi modul turunan **tetap bertanggung jawab penuh** untuk memanggil atau memanfaatkan mekanisme tersebut dengan benar.

- **Kewajiban Memanggil `before_request()`**:
  Base class tidak dapat mencegat pemanggilan socket raw di dalam `run()` secara otomatis pada Layer 1 jika modul anak lupa memanggil `await self.before_request(target)`. Modul anak **wajib** memanggil `before_request` sebelum menyentuh target eksternal.
- **Penanganan & Pelaporan Exception**:
  Modul anak harus menangkap error eksternal dan membungkusnya dengan `self._classify_error()`. Jika modul anak melempar raw exception atau silent `except: pass`, tracing audit dan failover engine akan terganggu.
- **Kepatuhan Terhadap `dry_run`**:
  Modul anak wajib memeriksa `ctx.dry_run` sebelum melakukan perubahan state atau aksi ofensif aktif, dan mengembalikan `ModuleResult(status="dry_run")` tanpa mengubah target.
- **Teardown & Cleanup State Target**:
  Modul yang mengubah sistem target (misal membuat registry key, memasang scheduled task, men-drop binary DLL, atau WMI subscription) **wajib menyediakan pembersihan fail-safe** agar sistem target kembali ke kondisi semula.
- **Sanitasi Kredensial & Anti-Leak**:
  Modul pemanen kredensial (seperti LSASS dump, SAM secrets, DPAPI, pass spray) dilarang mencatat plaintext kredensial ke log unredacted; mereka harus menyimpannya ke `vault` atau `new_credentials` secara aman.
- **Evaluasi Defensif Khusus Host**:
  Jika modul berhadapan dengan pertahanan khusus (misal EDR, Credential Guard, LSA Protection, AppLocker), modul anak wajib meng-override `assess_feasibility()` untuk melakukan deteksi pre-flight yang relevan.

---

## 3. Tabel Inventaris Lengkap Modul ARES

Tabel berikut memuat seluruh 88 file Python yang ada di bawah direktori `ares/modules/`, diurutkan berdasarkan path direktori.

| No | File Path | Teknik / Identitas Modul | Tipe | Tier Risiko | Status Test Suite | Estimasi Baris |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| 1 | [`ares/modules/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/__init__.py) | Package initialization (`ares.modules.__init__.py`) | Package Init | **TIER 3** | Tidak ada | 24 |
| 2 | [`ares/modules/base.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/base.py) | ARES Module Base Class & Result Contract | Base Class | **TIER 3** | Ada (14 test file) | 759 |
| 3 | [`ares/modules/descriptors.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/descriptors.py) | Module Metadata & Capability Descriptors Specification | Descriptor / Schema | **TIER 3** | Ada (5 test file) | 9,226 |
| 4 | [`ares/modules/params.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/params.py) | Pydantic Parameter Schemas for all modules | Parameter Schemas | **TIER 3** | Ada (7 test file) | 1,558 |
| 5 | [`ares/modules/sdk.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/sdk.py) | Developer SDK Facade & Decorators | SDK / Interface | **TIER 3** | Ada (3 test file) | 396 |
| 6 | [`ares/modules/ad/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/__init__.py) | Package initialization (`ares.modules.ad`) | Package Init | **TIER 3** | Tidak ada | 37 |
| 7 | [`ares/modules/ad/adcs.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/adcs.py) | ADCS Misconfiguration Scanner (ad.adcs) | Concrete Module | **TIER 1** | Ada (8 test file) | 1,386 |
| 8 | [`ares/modules/ad/asreproast.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/asreproast.py) | ASREPRoasting (ad.asreproast) | Concrete Module | **TIER 1** | Ada (16 test file) | 728 |
| 9 | [`ares/modules/ad/coerce.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/coerce.py) | Authentication Coercion (ad.coerce) | Concrete Module | **TIER 1** | Ada (4 test file) | 446 |
| 10 | [`ares/modules/ad/dcsync.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/dcsync.py) | DCSync (ad.dcsync) | Concrete Module | **TIER 1** | Ada (15 test file) | 357 |
| 11 | [`ares/modules/ad/delegation_abuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/delegation_abuse.py) | Kerberos Delegation Abuse (ad.delegation_abuse) | Concrete Module | **TIER 1** | Ada (4 test file) | 505 |
| 12 | [`ares/modules/ad/dependencies.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/dependencies.py) | Active Directory Binding & Dependency Plan | AD Helper | **TIER 3** | Ada (1 test file) | 215 |
| 13 | [`ares/modules/ad/enum_acl.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_acl.py) | AD ACL Enumeration (ad.enum_acl) | Concrete Module | **TIER 2** | Ada (2 test file) | 371 |
| 14 | [`ares/modules/ad/enum_computers.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_computers.py) | AD Computer Enumeration (ad.enum_computers) | Concrete Module | **TIER 2** | Ada (3 test file) | 352 |
| 15 | [`ares/modules/ad/enum_spn.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_spn.py) | AD SPN Enumeration (ad.enum_spn) | Concrete Module | **TIER 2** | Ada (8 test file) | 384 |
| 16 | [`ares/modules/ad/enum_users.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_users.py) | AD User Enumeration (ad.enum_users) | Concrete Module | **TIER 2** | Ada (12 test file) | 430 |
| 17 | [`ares/modules/ad/ghost_forge.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/ghost_forge.py) | ADCS Cryptographic Identity & PKINIT Takeover (ad.ghost_forge) [DISABLED / MITIGATED] | Concrete Module | **TIER 1** | Ada (1 test file) | 420 |
| 18 | [`ares/modules/ad/kerberoast.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/kerberoast.py) | Kerberoasting (ad.kerberoast) | Concrete Module | **TIER 1** | Ada (26 test file) | 711 |
| 19 | [`ares/modules/ad/laps_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/laps_enum.py) | LAPS Password Enumeration (ad.laps_enum) | Concrete Module | **TIER 2** | Ada (3 test file) | 400 |
| 20 | [`ares/modules/ad/sccm.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/sccm.py) | SCCM/MECM Abuse (ad.sccm) | Concrete Module | **TIER 1** | Ada (1 test file) | 628 |
| 21 | [`ares/modules/ai/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ai/__init__.py) | Package initialization (`ares.modules.ai`) | Package Init | **TIER 3** | Tidak ada | 12 |
| 22 | [`ares/modules/ai/autonomous_planner.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ai/autonomous_planner.py) | AI Autonomous Attack Planner (ai.autonomous_planner) | Concrete Module | **TIER 3** | Ada (5 test file) | 1,044 |
| 23 | [`ares/modules/ai/plan_validator.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ai/plan_validator.py) | AI Autonomous Plan Safety & Feasibility Validator | AI Validator | **TIER 3** | Ada (2 test file) | 129 |
| 24 | [`ares/modules/cloud/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/__init__.py) | Package initialization (`ares.modules.cloud`) | Package Init | **TIER 3** | Tidak ada | 25 |
| 25 | [`ares/modules/cloud/aws.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/aws.py) | AWS Recon & Attack (cloud.aws) | Concrete Module | **TIER 2** | Ada (5 test file) | 347 |
| 26 | [`ares/modules/cloud/aws_privesc.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/aws_privesc.py) | AWS IAM Privilege Escalation (cloud.aws_privesc) | Concrete Module | **TIER 1** | Ada (4 test file) | 342 |
| 27 | [`ares/modules/cloud/azure.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure.py) | Azure Recon & Attack (cloud.azure) | Concrete Module | **TIER 2** | Ada (3 test file) | 613 |
| 28 | [`ares/modules/cloud/azure_ad.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure_ad.py) | Azure AD Identity Attacks (cloud.azure_ad) | Concrete Module | **TIER 2** | Ada (4 test file) | 465 |
| 29 | [`ares/modules/cloud/gcp.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/gcp.py) | GCP Recon & Attack (cloud.gcp) | Concrete Module | **TIER 2** | Ada (3 test file) | 648 |
| 30 | [`ares/modules/cloud/identity_federation.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/identity_federation.py) | Cloud Identity Federation Abuse (cloud.identity_federation_abuse) | Concrete Module | **TIER 1** | Ada (3 test file) | 1,190 |
| 31 | [`ares/modules/cloud/phantom_token.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/phantom_token.py) | Hybrid Entra ID PRT Hijack (cloud.phantom_token) | Concrete Module | **TIER 1** | Ada (1 test file) | 385 |
| 32 | [`ares/modules/credential/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/__init__.py) | Package initialization (`ares.modules.credential`) | Package Init | **TIER 3** | Tidak ada | 29 |
| 33 | [`ares/modules/credential/crack.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/crack.py) | Hash Cracking (credential.crack) | Concrete Module | **TIER 1** | Ada (4 test file) | 350 |
| 34 | [`ares/modules/credential/golden_ticket.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/golden_ticket.py) | Golden Ticket Forgery (credential.golden_ticket) | Concrete Module | **TIER 1** | Ada (9 test file) | 475 |
| 35 | [`ares/modules/credential/pass_spray.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/pass_spray.py) | Password Spray (credential.pass_spray) | Concrete Module | **TIER 1** | Ada (8 test file) | 794 |
| 36 | [`ares/modules/credential/pass_the_hash.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/pass_the_hash.py) | Pass-the-Hash (credential.pass_the_hash) | Concrete Module | **TIER 1** | Ada (5 test file) | 359 |
| 37 | [`ares/modules/credential/reuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/reuse.py) | Credential Reuse (credential.reuse) | Concrete Module | **TIER 1** | Ada (5 test file) | 314 |
| 38 | [`ares/modules/credential/ssh_spray.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ssh_spray.py) | SSH Credential Spray & Authentication Audit (credential.ssh_spray) | Concrete Module | **TIER 1** | Ada (1 test file) | 332 |
| 39 | [`ares/modules/credential/ticket_converter.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ticket_converter.py) | Bi-Directional Kerberos Ticket Converter (credential.ticket_converter) | Concrete Module | **TIER 1** | Ada (1 test file) | 277 |
| 40 | [`ares/modules/edr/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/edr/__init__.py) | Package initialization (`ares.modules.edr`) | Package Init | **TIER 3** | Tidak ada | 12 |
| 41 | [`ares/modules/edr/bypass_adaptive.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/edr/bypass_adaptive.py) | Adaptive EDR Bypass Engine (edr.bypass_adaptive) | Concrete Module | **TIER 1** | Ada (5 test file) | 1,114 |
| 42 | [`ares/modules/exfil/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/__init__.py) | Package initialization (`ares.modules.exfil`) | Package Init | **TIER 3** | Tidak ada | 21 |
| 43 | [`ares/modules/exfil/secrets_scan.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/secrets_scan.py) | Secrets Scanner (exfil.secrets_scan) | Concrete Module | **TIER 2** | Ada (4 test file) | 652 |
| 44 | [`ares/modules/exfil/smb_shares.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/smb_shares.py) | SMB Share Enumeration (exfil.smb_shares) | Concrete Module | **TIER 2** | Ada (3 test file) | 331 |
| 45 | [`ares/modules/exfil/staged_collection.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/staged_collection.py) | Staged File Collection (exfil.staged_collection) | Concrete Module | **TIER 1** | Ada (5 test file) | 390 |
| 46 | [`ares/modules/lateral/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/__init__.py) | Package initialization (`ares.modules.lateral`) | Package Init | **TIER 3** | Tidak ada | 38 |
| 47 | [`ares/modules/lateral/dcom.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/dcom.py) | DCOM Lateral (lateral.dcom) | Concrete Module | **TIER 1** | Ada (5 test file) | 388 |
| 48 | [`ares/modules/lateral/modules.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/modules.py) | PsExec Lateral (lateral.psexec), WmiExec Lateral (lateral.wmiexec), WinRM Lateral (lateral.winrm), SSH Pivot (lateral.ssh_pivot), RDP Lateral (lateral.rdp) | Concrete Module | **TIER 1** | Ada (17 test file) | 1,532 |
| 49 | [`ares/modules/lateral/mssql.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/mssql.py) | MSSQL Lateral Movement (lateral.mssql) | Concrete Module | **TIER 1** | Ada (5 test file) | 501 |
| 50 | [`ares/modules/lateral/ntlm_relay.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/ntlm_relay.py) | NTLM Relay Automation (lateral.ntlm_relay) | Concrete Module | **TIER 1** | Ada (4 test file) | 982 |
| 51 | [`ares/modules/lateral/smb_relay.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/smb_relay.py) | SMB Signing Audit (Relay Prerequisite) (lateral.smb_relay) | Concrete Module | **TIER 1** | Ada (4 test file) | 513 |
| 52 | [`ares/modules/linux/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/__init__.py) | Package initialization (`ares.modules.linux`) | Package Init | **TIER 3** | Tidak ada | 35 |
| 53 | [`ares/modules/linux/_parsers.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/_parsers.py) | Low-level Binary Credential Parsers (ccache, keytab, kirbi, TDB) | Parser Engine | **TIER 2** | Ada (1 test file) | 842 |
| 54 | [`ares/modules/linux/ccache_hunt.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/ccache_hunt.py) | Linux Kerberos Ticket Hunter (linux.ccache_hunt) | Concrete Module | **TIER 1** | Ada (1 test file) | 387 |
| 55 | [`ares/modules/linux/container.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/container.py) | Container Escape (linux.container) | Concrete Module | **TIER 1** | Ada (4 test file) | 348 |
| 56 | [`ares/modules/linux/kernel_suggester.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/kernel_suggester.py) | Linux Kernel Exploit Suggester (linux.kernel_suggester) | Concrete Module | **TIER 2** | Ada (3 test file) | 307 |
| 57 | [`ares/modules/linux/keytab_abuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/keytab_abuse.py) | Host Keytab Harvester & Silver Ticket Generator (linux.keytab_abuse) | Concrete Module | **TIER 1** | Ada (1 test file) | 292 |
| 58 | [`ares/modules/linux/ld_preload.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/ld_preload.py) | LD_PRELOAD / Library Hijack Detection (linux.ld_preload) | Concrete Module | **TIER 1** | Ada (4 test file) | 547 |
| 59 | [`ares/modules/linux/nfs_escape.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/nfs_escape.py) | NFS no_root_squash Detection (linux.nfs_escape) | Concrete Module | **TIER 1** | Ada (4 test file) | 497 |
| 60 | [`ares/modules/linux/privesc.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/privesc.py) | Linux Privilege Escalation (linux.privesc) | Concrete Module | **TIER 1** | Ada (8 test file) | 456 |
| 61 | [`ares/modules/linux/samba_secrets.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/samba_secrets.py) | Samba & Winbind Secrets Extractor (linux.samba_secrets) | Concrete Module | **TIER 1** | Ada (1 test file) | 298 |
| 62 | [`ares/modules/linux/service_hijack.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/service_hijack.py) | Service Binary Hijack Detection (linux.service_hijack) | Concrete Module | **TIER 1** | Ada (4 test file) | 583 |
| 63 | [`ares/modules/linux/sssd_harvest.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/sssd_harvest.py) | SSSD Cache & Credential Harvester (linux.sssd_harvest) | Concrete Module | **TIER 1** | Ada (1 test file) | 327 |
| 64 | [`ares/modules/network/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/__init__.py) | Package initialization (`ares.modules.network`) | Package Init | **TIER 3** | Tidak ada | 27 |
| 65 | [`ares/modules/network/dns_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/dns_enum.py) | DNS Enumeration (network.dns_enum) | Concrete Module | **TIER 2** | Ada (3 test file) | 365 |
| 66 | [`ares/modules/network/http_fingerprint.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/http_fingerprint.py) | HTTP Fingerprinting (network.http_fingerprint) | Concrete Module | **TIER 2** | Ada (3 test file) | 360 |
| 67 | [`ares/modules/network/pivot.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/pivot.py) | Pivot Tunnel Management (network.pivot) | Concrete Module | **TIER 1** | Ada (4 test file) | 358 |
| 68 | [`ares/modules/network/port_scan.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/port_scan.py) | TCP Port Scanner (network.port_scan) | Concrete Module | **TIER 1** | Ada (6 test file) | 574 |
| 69 | [`ares/modules/network/service_detect.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/service_detect.py) | Service Detection (network.service_detect) | Concrete Module | **TIER 2** | Ada (3 test file) | 398 |
| 70 | [`ares/modules/network/snmp_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/snmp_enum.py) | SNMP Enumeration (network.snmp_enum) | Concrete Module | **TIER 2** | Ada (3 test file) | 414 |
| 71 | [`ares/modules/opsec/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/opsec/__init__.py) | Package initialization (`ares.modules.opsec`) | Package Init | **TIER 3** | Tidak ada | 14 |
| 72 | [`ares/modules/opsec/coverage_predictor.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/opsec/coverage_predictor.py) | OPSEC Coverage Predictor (opsec.coverage_predictor) | Concrete Module | **TIER 3** | Ada (6 test file) | 970 |
| 73 | [`ares/modules/persistence/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/persistence/__init__.py) | Package initialization (`ares.modules.persistence`) | Package Init | **TIER 3** | Tidak ada | 21 |
| 74 | [`ares/modules/persistence/scheduled_task.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/persistence/scheduled_task.py) | Scheduled Task Persistence (persistence.scheduled_task), Registry Run Key Persistence (persistence.registry_run) | Concrete Module | **TIER 1** | Ada (7 test file) | 606 |
| 75 | [`ares/modules/persistence/wmi_subscription.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/persistence/wmi_subscription.py) | WMI Event Subscription Persistence (persistence.wmi_subscription) | Concrete Module | **TIER 1** | Ada (6 test file) | 409 |
| 76 | [`ares/modules/recon/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/recon/__init__.py) | Package initialization (`ares.modules.recon`) | Package Init | **TIER 3** | Tidak ada | 17 |
| 77 | [`ares/modules/recon/fingerprint.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/recon/fingerprint.py) | Target Environment Fingerprinting (recon.fingerprint) | Concrete Module | **TIER 2** | Ada (3 test file) | 303 |
| 78 | [`ares/modules/reporting/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/reporting/__init__.py) | Package initialization (`ares.modules.reporting`) | Package Init | **TIER 3** | Tidak ada | 24 |
| 79 | [`ares/modules/reporting/report_gen.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/reporting/report_gen.py) | Campaign Finding Report Generator (HTML/PDF/JSON/Markdown) | Reporting Engine | **TIER 3** | Ada (7 test file) | 2,367 |
| 80 | [`ares/modules/windows/__init__.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/__init__.py) | Package initialization (`ares.modules.windows`) | Package Init | **TIER 3** | Tidak ada | 31 |
| 81 | [`ares/modules/windows/applocker_bypass.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/applocker_bypass.py) | AppLocker Policy Enumeration (windows.applocker_bypass) | Concrete Module | **TIER 1** | Ada (4 test file) | 570 |
| 82 | [`ares/modules/windows/dpapi.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/dpapi.py) | DPAPI Credential Recovery (windows.dpapi) | Concrete Module | **TIER 1** | Ada (7 test file) | 655 |
| 83 | [`ares/modules/windows/lsa_secrets.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/lsa_secrets.py) | LSA Secrets & SAM Dump (windows.lsa_secrets) | Concrete Module | **TIER 1** | Ada (8 test file) | 446 |
| 84 | [`ares/modules/windows/lsass_dump.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/lsass_dump.py) | LSASS Memory Dump (windows.lsass_dump) | Concrete Module | **TIER 1** | Ada (8 test file) | 805 |
| 85 | [`ares/modules/windows/registry_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/registry_enum.py) | Registry Credential Enumeration (windows.registry_enum) | Concrete Module | **TIER 2** | Ada (4 test file) | 737 |
| 86 | [`ares/modules/windows/scheduled_tasks_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/scheduled_tasks_enum.py) | Scheduled Tasks Enumeration (windows.scheduled_tasks_enum) | Concrete Module | **TIER 2** | Ada (3 test file) | 523 |
| 87 | [`ares/modules/windows/token_impersonation.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/token_impersonation.py) | Token Impersonation (windows.token_impersonation) | Concrete Module | **TIER 1** | Ada (7 test file) | 453 |
| 88 | [`ares/modules/windows/uac_bypass.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/uac_bypass.py) | UAC Configuration Audit (windows.uac_bypass) | Concrete Module | **TIER 1** | Ada (4 test file) | 535 |

---

## 4. Rencana Batch Audit Keamanan (Urut Prioritas)

Seluruh modul **TIER 1 (Critical)** dan **TIER 2 (High)** telah dikelompokkan ke dalam **12 batch terfokus** (maksimal 3–7 file per batch) berdasarkan kesamaan domain fungsional dan vektor risiko. Audit keamanan mendalam pada fase berikutnya akan dieksekusi per batch sesuai urutan prioritas di bawah.

### Batch 1: Active Directory Exploitation & Kerberos Attack Core (TIER 1 - CRITICAL) - [STATUS: AUDITED]
- **Deskripsi**: Modul-modul inti eksploitasi Active Directory yang memanipulasi protokol otentikasi Kerberos, replikasi domain, delegasi hak istimewa, dan pemaksaan RPC (coercion).
- **Fokus Risiko Audit**: Manipulasi tiket Kerberos, eksposur hash NTLM/Kerberos, bypass otentikasi domain, abuse RPC unauthenticated.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **8 Temuan Terkonfirmasi** (3 Critical, 3 High, 2 Medium)
  - `MOD-001` (Critical): NameError `target` unhandled pada exception handler `ad.delegation_abuse._rbcd_attack_sync`.
  - `MOD-002` (Critical): Kerberos ticket material hilang/tidak di-assign ke `CCache()` sebelum `saveFile()`, menghasilkan file `.ccache` kosong.
  - `MOD-003` (High): File residu `.ccache` di-create via `secure_mkstemp` tanpa pembersihan/teardown handler (`fail-closed` cleanup).
  - `MOD-004` (High - **DIKONFIRMASI VALID**): Parameter `listener_ip` pada `ad.coerce` tidak divalidasi terhadap scope campaign. Verifikasi independen mengonfirmasi bahwa `engine._extract_all_targets()` hanya mengekstrak keys `_TARGET_KEYS`, di mana `listener_ip` dan `listener` TIDAK termasuk. Tidak ada validasi scope pada layer dispatcher, coordinator, maupun module level.
  - `MOD-005` (Critical - **MITIGATED (disabled) - keputusan final pending**): Fictitious implementation pada `ad.ghost_forge` melanggar anti-hype policy & tanpa network calls menginjeksi fake credential ke vault. Modul telah dinonaktifkan sementara dari pipeline produksi (`ENABLED = False`) dan disaring keluar dari registry catalog / execution chains; pemanggilan langsung via class, engine, atau API gagal deterministik dengan error eksplisit `"module disabled: implementation incomplete, see MOD-005"`.
  - `MOD-006` (High - **DIKONFIRMASI VALID**): Key mismatch pipeline normalisasi: `ArtifactNormalizer._normalize_kerberos_hashes`, `_normalize_asrep_hashes`, dan `_normalize_ntlm_hashes` membaca `raw["hashes"]`, sedangkan modul aktif menghasilkan `raw["kerberos_hashes"]`, `raw["asrep_hashes"]`, dan `raw["ntlm_hashes"]`. Verifikasi independen membuktikan 100% hash dari 3 modul ini hilang dari `ArtifactStore` dan tidak pernah disimpan ke DB/vault. Test suite sebelumnya luput karena hanya mengetes `ArtifactStore` secara terisolasi tanpa integrasi module output.
  - `MOD-007` (Medium): Plaintext unredacted NTLM hash tersimpan dalam `Finding.evidence["sample"]` pada `ad.dcsync`.
  - `MOD-008` (Medium): Host parameter kosong / disassociated pada temuan `ad.asreproast` dan `ad.kerberoast`.
- **Jumlah File**: 6 file
- **Daftar File**:
  - [`ares/modules/ad/kerberoast.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/kerberoast.py) — *Kerberoasting (`ad.kerberoast`)* (711 baris)
  - [`ares/modules/ad/asreproast.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/asreproast.py) — *ASREPRoasting (`ad.asreproast`)* (728 baris)
  - [`ares/modules/ad/dcsync.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/dcsync.py) — *DCSync (`ad.dcsync`)* (357 baris)
  - [`ares/modules/ad/delegation_abuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/delegation_abuse.py) — *Kerberos Delegation Abuse (`ad.delegation_abuse`)* (505 baris)
  - [`ares/modules/ad/coerce.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/coerce.py) — *Authentication Coercion (`ad.coerce`)* (446 baris)
  - [`ares/modules/ad/ghost_forge.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/ghost_forge.py) — *ADCS Cryptographic Identity & PKINIT Takeover (`ad.ghost_forge`)* (420 baris)

### Batch 2: AD Infrastructure Escalation & Lateral Coercion (TIER 1 - CRITICAL) - [STATUS: AUDITED]
- **Deskripsi**: Modul eksploitasi infrastruktur skala enterprise (ADCS PKI, SCCM MECM) dan relay protokol lintas sistem (NTLM Relay, SMB Relay, MSSQL Lateral).
- **Fokus Risiko Audit**: Pengambilan sertifikat CA berbahaya (ESC1-ESC8), eksekusi kode melalui SCCM policy injection, relay NTLM ke LDAP/ADCS, dan eksekusi SQL xp_cmdshell.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **8 Temuan Terkonfirmasi** (2 Critical, 5 High, 1 Medium)
  - `MOD-009` (High): Scope Bypass & Out-of-Scope HTTP Enrollment pada ADCS di `ad.adcs._submit_csr_to_ca`. Target `ca_host` (dari LDAP `dNSHostName`) dihubungi via HTTP tanpa `self.before_request(ca_host, "http")`.
  - `MOD-010` (High): Scope Bypass pada WMI/DCOM dan PXE Port Probing di `ad.sccm`. Koneksi DCOM ke `naa_target` dan TCP connect ke port 4011/67 pada distribution points dilakukan tanpa `before_request(dp)`.
  - `MOD-011` (Critical): Mass Out-of-Scope Port Probing pada 50 Host Domain di `lateral.ntlm_relay._check_relay_targets`. Mengirim paket SMB2 NEGOTIATE ke hingga 50 komputer hasil enumerasi LDAP tanpa validasi apakah host-host tersebut berada dalam scope campaign.
  - `MOD-012` (Critical): Persistent Rogue Machine Account & Backdoor DACL Ditinggalkan di AD Tanpa Teardown di `lateral.ntlm_relay._rbcd_attack`. Akun mesin `ARESXXXXXX$` dan modifikasi `msDS-AllowedToActOnBehalfOfOtherIdentity` tidak memiliki blok `finally` atau mekanisme cleanup, meninggalkan backdoor permanen di AD target (melanggar Rule 4).
  - `MOD-013` (High): Fictitious S4U Impersonation Claim di `lateral.ntlm_relay._s4u_attack`. Komentar mengklaim S4U2self + S4U2proxy untuk impersonasi Administrator, tetapi implementasi hanya meminta TGS biasa untuk akun mesin (`ARESXXXXXX$`), menyimpannya sebagai `administrator@target.ccache`, dan menerbitkan finding CRITICAL palsu (melanggar Rule 1).
  - `MOD-014` (High): Scope Bypass pada UNC Path Coercion Listener & Linked Server Execution di `lateral.mssql`. Parameter `listener`/`listener_ip` pada `xp_dirtree` dan target `linked_server` tidak divalidasi terhadap scope campaign (pola identik MOD-004).
  - `MOD-015` (Medium): Omission Scope Enforcement & Jitter pada Loop Utama SMB Signing Audit di `lateral.smb_relay.run`. Loop `_check_smb_signing` mengirim paket SMB2 ke semua target tanpa `await self.before_request(target, "smb")`.
  - `MOD-016` (High): Cleartext Credential Evaporation & Misleading DPAPI Extraction di `ad.sccm`. NAA credentials diekstrak dalam bentuk ciphertext DPAPI blob namun dilaporkan sebagai `cleartext_credentials`, tidak dinormalisasi oleh `ArtifactNormalizer`, dan tidak pernah disimpan ke `CredentialVault`.
- **Jumlah File**: 5 file
- **Daftar File**:
  - [`ares/modules/ad/adcs.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/adcs.py) — *ADCS Misconfiguration Scanner (`ad.adcs`)* (1,386 baris)
  - [`ares/modules/ad/sccm.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/sccm.py) — *SCCM/MECM Abuse (`ad.sccm`)* (628 baris)
  - [`ares/modules/lateral/ntlm_relay.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/ntlm_relay.py) — *NTLM Relay Automation (`lateral.ntlm_relay`)* (982 baris)
  - [`ares/modules/lateral/smb_relay.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/smb_relay.py) — *SMB Signing Audit (Relay Prerequisite) (`lateral.smb_relay`)* (513 baris)
  - [`ares/modules/lateral/mssql.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/mssql.py) — *MSSQL Lateral Movement (`lateral.mssql`)* (501 baris)

### Batch 3: Remote Execution & Lateral Movement Transports (TIER 1 - CRITICAL)
- **Deskripsi**: Modul penggerak lateral movement multi-transport (PsExec, WmiExec, WinRM, SSH, RDP, DCOM), tunnel pivoting socket interaktif, dan adaptasi evasion EDR.
- **Fokus Risiko Audit**: Eksekusi perintah remote pada target eksternal, pembuatan service remote, pembukaan socket tunnel, bypass EDR in-memory.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **8 Temuan Terkonfirmasi** (1 Critical, 5 High, 2 Medium)
  - `MOD-017` (High): Scope Bypass pada Destinasi Port Forwarding Lokal/Dinamis di `network.pivot` / `ares.pivot.infrastructure`. Parameter `remote_host` dan `reachable_subnets` pada `establish_local_forward` tidak divalidasi terhadap `campaign.is_in_scope()`, memungkinkan tunneling trafik ke jaringan di luar batasan engagement.
  - `MOD-018` (High): Teardown Omission & Orphaned Background SSH Subprocesses / Tunnels di `network.pivot`. Method `PivotModule.teardown()` tidak pernah dipanggil oleh engine/campaign lifecycle, meninggalkan background child processes (`ssh -N -D`) dan socket asyncssh berjalan permanen di workstation (melanggar Rule 4).
  - `MOD-019` (High): Fictitious Implementation & Phantom Active Status di `network.pivot` / `ares.pivot.infrastructure`. Jika asyncssh dan binary ssh sistem tidak tersedia, tunnel ditandai `TunnelState.ACTIVE`, memicu penerbitan finding INFO palsu bahwa tunnel aktif dan seluruh modul dapat merute trafik melaluinya (melanggar Rule 1).
  - `MOD-020` (High): Fictitious SOCKS5 Proxy Implementation & Dead-End di `lateral.ssh_pivot`. Method `establish_socks5` mengembalikan konfigurasi proxy lokal padahal method `move()` mengabaikan parameter `socks_port`, hanya menjalankan command `echo` lalu langsung menutup koneksi SSH (melanggar Rule 1).
  - `MOD-021` (Critical): False-Positive Lateral Movement Execution & Over-claiming pada Port Reachability di `lateral.rdp`. Modul menandai `success=True` hanya berdasarkan keterbukaan port TCP 3389 (bahkan tanpa otentikasi), memicu `BaseLateralModule.run` menerbitkan finding CRITICAL dengan confidence 1.0 bahwa pergerakan lateral berhasil sebagai Domain Admin/Administrator (melanggar Rule 1).
  - `MOD-022` (High): Workstation Egress Disruption & Out-of-Scope Cloud Probing dengan Atribusi Egress Target Menyesatkan di `exfil.staged_collection`. Method `_audit_lots_egress_sync` melakukan probe HTTP langsung dari workstation operator ke Microsoft/AWS/Azure tanpa scope guard, dan menyimpulkan target kekurangan Tenant Restrictions berdasarkan kegagalan header di workstation operator.
  - `MOD-023` (Medium): Staged Collection Phantom Pipeline & 100% Data Loss pada File Sensitif di `exfil.staged_collection`. Modul mewajibkan parameter `destination`, tetapi tidak pernah memindahkan/men-stage file yang ditemukan. Key `files_staged` tidak pernah diisi sehingga `sensitive_file_paths` dan `collection_inventory` selalu mengembalikan list kosong `[]`.
  - `MOD-024` (Medium): CIDR Parsing Incompatibility & Unhandled Socket Error di `network.port_scan`. Pesan validasi mengklaim mendukung "IP or CIDR", namun passing CIDR string (misal `192.168.1.0/24`) langsung ke `asyncio.open_connection` memicu `getaddrinfo` error pada seluruh port tanpa pemecahan subnet ke individual hosts.
- **Jumlah File**: 6 file
- **Daftar File**:
  - [`ares/modules/lateral/modules.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/modules.py) — *PsExec Lateral (`lateral.psexec`), WmiExec Lateral (`lateral.wmiexec`), WinRM Lateral (`lateral.winrm`), SSH Pivot (`lateral.ssh_pivot`), RDP Lateral (`lateral.rdp`)* (1,532 baris)
  - [`ares/modules/lateral/dcom.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/lateral/dcom.py) — *DCOM Lateral (`lateral.dcom`)* (388 baris)
  - [`ares/modules/network/pivot.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/pivot.py) — *Pivot Tunnel Management (`network.pivot`)* (358 baris)
  - [`ares/modules/network/port_scan.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/port_scan.py) — *TCP Port Scanner (`network.port_scan`)* (574 baris)
  - [`ares/modules/edr/bypass_adaptive.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/edr/bypass_adaptive.py) — *Adaptive EDR Bypass Engine (`edr.bypass_adaptive`)* (1,114 baris)
  - [`ares/modules/exfil/staged_collection.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/staged_collection.py) — *Staged File Collection (`exfil.staged_collection`)* (390 baris)

### Batch 4: Windows Credential Access & Memory Harvesting (TIER 1 - CRITICAL) - [STATUS: AUDITED]
- **Deskripsi**: Modul pemanen kredensial dan manipulasi hak akses memori pada host target Windows (LSASS, SAM/LSA, DPAPI, Token Impersonation, UAC & AppLocker Bypass).
- **Fokus Risiko Audit**: Injeksi proses target, pembacaan memori terproteksi (LSASS minidump), dumping registry SAM, dekripsi DPAPI masterkeys, manipulasi access token.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **6 Temuan Terkonfirmasi** (1 Critical, 3 High, 2 Medium)
  - `MOD-025` (High): Teardown Omission on Transfer Exception & Unguarded Remote Artifact Deletion di `windows.lsass_dump`. Kegagalan SMB transfer meninggalkan local temp dump `ares_lsass_*.dmp` tanpa penghapusan aman, dan kegagalan login saat `_get_lsass_pid` meninggalkan file `ARESPID*.txt` permanen di `C:\Windows\Temp` target (melanggar Rule 4).
  - `MOD-026` (Medium): Phantom Capability Claim & Incomplete Kerberos Ticket Extraction di `windows.lsass_dump`. Output capability mengklaim `kerberos_tickets`, namun parser pypykatz hanya membaca `msv_creds` dan meng-hardcode `raw["kerberos_tickets"] = []` (melanggar Rule 1).
  - `MOD-027` (Medium): Plaintext Unredacted NTLM & DCC2 Hash Material Stored in Finding Evidence di `windows.lsa_secrets`. Password hashes SAM dan DCC2 disimpan langsung tanpa redaksi ke dalam `Finding.evidence["hashes"]`, mengekspos hash ke log audit, reporting, dan API (pola MOD-007).
  - `MOD-028` (High): LSA Secrets & Cached Domain Credentials Pipeline Evaporation (100% Data Loss) di `windows.lsa_secrets`. Output capability `lsa_secrets` dan `cached_credentials` tidak memiliki handler di `ArtifactNormalizer` dan tidak pernah disimpan ke `CredentialVault`, menyebabkan 100% rahasia LSA dan cached hashes hilang setelah eksekusi modul.
  - `MOD-029` (Critical): Fictitious Cleartext Decryption Implementation & False CRITICAL Finding di `windows.dpapi`. Modul mengklaim mengekstrak dan menyimpan cleartext credentials ke vault dengan status CRITICAL, padahal dekripsi masterkey offline dan backup key berupa stub/unimplemented (`# decryption would go here`), dan Chrome password disimpan terenkripsi (`"encrypted": True`). 0 kredensial tersimpan ke vault (melanggar Rule 1).
  - `MOD-030` (High): Fictitious Privilege Escalation Confirmation & Heuristic Over-claiming di `windows.token_impersonation`. Modul menandai temuan sebagai CRITICAL "PrintSpoofer SYSTEM Escalation Vector Confirmed" dengan confidence 0.95 hanya berdasarkan pencocokan substring username service account dan keberadaan named pipe `\pipe\spoolss` yang terbuka secara default di Windows, tanpa verifikasi token privilege sesungguhnya (melanggar Rule 1).
- **Jumlah File**: 6 file
- **Daftar File**:
  - [`ares/modules/windows/lsass_dump.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/lsass_dump.py) — *LSASS Memory Dump (`windows.lsass_dump`)* (805 baris)
  - [`ares/modules/windows/lsa_secrets.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/lsa_secrets.py) — *LSA Secrets & SAM Dump (`windows.lsa_secrets`)* (446 baris)
  - [`ares/modules/windows/dpapi.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/dpapi.py) — *DPAPI Credential Recovery (`windows.dpapi`)* (655 baris)
  - [`ares/modules/windows/token_impersonation.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/token_impersonation.py) — *Token Impersonation (`windows.token_impersonation`)* (453 baris)
  - [`ares/modules/windows/uac_bypass.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/uac_bypass.py) — *UAC Configuration Audit (`windows.uac_bypass`)* (535 baris)
  - [`ares/modules/windows/applocker_bypass.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/applocker_bypass.py) — *AppLocker Policy Enumeration (`windows.applocker_bypass`)* (570 baris)

### Batch 5: Credential Spraying, Ticket Forging & Vault Operations (TIER 1 - CRITICAL) - [STATUS: AUDITED]
- **Deskripsi**: Modul spray otentikasi massal (Password Spray, SSH Spray), teknik Pass-the-Hash, forging Golden/Silver Ticket, hash cracking lokal, dan transcoding tiket Kerberos.
- **Fokus Risiko Audit**: Account lockout risk pada password spraying, penanganan aman material kunci/hash di memory dan vault, integritas transcoding ASN.1 ccache/kirbi.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **6 Temuan Terkonfirmasi** (1 Critical, 4 High, 1 Medium)
  - `MOD-031` (Critical): Complete Omission of Scope Guard, Rate Limiting, and Jitter di `credential.ssh_spray`. Method `run()` mengeksekusi loop koneksi SSH autentikasi ke target tanpa memanggil `await self.before_request(target, "ssh")`, tanpa memeriksa scope Layer 1, tanpa mengakuisisi rate limiter (`self.noise.rate_limiter.acquire("ssh")`), dan tanpa OPSEC jitter sleep (melanggar Rule 1 dan Rule 4).
  - `MOD-032` (High): Out-of-Scope Microsoft Cloud Probing & False Positive Attribution on RFC1918 Targets di `credential.reuse`. Sebelum memanggil `before_request`, modul menjalankan probe HTTP POST ke `login.microsoftonline.com` dari workstation operator. Target IP privat (misal `10.0.0.5`) memicu error HTTP 400 dari Microsoft yang disalahartikan sebagai "Device Code Flow Permitted", menghasilkan finding MEDIUM palsu untuk host lokal (melanggar Rule 1 dan Rule 4, pola MOD-022).
  - `MOD-033` (High): `valid_credentials` Pipeline Evaporation & Type Incoherence (100% Data Loss) di seluruh modul Credential (`credential.pass_spray`, `credential.ssh_spray`, `credential.pass_the_hash`, `credential.reuse`). Seluruh modul mengekspor output `valid_credentials`, namun `ArtifactNormalizer` tidak memiliki handler untuk capability tersebut. Tipe data yang dihasilkan juga saling bertentangan (`pass_the_hash` menyimpan `list[Finding]`, `reuse` menyimpan `list[str]` ID, `pass_spray` dan `ssh_spray` menyimpan `list[dict]`), dan password pada `pass_spray` dimasking `"***REDACTED***"` sehingga kredensial valid hilang permanen dari `ArtifactStore`.
  - `MOD-034` (High): Orphaned Sensitive Ccache Artifacts & Teardown Omission on Operator Machine di `credential.golden_ticket`. Modul men-generate tiket Kerberos TGT lokal (`ares_gt_*.ccache`) pada disk operator tanpa registrasi cleanup atau method `teardown()`. File kredensial sensitif tertinggal permanen di filesystem operator (melanggar Rule 4).
  - `MOD-035` (High): Fictitious Fallback TGT Ticket Construction via `CCache.fromKRBCRED` di `credential.golden_ticket`. Jika impacket ticketer tidak tersedia, fallback membangun tiket palsu tanpa PAC, PAC signature, atau struktur TGT ASN.1 yang valid, namun tetap mengklaim `success=True` dan menerbitkan finding CRITICAL dengan confidence 1.0 (melanggar Rule 1).
  - `MOD-036` (Medium): Output Key Mismatch (`converted_ticket` vs `converted_ticket_b64`) & Normalizer Evaporation di `credential.ticket_converter`. Modul mendeklarasikan `OUTPUTS = ["converted_ticket"]`, namun `run()` menghasilkan `raw["converted_ticket_b64"]`. Tidak ada handler di `ArtifactNormalizer` sehingga tiket hasil konversi hilang dari pipeline data.
- **Jumlah File**: 7 file
- **Daftar File**:
  - [`ares/modules/credential/pass_spray.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/pass_spray.py) — *Password Spray (`credential.pass_spray`)* (794 baris)
  - [`ares/modules/credential/ssh_spray.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ssh_spray.py) — *SSH Credential Spray & Authentication Audit (`credential.ssh_spray`)* (332 baris)
  - [`ares/modules/credential/pass_the_hash.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/pass_the_hash.py) — *Pass-the-Hash (`credential.pass_the_hash`)* (359 baris)
  - [`ares/modules/credential/golden_ticket.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/golden_ticket.py) — *Golden Ticket Forgery (`credential.golden_ticket`)* (475 baris)
  - [`ares/modules/credential/reuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/reuse.py) — *Credential Reuse (`credential.reuse`)* (314 baris)
  - [`ares/modules/credential/crack.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/crack.py) — *Hash Cracking (`credential.crack`)* (350 baris)
  - [`ares/modules/credential/ticket_converter.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/credential/ticket_converter.py) — *Bi-Directional Kerberos Ticket Converter (`credential.ticket_converter`)* (277 baris)

### Batch 6: Linux Local Privilege Escalation & Binary Hijacking (TIER 1 - CRITICAL) - [STATUS: AUDITED]
- **Deskripsi**: Modul eksploitasi eskalasi privilege lokal pada host Linux (SUID/sudo, pembajakan dynamic library LD_PRELOAD, pembajakan binary service, escape container Docker, NFS squash).
- **Fokus Risiko Audit**: Penulisan file library/binary berbahaya pada sistem target, container breakout (cgroup/capabilities), eksploitasi mounting NFS, stabilitas sistem target.
- **Status Audit**: **SELESAI (AUDITED)**
- **Hasil Temuan**: **6 Temuan Terkonfirmasi** (0 Critical, 3 High, 3 Medium)
  - `MOD-037` (High): SSH Connection Leak — `asyncssh.connect()` di `_make_ssh_runner()` pada 4 modul (`linux.privesc`, `linux.service_hijack`, `linux.ld_preload`, `linux.nfs_escape`) tidak pernah di-`close()`. Koneksi SSH tertinggal open, mengandalkan GC (melanggar Rule 4).
  - `MOD-038` (Medium): `linux.privesc._check_writable_path()` memeriksa `os.environ["PATH"]` dan `os.access()` pada workstation operator, bukan target remote SSH. Finding writable PATH menyesatkan jika target != localhost (melanggar Rule 1).
  - `MOD-039` (Medium): `linux.container._check_host_network()` menggunakan heuristik lemah `len(lines) > 50` pada `/proc/net/tcp` untuk mendeteksi `--net=host`. False-positive rate tinggi pada container dengan koneksi banyak (melanggar Rule 1, pola MOD-021).
  - `MOD-040` (Medium): Unhandled Outputs `container_escape_vectors` dan `k8s_rbac_findings` pada `linux.container`. Kedua capability tidak memiliki handler di `ArtifactNormalizer`.
  - `MOD-041` (High): Unhandled Outputs `machine_account_hash` dan `samba_secrets` pada `linux.samba_secrets`. Extracted NTLM hashes tidak terserap ke `ArtifactStore` meskipun tersimpan di vault.
  - `MOD-042` (High): Plaintext NTLM hash unredacted di `Finding.evidence["ntlm_hash"]` dan `EvidenceRecord.data["ntlm_hash"]` pada `linux.samba_secrets` (pola MOD-007, MOD-027).
- **Jumlah File**: 6 file
- **Daftar File**:
  - [`ares/modules/linux/privesc.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/privesc.py) — *Linux Privilege Escalation (`linux.privesc`)* (456 baris)
  - [`ares/modules/linux/service_hijack.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/service_hijack.py) — *Service Binary Hijack Detection (`linux.service_hijack`)* (583 baris)
  - [`ares/modules/linux/ld_preload.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/ld_preload.py) — *LD_PRELOAD / Library Hijack Detection (`linux.ld_preload`)* (547 baris)
  - [`ares/modules/linux/container.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/container.py) — *Container Escape (`linux.container`)* (348 baris)
  - [`ares/modules/linux/nfs_escape.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/nfs_escape.py) — *NFS no_root_squash Detection (`linux.nfs_escape`)* (497 baris)
  - [`ares/modules/linux/samba_secrets.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/samba_secrets.py) — *Samba & Winbind Secrets Extractor (`linux.samba_secrets`)* (298 baris)

### Batch 7: Linux Kerberos Identity Harvest & Target Persistence (TIER 1 - CRITICAL)
- **Deskripsi**: Modul perburuan kredensial domain pada host Linux (ccache, keytab, database SSSD) dan modul pemasang persistensi target (Scheduled Task, WMI Event Subscription).
- **Fokus Risiko Audit**: Pembacaan cache kredensial root/daemon Linux, modifikasi konfigurasi autorun target (penulisan scheduled tasks dan event consumers), fail-safe cleanup.
- **Jumlah File**: 5 file
- **Daftar File**:
  - [`ares/modules/linux/ccache_hunt.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/ccache_hunt.py) — *Linux Kerberos Ticket Hunter (`linux.ccache_hunt`)* (387 baris)
  - [`ares/modules/linux/keytab_abuse.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/keytab_abuse.py) — *Host Keytab Harvester & Silver Ticket Generator (`linux.keytab_abuse`)* (292 baris)
  - [`ares/modules/linux/sssd_harvest.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/sssd_harvest.py) — *SSSD Cache & Credential Harvester (`linux.sssd_harvest`)* (327 baris)
  - [`ares/modules/persistence/scheduled_task.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/persistence/scheduled_task.py) — *Scheduled Task Persistence (`persistence.scheduled_task`), Registry Run Key Persistence (`persistence.registry_run`)* (606 baris)
  - [`ares/modules/persistence/wmi_subscription.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/persistence/wmi_subscription.py) — *WMI Event Subscription Persistence (`persistence.wmi_subscription`)* (409 baris)

### Batch 8: Cloud Privilege Escalation & Identity Federation Abuse (TIER 1 - CRITICAL)
- **Deskripsi**: Modul eksploitasi kontrol akses multi-cloud (AWS, Azure AD, GCP) melalui eskalasi role IAM, penyalahgunaan trust federasi identitas (OIDC/SAML), dan manipulasi OAuth phantom token.
- **Fokus Risiko Audit**: Penyalahgunaan token otentikasi cloud, impersonasi peran istimewa IAM, eskalasi lintas tenant / hybrid identity takeover.
- **Jumlah File**: 3 file
- **Daftar File**:
  - [`ares/modules/cloud/aws_privesc.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/aws_privesc.py) — *AWS IAM Privilege Escalation (`cloud.aws_privesc`)* (342 baris)
  - [`ares/modules/cloud/identity_federation.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/identity_federation.py) — *Cloud Identity Federation Abuse (`cloud.identity_federation_abuse`)* (1,190 baris)
  - [`ares/modules/cloud/phantom_token.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/phantom_token.py) — *Hybrid Entra ID PRT Hijack (`cloud.phantom_token`)* (385 baris)

### Batch 9: Active Directory Discovery & Security Posture Enumeration (TIER 2 - HIGH)
- **Deskripsi**: Modul recon LDAP dan pembacaan read-only objek direktori Active Directory (Users, Computers, SPN, ACLs, dan LAPS password attributes).
- **Fokus Risiko Audit**: Ketahanan parsing query LDAP terhadap karakter kontrol/malformed input, kebocoran query LDAP berlebihan, validasi scope target domain controller.
- **Jumlah File**: 5 file
- **Daftar File**:
  - [`ares/modules/ad/enum_users.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_users.py) — *AD User Enumeration (`ad.enum_users`)* (430 baris)
  - [`ares/modules/ad/enum_computers.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_computers.py) — *AD Computer Enumeration (`ad.enum_computers`)* (352 baris)
  - [`ares/modules/ad/enum_spn.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_spn.py) — *AD SPN Enumeration (`ad.enum_spn`)* (384 baris)
  - [`ares/modules/ad/enum_acl.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/enum_acl.py) — *AD ACL Enumeration (`ad.enum_acl`)* (371 baris)
  - [`ares/modules/ad/laps_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/laps_enum.py) — *LAPS Password Enumeration (`ad.laps_enum`)* (400 baris)

### Batch 10: Network Reconnaissance & Service Fingerprinting (TIER 2 - HIGH)
- **Deskripsi**: Modul discovery pasif dan semi-aktif jaringan (Target Fingerprinting, DNS Enumeration, HTTP Header Banner, Service Version Detection, SNMP MIB Walk).
- **Fokus Risiko Audit**: Parsing response banner mentah, penanganan timeout & unhandled network packet exceptions, validasi kepatuhan scope network.
- **Jumlah File**: 5 file
- **Daftar File**:
  - [`ares/modules/recon/fingerprint.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/recon/fingerprint.py) — *Target Environment Fingerprinting (`recon.fingerprint`)* (303 baris)
  - [`ares/modules/network/dns_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/dns_enum.py) — *DNS Enumeration (`network.dns_enum`)* (365 baris)
  - [`ares/modules/network/http_fingerprint.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/http_fingerprint.py) — *HTTP Fingerprinting (`network.http_fingerprint`)* (360 baris)
  - [`ares/modules/network/service_detect.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/service_detect.py) — *Service Detection (`network.service_detect`)* (398 baris)
  - [`ares/modules/network/snmp_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/network/snmp_enum.py) — *SNMP Enumeration (`network.snmp_enum`)* (414 baris)

### Batch 11: Cloud Asset & Infrastructure Discovery (TIER 2 - HIGH)
- **Deskripsi**: Modul enumerasi read-only aset infrastruktur cloud publik (AWS EC2/S3/IAM, Azure VMs/Subscriptions, Entra ID / Azure AD, GCP Projects & Compute).
- **Fokus Risiko Audit**: Penanganan rate limiting / throttling API cloud, parsing response JSON API tak terduga, isolasi credential cloud antar target tenant.
- **Jumlah File**: 4 file
- **Daftar File**:
  - [`ares/modules/cloud/aws.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/aws.py) — *AWS Recon & Attack (`cloud.aws`)* (347 baris)
  - [`ares/modules/cloud/azure.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure.py) — *Azure Recon & Attack (`cloud.azure`)* (613 baris)
  - [`ares/modules/cloud/azure_ad.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/azure_ad.py) — *Azure AD Identity Attacks (`cloud.azure_ad`)* (465 baris)
  - [`ares/modules/cloud/gcp.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/cloud/gcp.py) — *GCP Recon & Attack (`cloud.gcp`)* (648 baris)

### Batch 12: Host Configuration, Binary Parsing & Secrets Reconnaissance (TIER 2 - HIGH)
- **Deskripsi**: Modul pembacaan konfigurasi sistem host (Windows Registry Enum, Scheduled Tasks Enum, Linux Kernel Exploit Suggester), engine parser data binary, dan pemindai file rahasia / share SMB.
- **Fokus Risiko Audit**: Crash / Denial-of-Service pada parser struktur binary eksternal (ccache v4, keytab, kirbi ASN.1, TDB SAMBA), memory bloat saat scanning file besar.
- **Jumlah File**: 6 file
- **Daftar File**:
  - [`ares/modules/windows/registry_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/registry_enum.py) — *Registry Credential Enumeration (`windows.registry_enum`)* (737 baris)
  - [`ares/modules/windows/scheduled_tasks_enum.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/windows/scheduled_tasks_enum.py) — *Scheduled Tasks Enumeration (`windows.scheduled_tasks_enum`)* (523 baris)
  - [`ares/modules/linux/kernel_suggester.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/kernel_suggester.py) — *Linux Kernel Exploit Suggester (`linux.kernel_suggester`)* (307 baris)
  - [`ares/modules/linux/_parsers.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/linux/_parsers.py) — *_parsers.py* (842 baris)
  - [`ares/modules/exfil/secrets_scan.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/secrets_scan.py) — *Secrets Scanner (`exfil.secrets_scan`)* (652 baris)
  - [`ares/modules/exfil/smb_shares.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/exfil/smb_shares.py) — *SMB Share Enumeration (`exfil.smb_shares`)* (331 baris)

---

## 5. Ringkasan Modul & Utility TIER 3 (Medium - Audit Belakangan)

Modul dan file di bawah ini tidak menyentuh sistem eksternal secara aktif, tidak memodifikasi target, dan tidak mengeksekusi serangan remote. Mereka berfungsi sebagai framework dasar, parser schema, validator internal, perencanaan AI, model prediktif, atau pelaporan.

| File Path | Peran / Fungsi Komponen | Keterangan & Batas Audit | Estimasi Baris |
| :--- | :--- | :--- | :---: |
| [`ares/modules/base.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/base.py) | ARES Module Base Class & Result Contract | Internal engine / SDK component | 759 |
| [`ares/modules/descriptors.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/descriptors.py) | Module Metadata & Capability Descriptors Specification | Internal engine / SDK component | 9,226 |
| [`ares/modules/params.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/params.py) | Pydantic Parameter Schemas for all modules | Internal engine / SDK component | 1,558 |
| [`ares/modules/sdk.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/sdk.py) | Developer SDK Facade & Decorators | Internal engine / SDK component | 396 |
| [`ares/modules/ad/dependencies.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ad/dependencies.py) | Active Directory Binding & Dependency Plan | Internal engine / SDK component | 215 |
| [`ares/modules/ai/autonomous_planner.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ai/autonomous_planner.py) | AI Autonomous Attack Planner (ai.autonomous_planner) | Internal engine / SDK component | 1,044 |
| [`ares/modules/ai/plan_validator.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/ai/plan_validator.py) | AI Autonomous Plan Safety & Feasibility Validator | Internal engine / SDK component | 129 |
| [`ares/modules/opsec/coverage_predictor.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/opsec/coverage_predictor.py) | OPSEC Coverage Predictor (opsec.coverage_predictor) | Internal engine / SDK component | 970 |
| [`ares/modules/reporting/report_gen.py`](file:///c:/Users/ASUS/Desktop/ARES/ares/modules/reporting/report_gen.py) | Campaign Finding Report Generator (HTML/PDF/JSON/Markdown) | Internal engine / SDK component | 2,367 |
| *15 File Package Initialization (`__init__.py`)* | Inisialisasi package namespace modul Python | Safe packaging imports tanpa logika eksternal | 338 total baris |

---

## 6. Rekomendasi Langkah Selanjutnya (Audit Execution Roadmap)

1. **Eksekusi Bertahap per Batch**: Lakukan security audit mendalam dimulai dari **Batch 1 (Active Directory & Kerberos Core)** hingga **Batch 8 (Cloud Attacks)**.
2. **Verifikasi Scope Enforcement**: Pada setiap modul di Batch 1–8, pastikan pemanggilan `await self.before_request(target)` terpasang sebelum socket atau remote connection diinisialisasi.
3. **Verifikasi Fail-Safe Teardown**: Pada modul di Batch 3, 6, dan 7 yang memodifikasi state target (misal Scheduled Task, Registry, Service Hijacking), pastikan ada blok `finally` atau mekanisme rollback teardown yang teruji.
4. **Validasi Robustness Parser**: Pada Batch 12 (`_parsers.py`), uji ketahanan deserialisasi terhadap input ASN.1 / Kerberos yang rusak atau sengaja di-corrupt.
