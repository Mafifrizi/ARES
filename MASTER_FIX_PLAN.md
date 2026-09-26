# ARES Master Remediation Plan: Consolidated Deferred Findings (Batch 1–12 — AUDIT COMPLETE)

> **Dokumen**: `MASTER_FIX_PLAN.md`  
> **Status**: Living Execution Blueprint — Audit 100% Complete  
> **Tanggal Konsolidasi**: 26 September 2026  
> **Cakupan Audit**: Seluruh 12 Batch Selesai (60 modul & parser offensive/core, 75 modul total)  
> **Aturan Eksekusi**: Rule 1 (Zero Over-claiming), Rule 3 (Fix at Root & Grep Before Complete), Rule 4 (Zero Collateral & Guaranteed Teardown)

---

## 1. Status Ringkasan Temuan (Batch 1–12 — FINAL)

| Metrik Audit | Jumlah | Keterangan |
|---|:---:|---|
| **Total Temuan Teridentifikasi** | **74** | MOD-001 s/d MOD-074 (Batch 1 s/d Batch 12) |
| **Sudah Diperbaiki (FIXED)** | **50** | Code fixes + regression tests lulus di main branch (termasuk Fase 1, Fase 2, Fase 3, dan Fase 4 COMPLETE - 7/7) |
| **Mitigasi / Dinonaktifkan (DISABLED)** | **4** | `ad.ghost_forge`, `windows.dpapi`, `windows.token_impersonation`, `cloud.phantom_token` |
| **Masih Open (DEFERRED)** | **20** | Sisa Grup E (Technical Honesty) & Grup F (Cloud Scope) |

### Ringkasan Status per Kelompok
```
Total Temuan: 74
├── FIXED (50)       [67.6%] ══════════════════════════════════════════
├── DISABLED (4)     [ 5.4%] ═══
└── DEFERRED (20)    [27.0%] ═════════════════
    ├── Grup A: Normalizer Handlers Missing (✅ SELESAI - commit 9f8b111)
    ├── Grup B: Hash Masking di Finding.evidence (✅ SELESAI - commit e94533b)
    ├── Grup C: Teardown & Resource Cleanup (✅ SELESAI - 7/7 FIXED - commit facdb61)
    ├── Grup D: Scope Bypass Listener / Destination Parameter (✅ SELESAI - commit cc2e980)
    ├── Grup E: Fake/Stub Implementation & Pipeline Disconnect (15 temuan open, 3 fixed)
    └── Grup F: Architectural Decisions Needed (5 temuan / gates)
```

---

## 2. Temuan yang Sudah Fixed (Referensi)

Berikut adalah daftar temuan yang telah diselesaikan dengan bukti commit pada branch `main`:

| ID | Modul / Area | Deskripsi Singkat | Commit Hash |
|---|---|---|:---:|
| **MOD-006** | `ares/normalize/artifacts.py` | Key mismatch normalizer vs hashes (Dual-Read Fallback) | `17e57c8` |
| **MOD-028** | `ares/normalize/artifacts.py` | LSA secrets & cached domain credentials normalizer handlers | `56ca232` |
| **MOD-031** | `credential.ssh_spray` | Scope guard & rate limiting / jitter omission | `a1c45ff` |
| **MOD-033** | `credential.*` | Standardisasi contract `valid_credentials` + normalizer handler | `e3755ad` |
| **MOD-034** | `credential.golden_ticket` | Orphaned ccache sensitive file cleanup via `finally` | `8eb586e` |
| **MOD-035** | `credential.golden_ticket` | Blokir PAC-less synthetic ticket fallback generation | `9552b34` |
| **MOD-037** | `linux.privesc`, `service_hijack`, `ld_preload`, `nfs_escape` | SSH connection leak (`conn.close()` via `finally`) | `6b040aa` |
| **MOD-038** | `linux.privesc` | `_check_writable_path` eksekusi remote di target bukan operator host | `907d38c` |
| **MOD-045** | `linux.sssd_harvest` | SHA-512 crypt hash classification (`CredentialType.HASH`) + dual-write | `bd24fb5` |
| **MOD-050** | `cloud.identity_federation_abuse` | Scope enforcement on on-premise ADFS probing URL | `802f2ca` |
| **MOD-052** | `cloud.aws_privesc` | Type confusion separation (`iam_privesc_paths` vs `aws_findings`) | `40a928e` |
| **MOD-054** | `ad.enum_spn` | Internal key mismatch sync (`spn_list` $\leftrightarrow$ `spns`) | `f0825df` |
| **MOD-055** | `ad.laps_enum` | Direct vault write + OPSEC-safe raw output (`has_password: True`) | `4bbf61d` |
| **MOD-056 (P)** | `ad.enum_users` | Dual-write standard `users` key (`user_list` & `users`) | `bc8c830` |
| **MOD-061** | `network.snmp_enum` | Direct vault write (Gate 6) + standard `valid_credentials` contract | `5635362` |
| **MOD-064** | `cloud.aws`, `cloud.gcp` | Removal of operator-host link-local metadata probe (`169.254.169.254` / `metadata.google.internal`) | `d86750b` |
| **MOD-067** | `cloud.azure_ad` | Indentation defect fix: resolved UnboundLocalError & restored Microsoft Graph API enumeration | `bd2c9b4` |
| **FASE 1 (Grup A)** | `ares/normalize/artifacts.py` | 16 new normalizer pipeline handlers & multi-key fallbacks (MOD-016, MOD-040, MOD-041, MOD-044, MOD-051, MOD-062, MOD-066, MOD-068, MOD-070, MOD-074) | `9f8b111` |
| **FASE 2 (Grup B)** | `ares/core/security.py`, modules | Redaction masking `mask_secret_hash()` for password hashes in `Finding.evidence` & `EvidenceRecord.data` (MOD-027, MOD-042, systematic grep) | `e94533b` |
| **FASE 3 (Grup D)** | `ares/modules/*` (10 modules) | Strict Layer 1 & 2 scope enforcement on secondary target destinations (`before_request` & `is_in_scope`) (MOD-004, MOD-009, MOD-010, MOD-011, MOD-014, MOD-015, MOD-017, MOD-032, MOD-058, MOD-059) | `cc2e980` |
| **CHAINS FIX** | `ares/core/execution_chains.py` | Remove disabled modules from execution chains for 100% catalog parity | `ae44730` |
| **MOD-060 (Grup C)** | `ares/modules/network/service_detect.py` | Asyncio TCP writer socket cleanup via `try/finally` on banner timeout | `4147e9f` |
| **MOD-025 (Grup C)** | `ares/modules/windows/lsass_dump.py` | Local dump unlinking via `finally` and remote PID artifact cleanup | `9ccdbde` |
| **MOD-048 (Grup C)** | `ares/modules/persistence/wmi_subscription.py` | Fix broken cleanup tuple for `__FilterToConsumerBinding` and `dcom` init | `e76f041` |
| **MOD-047 (Grup C)** | `ares/modules/persistence/scheduled_task.py` | Default `dry_run=False` in `RegistryRunKeyPersistence` and RRP RPC handle cleanup | `e9c7cdd` |
| **MOD-046 (Grup C)** | `ares/modules/persistence/scheduled_task.py` | `created_artifacts` tracking, RPC task deletion via `finally` & `teardown()` method | `327458b` |
| **MOD-012 (Grup C)** | `ares/modules/lateral/ntlm_relay.py` | RBCD machine account deletion via `conn.delete()` and initial DACL restoration | `28e983a` |

*Catatan: Modul yang dinonaktifkan demi keamanan operator (`ad.ghost_forge` [MOD-005], `windows.dpapi` [MOD-029], `windows.token_impersonation` [MOD-030], `cloud.phantom_token` [MOD-049]) dilindungi fail-fast guard dan tidak diizinkan masuk active catalog.*

---

## 3. Temuan Open — Dikelompokkan per Kategori Fix

---

### Grup A: Normalizer Handlers Missing (Fix di `ares/normalize/artifacts.py`) — ✅ SELESAI (commit `9f8b111`)

Seluruh temuan berikut mengalami fenomena **data evaporation (100% data loss)** di mana modul offensive berhasil mengambil telemetry bernilai tinggi, namun `ArtifactNormalizer.normalize()` mengabaikannya karena belum memiliki handler routing. Seluruh handler dan dual-read fallback telah diimplementasikan penuh pada **Fase 1 (commit `9f8b111`)** dan diverifikasi dengan 42/42 tests passing di `tests/unit/test_artifact_normalizer_pipeline.py`.

| ID | Modul | Capability / Output Key | Tipe Artifact yang Dibutuhkan | Rencana Solusi di `artifacts.py` |
|---|---|---|---|---|
| **MOD-016** | `ad.sccm` | `cleartext_credentials` (DPAPI NAA blobs) | `CredentialArtifact(cred_type="dpapi_blob")` | Tambah handler `_normalize_sccm_credentials` atau perbaiki extractor agar tidak melabeli ciphertext sebagai cleartext. |
| **MOD-036** | `credential.ticket_converter` | `converted_ticket` / `converted_ticket_b64` | `CredentialArtifact(cred_type="kerberos_ticket")` | *(Handler normalizer diimplementasikan di `5635362`)*. Routing `_normalize_converted_ticket`. |
| **MOD-040** | `linux.container` | `container_escape_vectors`, `k8s_rbac_findings` | `HostVulnArtifact` & `PermissionArtifact` | Buat handler `_normalize_container_vectors` & `_normalize_k8s_rbac`. |
| **MOD-041** | `linux.samba_secrets` | `machine_account_hash`, `samba_secrets` | `HashArtifact(hash_type="ntlm")`, `CredentialArtifact` | *(Handler normalizer diimplementasikan di `5635362`)*. Routing `_normalize_samba_secrets`. |
| **MOD-044** | `linux.keytab_abuse` | `machine_credentials`, `kerberos_keys` | `CredentialArtifact(cred_type="keytab_key")` | *(Handler normalizer diimplementasikan di `5635362`)*. Routing `_normalize_keytab_keys`. |
| **MOD-051** | `cloud.identity_federation_abuse` | `federation_trusts`, `golden_saml_paths`, `oauth_tokens`, `pivot_paths` | `CloudResourceArtifact` & `CredentialArtifact` | Handler modular untuk token OAuth dan topologi trust federasi cloud. |
| **MOD-052** | `cloud.aws_privesc` | `aws_privesc_paths`, `iam_privesc_paths` | `PermissionArtifact(privilege="privesc_vector")` | *(Handler normalizer diimplementasikan di `5635362`)*. Routing `_normalize_iam_privesc`. |
| **MOD-056** | `ad.enum_users` | `password_policy` | `DomainPolicyArtifact` (atau `HostArtifact` metadata) | Buat handler `_normalize_password_policy` untuk mencatat panjang password, threshold lockout, dan durasi audit. |
| **MOD-061** | `network.snmp_enum` | `snmp_findings`, `valid_credentials` (SNMP) | `CredentialArtifact(cred_type="snmp_community")` | **FIXED** (commit `5635362`). Vault write Gate 6 + standard `valid_credentials` contract. |
| **MOD-062** | `recon.fingerprint`, `network.*` | `fingerprint_result`, `dns_records`, `subdomains`, `web_fingerprint`, `admin_interfaces`, `service_versions`, `vulnerable_services` | `HostArtifact` & `HostVulnArtifact` | *(7 Handler normalizer diimplementasikan di `5635362`)* (`dns_records`, `subdomains`, `service_versions`, `vulnerable_services`, `web_fingerprint`, `admin_interfaces`). Sisa recon capability ditunda ke batch fix serentak. |
| **MOD-066** | `cloud.azure`, `cloud.azure_ad` | `azure_findings`, `azure_ad_findings`, `access_tokens` | `CloudResourceArtifact` & `CredentialArtifact` | Tambah handler `_normalize_azure` & `_normalize_azure_ad` untuk mengekstrak storage accounts, RBAC bindings, NSG rules, guest users, dan token akses. |
| **MOD-068** | `cloud.gcp` | `gcp_findings` | `CloudResourceArtifact` & `PermissionArtifact` | Tambah handler `_normalize_gcp` untuk mengekstrak GCS public buckets, project IAM bindings, dan service account keys. |
| **MOD-070** | `windows.*`, `linux.kernel_suggester` | `cleartext_credentials`, `credential_hints`, `scheduled_tasks`, `privesc_vectors` | `CredentialArtifact`, `PermissionArtifact` | Hapus assign Finding model objek ke raw output dict; tambahkan handler normalizer untuk registry credentials & privesc vectors. |
| **MOD-074** | `exfil.secrets_scan`, `exfil.smb_shares` | `credential_list`, `discovered_secrets`, `sensitive_data_found`, `file_share_list`, `sensitive_file_paths` | `CredentialArtifact`, `HostArtifact` | Tambahkan handler `_normalize_secrets_scan` dan `_normalize_smb_shares` untuk menangkap kredensial dan file path sensitif ke `ArtifactStore`. |

**Estimasi Pengerjaan**: 1 commit per sub-kategori capability (AD, Linux, Cloud, Host/Exfil). Semua perubahan terlokalisasi di `ares/normalize/artifacts.py` dan unit test di `tests/unit/test_artifact_normalizer_pipeline.py`.

---

### Grup B: Hash Masking di `Finding.evidence` — ✅ SELESAI (commit `e94533b`)

Mengekspos hash kredensial secara plaintext pada log audit, reporting API, atau `Finding.evidence` melanggar standar OPSEC dan privacy ARES (pola MOD-007). Seluruh kemunculan raw hash telah diredaksi dengan `mask_secret_hash()` pada **Fase 2 (commit `e94533b`)** dan diverifikasi via `tests/unit/test_hash_masking_grup_b.py`.

| ID | Modul | Lokasi Kode | Field Sensitif yang Bocor | Pola Redaksi yang Diwajibkan |
|---|---|---|---|---|
| **MOD-027** | `windows.lsa_secrets` | `lsa_secrets.py:383, 431` | `Finding.evidence["hashes"]` (NTLM & DCC2) | `f"{h[:6]}...{h[-4:]}"` |
| **MOD-042** | `linux.samba_secrets` | `samba_secrets.py:197, 216` | `Finding.evidence["ntlm_hash"]`, `EvidenceRecord.data["ntlm_hash"]` | `f"{ntlm[:6]}...{ntlm[-4:]}"` |

**Fix Pattern**:
```python
# Canonical redaction pattern
def mask_secret_hash(val: str) -> str:
    if not val or len(val) <= 10:
        return "***"
    return f"{val[:6]}...{val[-4:]}"
```

---

### Grup C: Teardown Missing di Persistence & Lateral Modules — ⚠️ PARTIAL (6/7 FIXED, MOD-018 Menunggu Konfirmasi Arsitektur)

Modul-modul ini melakukan perubahan status permanen pada sistem atau domain target klien tanpa menyediakan mekanisme rollback / cleanup otomatis. Melanggar **Rule 4 ARES (Guaranteed Teardown & Zero Collateral)**. 6 dari 7 temuan telah diselesaikan dan diverifikasi dengan failure-injection tests.

| ID | Modul | Modifikasi Target Klien | Resiko Bahaya (Engagement Risk) | Status & Bukti Commit |
|---|---|---|---|---|
| **MOD-012** | `lateral.ntlm_relay` | Membuat akun mesin `ARESXXXXXX$` & inject RBCD DACL | Backdoor permanen tertinggal di AD domain klien. | ✅ **FIXED** (commit `28e983a`). Simpan DACL awal $\rightarrow$ bungkus S4U di `try/finally` $\rightarrow$ `conn.delete(machine_dn)` dan pulihkan atribut `msDS-AllowedToActOnBehalfOfOtherIdentity`. 2/2 tests passing. |
| **MOD-018** | `network.pivot` | Background SSH forwarding processes | Background SSH tunnel yatim di memory operator/target. | ⏳ **PENDING CONFIRMATION**. `PivotModule.teardown()` tidak pernah dipanggil karena belum ada general engine teardown lifecycle. STOP menunggu konfirmasi. |
| **MOD-025** | `windows.lsass_dump` | SMB transfer temp files & `ARESPID*.txt` | File artefak forensik tertinggal di `%TEMP%` atau share C$. | ✅ **FIXED** (commit `9ccdbde`). Secure unlinking file dump lokal di blok `finally` (termasuk crash) dan fallback remote `del` command untuk file `ARESPID*.txt`. 3/3 tests passing. |
| **MOD-046** | `persistence.scheduled_task` | Scheduled Task RPC & Registry Run Key | Persistent autorun backdoor tertinggal di OS target klien. | ✅ **FIXED** (commit `327458b`). `created_artifacts` disimpan sebelum task dibuat; RPC task delete di blok `finally` dan implementasi `teardown()` method. 3/3 tests passing. |
| **MOD-047** | `persistence.scheduled_task` | Unhandled DCE/RPC connection disconnect | Connection handle RPC leak saat registrasi gagal. | ✅ **FIXED** (commit `e9c7cdd`). Default `dry_run=False` pada `RegistryRunKeyPersistence`, bungkus `hRootKey`/`hRunKey` dan `dce.disconnect()` dalam `try/finally`. 2/2 tests passing. |
| **MOD-048** | `persistence.wmi_subscription` | WMI Event Filter, Consumer, & Binding | Broken cleanup tuple (`None` key), WMI autorun tertinggal. | ✅ **FIXED** (commit `e76f041`). Perbaiki penghapusan `__FilterToConsumerBinding` di `cleanup()`, inisialisasi `dcom = None`, dan `persistence_established` string kosong saat gagal. 2/2 tests passing. |
| **MOD-060** | `network.service_detect` | Unclosed asyncio TCP writer socket on read timeout | Socket descriptor handle leak saat banner read timeout. | ✅ **FIXED** (commit `4147e9f`). Bungkus `reader.read()` dalam `try ... finally: writer.close(); await writer.wait_closed()`. 2/2 tests passing. |

---

### Grup D: Scope Bypass Listener Parameter — ✅ SELESAI (commit `cc2e980`)

Engine `_extract_all_targets` hanya mengekstrak parameter target primer (`target`, `dc`, `host`, `ip`). Parameter tujuan sekunder yang dapat memicu koneksi keluar (listener UNC, proxy, CA host, relay target list) terlewat dari validasi `campaign.is_in_scope()`. Seluruh 10 modul target telah diperbaiki pada **Fase 3 (commit `cc2e980`)** dan diverifikasi via `tests/unit/test_scope_enforcement_grup_d.py`.

| ID | Modul | Parameter yang Bypass Scope | Protokol / Port | Lokasi Fix |
|---|---|---|---|---|
| **MOD-004** | `ad.coerce` | `listener_ip` / `listener` | SMB (445), WebDAV (80/443) | Tambah `await self.before_request(listener_ip, "smb")`. |
| **MOD-009** | `ad.adcs` | `ca_host` | HTTP / HTTPS (80/443) | Tambah `await self.before_request(ca_host, "http")` sebelum submit CSR. |
| **MOD-010** | `ad.sccm` | `site_server`, `dp_host` | DCOM / PXE (4011/67) | Tambah `before_request` sebelum probe DCOM & PXE. |
| **MOD-011** | `lateral.ntlm_relay` | `_check_relay_targets` (list 50 host AD) | SMB (445) | Filter list target via `campaign.is_in_scope(host)` sebelum connect socket. |
| **MOD-014** | `lateral.mssql` | `listener_ip`, `linked_server` | SMB / MSSQL (1433) | Validasi listener & linked server via `before_request`. |
| **MOD-015** | `lateral.smb_relay` | Primary negotiate loop target | SMB (445) | Panggil `await self.before_request(target, "smb")` sebelum negosiasi. |
| **MOD-017** | `network.pivot` | `remote_host`, `reachable_subnets` | SSH (22) / TCP | Validasi seluruh subnet target terhadap scope campaign. |
| **MOD-022** | `exfil.staged_collection` | Cloud egress endpoints | HTTP HEAD | Tolak request jika egress endpoint berada di luar scope campaign. |
| **MOD-032** | `credential.reuse` | `login.microsoftonline.com` | HTTPS (443) | Cegah auto-probing endpoint publik jika target bertipe RFC1918 internal. |
| **MOD-058** | `network.dns_enum` | `ns_host` / `ns_clean` (AXFR zone transfer) | TCP (53) | Tambah `await self.before_request(ns_clean, "dns")` sebelum query zone transfer AXFR. |
| **MOD-059** | `network.http_fingerprint` | External redirect URLs via `follow_redirects=True` | HTTP / HTTPS | Custom redirect hook untuk memvalidasi `campaign.is_in_scope()` sebelum mengikuti redirect ke host luar. |
| **MOD-064** | `cloud.aws`, `cloud.gcp` | `http://169.254.169.254`, `http://metadata.google.internal` | HTTP (80) | **FIXED** (commit `d86750b`). Probing metadata lokal workstation operator telah dihapus dari `cloud.aws` dan `cloud.gcp`. |

**Fix Pattern**:
```python
# Canonical scope enforcement for secondary destinations
if listener_ip:
    await self.before_request(listener_ip, "listener")
```

---

### Grup E: Fake/Stub Implementation & Pipeline Disconnect (Masih Aktif)

Modul-modul ini masih aktif di katalog, namun memiliki klaim kemampuan fiktif, parsing hardcoded kosong, atau heuristik lemah yang memicu false positive. Melanggar **Rule 1 ARES (Anti-Hype Policy & Zero Over-claiming)**.

| ID | Modul | Deskripsi Implementasi Palsu / Stub | Rekomendasi Solusi |
|---|---|---|---|
| **MOD-013** | `lateral.ntlm_relay` | Mengklaim S4U impersonasi Administrator, padahal hanya minta TGS akun mesin biasa dan menyimpan nama file palsu `administrator@target.ccache`. | Implementasi protokol S4U2self + S4U2proxy nyata via impacket atau turunkan klaim & ubah nama ccache menjadi tiket akun mesin. |
| **MOD-019** | `network.pivot` | Menandai tunnel ACTIVE dan menerbitkan finding sukses saat backend SSH tidak terpasang. | Return failure / raise `ModuleExecutionError` jika dependency tidak terpenuhi. |
| **MOD-020** | `lateral.ssh_pivot` | `establish_socks5` mengembalikan dict proxy padahal `move()` mengabaikan port dan menutup koneksi. | Implementasikan SOCKS5 proxy handler berbasis asyncio atau tandai experimental. |
| **MOD-021** | `lateral.rdp` | Port 3389 terbuka langsung dilaporkan sebagai exploit lateral movement CRITICAL sukses tanpa otentikasi. | Ubah severity menjadi INFO/LOW (Port Detection) kecuali otentikasi NLA berhasil dikonfirmasi. |
| **MOD-023** | `exfil.staged_collection` | Parameter `destination` wajib tapi diabaikan; output `files_staged` selalu kosong. | Implementasi staging logic riil (arsip zip/tar) atau hapus parameter tak terpakai. |
| **MOD-024** | `network.port_scan` | String CIDR di-pass mentah ke `asyncio.open_connection` memicu error socket. | Ekspansi CIDR menjadi list IP individual via `ipaddress.ip_network` sebelum scanning. |
| **MOD-026** | `windows.lsass_dump` | Deklarasi output `kerberos_tickets`, tapi pypykatz parser mengembalikan list kosong hardcoded `[]`. | Hapus `kerberos_tickets` dari `OUTPUTS` sampai parser Kirbi/ccache diimplementasikan. |
| **MOD-039** | `linux.container` | Heuristik `len(lines) > 50` pada `/proc/net/tcp` memicu false finding `--net=host`. | Periksa kesamaan inode namespace network (`/proc/1/ns/net` vs `/proc/self/ns/net`). |
| **MOD-043** | `linux.ccache_hunt` | Scan `/proc/keys` dan socket KCM menyuntikkan string kosong `""` ke `AresVault`. | Blokir penyimpanan vault jika byte tiket kosong (sejalan dengan Gate 6). |
| **MOD-047** | `persistence.scheduled_task` | Inverted default `dry_run=True` pada `RegistryRunKeyPersistence`. | Set default `dry_run=False` (mengikuti setting context eksekusi). |
| **MOD-057** | `ad.enum_acl`, `ad.laps_enum` | Raw string concatenation `user=f"{domain}\\{username}"` membypass `build_ad_bind_plan()`. | Migrasi ke `build_ad_bind_plan()` untuk standardisasi UPN/NTLM domain binding. |
| **MOD-061** | `network.snmp_enum` | Menyimpan list `Finding` objek mentah di `raw["snmp_findings"]` dan tidak memformat ke kontrak standar `valid_credentials` (MOD-033). | **FIXED** (commit `5635362`). Serialisasi findings ke dicts dan tuliskan community string yang valid ke vault / `valid_credentials`. |
| **MOD-065** | `cloud.*` | `validate()` tidak memverifikasi import SDK cloud (`boto3`, `azure-identity`, `azure-mgmt-*`, `msal`, `google-auth`). | Tambahkan import pre-flight check dengan `find_spec()` dan raise `ModuleValidationError` informatif (Estimasi Fix: S - 4 file, pola identik). |
| **MOD-067** | `cloud.azure_ad` | Indentasi return statement salah pada `run()`, memicu `UnboundLocalError` pada default `technique="enumerate"` dan memutus 100% eksekusi Microsoft Graph API (dead code). | **FIXED** (commit `bd2c9b4`). Indentasi return blok `device_code` diperbaiki, inisialisasi `raw` di awal method, enumerasi Graph API dipulihkan. |
| **MOD-069** | `windows.registry_enum`, `scheduled_tasks_enum` | Asimetri validasi: `validate()` lolos tanpa username tapi `run()` abort diam-diam. | Tambahkan validasi username di `validate()` atau fallback deterministik dengan raise `ModuleValidationError`. |
| **MOD-071** | `linux.kernel_suggester` | CVE userspace (PwnKit, Baron Samedit) dicocokkan ke versi kernel dengan regex `r"[345]\.[0-9]+"` menghasilkan false finding CRITICAL. | Batasi daftar CVE hanya pada vulnerability kernel nyata (Dirty Pipe, Dirty COW, eBPF) dengan parsing versi semver yang ketat. |
| **MOD-072** | `linux._parsers` | `KirbiASN1Codec.decode_kirbi` mengklaim parsing ASN.1 DER tapi mengembalikan session key hardcoded nol (`"00" * 32`) dan tebakan principal. | Implementasikan ASN.1 DER parser riil untuk KRB-CRED (RFC 4120) agar konversi kirbi ke ccache menghasilkan tiket yang valid untuk autentikasi. |
| **MOD-073** | `exfil.secrets_scan`, `smb_shares` | Parameter protokol di-default ke `"default"` pada `before_request()` dan validasi username absen di `validate()`. | Lewatkan protokol spesifik (`"ssh"`, `"wmi"`, `"smb"`) ke `before_request()` dan verifikasi username pada `validate()` untuk eksekusi non-dry-run. |

---

### Grup F: Architectural Decisions Needed

Temuan arsitektural yang membutuhkan keputusan desain dan persetujuan lead engineer sebelum dieksekusi:

1. **MOD-053 & MOD-063: Cloud Scope Gap (Architectural Gap)**
   - **Masalah**: `ScopeGuard` hanya mengevaluasi IP/CIDR/DNS. Modul cloud (`aws_privesc`, `identity_federation_abuse`, `cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp`) menggunakan identifier cloud seperti `aws_account_id` (STS), `tenant_id`, `subscription_id`, `project_id`, `arn:aws:iam::*` yang saat ini lolos tanpa validasi scope campaign.
   - **Opsi Solusi**:
     - *Opsi 1*: Tambahkan dataclass `CloudScope` ke dalam `Campaign` (`allowed_aws_accounts`, `allowed_azure_tenants`, `allowed_gcp_projects`).
     - *Opsi 2*: Buat `CloudScopeGuard` terpisah yang diinjeksi via `ExecutionContext`.
   - **Rekomendasi**: Opsi 1 (ekstensi deklaratif pada `CampaignScope`) + helper `validate_cloud_scope`.

2. **Gate 1: Parameter & Boundary Integrity Guard**
   - Penegakan validasi schema Pydantic sebelum modul diizinkan memasuki tahap scheduling.

3. **Gate 2: In-Process Scope Interceptor vs OS-Level Packet Filter**
   - Sinkronisasi aturan blocking antara Layer 2 (`ScopeFirewall`) dan Layer 3 (`OSFirewallController`).

4. **Gate 4: Subprocess Sandboxing & Execution Isolation**
   - Mencegah eksekusi binary tidak tepercaya pada host operator tanpa containerization.

---

## 4. Urutan Eksekusi Fix yang Disarankan

Setelah seluruh 12 Batch audit selesai:

```mermaid
graph TD
    A[Selesai Seluruh Batch Audit 1-12] --> B[Fase 1: Grup A - Normalizer Handlers Missing]
    B --> C[Fase 2: Grup B - Hash Masking di Evidence]
    C --> D[Fase 3: Grup D - Scope Bypass Listener Parameter]
    D --> E[Fase 4: Grup C - Guaranteed Teardown Persistence]
    E --> F[Fase 5: Grup E - Fake/Stub Implementations]
    F --> G[Fase 6: Grup F - Architectural Decisions & Cloud Scope]
```

### Rincian Fase Eksekusi:
1. **Fase 1: Grup A (Normalizer Handlers)** — *Prioritas Tertinggi, Manfaat Maksimal*
   - Sentralisasi pada satu file (`ares/normalize/artifacts.py`).
   - Menyelesaikan data loss 100% pada downstream attack graph.
   - Risiko regresi sangat rendah berkat fixture pipeline test.
2. **Fase 2: Grup B (Hash Masking)** — *Pola Identik*
   - Penerapan helper fungsi redaksi di seluruh model finding/evidence.
   - Memastikan kepatuhan zero credential leak pada laporan purple-team.
3. **Fase 3: Grup D (Scope Bypass)** — *Penegakan Keamanan Operasional*
   - Penerapan `await self.before_request(...)` pada seluruh parameter sekunder.
   - Memastikan tidak ada packet keluar dari operator yang menyerang target di luar izin client.
4. **Fase 4: Grup C (Teardown Persistence)** — *Integritas & Zero Collateral*
   - Membutuhkan penulisan method `teardown()` dan fail-safe `try ... finally`.
   - Wajib diuji dengan skenario inject error (simulasi timeout / network drop di tengah eksploitasi).
5. **Fase 5: Grup E (Fake/Stub Implementations)** — *Technical Honesty*
   - Memperbaiki kode atau menurunkan klaim severity (misal RDP open port).
   - Menghapus klaim fiktif yang melanggar Anti-Hype Policy.
6. **Fase 6: Grup F (Arsitektur & Cloud Scope)** — *Perlu Review Owner*
   - Implementasi `CloudScopeGuard` dan integrasi campaign schema.

---

## 5. Estimasi Total Scope Perbaikan

| Grup Perbaikan | Perkiraan Jumlah File | Perkiraan Unit Test Baru | Estimasi Risiko Regresi | Durasi Eksekusi |
|---|:---:|:---:|:---:|:---:|
| **Grup A (Normalizer)** | 3–4 file (`artifacts.py`, test, serializers) | 16–18 test cases | **Low** | 3–4 jam |
| **Grup B (Hash Masking)** | 3–4 file modul | 4–6 test cases | **Low** | 1 jam |
| **Grup C (Teardown Persistence)** | 5–6 file modul | 8–10 failure-injection tests | **High** | 4–5 jam |
| **Grup D (Scope Bypass)** | 8–10 file modul | 10–12 scope violation tests | **Medium** | 3–4 jam |
| **Grup E (Fake Stubs / Logic / Parsers)** | 12–15 file modul | 18–22 behavior tests | **Medium** | 5–7 jam |
| **Grup F (Arsitektural / Cloud)** | 4–6 core files | 8–10 integration tests | **High** | Memerlukan alignment |
| **TOTAL KESELURUHAN** | **~40 file** | **~75 unit tests** | — | **~24–28 jam kerja terfokus** |

---

## 6. AUDIT COMPLETE — RINGKASAN FINAL

Audit keamanan 12 Batch terhadap seluruh offensive modules ARES telah **SELESAI 100%**. Berikut adalah sintesis menyeluruh dari temuan, status remedi, postur mitigasi, dan rencana eksekusi final.

### 6.1. Metrik Audit Komprehensif

| Dimensi Evaluasi | Metrik | Keterangan Rinci |
|---|:---:|---|
| **Total Batch Diaudit** | **12 / 12 Batch** | 100% modul Tier 1 & Tier 2 tuntas diaudit |
| **Total File Modul & Parser Diaudit** | **60 File** | 55 offensive modules + 5 core parser/engine utilities |
| **Total Katalog Modul (Termasuk Tier 3)** | **88 File** | 60 modul ofensif/parser + 13 framework engine + 15 namespace packages |
| **Total Temuan Teridentifikasi** | **74 Temuan** | `MOD-001` s/d `MOD-074` |
| **Sudah Diperbaiki (FIXED)** | **17 Temuan** | Verified passing main branch tests |
| **Mitigasi / Dinonaktifkan (DISABLED)** | **4 Modul** | Fail-fast guards aktif, 100% decoupled dari katalog |
| **Pending Fix Serentak (DEFERRED)** | **53 Temuan** | Terpetakan ke Grup A–F dengan pola solusi terstandarisasi |

---

### 6.2. Distribusi Temuan per Severity

| Severity Level | Jumlah | Status Breakdown | Persentase |
|---|:---:|---|:---:|
| **CRITICAL** | **10** | 1 Fixed (`MOD-067`), 3 Disabled (`MOD-005`, `MOD-029`, `MOD-049`), 6 Deferred (`MOD-001`, `MOD-002`, `MOD-011`, `MOD-012`, `MOD-021`, `MOD-046`) | 13.5% |
| **HIGH** | **42** | 15 Fixed, 1 Disabled (`MOD-030`), 26 Deferred | 56.8% |
| **MEDIUM** | **21** | 1 Fixed (`MOD-056`), 0 Disabled, 20 Deferred | 28.4% |
| **LOW** | **1** | 0 Fixed, 0 Disabled, 1 Deferred (`MOD-073`) | 1.3% |
| **TOTAL** | **74** | **17 Fixed, 4 Disabled, 53 Deferred** | **100.0%** |

---

### 6.3. Distribusi Temuan per Kategori Perbaikan (Grup A–F)

| Kategori Remediasi | Jumlah Temuan / Capability Sets | Rincian Temuan | Estimasi Kompleksitas |
|---|:---:|---|:---:|
| **Grup A: Normalizer Pipeline Gaps** | **14** | MOD-016, 036, 040, 041, 044, 051, 052, 056, 061 (fixed), 062, 066, 068, 070, 074 | Medium (sentralisasi di `artifacts.py`) |
| **Grup B: Hash Masking di Evidence** | **2** | MOD-027, MOD-042 | Low (standar helper fungsi redaksi) |
| **Grup C: Guaranteed Teardown & Cleanup** | **7** | MOD-012, 018, 025, 046, 047, 048, 060 | High (failure-injection unit testing) |
| **Grup D: Scope Bypass Listener / Destination** | **12** | MOD-004, 009, 010, 011, 014, 015, 017, 022, 032, 058, 059, MOD-064 (fixed) | Medium (enforce `before_request`) |
| **Grup E: Technical Honesty, Validation & Parsing** | **18** | MOD-013, 019, 020, 021, 023, 024, 026, 039, 043, 047, 057, 061 (fixed), 065, 067 (fixed), 069, 071, 072, 073 | Medium-High (real ASN.1 & logic fixes) |
| **Grup F: Architectural Decisions & Cloud Scope** | **5** | MOD-053/MOD-063 (CloudScopeGuard), Gate 1, Gate 2, Gate 4 | High (arsitektur & design review) |

---

### 6.4. Modul yang Dinonaktifkan & Rationale Pengamanan

4 modul offensive dinonaktifkan sementara dari pipeline produksi demi keselamatan keterlibatan (engagement safety), integritas cryptographic vault, dan kepatuhan anti-hype policy:

1. **`ad.ghost_forge` (`ares/modules/ad/ghost_forge.py`, MOD-005)**:
   - *Alasan*: Fictitious implementation. Mengklaim PKINIT takeover & ADCS shadow credential tanpa koneksi jaringan/LDAP/KDC riil, dan menyuntikkan dummy certificates ke vault.
   - *Status Mitigasi*: `ENABLED = False`, disaring dari katalog `ModuleRegistry`, API `/modules`, CLI, dan execution chains. Invokasi langsung melempar exception eksplisit `"module disabled: implementation incomplete, see MOD-005"`.
2. **`windows.dpapi` (`ares/modules/windows/dpapi.py`, MOD-029)**:
   - *Alasan*: Fictitious cleartext credential claim. Menghasilkan CRITICAL finding berhasil mendekripsi DPAPI tanpa masterkey atau LSASS dump yang valid.
   - *Status Mitigasi*: `ENABLED = False`, guard fail-fast pada `validate()`, `execute()`, dan `assess_feasibility()`.
3. **`windows.token_impersonation` (`ares/modules/windows/token_impersonation.py`, MOD-030)**:
   - *Alasan*: Heuristic over-claiming. Mengklaim eskalasi hak akses token berhasil dikonfirmasi tanpa melakukan duplikasi atau impersonasi token Windows riil.
   - *Status Mitigasi*: `ENABLED = False`, guard fail-fast pada seluruh method lifecycle.
4. **`cloud.phantom_token` (`ares/modules/cloud/phantom_token.py`, MOD-049)**:
   - *Alasan*: Fictitious PRT hijack. Mengklaim mengekstrak Primary Refresh Token (PRT) TPM Microsoft Entra ID tanpa memanggil COM interface atau LSASS API, mencemari vault dengan token sintetis palsu.
   - *Status Mitigasi*: `ENABLED = False`, fail-fast di seluruh entry point.

---

### 6.5. Status Gate Kualitas & Keamanan (Implemented vs Pending)

| Security Gate | Deskripsi Kontrol | Status | Komponen Penegak |
|---|---|:---:|---|
| **Gate 3** | Opsec Level & Rate Limiter / Jitter Enforcement | ✅ **IMPLEMENTED** | `NoiseController`, `rate_limiter.acquire()`, jitter calculation |
| **Gate 5** | Deterministic Scope Enforcement (Layer 1 & Layer 2) | ✅ **IMPLEMENTED** | `ScopeGuard`, `before_request()`, `ScopeFirewall` in-process socket hook |
| **Gate 6** | Cryptographic Vault Storage for Sensitive Material | ✅ **IMPLEMENTED** | `CredentialVault` direct write, validated di MOD-045, MOD-055, MOD-061 |
| **Gate 1** | Strict Parameter & Schema Pre-Flight Guard | ⏳ **PENDING** | Butuh penegakan Pydantic schema validation sebelum scheduling modul |
| **Gate 2** | In-Process Scope Interceptor vs OS-Level Packet Filter Sync | ⏳ **PENDING** | Butuh sinkronisasi aturan blocking antara `ScopeFirewall` dan `OSFirewallController` |
| **Gate 4** | Subprocess Sandboxing & Execution Isolation | ⏳ **PENDING** | Butuh isolasi runner untuk eksekusi CLI/binary eksternal agar zero collateral |

---

### 6.6. Rekomendasi Urutan Eksekusi Fix Serentak yang Final

Untuk meminimalkan waktu regresi dan memaksimalkan stabilitas, eksekusi remedi simultaneous fix harus mengikuti 6 fase terurut:

```
┌────────────────────────────────────────────────────────────────────────┐
│  FASE 1: Grup A — Normalizer Handlers Missing (ares/normalize/artifacts.py)  │
│  [STATUS: ✅ COMPLETED - commit 9f8b111]                                │
│  - 16 new handlers & multi-key fallbacks, 42/42 tests passing.         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  FASE 2: Grup B — Hash Masking di Finding.evidence                     │
│  [STATUS: ✅ COMPLETED - commit e94533b]                                │
│  - mask_secret_hash() in core/security.py, 4/4 tests passing.          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  FASE 3: Grup D — Scope Bypass Listener & Secondary Destination        │
│  [STATUS: ✅ COMPLETED - commit cc2e980]                                │
│  - 10 offensive modules scoped on secondary destinations, 10/10 tests. │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  FASE 4: Grup C — Guaranteed Teardown (Rule 4 Compliance)              │
│  [STATUS: ✅ COMPLETED (7/7 FIXED) - commit facdb61]                    │
│  - 7 modul persistence/lateral dilengkapi teardown & failure tests.    │
│  - MOD-018: pivot subprocess teardown via engine finally (Opsi B).     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  FASE 5: Grup E — Technical Honesty, Parsing & Validation Robustness    │
│  - Perbaikan ASN.1 parser di _parsers.py (MOD-072), semver di suggester│
│    (MOD-071), SDK check (MOD-065), dan eliminasi klaim fiktif.        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  FASE 6: Grup F — Architectural Decisions, Cloud Scope & Gates 1, 2, 4  │
│  - Perancangan CloudScopeGuard dataclass pada CampaignScope.            │
│  - Integrasi pre-flight admission Gate 1 dan sinkronisasi Gate 2.      │
└────────────────────────────────────────────────────────────────────────┘
```

