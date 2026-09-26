# ARES Architectural Contract Audit: Artifact Normalizer & Pipeline Key Mismatches

> **Status**: Comprehensive Systemic Audit
> **Scope**: `ares/normalize/artifacts.py` vs seluruh 70 modul di `ares/modules/`
> **Tanggal Audit**: 26 September 2026
> **Temuan Kunci**: Kerusakan sistemik pada pipeline normalisasi data telemetry ofensif ke `ArtifactStore`. Dari 9 capability yang didukung oleh `ArtifactNormalizer`, **hanya 2 capability yang berfungsi penuh (MATCH)**, 1 capability PARTIAL, dan **6 capability mengalami TOTAL MISMATCH (data 100% hilang)**. Selain itu, terdapat **86 capability output modul yang sama sekali tidak memiliki handler (UNHANDLED OUTPUT)**.

---

## 1. Ringkasan Eksekutif & Statistik Kontrak

Dalam arsitektur ARES, setelah setiap modul berhasil dieksekusi, `AresEngine.run_module` memanggil:
```python
# ares/core/engine.py:1336
normalized = ArtifactNormalizer().normalize(
    module_id=module_id,
    outputs=outputs,
    raw=result.raw_output,
    store=runtime_state.artifact_store,
)
```
`ArtifactNormalizer` bertanggung jawab mengonversi dictionary `raw` hasil modul menjadi objek bertipe terstruktur (`UserArtifact`, `HostArtifact`, `HashArtifact`, `PermissionArtifact`, `CloudResourceArtifact`) di dalam `runtime_state.artifact_store`. Objek-objek ini kemudian menjadi input bagi:
1. Modul downstream (misal `credential.crack` yang mencari `HashArtifact`, `credential.pass_spray` yang mencari `UserArtifact`).
2. Generator attack graph dan state graph (`StateGraphService`).
3. Pelaporan dan visualisasi campaign.

### Statistik Keselarasan Kontrak Normalizer

| Kategori Status Kontrak | Jumlah Pasangan Modul-Capability | Persentase | Status Data |
|---|:---:|:---:|---|
| ✅ **MATCH (Selaras Penuh)** | 6 pasangan modul | 30.0% | Data mengalir sempurna ke `ArtifactStore` |
| 🔧 **FIXED (Dual-Read Fallback Diterapkan)** | 14 pasangan modul | 70.0% | **Data dipulihkan via Dual-Read Fallback** |
| ⚠️ **ORPHANED HANDLER** | 0 handler | 0.0% | Semua handler memiliki minimal 1 modul deklarator |
| 🆕 **HANDLER BARU DITAMBAHKAN** | 15 capability | - | `lsa_secrets`, `cached_credentials`, `valid_credentials`, `cleartext_credentials`, `cracked_credentials`, `laps_passwords`, `kerberos_tickets`, `open_ports`, `converted_ticket`, `samba_secrets`, `keytab_keys`, `iam_privesc`, `dns_records`, `service_versions`, `web_fingerprint` |
| 🚫 **UNHANDLED OUTPUTS** | **71 capability** | - | Output modul diabaikan sepenuhnya oleh normalizer (berkurang dari 78 pasca 7 Group A handlers) |

---

## 2. Tabel Lengkap Pemetaan Kontrak Normalizer

Tabel di bawah ini memetakan seluruh 9 capability yang memiliki handler di `ares/normalize/artifacts.py:457-468` terhadap modul-modul yang mendeklarasikannya di `OUTPUTS`:

| Capability | Modul Penghasil | Key yang DIBACA Normalizer | Key yang DITULIS Modul (`raw`) | Status | Dampak Sistemik & Downstream Failure |
|---|---|---|---|:---:|---|
| `user_list` | `ad.enum_users` | `users` OR `user_list` (Dual-Read) | `user_list` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `UserArtifact` via fallback `raw.get("users") or raw.get("user_list")`. |
| `computer_list` | `ad.enum_computers` | `computers` OR `computer_list` (Dual-Read) | `computer_list` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via fallback `raw.get("computers") or raw.get("computer_list")`. |
| `kerberos_hashes` | `ad.kerberoast` | `hashes` OR `kerberos_hashes` (Dual-Read) | `kerberos_hashes` | ✅ **FIXED** (Dual-Read Fallback) | Hash Kerberoasting mengalir ke `HashArtifact` (mode 13100) via fallback. |
| `asrep_hashes` | `ad.asreproast` | `hashes` OR `asrep_hashes` (Dual-Read) | `asrep_hashes` | ✅ **FIXED** (Dual-Read Fallback) | Hash AS-REP mengalir ke `HashArtifact` (mode 18200) via fallback. |
| `ntlm_hashes` | `ad.dcsync` | `hashes` OR `ntlm_hashes` (Dual-Read) | `ntlm_hashes` | ✅ **FIXED** (Dual-Read Fallback) | Hash DCSync mengalir ke `HashArtifact` (mode 1000) via fallback. |
| `ntlm_hashes` | `windows.lsass_dump` | `hashes` OR `ntlm_hashes` (Dual-Read) | `hashes`, `ntlm_hashes` | ✅ **MATCH** | Data mengalir benar ke `HashArtifact` (mode 1000). Modul ini menuliskan kedua key. |
| `ntlm_hashes` | `windows.lsa_secrets` | `hashes` OR `ntlm_hashes` OR `sam_hashes` (Dual-Read) | `sam_hashes`, `ntlm_hashes` | ✅ **FIXED** (Dual-Read Fallback) | Hash SAM/LSA mengalir ke `HashArtifact` via fallback triple-key. |
| `spn_list` | `ad.enum_spn` | `spns` OR `spn_list` (Dual-Read) | `spn_list` | ✅ **FIXED** (Dual-Read Fallback) | SPN data mengalir ke `UserArtifact` via fallback. |
| `acl_findings` | `ad.enum_acl` | `misconfigs` (list of dict) | `misconfigs`, `acl_findings` | ✅ **MATCH** | Data mengalir benar ke `PermissionArtifact`. Modul menuliskan kedua key. |
| `aws_findings` | `cloud.aws` | `region`, `s3` (`public_buckets`) | `region`, `s3`, `aws_findings` | ✅ **MATCH** | S3 bucket publik berhasil dikonversi menjadi `CloudResourceArtifact`. |
| `aws_findings` | `cloud.aws_privesc` | `region`, `s3` (`public_buckets`) | `privesc_paths`, `aws_findings` | ❌ **MISMATCH** | Modul privilege escalation AWS tidak menghasilkan `s3`, sehingga normalizer mengembalikan 0 artifact. Jalur eskalasi IAM hilang dari store. |
| `privesc_vectors` | `linux.ld_preload` | `target` OR `host` (Dual-Read) | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. |
| `privesc_vectors` | `linux.nfs_escape` | `target` OR `host` (Dual-Read) | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. |
| `privesc_vectors` | `linux.service_hijack` | `target` OR `host` (Dual-Read) | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. |
| `privesc_vectors` | `linux.kernel_suggester` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. |
| `privesc_vectors` | `linux.privesc` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. |
| `privesc_vectors` | `windows.applocker_bypass` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. |
| `privesc_vectors` | `windows.scheduled_tasks_enum` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. |
| `privesc_vectors` | `windows.token_impersonation` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. *(Modul dinonaktifkan via MOD-030, tapi kontrak tetap diperbaiki)*. |
| `privesc_vectors` | `windows.uac_bypass` | `target` OR `host` (Dual-Read) | `target`, `privesc_vectors` | ✅ **FIXED** (Dual-Read Fallback) | Data mengalir ke `HostArtifact` via `raw.get("target") or raw.get("host")`. |
| **`lsa_secrets`** | **`windows.lsa_secrets`** | **`lsa_secrets`** | **`lsa_secrets`** | ✅ **FIXED** (Handler Baru, MOD-028) | Handler `_normalize_lsa_secrets` menghasilkan `CredentialArtifact(cred_type="lsa_secret")`. Data loss 100% teratasi. |
| **`cached_credentials`** | **`windows.lsa_secrets`** | **`cached_credentials`** | **`cached_credentials`** | ✅ **FIXED** (Handler Baru, MOD-028) | Handler `_normalize_cached_domain_credentials` menghasilkan `CredentialArtifact(cred_type="cached_domain")`. |
| **`valid_credentials`** | **`credential.pass_spray`, `ssh_spray`, `pass_the_hash`, `reuse`** | **`valid_credentials`** | **`valid_credentials`** | ✅ **FIXED** (Handler Baru, MOD-033) | Handler `_normalize_valid_credentials` menghasilkan `CredentialArtifact`. Tipe data distandardisasi ke `list[dict]`. |
| `converted_ticket` | `credential.ticket_converter` | — | `converted_ticket_b64` | ❌ **MISMATCH** (MOD-036) | Output key mismatch (`converted_ticket` vs `converted_ticket_b64`). Tidak ada handler. Tiket konversi hilang dari pipeline. |
| `container_escape_vectors` | `linux.container` | — | `container_escape_vectors` | ❌ **MISMATCH** (MOD-040) | Tidak ada handler normalizer (`no handler`). Data vektor container escape hilang dari `ArtifactStore`. |
| `k8s_rbac_findings` | `linux.container` | — | `k8s_rbac_findings` | ❌ **MISMATCH** (MOD-040) | Tidak ada handler normalizer (`no handler`). Data temuan K8s RBAC hilang dari `ArtifactStore`. |
| `machine_account_hash` | `linux.samba_secrets` | — | `machine_account_hash` | ❌ **MISMATCH** (MOD-041) | Tidak ada handler normalizer (`no handler`). Machine account NTLM hash tidak terserap ke `ArtifactStore`. |
| `samba_secrets` | `linux.samba_secrets` | — | `samba_secrets` | ❌ **MISMATCH** (MOD-041) | Tidak ada handler normalizer (`no handler`). Samba secrets tidak terserap ke `ArtifactStore`. |
| `machine_credentials` | `linux.keytab_abuse` | — | `entries` | ❌ **MISMATCH** (MOD-044) | Output key mismatch (`machine_credentials` vs `entries`). Tidak ada handler normalizer. Data kunci mesin hilang dari `ArtifactStore`. |
| `kerberos_keys` | `linux.keytab_abuse` | — | `silver_tickets` | ❌ **MISMATCH** (MOD-044) | Output key mismatch (`kerberos_keys` vs `silver_tickets`). Tidak ada handler normalizer. Data kunci Kerberos hilang dari `ArtifactStore`. |
| `cached_hashes` | `linux.sssd_harvest` | — | `cached_hashes`, `hashes` | ❌ **MISMATCH** (MOD-045) | Tidak ada handler normalizer khusus `cached_hashes` (`no handler`). Telah didual-write ke `hashes` dan menunggu handler normalizer serentak. |
| `domain_users` | `linux.sssd_harvest` | — | `domain_users`, `users` | ❌ **MISMATCH** (MOD-045) | Tidak ada handler normalizer khusus `domain_users` (`no handler`). Telah didual-write ke `users` dan menunggu handler normalizer serentak. |
| `federation_trusts` | `cloud.identity_federation_abuse` | — | `federation_trusts` | ❌ **MISMATCH** (MOD-051) | Tidak ada handler normalizer (`no handler`). Data trust federasi hilang dari `ArtifactStore`. |
| `golden_saml_paths` | `cloud.identity_federation_abuse` | — | `golden_saml_paths` | ❌ **MISMATCH** (MOD-051) | Tidak ada handler normalizer (`no handler`). Data rute Golden SAML hilang dari `ArtifactStore`. |
| `oauth_tokens` | `cloud.identity_federation_abuse` | — | `oauth_tokens` | ❌ **MISMATCH** (MOD-051) | Tidak ada handler normalizer (`no handler`). Token OAuth2 hilang dari `ArtifactStore`. |
| `pivot_paths` | `cloud.identity_federation_abuse` | — | `pivot_paths` | ❌ **MISMATCH** (MOD-051) | Tidak ada handler normalizer (`no handler`). Analisis jalur pivot lintas-cloud hilang dari `ArtifactStore`. |
| `aws_privesc_paths` | `cloud.aws_privesc` | — | `aws_privesc_paths` | ❌ **MISMATCH** (MOD-052) | Tidak ada handler normalizer (`no handler`). Jalur eskalasi hak akses IAM hilang dari `ArtifactStore`. |
| `iam_privesc_paths` | `cloud.aws_privesc` | — | `iam_privesc_paths` | ⚠️ **NEW KEY** (aws_privesc, handler pending) | Key baru pasca-fix MOD-052 untuk memisahkan output privesc IAM dari `aws_findings` milik `cloud.aws`. Handler normalizer pending. |
| `spn_list` (inner keys) | `ad.enum_spn` | `s["spns"]` OR `s["spn_list"]` | `spns`, `spn_list` | ✅ **FIXED** (MOD-054) | Inner object key synchronized (`spn_list` & `spns`), `UserArtifact.spns` populated properly. |
| `valid_credentials` | `ad.laps_enum` | `laps_passwords` / `valid_credentials` | direct vault write + OPSEC raw (`has_password: True`) | ✅ **FIXED** (MOD-055) | Passwords stored directly to vault (Gate 6 validated); raw output OPSEC-safe with `has_password: True`. |
| `user_list` / `users` | `ad.enum_users` | `users` OR `user_list` | `users`, `user_list` | ✅ **FIXED** (MOD-056 partial) | Dual-write `raw["users"]` and `raw["user_list"]` implemented. |
| `password_policy` | `ad.enum_users` | — | `password_policy` | ❌ **MISMATCH, no handler, DEFERRED** | Unhandled output telemetry (`no handler`). Ditunda ke batch fix serentak. |
| `snmp_findings` / `valid_credentials` | `network.snmp_enum` | `valid_credentials` | `valid_credentials`, `snmp_findings` | ✅ **FIXED** (MOD-061, commit `5635362`) | Direct vault write Gate 6 + `valid_credentials` contract standar `list[dict]`. |
| Reconnaissance capabilities (`dns_records`, `subdomains`, `web_fingerprint`, `admin_interfaces`, `service_versions`, `vulnerable_services`) | `recon.fingerprint`, `network.dns_enum`, `network.http_fingerprint`, `network.service_detect` | `dns_records`, `subdomains`, `service_versions`, `web_fingerprint`, dll. | Various raw dicts | ✅ **PARTIALLY FIXED** (7 Handlers in commit `5635362`) | 7 handler normalizer recon ditambahkan ke `ArtifactNormalizer`. Sisa recon capability ditunda ke batch fix serentak. |
| `azure_findings` | `cloud.azure` | — | `azure_findings` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-066) | Output capability `azure_findings` tidak memiliki handler di `ArtifactNormalizer`. Data storage accounts, RBAC, dan NSG hilang 100% dari `ArtifactStore`. |
| `azure_ad_findings` | `cloud.azure_ad` | — | `azure_ad_findings` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-066) | Output capability `azure_ad_findings` tidak memiliki handler di `ArtifactNormalizer`. Data user dan guest Entra ID serta privileged service principals hilang dari `ArtifactStore`. |
| `access_tokens` | `cloud.azure_ad` | — | `access_tokens` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-066) | Output capability `access_tokens` (captured device code / client credential tokens) tidak memiliki handler di `ArtifactNormalizer`. |
| `gcp_findings` | `cloud.gcp` | — | `gcp_findings` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-068) | Output capability `gcp_findings` tidak memiliki handler di `ArtifactNormalizer`. Data public GCS buckets, IAM project roles, dan SA keys hilang dari `ArtifactStore`. |
| `cleartext_credentials` | `windows.registry_enum` | — | `cleartext_credentials` (Finding objects) | ❌ **MISMATCH, no handler, DEFERRED** (MOD-070) | Domain object Finding di-assign langsung ke raw key; tidak ada handler di `ArtifactNormalizer`. Data kredensial registry hilang dari `ArtifactStore`. |
| `credential_hints` | `windows.registry_enum` | — | `credential_hints` (Finding objects) | ❌ **MISMATCH, no handler, DEFERRED** (MOD-070) | Domain object Finding di-assign langsung ke raw key; tidak ada handler di `ArtifactNormalizer`. |
| `scheduled_tasks` | `windows.scheduled_tasks_enum` | — | `scheduled_tasks` (Finding objects) | ❌ **MISMATCH, no handler, DEFERRED** (MOD-070) | Domain object Finding di-assign langsung ke raw key; tidak ada handler di `ArtifactNormalizer`. Data task berisiko tinggi hilang dari `ArtifactStore`. |
| `privesc_vectors` (finding objects) | `windows.scheduled_tasks_enum`, `linux.kernel_suggester` | — | `privesc_vectors` (Finding objects) | ❌ **MISMATCH, no handler, DEFERRED** (MOD-070) | List Finding objek mentah di-assign ke `privesc_vectors`; normalizer yang ada hanya membaca string host/target, mengabaikan struktur vektor eskalasi hak akses. |
| `credential_list` | `exfil.secrets_scan` | — | `credential_list` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-074) | Tidak ada handler normalizer di `ArtifactNormalizer`. Path file rahasia hilang dari `ArtifactStore`. |
| `discovered_secrets` | `exfil.secrets_scan` | — | `discovered_secrets` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-074) | Metadata rahasia (API key, private key, connection strings) dengan entropy tidak terserap ke `ArtifactStore`. |
| `sensitive_data_found` | `exfil.secrets_scan`, `exfil.smb_shares` | — | `sensitive_data_found` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-074) | Status boolean sensitif tidak dipetakan ke atribut `HostArtifact` atau `PermissionArtifact`. |
| `file_share_list` | `exfil.smb_shares` | — | `file_share_list` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-074) | Tidak ada handler normalizer untuk share SMB. Daftar share target hilang dari `ArtifactStore`. |
| `sensitive_file_paths` | `exfil.smb_shares` | — | `sensitive_file_paths` | ❌ **MISMATCH, no handler, DEFERRED** (MOD-074) | File sensitif (web.config, id_rsa, .kdbx) di share SMB hilang dari `ArtifactStore`. |

---

## 3. Analisis Mendalam Akar Masalah Kunci (Root Cause Analysis)

### 3.1. Pola Mismatch "Generic vs Explicit Key"
Normalizer awal ditulis dengan asumsi bahwa modul akan menulis key generik pendek (`"users"`, `"computers"`, `"hashes"`, `"spns"`). Namun, pengembang modul memberi nama key di dalam `raw` yang selaras dengan nama capability atau ID modul (`"user_list"`, `"computer_list"`, `"kerberos_hashes"`, `"asrep_hashes"`, `"ntlm_hashes"`, `"spn_list"`).

Akibatnya:
- Method `_normalize_kerberos_hashes` mencari `raw.get("hashes")` $\rightarrow$ modul menghasilkan `raw["kerberos_hashes"]` $\rightarrow$ **Hasil: List Kosong (0 artifacts)**.
- Method `_normalize_asrep_hashes` mencari `raw.get("hashes")` $\rightarrow$ modul menghasilkan `raw["asrep_hashes"]` $\rightarrow$ **Hasil: List Kosong (0 artifacts)**.
- Method `_normalize_ntlm_hashes` mencari `raw.get("hashes")` $\rightarrow$ modul menghasilkan `raw["ntlm_hashes"]` $\rightarrow$ **Hasil: List Kosong (0 artifacts)**.

### 3.2. Pola Mismatch "Host vs Target"
Method `_normalize_host_vuln` (penangan capability `privesc_vectors`) membaca `host = raw.get("host", "")`.
- 3 modul Linux (`ld_preload`, `nfs_escape`, `service_hijack`) menulis `raw["host"]`.
- 6 modul lain (2 Linux dan 4 Windows: `kernel_suggester`, `privesc`, `applocker_bypass`, `scheduled_tasks_enum`, `token_impersonation`, `uac_bypass`) menulis `raw["target"]`.
Akibatnya, seluruh modul Windows privesc gagal mencatatkan host ke `ArtifactStore`.

### 3.3. Mengapa Bug Ini Tersembunyi dari Unit & Integration Test?
1. **Mocking Terisolasi**: Pada `tests/unit/test_state_graph_fingerprint_service.py` dan `tests/simulation/test_scenarios.py`, test membuat objek `store = ArtifactStore()` secara manual lalu memanggil method mutator langsung (`store.add(HashArtifact(...))`).
2. **Ketiadaan End-to-End Test Normalizer**: ~~Tidak ada satupun test di `tests/` yang menjalankan modul lalu meneruskan `result.raw_output` ke `ArtifactNormalizer().normalize()`.~~ **DIPERBAIKI**: `tests/unit/test_artifact_normalizer_pipeline.py` sekarang menguji pipeline end-to-end.
3. **Penyembunyian Exception Diam-diam**: ~~Pada [`artifacts.py:449-450`](file:///c:/Users/ASUS/Desktop/ARES/ares/normalize/artifacts.py#L449-L450) blok `try ... except Exception: pass` tanpa logging.~~ **DIPERBAIKI**: Exception sekarang di-log via `logger.warning("artifact_normalization_failed", ...)` di [`artifacts.py:472-478`](file:///c:/Users/ASUS/Desktop/ARES/ares/normalize/artifacts.py#L472-L478).

---

## 4. Analisis Unhandled Outputs (86 Capability Tanpa Handler)

Sebanyak 86 capability yang dideklarasikan dalam `OUTPUTS` oleh berbagai modul di ARES sama sekali **tidak memiliki handler di `ArtifactNormalizer`**. Ketika capability ini diproses, normalizer hanya melewati dengan `return 0`.

### Kategori Kritis yang Mengalami "Data Evaporation":

1. **Kredensial & Rahasia Plaintext / Hash (Severity: CRITICAL)**
   - Capability: `cleartext_credentials`, `cracked_credentials`, `laps_passwords`, `cached_credentials`, `cached_hashes`, `browser_passwords`, `samba_secrets`, `lsa_secrets`, `machine_credentials`.
   - Modul Terkenal: `ad.sccm`, `credential.crack`, `ad.laps_enum`, `windows.dpapi`, `linux.samba_secrets`.
   - *Dampak*: Password plaintext hasil cracking, password LAPS Domain Admin, dan kredensial SCCM NAA menguap saat modul selesai dan tidak tersimpan di `ArtifactStore`.

2. **Tiket Kerberos & Token Sesi (Severity: HIGH)**
   - Capability: `kerberos_ticket`, `kerberos_tickets`, `converted_ticket`, `golden_ticket`, `access_tokens`, `oauth_tokens`, `prt_artifacts`.
   - Modul Terkenal: `lateral.ntlm_relay`, `ad.delegation_abuse`, `credential.golden_ticket`, `credential.ticket_converter`.
   - *Dampak*: Path file `.ccache` atau `.kirbi` yang dihasilkan modul ofensif tidak dicatat ke state store, memutus rantai serangan otomatis (attack chaining).

3. **Infrastruktur Jaringan & Discovery (Severity: HIGH)**
   - Capability: `open_ports`, `service_map`, `service_versions`, `dns_records`, `subdomains`, `relay_targets`, `relay_candidates`, `smb_signing_config`.
   - Modul Terkenal: `network.port_scan`, `network.service_detect`, `network.dns_enum`, `lateral.smb_relay`, `lateral.ntlm_relay`.
   - *Dampak*: Hasil reconnaissance port dan banner grab tidak memperbarui graph target host.

4. **Sesi Lateral Movement & Eksekusi Remote (Severity: MEDIUM)**
   - Capability: `command_output`, `lateral_session`, `powershell_session`, `owned_hosts`, `compromised_hosts`, `pivot_tunnel`, `socks5_proxy`.
   - Modul Terkenal: `lateral.mssql`, `lateral.dcom`, `lateral.psexec`, `lateral.wmiexec`, `lateral.winrm`, `network.pivot`.
   - *Dampak*: Status keberhasilan eksekusi remote dan tunnel aktif tidak dipetakan ke state campaign.

---

## 5. Rekomendasi Arsitektural untuk Sesi Perbaikan (Roadmap Fix)

1. **Jadikan Normalizer "Key-Agnostic" (Multi-Key Fallback)**:
   Ubah setiap method di `ArtifactNormalizer` untuk memeriksa list kunci alternatif:
   - `_normalize_kerberos_hashes`: `raw.get("kerberos_hashes") or raw.get("hashes", [])`
   - `_normalize_asrep_hashes`: `raw.get("asrep_hashes") or raw.get("hashes", [])`
   - `_normalize_ntlm_hashes`: `raw.get("ntlm_hashes") or raw.get("sam_hashes") or raw.get("hashes", [])`
   - `_normalize_users`: `raw.get("user_list") or raw.get("users", [])`
   - `_normalize_computers`: `raw.get("computer_list") or raw.get("computers", [])`
   - `_normalize_spns`: `raw.get("spn_list") or raw.get("spns", [])`
   - `_normalize_host_vuln`: `raw.get("host") or raw.get("target") or raw.get("rhost", "")`

2. **Tambahkan Handler Baru untuk Capability Kritis**:
   - `cleartext_credentials` & `cracked_credentials` $\rightarrow$ `CredentialArtifact` + `ctx.record_credential()`
   - `kerberos_ticket` $\rightarrow$ `CredentialArtifact(cred_type="kerberos_ticket")`
   - `open_ports` & `service_map` $\rightarrow$ `ServiceArtifact` / Update `HostArtifact`

3. **Buat Integration Test Wajib**:
   Tambahkan test di `tests/unit/test_artifact_normalizer_pipeline.py` yang menguji pipeline eksekusi seluruh modul penghasil output terhadap `ArtifactNormalizer().normalize()`.
