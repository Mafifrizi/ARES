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
| ✅ **MATCH (Selaras Penuh)** | 6 pasangan modul | 15.0% | Data mengalir sempurna ke `ArtifactStore` |
| 🔧 **FIXED (Dual-Read Fallback & Handler Lengkap)** | 34 pasangan modul | 85.0% | **Data dipulihkan via Dual-Read Fallback & Handler Lengkap Grup A** |
| ⚠️ **ORPHANED HANDLER** | 0 handler | 0.0% | Semua handler memiliki minimal 1 modul deklarator |
| 🆕 **HANDLER SELESAI (FASE 1)** | 35+ capability | - | Seluruh capability Grup A diimplementasikan dan diuji via `test_artifact_normalizer_pipeline.py` |
| 🚫 **UNHANDLED OUTPUTS (Grup A)** | **0 capability** | - | Seluruh capability target Grup A telah memiliki handler aktif |

---

## 2. Tabel Lengkap Pemetaan Kontrak Normalizer

Tabel di bawah ini memetakan seluruh 9 capability awal plus puluhan handler baru di `ares/normalize/artifacts.py` terhadap modul-modul yang mendeklarasikannya di `OUTPUTS`:

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
| `aws_findings` | `cloud.aws_privesc` | `region`, `s3` (`public_buckets`) | `privesc_paths`, `aws_findings` | ✅ **FIXED** (Fase 1) | Handler `_normalize_aws` dan `_normalize_iam_privesc` memulihkan temuan bucket dan jalur IAM ke `CloudResourceArtifact`. |
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
| `converted_ticket` | `credential.ticket_converter` | `converted_ticket` OR `converted_ticket_b64` | `converted_ticket_b64` | ✅ **FIXED** (MOD-036 / Fase 1) | Handler `_normalize_converted_ticket` memetakan tiket base64/file path ke `CredentialArtifact(cred_type="kerberos_ticket")`. |
| `container_escape_vectors` | `linux.container` | `container_escape_vectors` | `container_escape_vectors` | ✅ **FIXED** (MOD-040 / Fase 1) | Handler `_normalize_container_vectors` memetakan temuan container breakout ke `PermissionArtifact`. |
| `k8s_rbac_findings` | `linux.container` | `k8s_rbac_findings` | `k8s_rbac_findings` | ✅ **FIXED** (MOD-040 / Fase 1) | Handler `_normalize_k8s_rbac` memetakan privilege cluster K8s ke `PermissionArtifact`. |
| `machine_account_hash` | `linux.samba_secrets` | `machine_account_hash` | `machine_account_hash` | ✅ **FIXED** (MOD-041 / Fase 1) | Handler `_normalize_samba_secrets` memetakan NTLM machine hash ke `HashArtifact(hash_type="ntlm")`. |
| `samba_secrets` | `linux.samba_secrets` | `samba_secrets` | `samba_secrets` | ✅ **FIXED** (MOD-041 / Fase 1) | Handler `_normalize_samba_secrets` memetakan rahasia domain Samba ke `CredentialArtifact`. |
| `machine_credentials` | `linux.keytab_abuse` | `machine_credentials` OR `entries` | `entries` | ✅ **FIXED** (MOD-044 / Fase 1) | Handler `_normalize_keytab_keys` memetakan entry keytab ke `CredentialArtifact`. |
| `kerberos_keys` | `linux.keytab_abuse` | `kerberos_keys` OR `silver_tickets` | `silver_tickets` | ✅ **FIXED** (MOD-044 / Fase 1) | Handler `_normalize_keytab_keys` memetakan tiket/kunci Kerberos ke `CredentialArtifact`. |
| `cached_hashes` | `linux.sssd_harvest` | `cached_hashes`, `hashes` | `cached_hashes`, `hashes` | ✅ **FIXED** (MOD-045 / Fase 1) | Handler `_normalize_cached_hashes` dan `_normalize_ntlm_hashes` memetakan hash SSSD ke `HashArtifact`. |
| `domain_users` | `linux.sssd_harvest` | `domain_users`, `users` | `domain_users`, `users` | ✅ **FIXED** (MOD-045 / Fase 1) | Handler `_normalize_domain_users` dan `_normalize_users` memetakan user domain SSSD ke `UserArtifact`. |
| `federation_trusts` | `cloud.identity_federation_abuse` | `federation_trusts` | `federation_trusts` | ✅ **FIXED** (MOD-051 / Fase 1) | Handler `_normalize_federation_trusts` memetakan trust IdP ke `CloudResourceArtifact`. |
| `golden_saml_paths` | `cloud.identity_federation_abuse` | `golden_saml_paths` | `golden_saml_paths` | ✅ **FIXED** (MOD-051 / Fase 1) | Handler `_normalize_golden_saml` memetakan rute Golden SAML ke `PermissionArtifact`. |
| `oauth_tokens` | `cloud.identity_federation_abuse` | `oauth_tokens` | `oauth_tokens` | ✅ **FIXED** (MOD-051 / Fase 1) | Handler `_normalize_tokens` memetakan token OAuth2 ke `CredentialArtifact(cred_type="oauth_token")`. |
| `pivot_paths` | `cloud.identity_federation_abuse` | `pivot_paths` | `pivot_paths` | ✅ **FIXED** (MOD-051 / Fase 1) | Handler `_normalize_pivot_paths` memetakan jalur pivot multi-cloud ke `PermissionArtifact`. |
| `aws_privesc_paths` | `cloud.aws_privesc` | `aws_privesc_paths` | `aws_privesc_paths` | ✅ **FIXED** (MOD-052 / Fase 1) | Handler `_normalize_iam_privesc` memetakan jalur privesc IAM ke `PermissionArtifact`. |
| `iam_privesc_paths` | `cloud.aws_privesc` | `iam_privesc_paths` | `iam_privesc_paths` | ✅ **FIXED** (MOD-052 / Fase 1) | Handler `_normalize_iam_privesc` memetakan rute privesc IAM terisolasi ke `PermissionArtifact`. |
| `spn_list` (inner keys) | `ad.enum_spn` | `s["spns"]` OR `s["spn_list"]` | `spns`, `spn_list` | ✅ **FIXED** (MOD-054) | Inner object key synchronized (`spn_list` & `spns`), `UserArtifact.spns` populated properly. |
| `valid_credentials` | `ad.laps_enum` | `laps_passwords` / `valid_credentials` | direct vault write + OPSEC raw (`has_password: True`) | ✅ **FIXED** (MOD-055) | Passwords stored directly to vault (Gate 6 validated); raw output OPSEC-safe with `has_password: True`. |
| `user_list` / `users` | `ad.enum_users` | `users` OR `user_list` | `users`, `user_list` | ✅ **FIXED** (MOD-056 partial) | Dual-write `raw["users"]` and `raw["user_list"]` implemented. |
| `password_policy` | `ad.enum_users` | `password_policy` | `password_policy` | ✅ **FIXED** (MOD-056 / Fase 1) | Handler `_normalize_password_policy` menyimpan telemetry password policy ke metadata `HostArtifact`. |
| `snmp_findings` / `valid_credentials` | `network.snmp_enum` | `valid_credentials`, `snmp_findings` | `valid_credentials`, `snmp_findings` | ✅ **FIXED** (MOD-061 / Fase 1) | Direct vault write Gate 6 + community string ke `CredentialArtifact` & info sistem ke `HostArtifact`. |
| Reconnaissance capabilities (`dns_records`, `subdomains`, `web_fingerprint`, `admin_interfaces`, `service_versions`, `vulnerable_services`) | `recon.fingerprint`, `network.dns_enum`, `network.http_fingerprint`, `network.service_detect` | `dns_records`, `subdomains`, `service_versions`, `web_fingerprint`, dll. | Various raw dicts | ✅ **FIXED** (Fase 1) | Seluruh recon capability dipetakan ke `HostArtifact` (hostnames, services, vulns, metadata). |
| `azure_findings` | `cloud.azure` | `azure_findings` | `azure_findings` | ✅ **FIXED** (MOD-066 / Fase 1) | Handler `_normalize_azure` memetakan storage accounts, NSG, RBAC ke `CloudResourceArtifact`. |
| `azure_ad_findings` | `cloud.azure_ad` | `azure_ad_findings` | `azure_ad_findings` | ✅ **FIXED** (MOD-066 / Fase 1) | Handler `_normalize_azure_ad` memetakan Entra ID users & service principals ke `UserArtifact` & `CloudResourceArtifact`. |
| `access_tokens` | `cloud.azure_ad` | `access_tokens`, `access_token` | `access_tokens` | ✅ **FIXED** (MOD-066 / Fase 1) | Handler `_normalize_tokens` memetakan access tokens ke `CredentialArtifact(cred_type="access_token")`. |
| `gcp_findings` | `cloud.gcp` | `gcp_findings` | `gcp_findings` | ✅ **FIXED** (MOD-068 / Fase 1) | Handler `_normalize_gcp` memetakan GCS buckets, roles, SA keys ke `CloudResourceArtifact`. |
| `cleartext_credentials` | `windows.registry_enum` | `cleartext_credentials` | `cleartext_credentials` (Finding objects / dict) | ✅ **FIXED** (MOD-070 / Fase 1) | Handler `_normalize_registry_credentials` mengekstrak kredensial dari Finding objects ke `CredentialArtifact`. |
| `credential_hints` | `windows.registry_enum` | `credential_hints` | `credential_hints` (Finding objects / dict) | ✅ **FIXED** (MOD-070 / Fase 1) | Handler `_normalize_registry_credentials` mengekstrak hint registry ke `CredentialArtifact`. |
| `scheduled_tasks` | `windows.scheduled_tasks_enum` | `scheduled_tasks` | `scheduled_tasks` (Finding objects / dict) | ✅ **FIXED** (MOD-070 / Fase 1) | Handler `_normalize_scheduled_tasks` mengekstrak task berbahaya ke metadata `HostArtifact`. |
| `privesc_vectors` (finding objects) | `windows.scheduled_tasks_enum`, `linux.kernel_suggester` | `privesc_vectors` | `privesc_vectors` (Finding objects / strings) | ✅ **FIXED** (MOD-070 / Fase 1) | Handler `_normalize_host_vuln` mendukung list Finding objects maupun host strings tanpa crash. |
| `credential_list` | `exfil.secrets_scan` | `credential_list` | `credential_list` | ✅ **FIXED** (MOD-074 / Fase 1) | Handler `_normalize_secrets_scan` memetakan file paths dan credential records ke `CredentialArtifact`. |
| `discovered_secrets` | `exfil.secrets_scan` | `discovered_secrets` | `discovered_secrets` | ✅ **FIXED** (MOD-074 / Fase 1) | Handler `_normalize_secrets_scan` memetakan API keys & private keys ke `CredentialArtifact`. |
| `sensitive_data_found` | `exfil.secrets_scan`, `exfil.smb_shares` | `sensitive_data_found` | `sensitive_data_found` | ✅ **FIXED** (MOD-074 / Fase 1) | Handler `_normalize_secrets_scan` & `_normalize_smb_shares` mencatat temuan data sensitif ke `HostArtifact`. |
| `file_share_list` | `exfil.smb_shares` | `file_share_list` | `file_share_list` | ✅ **FIXED** (MOD-074 / Fase 1) | Handler `_normalize_smb_shares` memetakan SMB shares dan permissions ke metadata `HostArtifact`. |
| `sensitive_file_paths` | `exfil.smb_shares` | `sensitive_file_paths` | `sensitive_file_paths` | ✅ **FIXED** (MOD-074 / Fase 1) | Handler `_normalize_smb_shares` memetakan file sensitif ke metadata `HostArtifact`. |

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
