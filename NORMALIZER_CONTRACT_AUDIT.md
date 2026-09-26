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
| ❌ **MISMATCH (Kunci Tidak Cocok)** | 14 pasangan modul | 70.0% | **Data 100% dibuang/hilang dari ArtifactStore** |
| ⚠️ **ORPHANED HANDLER** | 0 handler | 0.0% | Semua 9 handler memiliki minimal 1 modul deklarator |
| 🚫 **UNHANDLED OUTPUTS** | **86 capability** | - | Output modul diabaikan sepenuhnya oleh normalizer |

---

## 2. Tabel Lengkap Pemetaan Kontrak Normalizer

Tabel di bawah ini memetakan seluruh 9 capability yang memiliki handler di `ares/normalize/artifacts.py:457-468` terhadap modul-modul yang mendeklarasikannya di `OUTPUTS`:

| Capability | Modul Penghasil | Key yang DIBACA Normalizer | Key yang DITULIS Modul (`raw`) | Status | Dampak Sistemik & Downstream Failure |
|---|---|---|---|:---:|---|
| `user_list` | `ad.enum_users` | `users` (list of dict) | `user_list` | ❌ **MISMATCH** | **`UserArtifact` tidak pernah dibuat**. Modul downstream (`ad.kerberoast`, `credential.pass_spray`) tidak menerima daftar user via store. *(Modul melakukan bypass sementara via lokal `ISU-07`)*. |
| `computer_list` | `ad.enum_computers` | `computers` (list of dict) | `computer_list` | ❌ **MISMATCH** | **`HostArtifact` tidak pernah dibuat** oleh normalizer. Graph jaringan tidak terisi otomatis dari enumerasi AD. |
| `kerberos_hashes` | `ad.kerberoast` | `hashes` (list of str), `accounts` | `kerberos_hashes` (list of str) | ❌ **MISMATCH** | **100% hash Kerberoasting hilang**. `HashArtifact` (mode 13100) tidak pernah masuk ke `ArtifactStore`. `credential.crack` tidak dapat memecahkan hash secara otomatis. |
| `asrep_hashes` | `ad.asreproast` | `hashes` (list of str) | `asrep_hashes` (list of str) | ❌ **MISMATCH** | **100% hash AS-REP hilang**. `HashArtifact` (mode 18200) tidak pernah masuk ke `ArtifactStore`. Pipeline cracking otomatis lumpuh total. |
| `ntlm_hashes` | `ad.dcsync` | `hashes` (list of dict) | `ntlm_hashes` (list of dict) | ❌ **MISMATCH** | **100% hash domain DCSync hilang**. Hash admin domain tidak tersimpan di `ArtifactStore` dan tidak pernah dipersistensikan ke database. |
| `ntlm_hashes` | `windows.lsass_dump` | `hashes` (list of dict) | `hashes`, `ntlm_hashes` | ✅ **MATCH** | Data mengalir benar ke `HashArtifact` (mode 1000). Modul ini secara kebetulan menuliskan kedua key (`hashes` dan `ntlm_hashes`). |
| `ntlm_hashes` | `windows.lsa_secrets` | `hashes` (list of dict) | `sam_hashes`, `ntlm_hashes` | ❌ **MISMATCH** | Hash SAM/LSA dari target Windows tidak terserap ke normalizer karena modul menulis ke `sam_hashes` dan `ntlm_hashes`, bukan `hashes`. |
| `spn_list` | `ad.enum_spn` | `spns` (list of dict) | `spn_list` | ❌ **MISMATCH** | **0 UserArtifact SPN dibuat**. Atribut `is_kerberoastable` tidak terpetakan di `ArtifactStore`. |
| `acl_findings` | `ad.enum_acl` | `misconfigs` (list of dict) | `misconfigs`, `acl_findings` | ✅ **MATCH** | Data mengalir benar ke `PermissionArtifact`. Modul menuliskan kedua key. |
| `aws_findings` | `cloud.aws` | `region`, `s3` (`public_buckets`) | `region`, `s3`, `aws_findings` | ✅ **MATCH** | S3 bucket publik berhasil dikonversi menjadi `CloudResourceArtifact`. |
| `aws_findings` | `cloud.aws_privesc` | `region`, `s3` (`public_buckets`) | `privesc_paths`, `aws_findings` | ❌ **MISMATCH** | Modul privilege escalation AWS tidak menghasilkan `s3`, sehingga normalizer mengembalikan 0 artifact. Jalur eskalasi IAM hilang dari store. |
| `privesc_vectors` | `linux.ld_preload` | `host` | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. *(Catatan: detail vektor privesc itu sendiri tidak disimpan)*. |
| `privesc_vectors` | `linux.nfs_escape` | `host` | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. |
| `privesc_vectors` | `linux.service_hijack` | `host` | `host`, `privesc_vectors` | ✅ **MATCH** | Menghasilkan `HostArtifact` dengan IP/hostname target. |
| `privesc_vectors` | `linux.kernel_suggester` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |
| `privesc_vectors` | `linux.privesc` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |
| `privesc_vectors` | `windows.applocker_bypass` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |
| `privesc_vectors` | `windows.scheduled_tasks_enum` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |
| `privesc_vectors` | `windows.token_impersonation` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |
| `privesc_vectors` | `windows.uac_bypass` | `host` | `target`, `privesc_vectors` | ❌ **MISMATCH** | Normalizer mencari `raw["host"]`, modul menulis `raw["target"]`. HostArtifact tidak dibuat. |

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
2. **Ketiadaan End-to-End Test Normalizer**: Tidak ada satupun test di `tests/` yang menjalankan modul lalu meneruskan `result.raw_output` ke `ArtifactNormalizer().normalize()`.
3. **Penyembunyian Exception Diam-diam**: Pada [`artifacts.py:449-450`](file:///c:/Users/ASUS/Desktop/ARES/ares/normalize/artifacts.py#L449-L450):
   ```python
   except Exception:
       pass  # Never let normalization failures block the engine
   ```
   Blok `try ... except Exception: pass` tanpa logging error menelan kegagalan normalisasi secara diam-diam.

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
