# ARES COMPREHENSIVE SYSTEM AUDIT REPORT
**Standard:** Microsoft Engineering Excellence / Google Engineering Practices  
**Auditor Role:** Principal Engineer + Staff Security Reviewer + Staff SRE  
**Mode:** READ-ONLY Verification (Zero Code Modification)  
**Timestamp:** 2026-09-30T06:18:00+07:00  
**Baseline Git Commit:** `5271dd1`  

---

## 1. EXECUTIVE SUMMARY

### Skor Kesehatan Sistem per Dimensi (Skala 1–10)
* **Security**: `8.2 / 10` — Model ScopeGuard, isolasi Sandbox, dan enkripsi Vault sangat kuat. Namun terdapat celah autentikasi loopback pada reload endpoint serta potensi command injection pada modul Linux ccache hunter.
* **Performance**: `7.8 / 10` — Bundler frontend efisien dan SQLite WAL terbukti cepat, tetapi terdapat N+1 query pada routine backup export serta absennya code-splitting pada 10 halaman dashboard utama.
* **Code Quality Frontend**: `7.5 / 10` — Zero console.log dan linting bersih, tetapi arsitektur monolithic component (`DashboardPages.tsx` > 290 KB) dan 17 casting `as any` mengurangi type safety.
* **Code Quality Backend**: `8.0 / 10` — Pola async/await konsisten dan architecture boundary jelas, namun terdapat lebih dari 300 blok `except: pass` (sebagian menelan kegagalan penulisan vault).
* **Database & Data Layer**: `9.0 / 10` — 100% kueri berparameter (Zero SQL Injection), schema versioning formal dengan Alembic, dan foreign key constraints aktif di semua tabel relasional.
* **Documentation**: `8.5 / 10` — Panduan dashboard dan security model sangat mendalam, namun terdapat deviasi port default (8000 vs 8080) pada SDK docs serta 5 endpoint belum terdokumentasi di API reference.
* **User Experience (UX)**: `8.5 / 10` — Seluruh mitigasi UX Batch 1 (SEC-01, SEC-02, REP-01, SHL-01) terbukti stabil, responsive layout aktif hingga 640px, namun rendering attack graph belum memiliki unit test harness.

### Distribusi Temuan Berdasarkan Severity
* **CRITICAL**: 1 temuan (AUD-001)
* **HIGH**: 3 temuan (AUD-002, AUD-003, AUD-005)
* **MEDIUM**: 5 temuan (AUD-004, AUD-006, AUD-007, AUD-008, AUD-009)
* **LOW / INFO**: 2 temuan (AUD-010, AUD-011)
* **TOTAL**: **11 Temuan**

### Top 5 Risiko Prioritas
1. **[AUD-001 - CRITICAL]** Bypass Autentikasi Loopback pada Endpoint `/modules/reload` via Reverse Proxy / SSRF.
2. **[AUD-003 - HIGH]** Injeksi Perintah Subprocess Menggunakan `shell=True` dan String Interpolasi pada Modul `linux.ccache_hunt`.
3. **[AUD-007 - MEDIUM/HIGH]** Silent Exception Swallowing (`except Exception: pass`) pada Penulisan Vault Kredensial di `ares/core/context.py`.
4. **[AUD-005 - HIGH]** Pola Kueri N+1 pada `AresDatabase.export_backup()` Membebani I/O Database.
5. **[AUD-006 - MEDIUM]** Arsitektur Monolitik Dashboard Frontend (`DashboardPages.tsx` 290 KB) Tanpa Route-level Code Splitting.

---

## 2. TEMUAN DETAIL

| Field | Isi |
|---|---|
| **ID** | **AUD-001** |
| **Status** | **FIXED** (Commit `06abea4`) |
| **Dimensi** | Security (Authentication & Authorization) |
| **Severity** | **CRITICAL** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `ares/api/server.py:2269-2286` |
| **Masalah** | Endpoint `POST /modules/reload` tidak mewajibkan token autentikasi jika `client_host` terdeteksi sebagai loopback (`127.0.0.1`, `::1`, `localhost`, `testclient`). Jika `request.client` bernilai `None`, kode secara default mengasumsikan client adalah `127.0.0.1`. |
| **Dampak** | Apabila server ARES di-deploy di belakang reverse proxy lokal (seperti Nginx, Caddy, Envoy) yang tidak meneruskan client IP dengan trusted proxy configuration, atau jika terjadi SSRF lokal, penyerang tanpa kredensial dapat memicu reload modul yang mem-purge seluruh cache in-memory `sys.modules` (`ares.modules.*`), mengakibatkan Denial of Service atau state disruption pada engine. |
| **Reproduksi** | 1. Kirim HTTP POST ke `http://127.0.0.1:8080/modules/reload` tanpa header `Authorization` atau `X-API-Key`.<br>2. Request diterima dengan status HTTP 200 OK dan mengeksekusi `sys.modules.pop()` serta `engine.load_modules()`. |
| **Rekomendasi** | Wajibkan otorisasi `require_operator()` atau `require_team_lead()` tanpa pengecualian IP loopback, atau hanya izinkan bypass jika `app.state.is_testing` bernilai True pada environment pytest internal. |
| **Resolusi** | Seluruh pemeriksaan loopback IP dihapus. Endpoint diwajibkan `Depends(require_operator())` atau `app.state.is_testing`. Ditambahkan test suite `tests/unit/test_modules_reload_security.py`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-002** |
| **Status** | **FIXED** (Commit `5ab63a0`) |
| **Dimensi** | Security (Input Validation & Injection) |
| **Severity** | **HIGH** |
| **Keyakinan** | **KUAT** |
| **Lokasi** | `ares/modules/lateral/mssql.py:511` |
| **Masalah** | Konstruksi perintah T-SQL `xp_dirtree` menggunakan f-string interpolasi mentah: `cur.execute(f"EXEC xp_dirtree '\\\\{listener_ip}\\share'")` tanpa sanitasi karakter kutip tunggal atau validasi format IPv4/IPv6/hostname ketat pada variabel `listener_ip`. |
| **Dampak** | Jika operator memasukkan input parameter yang tercemar karakter khusus atau jika data input berasal dari chain module sekunder yang tidak tervalidasi, kueri SQL di target MSSQL dapat pecah atau dieksploitasi untuk SQL injection sekunder pada remote host. |
| **Reproduksi** | Jalankan modul MSSQL dengan parameter `listener_ip = "10.0.0.1'; WAITFOR DELAY '0:0:5'--"`. |
| **Rekomendasi** | Validasi `listener_ip` menggunakan `ipaddress.ip_address()` sebelum injeksi string, atau gunakan parameterisasi native DB-API jika didukung driver. |
| **Resolusi** | Variabel `listener_ip` divalidasi ketat menggunakan `_validate_listener_ip()` (`ipaddress.ip_address()`) pada tahap `validate()` dan sebelum perakitan query di `unc_coerce_sync()`. Ditambahkan test suite `tests/unit/modules/test_mssql_input_validation_aud002.py`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-003** |
| **Status** | **FIXED** (Commit `da77cca`) |
| **Dimensi** | Security (Command Injection & Subprocess Execution) |
| **Severity** | **HIGH** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `ares/modules/linux/ccache_hunt.py:325, 386, 421` |
| **Masalah** | Fungsi `_execute_command` memanggil `subprocess.run(cmd, shell=True, capture_output=True, timeout=5)`. Selain itu, baris 386 mengeksekusi pipeline shell mentah (`cat /proc/keys \| grep krb5`), dan baris 421 menggunakan string f-string: `keyctl print {key_id}`. |
| **Dampak** | Pelanggaran standar keamanan ARES (larangan eksekusi subshell untuk menghindari tripwire `auditd` dan injection). Jika output `/proc/keys` termanipulasi atau mengandung karakter kontrol shell, eksekusi perintah arbitrer di host lokal dapat terjadi. |
| **Reproduksi** | Eksekusi `ccache_hunt` pada sistem dengan file atau key description yang mengandung metakarakter shell (misal: `;`, `|`, `` ` ``). |
| **Rekomendasi** | Ganti pemanggilan shell dengan pembacaan langsung filesystem Python (`Path('/proc/keys').read_text()`) dan gunakan parameter array `["keyctl", "print", str(key_id)]` dengan `shell=False`. |
| **Resolusi** | Pipeline shell dieliminasi penuh. `/proc/keys` dibaca langsung melalui Python I/O, `key_id` divalidasi integer/hexadecimal via `_validate_key_id()`, dan `subprocess.run` menggunakan `shell=False` dengan argumen list. Ditambahkan test suite `tests/unit/modules/test_ccache_hunt_security_aud003.py`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-004** |
| **Status** | **FIXED** (Commit `7146504`) |
| **Dimensi** | Security (Dependency Vulnerabilities) |
| **Severity** | **MEDIUM** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `frontend/package.json` (`node_modules`) |
| **Masalah** | Hasil eksekusi `npm audit` menunjukkan 14 kerentanan pada dependency frontend (1 Low, 6 Moderate, 6 High, 1 Critical). Paket terdampak meliputi: `brace-expansion`, `browserslist`, `nanoid`, `postcss`, `react-router-dom`, dan `esbuild`. |
| **Dampak** | Komponen build dan routing memiliki risiko teoritis DoS (ReDoS/uncontrolled AST recursion) dan Open Redirect via backslash pada react-router (`GHSA-wrjc-x8rr-h8h6`). |
| **Reproduksi** | Jalankan `npm audit` di dalam direktori `frontend/`. |
| **Rekomendasi** | Jalankan `npm update` dan perbarui `react-router-dom` ke versi patch aman terbaru (>=6.28.1 / 7.x) serta patch transitive dependencies melalui package-lock. |
| **Resolusi** | `react-router-dom` diperbarui ke `7.18.4`, paket transitive di-update via `npm update`. Seluruh 195 test Vitest dan produksi bundle Vite lolos 100%. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-005** |
| **Status** | **FIXED** (Commit `546da22`) |
| **Dimensi** | Performance (Database Queries - N+1) |
| **Severity** | **HIGH** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `ares/db/database.py:1307-1319` |
| **Masalah** | Dalam method `export_backup()`, sistem mengambil semua campaign (`SELECT * FROM campaigns`), lalu di dalam loop `for campaign in campaigns:` melakukan 2 query terpisah per iterasi (`SELECT * FROM findings WHERE campaign_id=?` dan `SELECT * FROM hosts WHERE campaign_id=?`). |
| **Dampak** | Jika database memiliki 500 campaign, sistem mengeksekusi 1.001 query SQL secara berurutan. Ini memicu lonjakan latensi I/O tinggi, mengunci resource SQLite WAL, dan membebani memori proses API. |
| **Reproduksi** | Buat database pengujian dengan 100 campaign, panggil `db.export_backup()`, amati log tracing database. |
| **Rekomendasi** | Gunakan single batch query dengan `IN (...)` atau lakukan 3 kueri tabel penuh yang kemudian dikelompokkan secara in-memory menggunakan `collections.defaultdict(list)`. |
| **Resolusi** | `export_backup()` direfaktor mengeksekusi 3 batch query mandiri (`campaigns`, `findings`, `hosts`) lalu dikelompokkan in-memory via `defaultdict(list)`. Kompleksitas turun dari O(2N+1) ke O(3). Ditambahkan test suite `tests/unit/test_export_backup_performance_aud005.py`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-006** |
| **Status** | **OPEN** (Ditunda ke sesi khusus refactoring arsitektur frontend) |
| **Dimensi** | Performance (Frontend Bundling & Code Splitting) |
| **Severity** | **MEDIUM** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `frontend/src/features/dashboard/DashboardRouter.tsx:5-16` & `DashboardPages.tsx` |
| **Masalah** | File `DashboardPages.tsx` berukuran sangat masif (290.939 byte, ~7.500 baris kode) dan seluruh 10 halaman (`OverviewPage`, `CampaignsPage`, `ModulesPage`, `ReportsPage`, `SecurityPage`, dll.) diimpor secara sinkron ke dalam root bundle `index-D-zhhYaE.js` (431 kB). |
| **Dampak** | User yang hanya membuka form login (`/login`) atau halaman awal dipaksa mengunduh dan menguraikan (parse/compile) seluruh JavaScript kode halaman audit, strategi, dan reports, meningkatkan First Contentful Paint (FCP) dan Time to Interactive (TTI). |
| **Reproduksi** | Buka Developer Tools Network tab pada browser di rute `/login`. Perhatikan bundle utama 431 kB diunduh penuh. |
| **Rekomendasi** | Pecah `DashboardPages.tsx` menjadi file-file modular terpisah (`OverviewPage.tsx`, `CampaignsPage.tsx`, dsb.) dan manfaatkan `React.lazy()` + `<Suspense>` pada `DashboardRouter.tsx` sebagaimana yang telah sukses diterapkan pada `GraphPage.tsx`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-007** |
| **Status** | **FIXED** (Commit `957397e`) |
| **Dimensi** | Code Quality Backend (Error Handling) |
| **Severity** | **MEDIUM** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `ares/core/context.py:191-192, 253-254` |
| **Masalah** | Pada method `ExecutionContext.record_finding` dan `ExecutionContext.record_credential`, jika pemanggilan `self.runtime_state.record_finding()` atau `self.vault.add()` melemparkan exception, kode mengeksekusi `except Exception: pass` tanpa pencatatan log apapun. |
| **Dampak** | Jika database vault terkunci, disk penuh, atau enkripsi PBKDF2/AES-GCM gagal saat modul menemukan password target penting, kredensial tersebut hilang tanpa jejak dan operator tidak mendapatkan indikasi kegagalan di antarmuka maupun log file. |
| **Reproduksi** | Mock `self.vault.add` untuk me-raise `RuntimeError("Vault write error")`, panggil `record_credential()`. Nilai return adalah `None` tanpa ada log error yang diterbitkan. |
| **Rekomendasi** | Tangkap exception secara spesifik, lakukan logging terstruktur via `logger.error("vault_record_credential_failed", error=str(exc))`, dan kembalikan status kegagalan eksplisit. |
| **Resolusi** | Blok `except Exception: pass` digantikan dengan logging terstruktur (`logger.error("vault_record_credential_failed", ...)` dan `logger.error("finding_record_failed", ...)`), serta fungsi mengembalikan boolean `False` secara eksplisit saat gagal. Ditambahkan test suite `tests/unit/test_context_exception_logging_aud007.py`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-008** |
| **Status** | **OPEN** (Ditunda ke sesi khusus refactoring arsitektur frontend bersama AUD-006) |
| **Dimensi** | Code Quality Frontend (Type Safety) |
| **Severity** | **MEDIUM** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `frontend/src/features/dashboard/DashboardPages.tsx:471, 518, 519, 541, 542, 549, 1553, 1606` |
| **Masalah** | Terdapat 17 penggunaan type-cast `as any` pada komponen dashboard produksi untuk menangani event WebSocket dan payload API (misal: `(item as any)?.campaign_id`, `(event as any).timestamp`, `(data as any)?.plan`). |
| **Dampak** | Melemahkan jaminan keselamatan tipe TypeScript. Jika backend memodifikasi struktur event JSON, compiler tidak dapat mendeteksi broken fields saat build, memicu potensi runtime `TypeError: undefined is not an object` di browser. |
| **Reproduksi** | Audit statis via regex pencarian `as any` pada `frontend/src/features/dashboard/DashboardPages.tsx`. |
| **Rekomendasi** | Deklarasikan TypeScript interface yang presisi untuk `LiveWebSocketEvent`, `VaultRestoreResult`, dan `ExecutionPlanSummary` pada `frontend/src/api/types.ts`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-009** |
| **Status** | **OPEN** (Ditunda ke sesi khusus refactoring arsitektur frontend) |
| **Dimensi** | UX & Frontend Test Coverage |
| **Severity** | **MEDIUM** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `frontend/src/features/graph/GraphPage.tsx` & `frontend/src/features/auth/LoginPage.tsx` |
| **Masalah** | Dari 26 file komponen frontend, 10 file tidak memiliki unit test langsung di Vitest. Komponen paling kritikal yang belum memiliki test langsung adalah `GraphPage.tsx` (72.670 byte) dan `LoginPage.tsx` (8.601 byte). |
| **Dampak** | Fitur visualisasi attack graph (Cobalt Strike node mapping, drag-and-drop node, drawer inspector) dapat mengalami regresi visual atau fungsional tanpa terdeteksi oleh CI runner. |
| **Reproduksi** | Jalankan verifikasi test matrix: `vitest run` meloloskan 22 test suite tanpa pernah meng-instantiate komponen `GraphPage` secara terisolasi. |
| **Rekomendasi** | Tambahkan unit test suite `GraphPage.test.tsx` dengan mock provider `@xyflow/react` dan `LoginPage.test.tsx` untuk memvalidasi interaksi submit dan pesan error. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-010** |
| **Status** | **FIXED** (Commit `8255f6b`) |
| **Dimensi** | Documentation (API & Configuration Inconsistency) |
| **Severity** | **LOW** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `README.md:697`, `docs/module_sdk.md:155`, `docs/module-development.md:456` |
| **Masalah** | Contoh kode inisialisasi SDK klien tertulis: `AresClient(base_url="http://127.0.0.1:8000")`, sedangkan port default resmi pada `APISettings` (`ares/core/config.py:37`) dan `docs/api-reference.md:3` adalah port `8080`. |
| **Dampak** | Pengembang modul atau operator yang menyalin contoh kode dokumentasi akan mengalami kegagalan koneksi (`ConnectionRefusedError: [Errno 111] Connect call failed`). |
| **Reproduksi** | Jalankan server dengan setelan default (`python -m ares.api.server`), lalu jalankan snippet dari `README.md` baris 697. |
| **Rekomendasi** | Sinkronkan seluruh contoh dokumentasi port SDK menjadi `http://127.0.0.1:8080`. |
| **Resolusi** | Seluruh contoh inisialisasi SDK klien pada `README.md`, `docs/module_sdk.md`, dan `docs/module-development.md` disinkronkan ke port default resmi `http://127.0.0.1:8080`. |

---

| Field | Isi |
|---|---|
| **ID** | **AUD-011** |
| **Status** | **FIXED** (Commit `8255f6b`) |
| **Dimensi** | Documentation (API Reference Completeness) |
| **Severity** | **LOW** |
| **Keyakinan** | **TERBUKTI** |
| **Lokasi** | `docs/api-reference.md` vs `ares/api/server.py` |
| **Masalah** | Terdapat 5 endpoint API aktif yang belum dicantumkan di dalam dokumen `docs/api-reference.md`: `GET /campaigns/{id}/cvss`, `GET /campaigns/{id}/diff/{other_id}`, `GET /campaigns/{id}/findings`, `GET /stats/monthly`, dan `POST /campaigns/{id}/restore-vault`. |
| **Dampak** | Integrator eksternal dan operator CI/CD tidak mengetahui ketersediaan skema request/response resmi untuk diffing campaign dan pemulihan vault via API. |
| **Reproduksi** | Bandingkan route list FastAPI runtime dengan tabel isi `docs/api-reference.md`. |
| **Rekomendasi** | Tambahkan spesifikasi formal kelima endpoint tersebut ke dalam `docs/api-reference.md`. |
| **Resolusi** | Spesifikasi formal untuk seluruh 5 endpoint (`GET /campaigns/{id}/findings`, `GET /campaigns/{id}/cvss`, `GET /campaigns/{id}/diff/{other_id}`, `POST /campaigns/{id}/restore-vault`, dan `GET /stats/monthly`) lengkap dengan parameter query, header autentikasi, dan schema response JSON telah ditambahkan ke `docs/api-reference.md`. |

---

## 3. TEMUAN SISTEMIK (ARCHITECTURAL PATTERNS)

1. **Pemisahan Antara Deklarasi Route dan Boundary Protection**:
   * Mayoritas endpoint menggunakan FastAPI dependencies (`Depends(_check)`). Namun endpoint `/modules/reload` mengimplementasikan logika autorisasi manual di dalam body fungsi dengan basis pengecekan IP client. Hal ini memicu inkonsistensi pertahanan boundary (AUD-001).
2. **Defensive Error Handling yang Mengaburkan Observabilitas (Over-Defensive Swallowing)**:
   * Ditemukan 340 blok `except ...: pass` di codebase backend. Meskipun sebagian besar bertujuan mencegah crash pada operasi non-kritis, penerapan pola ini pada layer inti seperti `record_credential` dan `record_finding` justru membahayakan integritas data (AUD-007).
3. **Monolithic Page Grouping di Frontend**:
   * Frontend memiliki kecenderungan mengumpulkan seluruh logic halaman dalam satu file raksasa (`DashboardPages.tsx` > 290 KB) alih-alih memanfaatkan modularisasi berbasis fitur (feature-based modular structure).

---

## 4. BLIND SPOTS (BATASAN AUDIT SESI INI)

* **Production Reverse Proxy Behavioral Verification**: Interaksi header `X-Forwarded-For` dan `X-Real-IP` pada lingkungan AWS ALB / Cloudflare / Nginx produksi tidak dapat diuji secara fisik di lingkungan sandbox lokal.
* **Concurrent Database Locking Under Extreme Load**: SQLite WAL mode mampu melayani ribuan pembaca secara bersamaan, tetapi konkurensi penulisan tinggi (high write concurrency) memerlukan stress test benchmarking terpisah di server multi-core.
* **Live EDR/Antivirus Telemetry Bypass Verification**: Modul penghindaran EDR (`ares/modules/evasion/`) hanya diaudit secara logika statis, tanpa eksekusi langsung terhadap sensor EDR komersial aktif (CrowdStrike, Defender for Endpoint).

---

## 5. STATUS REMEDIATION & JADWAL PENYELESAIAN

```text
┌────────────────────────────────────────────────────────────────────────┐
│ TAHAP 1: IMMEDIATE CRITICAL SECURITY PATCHES [RESOLVED]                │
│ ✔ [AUD-001] Tutup bypass loopback pada /modules/reload (Commit 06abea4) │
│ ✔ [AUD-003] Ganti shell=True & format string ccache_hunt (Commit da77cca)│
│ ✔ [AUD-002] Validasi IPv4/IPv6 ketat MSSQL xp_dirtree (Commit 5ab63a0) │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│ TAHAP 2: DATA INTEGRITY & PERFORMANCE [RESOLVED]                       │
│ ✔ [AUD-007] Ganti except: pass dengan error logging (Commit 957397e)   │
│ ✔ [AUD-005] Refactor export_backup() eliminasi query N+1 (Commit 546da22)│
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│ TAHAP 3: FRONTEND AUDIT & ARCHITECTURE                                 │
│ ✔ [AUD-004] [RESOLVED] npm audit & update dependensi (Commit 7146504)  │
│ ⏳ [AUD-006] [POSTPONED] Pemecahan modular DashboardPages.tsx           │
│ ⏳ [AUD-008] [POSTPONED] Refactor 17 type-casting 'as any'              │
│ ⏳ [AUD-009] [POSTPONED] Vitest test harness GraphPage.tsx & LoginPage  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│ TAHAP 4: DOCUMENTATION SYNCHRONIZATION [RESOLVED]                      │
│ ✔ [AUD-010] Sinkronisasi port default 8000 -> 8080 (Commit 8255f6b)    │
│ ✔ [AUD-011] Dokumentasi 5 endpoint di api-reference.md (Commit 8255f6b)│
└────────────────────────────────────────────────────────────────────────┘
```

| ID | Prioritas | Status | Commit / Catatan | Estimasi Effort | Ketergantungan |
|---|---|:---:|---|:---:|---|
| **AUD-001** | P0 (Critical) | **FIXED** | `06abea4` | S (1–2 jam) | Independen |
| **AUD-003** | P1 (High) | **FIXED** | `da77cca` | S (1–2 jam) | Independen |
| **AUD-002** | P1 (High) | **FIXED** | `5ab63a0` | S (1 jam) | Independen |
| **AUD-007** | P1 (High) | **FIXED** | `957397e` | S (2 jam) | Independen |
| **AUD-005** | P2 (Medium) | **FIXED** | `546da22` | M (3–4 jam) | Independen |
| **AUD-004** | P3 (Medium) | **FIXED** | `7146504` | S (1–2 jam) | Validasi build |
| **AUD-010** | P3 (Low) | **FIXED** | `8255f6b` | S (30 menit)| Independen |
| **AUD-011** | P3 (Low) | **FIXED** | `8255f6b` | S (1 jam) | Independen |
| **AUD-006** | P2 (Medium) | **OPEN (POSTPONED)** | Ditunda ke sesi arsitektur FE | L (1–2 hari)| Bersama AUD-008 |
| **AUD-008** | P2 (Medium) | **OPEN (POSTPONED)** | Ditunda ke sesi arsitektur FE | M (3–4 jam) | Bersama AUD-006 |
| **AUD-009** | P2 (Medium) | **OPEN (POSTPONED)** | Ditunda ke sesi arsitektur FE | M (4–6 jam) | Independen |

---
*Laporan audit sistem ini diperbarui secara berkala. Seluruh item remediation Tahap 1, 2, 4, dan AUD-004 telah selesai diimplementasikan, diverifikasi melalui unit test otomatis, dan dicatat dalam riwayat git.*
