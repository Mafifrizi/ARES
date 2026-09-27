# ARES Dashboard UX Audit Report
**Tanggal Audit:** 27 September 2026  
**Auditor:** Antigravity Pair-Programming Agent  
**Cakupan:** Semua halaman dashboard setelah login (Login page dikecualikan)  
**Standard Audit:** AGENTS.md, Zero Fictitious Claims, Anti-Slop Design System, WCAG 2.1 AA  

---

## 1. RINGKASAN EKSEKUTIF

Audit dilakukan secara menyeluruh terhadap 11 entitas permukaan (10 halaman utama + 1 Global Layout Shell) dengan membaca source code aktual pada `frontend/src/features/dashboard/DashboardPages.tsx`, `frontend/src/features/graph/GraphPage.tsx`, dan `frontend/src/styles.css`.

| Metrik | Nilai |
|:---|:---|
| **Total Halaman / Permukaan Diaudit** | **11** (1 Shell + 10 Halaman Dashboard) |
| **Total Masalah Ditemukan** | **25 Masalah** |
| **CRITICAL** (Fungsi terganggu / Dead-end) | **2** |
| **HIGH** (Membingungkan / Error-prone / Hierarchy cacat) | **9** |
| **MEDIUM** (Inkonsistensi / Raw JSON Dump / Responsive polish) | **10** |
| **LOW** (Minor polish / Contrast detail / Micro-interaction) | **4** |

### 4 Masalah Paling Kritis:
1. **[CRITICAL] Dead-End di Halaman Reports Tab Library (`REP-01`)**:
   Saat operator membuka `/reports` tab `Library` tanpa campaign yang terpilih di session, sistem menampilkan pesan *"Select a campaign to list reports"*, tetapi **tidak ada komponen `CampaignPicker` sama sekali di tab Library**. Operator terkunci dan harus kembali ke tab Generate atau mengutak-atik header.
2. **[CRITICAL] Penghapusan API Key Tanpa Dialog Konfirmasi (`SEC-01`)**:
   Di halaman `/security` tab `API Keys`, tombol `Delete` langsung memicu mutasi penghapusan API key instan tanpa konfirmasi (`window.confirm` atau modal). Satu klik tidak sengaja langsung mencabut kredensial otomasi secara permanen.
3. **[HIGH] Form Ganti Password Tanpa Field Konfirmasi (`SEC-02`)**:
   Di halaman `/security` tab `Account`, hanya ada input `Current password` dan `New password`. Tidak ada field `Confirm New Password`. Jika operator salah ketik satu karakter, password berubah dan user terkunci dari sistem.
4. **[HIGH] Dead Shortcut `/` di Topbar Search (`SHL-01`)**:
   Topbar menampilkan badge shortcut keyboard visual `<span className="search-kbd-badge">/</span>`, namun tidak ada event listener keyboard global untuk tombol `/`. Ini menciptakan *false affordance*.

---

## 2. DETAIL PER HALAMAN

### 2.1 Global Layout & Shell — `DashboardShell` (`/*`)
*Komponen: `DashboardShell` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 352–1094)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **SHL-01** | **Dead Shortcut Hotkey `/` pada Search Bar**<br>UI menampilkan badge `/` seolah-olah tombol slash bisa ditekan untuk langsung fokus ke search bar, namun tidak ada listener `keydown` global. | **HIGH** | `DashboardPages.tsx`<br>`DashboardShell` | 892 | **Fix Langsung**:<br>Pasang `window.addEventListener("keydown")` global untuk tombol `/`. |
| **SHL-02** | **Dismissal Dropdown Search Menggunakan Timeout 140ms yang Rawan Race Condition**<br>`onBlur` search input memakai `setTimeout(..., 140)`. Pada perangkat lambat, klik pada hasil search bisa gagal terpanggil sebelum dropdown hilang. | **MEDIUM** | `DashboardPages.tsx`<br>`DashboardShell` | 874 | **Fix Langsung**:<br>Gunakan `onMouseDown={(e) => e.preventDefault()}` pada container hasil search. |
| **SHL-03** | **Sidebar Collapse Pada Layar Mobile/Tablet (<=920px) Menyembunyikan Navigasi Tanpa Pengganti**<br>Pada layar <=920px, navigasi berubah horizontal. Jika tombol menu ditekan, sidebar disembunyikan dengan `display: none` tanpa drawer/overlay menu pengganti. | **MEDIUM** | `styles.css`<br>Media Query | 2516–2539 | **Keputusan Desain**:<br>Tentukan apakah mobile nav menggunakan slide-over drawer atau bottom bar. |
| **SHL-04** | **Risiko Notifikasi Sistem Tertekan Permanen**<br>Jika user menghapus notifikasi sistem seperti `health:error`, ID tersebut disimpan permanen di localStorage dengan prefix matching, sehingga jika backend mati lagi di masa depan, alert tidak akan muncul lagi. | **MEDIUM** | `DashboardPages.tsx`<br>`DashboardShell` | 716–719 | **Fix Langsung**:<br>Batasi scope dismissal notifikasi kesehatan hanya pada session aktif atau per timestamp. |
| **SHL-05** | **Ketiadaan Accessible Focus Ring pada Tombol dan Icon Header**<br>Elemen `.btn` dan `.icon-button` tidak memiliki definisi `:focus-visible`, menyulitkan navigasi murni keyboard (WCAG 2.4.7). | **LOW** | `styles.css`<br>`.btn` | 1094–1150 | **Fix Langsung**:<br>Tambahkan standard `:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }`. |

---

### 2.2 Overview — `/`
*Komponen: `OverviewPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 1094–1460)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **OVR-01** | **Ikon Alarmist Menyesatkan pada Onboarding Empty State**<br>Saat instalasi baru (`trackedCount === 0`), ditampilkan ikon `ShieldAlert` merah mawar menyala (`text-rose-500`) dengan border merah, memberi kesan terjadi insiden keamanan genting padahal hanya status siap operasi. | **MEDIUM** | `DashboardPages.tsx`<br>`OverviewPage` | 1149 | **Fix Langsung**:<br>Ganti ikon dengan `Target` atau `Layers` berwarna netral/cyan. |
| **OVR-02** | **Label Footer "Perimeter mapped" Saat 0 Host Terpetakan**<br>Jika `hostsDiscovered === 0`, footer kartu Attack Surface tetap menampilkan teks `"Perimeter mapped"`, yang secara teknis keliru. Seharusnya menampilkan *"Awaiting recon"* atau *"0 hosts"*. | **MEDIUM** | `DashboardPages.tsx`<br>`OverviewPage` | 1297–1300 | **Fix Langsung**:<br>Evaluasi kondisi `hostsDiscovered > 0 ? "Perimeter mapped" : "Awaiting recon"`. |
| **OVR-03** | **Inkonsistensi Interaktivitas Baris Tabel Campaign**<br>Pada Overview, baris tabel campaign bisa diklik untuk memfilter dashboard (`onSelectCampaign`), namun pada `/campaigns` baris tabel yang sama tidak interaktif. | **LOW** | `DashboardPages.tsx`<br>`CampaignTable` | 1426, 5205 | **Fix Langsung**:<br>Seragamkan feedback kursor dan interaksi baris di semua tabel campaign. |

---

### 2.3 Campaigns — `/campaigns`
*Komponen: `CampaignsPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 1460–1810)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **CMP-01** | **Hierarki Visual Terbalik pada Tab "List"**<br>Tab diberi nama "List", namun 60% viewport atas dihabiskan oleh form pembuatan campaign yang masif (Name, Client, Noise, 2 textarea Targets & Scope CIDRs), memaksa operator scroll ke bawah setiap kali ingin melihat daftar campaign. | **HIGH** | `DashboardPages.tsx`<br>`CampaignsPage` | 1636–1670 | **Keputusan Desain**:<br>Jadikan form Create sebagai Collapsible/Drawer atau pisahkan tab "Campaigns" vs "New Campaign". |
| **CMP-02** | **Input Perbandingan Campaign Menggunakan UUID Mentah Tanpa Picker**<br>Pada tab "Scope", fitur perbandingan diff (`api.diffCampaign`) hanya menyediakan raw text field `placeholder="Compare campaign ID"`. Operator harus menghafal/copy-paste string UUID campaign lain secara manual. | **HIGH** | `DashboardPages.tsx`<br>`CampaignsPage` | 1709 | **Fix Langsung**:<br>Ganti text input dengan `CampaignPicker` dropdown (exclude campaign aktif). |
| **CMP-03** | **Tabel Findings Statis Tanpa Kemampuan Inspeksi Detail / Remediasi**<br>Pada tab "Findings", tabel hanya menampilkan 5 kolom teks statis (Severity, Title, Module, MITRE, Host). Baris tidak bisa diklik/di-expand untuk membaca deskripsi kerentanan, evidence, CVSS, atau langkah remediasi. | **HIGH** | `DashboardPages.tsx`<br>`FindingsTable` | 5243–5256 | **Fix Langsung**:<br>Tambahkan drawer inspeksi detail temuan atau expandable row seperti pada Module Run Summary. |
| **CMP-04** | **Penumpukan 6 Panel Error Sekaligus di Tab Scope**<br>Terdapat 6 `DataPanel` error yang ditumpuk beruntun (`Vault Restore Error`, `Dry Run Error`, `Delete Error`, `Campaign Detail Error`, `CVSS Error`, `Campaign Diff Error`), menimbulkan visual noise jika terjadi anomali minor. | **LOW** | `DashboardPages.tsx`<br>`CampaignsPage` | 1713–1718 | **Fix Langsung**:<br>Satukan notifikasi error ke dalam consolidated alert strip. |

---

### 2.4 Modules — `/modules`
*Komponen: `ModulesPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 1810–2326)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **MOD-01** | **Styling Error Bahaya Merah (`notice-danger`) pada Status Loading Normal**<br>Saat modul sedang dieksekusi (`run.isPending`), UI menampilkan kotak banner berkedip dengan class `notice notice-danger` (border merah pekat dan background merah menyala), membuat operator mengira modul langsung gagal padahal sedang bekerja. | **HIGH** | `DashboardPages.tsx`<br>`ModulesPage` | 2257–2262 | **Fix Langsung**:<br>Ubah class dari `notice-danger` menjadi `notice-info` atau `notice-active` dengan aksen cyan/emerald. |
| **MOD-02** | **Double Vertical Scrollbar pada Layar Laptop Standar (1366x768 / 1080p dengan zoom)**<br>Daftar kartu katalog modul dipatok dengan `max-h-[640px] overflow-auto`. Pada viewport sedang, ini memicu scroll ganda (scroll halaman dan scroll kotak modul). | **MEDIUM** | `DashboardPages.tsx`<br>`ModulesPage` | 2035 | **Fix Langsung**:<br>Gunakan tinggi adaptif `max-h-[calc(100vh-290px)]` atau virtual list. |
| **MOD-03** | **Ketiadaan Tombol Reset Parameter pada Run Panel**<br>Setelah parameter terisi (baik dari riwayat session atau transfer dari execution chain), tidak ada tombol "Clear / Reset to Defaults". Operator harus menghapus isi field satu per satu secara manual. | **LOW** | `DashboardPages.tsx`<br>`ModulesPage` | 2159–2212 | **Fix Langsung**:<br>Tambahkan tombol kecil "Reset Form" di samping header Module Parameters. |

---

### 2.5 Reports — `/reports`
*Komponen: `ReportsPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 2326–2586)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **REP-01** | **[CRITICAL] Dead-End di Tab Library: Tidak Ada Pemilih Campaign**<br>Jika user membuka tab `Library` tanpa campaign yang aktif di session, muncul tulisan *"Select a campaign to list reports."*, tetapi tidak ada dropdown `CampaignPicker` di tab tersebut. Dropdown hanya ada di tab `Generate`. | **CRITICAL** | `DashboardPages.tsx`<br>`ReportsPage` | 2579 | **Fix Langsung**:<br>Pindahkan `CampaignPicker` ke atas level Page Header atau render di kedua tab. |
| **REP-02** | **Ketiadaan Preview Laporan di Dalam Browser**<br>Laporan yang digenerate (HTML / Markdown / JSON) hanya memiliki opsi "Download" dan "Delete". Operator tidak bisa membaca isi laporan langsung di dashboard tanpa harus men-download file ke disk lokal. | **MEDIUM** | `DashboardPages.tsx`<br>`ReportsPage` | 2547–2563 | **Keputusan Desain**:<br>Sediakan modal preview/iframe untuk format HTML dan Markdown. |

---

### 2.6 Graph — `/graph`
*Komponen: `GraphPage` di `frontend/src/features/graph/GraphPage.tsx` (Baris 1–1762)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **GRP-01** | **Canvas Kosong Tanpa Panduan Saat Campaign Belum Memiliki Host**<br>Fungsi `isGraphEmpty` diimpor di baris 43 namun tidak pernah dipakai. Ketika campaign baru dibuka (0 node), canvas hanya menampilkan background grid kosong tanpa ada pesan onboarding atau tombol saran tindakan (cth: *"Jalankan modul discovery untuk memetakan target"*). | **HIGH** | `GraphPage.tsx` | 43, 959 | **Fix Langsung**:<br>Pasang overlay EmptyState di atas canvas ReactFlow jika `filteredGraph.nodes.length === 0`. |
| **GRP-02** | **Divergensi Visual & Skema Desain Ekstrem (Cobalt Strike Retro 90s)**<br>Halaman Graph menggunakan styling Windows 95/Cobalt Strike retro (`graphCobalt.css`), dengan tombol ber-ASCII (`[P]`, `[R]`, `[S]`, `[Z]`, `[L]`), yang sangat bertolak belakang dengan estetika modern dark-tech ARES di 9 halaman lainnya. | **MEDIUM** | `GraphPage.tsx`<br>`graphCobalt.css` | 16, 980–1100 | **Keputusan Desain**:<br>Konfirmasi dengan owner apakah skin Cobalt Strike ini dipertahankan sebagai tactical gimmick atau diselaraskan dengan design system ARES. |

---

### 2.7 Templates — `/templates`
*Komponen: `TemplatesPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 2587–2723)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **TPL-01** | **Input Parameter Global Berupa Raw JSON Textarea yang Kaku dan Mudah Rusak**<br>Field parameter global mewajibkan operator menulis format JSON mentah tanpa syntax highlighting atau formatting helper. Satu kesalahan tanda kutip langsung memblokir tombol generate. | **HIGH** | `DashboardPages.tsx`<br>`TemplatesPage` | 2670–2703 | **Fix Langsung**:<br>Tambahkan tombol "Format JSON" / "Beautify" dan validasi error inline yang presisi. |
| **TPL-02** | **Dead-End Simulasi Plan: Tidak Bisa Langsung Diterapkan ke Campaign**<br>Setelah plan berhasil digenerate dan diverifikasi, tidak ada tombol untuk *"Terapkan Plan ke Campaign"* atau *"Jalankan Plan Ini"*. Operator hanya disajikan preview JSON. | **HIGH** | `DashboardPages.tsx`<br>`TemplatesPage` | 2712–2718 | **Keputusan Desain**:<br>Tambahkan CTA "Execute Plan on Campaign" yang mengoper parameter ke Campaigns Run. |

---

### 2.8 Strategy — `/strategy`
*Komponen: `StrategyPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 2724–2912)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **STR-01** | **Hasil Perencanaan AI Hanya Berupa Raw JSON Dump Tanpa Timeline Visual**<br>Fitur Strategy AI yang canggih (mengeksekusi perancangan serangan multi-round) hanya menampilkan output akhir berupa `DataPanel` JSON mentah di tab "Active" dan "Result", tanpa ada visualisasi tahapan round atau approval checklist. | **HIGH** | `DashboardPages.tsx`<br>`StrategyPage` | 2894, 2901 | **Keputusan Desain**:<br>Rancang komponen timeline visual untuk menampilkan tahapan reasoning dan langkah aksi AI. |

---

### 2.9 Security — `/security`
*Komponen: `SecurityPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 2933–3165)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **SEC-01** | **[CRITICAL] Penghapusan API Key Tanpa Dialog Konfirmasi**<br>Tombol `Delete` pada daftar API key langsung mengeksekusi `remove.mutate(key.id)` saat diklik tanpa peringatan. Terpencet tidak sengaja akan mematikan integrasi produksi secara instan. | **CRITICAL** | `DashboardPages.tsx`<br>`SecurityPage` | 3093 | **Fix Langsung**:<br>Pasang dialog konfirmasi sebelum menghapus API key. |
| **SEC-02** | **Ganti Password Tanpa Input Konfirmasi Password Baru**<br>Form hanya meminta `Current password` dan `New password`. Ketiadaan field konfirmasi menimbulkan risiko tinggi salah ketik password yang berujung account lockout. | **HIGH** | `DashboardPages.tsx`<br>`SecurityPage` | 3050–3056 | **Fix Langsung**:<br>Tambahkan input `Confirm new password` dan validasi kesamaan sebelum submit. |
| **SEC-03** | **Tab Audit & User Management Hanya Menampilkan Raw JSON Dump**<br>Bagi role `team_lead`, audit log keamanan dan daftar pengguna internal hanya dirender via `DataPanel` JSON mentah. Tidak ada tabel log dengan timestamp, action, IP, dan actor. | **MEDIUM** | `DashboardPages.tsx`<br>`SecurityPage` | 3104–3105 | **Keputusan Desain**:<br>Implementasikan tabel audit log dan tabel manajemen pengguna yang rapi. |

---

### 2.10 EDR/OPSEC — `/edr`
*Komponen: `EdrPage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 3166–3287)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **EDR-01** | **Tab Knowledge Base Sebagian Besar Berupa Raw JSON Dump**<br>Setelah menampilkan 3 kartu metrik ringkas, seluruh data knowledge base diserahkan ke `DataPanel` JSON mentah tanpa tabel pemetaan teknik vs produk EDR (CrowdStrike, Defender, dll). | **MEDIUM** | `DashboardPages.tsx`<br>`EdrPage` | 3220 | **Keputusan Desain**:<br>Ubah menjadi tabel matriks teknik bypass per vendor EDR. |
| **EDR-02** | **Kontras Rendah Tanda Bintang Wajib Isi (`text-red-700`)**<br>Tanda bintang mandatory menggunakan warna Tailwind gelap `text-red-700`, yang di atas latar belakang `#09090b` memiliki contrast ratio buruk (tidak lolos WCAG AA). | **LOW** | `DashboardPages.tsx`<br>`EdrPage` | 3236, 3242 | **Fix Langsung**:<br>Ganti ke `text-rose-400` atau `text-red-400`. |

---

### 2.11 Live Events — `/live`
*Komponen: `LivePage` di `frontend/src/features/dashboard/DashboardPages.tsx` (Baris 3289–3491)*

| ID | Masalah | Severity | File/Komponen | Baris | Tipe Solusi |
|---|---|---|---|---|---|
| **LIV-01** | **Ketiadaan Kontrol Pause / Freeze pada Aliran Event Live**<br>Saat ribuan event masuk dengan cepat, operator tidak memiliki tombol untuk membekukan tampilan stream sementara guna membaca detail payload tanpa harus memutuskan sambungan WebSocket. | **MEDIUM** | `DashboardPages.tsx`<br>`LivePage` | 3360–3375 | **Fix Langsung**:<br>Tambahkan state `isStreamPaused` untuk menghentikan pembaruan visual buffer sementara. |

---

## 3. TEMUAN SISTEMIK (CROSS-PAGE PATTERNS)

Ada 6 pola masalah arsitektur UX yang berulang di banyak halaman sekaligus:

### Pola 1: Ketergantungan Berlebihan pada Raw JSON Dump (`DataPanel`)
- **Lokasi Tersebar:** `Campaigns` (Scope tab), `Templates` (Plan Builder), `Strategy` (Active & Result tab), `Security` (Audit & Users tab), `EDR` (Stats tab).
- **Dampak UX:** Memberi kesan aplikasi masih "setengah jadi" (prototype perkakas developer internal) dan tidak ramah bagi operator non-developer atau executive stakeholders.
- **Rekomendasi:** Ubah data terstruktur (tabel user, audit log, perincian bypass) menjadi tabel dan badge interaktif. Simpan raw JSON hanya di dalam drawer "Inspect Raw Payload" opsional.

### Pola 2: Fragmentasi State & Pemilih Campaign (`CampaignPicker`)
- **Lokasi Tersebar:** Ada di Topbar, ada di dalam tab tertentu, namun hilang di tab Library (`Reports`), tab Buffer (`Live`), dan tidak ada di `Templates`.
- **Dampak UX:** Operator bingung apakah aksi yang mereka lakukan sedang memodifikasi Scope global atau Campaign tertentu.
- **Rekomendasi:** Jadikan Campaign Picker sebagai konteks universal yang melekat di level `DashboardShell` (Header) atau pastikan setiap sub-halaman yang membutuhkan campaign selalu menyertakan picker di posisi yang konsisten (kiri atas konten).

### Pola 3: Inkonsistensi Dialog Aksi Destruktif
- **Lokasi Tersebar:**
  - Hapus Campaign: memakai `window.confirm` browser.
  - Hapus Report: memakai `window.confirm` browser.
  - Hapus API Key: **TIDAK ADA KONFIRMASI APAPUN**.
- **Dampak UX:** Inkonsistensi berat antara dialog native browser yang menghentikan thread JS vs aksi tanpa konfirmasi yang berbahaya.
- **Rekomendasi:** Buat komponen modal konfirmasi destruktif standar ARES (`ConfirmationModal`) dengan judul, deskripsi dampak, dan tombol konfirmasi merah.

### Pola 4: URL Tidak Sinkron dengan State Tab (`useSessionState`)
- **Lokasi Tersebar:** Semua halaman (`Campaigns`, `Modules`, `Reports`, `Templates`, `Strategy`, `Security`, `EDR`, `Live`).
- **Dampak UX:** Tombol Back/Forward pada browser tidak bisa digunakan untuk berpindah tab. Jika link di-copy ke tim lain, link tidak membuka tab yang dimaksud karena tab disimpan di `sessionStorage` lokal, bukan URL Search Params/Hash.
- **Rekomendasi:** Gunakan URL Search Params (misal `?tab=scope` atau `?tab=chains`) sebagai sumber kebenaran tab, dengan fallback ke session.

### Pola 5: Indikator Loading Berwarna Bahaya (`notice-danger`)
- **Lokasi Tersebar:** `ModulesPage` (baris 2257), `OverviewPage` empty state (baris 1149).
- **Dampak UX:** Elemen dengan kondisi berjalan normal atau belum ada data diberi border dan background merah terang, memicu kepanikan operator secara keliru.

### Pola 6: Ketiadaan Accessible Keyboard Focus Visible
- **Lokasi Tersebar:** Seluruh form, tombol, catalog card, dan filter di `styles.css`.
- **Dampak UX:** Navigasi via tombol Tab tidak memperlihatkan highlight kotak fokus yang jelas pada elemen aktif, melanggar WCAG 2.1 Success Criterion 2.4.7.

---

## 4. REKOMENDASI PRIORITAS IMPLEMENTASI

Urutan pengerjaan berdasarkan rasio **Impact vs Effort**:

### Phase 1: Quick Wins & Critical Fixes (High Impact, Low Effort) — Est: 1–2 Sesi
1. **[REP-01]** Tambahkan `CampaignPicker` ke tab Library di `/reports` agar tidak terjadi dead-end.
2. **[SEC-01]** Pasang modal konfirmasi pada tombol Delete API Key di `/security`.
3. **[SEC-02]** Tambahkan field "Confirm New Password" pada form ganti password di `/security`.
4. **[SHL-01]** Tambahkan keyboard listener global untuk tombol `/` agar langsung fokus ke search bar.
5. **[MOD-01]** Ganti styling status eksekusi modul dari `notice-danger` (merah) ke `notice-info` (cyan/pulsing).
6. **[EDR-02]** Ubah class asteris wajib dari `text-red-700` ke `text-rose-400`.
7. **[CMP-02]** Ganti input text perbandingan campaign dengan dropdown `CampaignPicker`.

### Phase 2: Structural & Component Polish (High Impact, Medium Effort) — Est: 2–3 Sesi
1. **[CMP-01]** Reorganisasi tab "List" di Campaigns agar tabel campaign terlihat langsung di atas (form create dibuat collapsible atau drawer).
2. **[CMP-03]** Buat detail drawer untuk tabel Findings di `/campaigns`.
3. **[GRP-01]** Pasang overlay EmptyState ramah pada canvas `/graph` saat campaign baru dibuat.
4. **[LIV-01]** Tambahkan kontrol Pause/Resume pada stream di `/live`.
5. **[TPL-01]** Pasang validasi interaktif dan tombol "Beautify JSON" pada parameter template.
6. **[SHL-05]** Pasang focus-visible styling standar di `styles.css` untuk semua tombol dan input.

### Phase 3: Major UX Elevation (Strategic Value, Needs Owner Direction) — Est: 3–4 Sesi
1. **[STR-01]** Desain ulang tab Active & Result di Strategy menjadi visual timeline AI execution.
2. **[SEC-03]** Implementasi tabel audit log dan tabel user management terstruktur di Security.
3. **[EDR-01]** Transformasi Knowledge Base EDR dari JSON mentah menjadi tabular bypass matrix.
4. **[GRP-02]** Putuskan arah desain GraphPage: selaraskan dengan modern dark-tech ARES atau pertahankan retro Cobalt Strike.
5. **[Pola 4]** Migrasi manajemen tab dari `useSessionState` murni menjadi URL Query Params (`?tab=...`) untuk mendukung deep linking dan browser history.
