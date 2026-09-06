# Panduan & Setup Single Sign-On (SSO) Enterprise — ARES Dashboard

Dokumen ini menjelaskan penggunaan dan konfigurasi **Enterprise Multi-Tenant SSO (SAML 2.0 & OpenID Connect)** di ARES Dashboard, baik untuk pengguna akhir (operator/pentester) maupun administrator sistem.

---

## BAGIAN 1 — Panduan Untuk Pengguna (End-User)

### Kapan Menggunakan "Sign in" Biasa vs "Or continue with SSO"?

| Metode Login | Kapan Digunakan? | Kredensial yang Digunakan |
| :--- | :--- | :--- |
| **"Sign in" Biasa** | Digunakan untuk akun lokal/internal (misalnya akun superadmin awal `admin` atau operator lab yang dibuat langsung di database lokal ARES). | Username dan password lokal yang tersimpan di database ARES (dienkripsi dengan bcrypt). |
| **"Or continue with SSO"** | Digunakan jika organisasi/perusahaan Anda mengelola identitas terpusat melalui Identity Provider (IdP) seperti Okta, Google Workspace, Microsoft Entra ID (Azure AD), Ping Identity, atau Keycloak. | Kredensial akun kantor/organisasi Anda di halaman login resmi IdP Anda. |

> [!NOTE]
> **Proteksi Keamanan Akun SSO**: Jika akun Anda telah terdaftar sebagai pengguna SSO (`auth_provider = 'saml'` atau `'oidc'`), akun Anda **secara otomatis ditolak** jika mencoba login melalui form password lokal. Anda wajib masuk menggunakan tombol **"Or continue with SSO"**.

### Pesan: *"SSO belum dikonfaktorasi untuk organisasi ini. Hubungi admin."*

Jika Anda mengklik tombol **"Or continue with SSO"** dan muncul pesan peringatan warna amber:
> ⚠️ **SSO belum dikonfigurasi untuk organisasi ini. Hubungi admin.**

**Artinya:**
1. Profil SSO (SAML 2.0 atau OIDC) untuk organisasi Anda belum didaftarkan di database ARES atau statusnya sedang dinonaktifkan (`is_enabled = 0`).
2. Backend ARES menolak memulai alur federasi karena tidak memiliki endpoint IdP, sertifikat x.509, atau client ID yang valid.

**Langkah yang Harus Diambil:**
- Jangan mencoba menebak password di form lokal.
- Hubungi Administrator ARES atau tim Security Operations (SecOps) organisasi Anda dan minta mereka mengonfigurasi federasi identitas organisasi Anda mengikuti panduan Bagian 2 di bawah.

---

## BAGIAN 2 — Panduan Untuk Administrator: Setup SSO Organisasi Baru

### 1. Prasyarat: Environment Variable `ARES_ENCRYPTION_KEY`

ARES menerapkan enkripsi tingkat aplikasi (*app-level encryption*) menggunakan modul `DataEncryptor` (berbasis Fernet: `PBKDF2-HMAC-SHA256` 100.000 iterasi + `AES-128-CBC` + `HMAC-SHA256` dengan *salt* acak unik per *record*). Semua sertifikat SAML dan secret OIDC disimpan dalam bentuk terenkripsi di database.

Aplikasi mewajibkan `ARES_ENCRYPTION_KEY` memiliki panjang **minimal 32 karakter**. Jika tidak diset atau kurang dari 32 karakter, ARES akan menolak *startup*.

#### Cara Generate Kunci:
Jalankan perintah Python berikut:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
*Contoh output: `16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w=`*

#### Cara Set Environment Variable:
- **Di file `.env` (disarankan):**
  ```env
  ARES_ENCRYPTION_KEY=16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w=
  ```
- **Di Linux / macOS (Terminal):**
  ```bash
  export ARES_ENCRYPTION_KEY="16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w="
  ```
- **Di Windows (PowerShell):**
  ```powershell
  $env:ARES_ENCRYPTION_KEY="16R2yRp-PWlbNT49xq6sZzp39ArxJJ7Tlap1MqYWp3w="
  ```

---

### 2. Mendaftarkan Konfigurasi SSO ke ARES

Pendaftaran konfigurasi SSO dapat dilakukan melalui **REST API Endpoint Admin** (memerlukan role `team_lead`, yaitu tingkatan role tertinggi dalam hierarki ARES: `team_lead > operator > recon > reporter`; akun bootstrap `admin` secara default memiliki role `team_lead`) atau langsung ke database jika API gateway belum diakses.

> [!IMPORTANT]
> **Kebijakan Arsitektur: SP-Initiated SSO Only**  
> ARES saat ini **hanya mendukung SP-initiated SSO**. User harus selalu memulai login dari halaman ARES (klik tombol *"Or continue with SSO"*), bukan dari portal aplikasi IdP mereka (seperti dashboard Okta atau My Apps Azure AD / Entra ID).  
> **Sampaikan hal ini ke tim IT organisasi saat onboarding SSO mereka**, karena ini berbeda dari flow yang biasa mereka pakai untuk aplikasi SaaS lain. ARES secara ketat menolak SAML response tanpa parameter `InResponseTo` yang valid serta callback OIDC tanpa token `state` yang terdaftar demi mencegah serangan pemalsuan sesi dan token replay.

#### Opsi A: Melalui REST API Admin (Direkomendasikan)
ARES menyediakan endpoint manajemen SSO (khusus role `team_lead`):
- **`GET /auth/sso/config/{org_slug}`**: Melihat status konfigurasi SSO organisasi.
- **`POST /auth/sso/config/{org_slug}`**: Menyimpan atau memperbarui konfigurasi SSO organisasi.

Format request payload `POST /auth/sso/config/{org_slug}`:
```json
{
  "protocol": "saml", // atau "oidc"
  "issuer_or_entity_id": "https://idp.example.com/entityid",
  "sso_url": "https://idp.example.com/sso/endpoint",
  "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
  "client_id": "",
  "client_secret": "",
  "jwks_uri": "",
  "default_role": "reporter",
  "role_mapping": {
    "SecurityAdmins": "team_lead",
    "RedTeam": "operator",
    "Auditors": "reporter"
  },
  "is_enabled": true
}
```
*Catatan: Backend ARES akan secara otomatis mengenkripsi `idp_certificate` dan `client_secret` menggunakan Fernet `DataEncryptor` sebelum menyimpannya ke tabel `sso_configurations`.*

#### Opsi B: Melalui Database SQL Langsung
Jika mendaftarkan langsung melalui SQLite (`ares.db`) atau PostgreSQL:
1. Pastikan organisasi terdaftar di tabel `organizations`:
   ```sql
   INSERT INTO organizations (id, slug, name, is_active)
   VALUES ('org-corp-01', 'corp', 'ACME Corp', 1);
   ```
2. Nilai kolom `idp_certificate_enc` atau `client_secret_enc` harus dienkripsi terlebih dahulu menggunakan helper ARES:
   ```bash
   python -c "from ares.core.config import get_settings; from ares.core.sso import encrypt_sso_secret; print(encrypt_sso_secret('YOUR_SECRET_HERE', get_settings()))"
   ```
3. Masukkan ke tabel `sso_configurations`:
   ```sql
   INSERT INTO sso_configurations (
       id, org_id, protocol, is_enabled,
       issuer_or_entity_id, sso_url, idp_certificate_enc,
       default_role, role_mapping_json
   ) VALUES (
       'sso-cfg-01', 'org-corp-01', 'saml', 1,
       'https://idp.example.com/entityid', 'https://idp.example.com/sso', 'HASIL_ENKRIPSI',
       'reporter', '{"SecAdmins": "team_lead"}'
   );
   ```

---

### 3. Detail Integrasi Protokol SAML 2.0

#### A. Data yang Harus Disiapkan Organisasi dari IdP Mereka:
1. **IdP Entity ID**: URI pengenal unik IdP (misal: `https://sts.windows.net/tenant-uuid/` atau `http://www.okta.com/exk123`).
2. **SSO URL (Single Sign-On Service URL)**: Endpoint HTTP-Redirect atau HTTP-POST milik IdP tempat user diarahkan untuk autentikasi.
3. **IdP x.509 Certificate**: Sertifikat publik IdP dalam format PEM untuk memvalidasi tanda tangan digital (*signature*) XML assertion.

#### B. Data yang Diberikan ARES ke IdP Organisasi:
- **Assertion Consumer Service (ACS) URL**:
  ```
  POST https://<domain-ares>/auth/sso/saml/acs
  ```
  *(Binding: HTTP-POST)*
- **Service Provider (SP) Entity ID / Audience**:
  ```
  https://<domain-ares>/auth/sso/saml/metadata
  ```
- **NameID Format**: Email Address (`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`) atau Persistent (`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`).

---

### 4. Detail Integrasi Protokol OpenID Connect (OIDC)

#### A. Data yang Harus Disiapkan Organisasi dari IdP Mereka:
1. **Issuer URL**: Base URL penyedia identitas (misal: `https://accounts.google.com` atau `https://login.microsoftonline.com/{tenant}/v2.0`).
2. **Client ID & Client Secret**: Kredensial client yang digenerate oleh IdP saat membuat aplikasi ARES.
3. **JWKS URI (Opsional/Direkomendasikan)**: Endpoint kunci publik IdP (misal: `https://idp.example.com/.well-known/jwks.json`) untuk verifikasi tanda tangan ID Token JWT.
4. **Authorization & Token Endpoint**: Endpoint otorisasi OAuth2/OIDC dari IdP.

#### B. Data yang Diberikan ARES ke IdP Organisasi:
- **Redirect URI / Callback URL**:
  ```
  GET https://<domain-ares>/auth/sso/oidc/callback
  ```
- **Response Type**: `code` (Authorization Code Flow).
- **Scope**: `openid email profile`.

---

### 5. Cara Pengujian & Verifikasi (Tanpa Buka Database)

Setelah konfigurasi disimpan, lakukan verifikasi melalui browser:

1. **Cek Respons Endpoint Inisialisasi**:
   Akses di browser atau `curl`:
   ```bash
   curl -i "http://127.0.0.1:8080/auth/sso/init?org=default"
   ```
   **Indikator Sukses**: Mengembalikan status HTTP `200 OK` dengan payload:
   ```json
   {
     "configured": true,
     "protocol": "saml", // atau "oidc"
     "redirect_url": "https://idp.example.com/...",
     "flow_id": "..."
   }
   ```

2. **Uji Melalui UI ARES Dashboard**:
   - Buka `http://127.0.0.1:5173/dashboard/login`.
   - Klik tombol **"Or continue with SSO"**.
   - Browser akan langsung mengarahkan Anda ke halaman login IdP Anda (Okta, Azure AD, atau Google).
   - Masukkan kredensial IdP Anda hingga selesai.
   - IdP akan me-redirect kembali ke ARES, dan Anda akan langsung masuk ke halaman utama Dashboard (`/dashboard/`) dengan sesi login aktif (cookie `ares-dev-refresh` dan `ares-dev-csrf` terpasang).
   - Akun Anda akan otomatis dibuat secara *Just-In-Time* (JIT) di ARES dengan role sesuai mapping atau default (`reporter`).

---

## BAGIAN 3 — Troubleshooting Singkat untuk Admin

Berikut adalah daftar pesan error umum yang dapat muncul pada URL login (`/dashboard/login?error=...`) dan penjelasan solusinya:

| Pesan Error di Login Page | Penyebab Utama | Solusi Tindakan Admin |
| :--- | :--- | :--- |
| **`Invalid or expired OIDC state (replay rejected)`** atau<br>**`Invalid or expired SAML request ID (replay rejected)`** | User membutuhkan waktu lebih dari 10 menit untuk menyelesaikan login di halaman IdP, atau user menekan tombol **Back**, me-refresh halaman callback, atau mencoba memakai link callback yang sama dua kali. | Minta user untuk kembali ke halaman `/dashboard/login` dan mengklik kembali tombol **"Or continue with SSO"** untuk menghasilkan sesi autentikasi baru yang aman. |
| **`SAML assertion missing InResponseTo (replay protection)`** | IdP mengirimkan SAML Assertion tanpa menyertakan ID AuthnRequest asal (*InResponseTo*), yang umumnya terjadi jika login dimulai dari portal IdP (*IdP-initiated SSO*). | ARES secara ketat hanya mengizinkan alur *SP-initiated SSO* demi mencegah serangan replay token SAML. Pastikan user selalu memulai login dari halaman login ARES Dashboard. |
| **`Invalid SAML signature`** atau<br>**`Signature validation failed`** | Sertifikat x.509 IdP yang tersimpan di ARES tidak cocok dengan sertifikat private key yang dipakai IdP saat menandatangani respons SAML (misalnya sertifikat IdP baru saja di-renew atau expired). | Dapatkan sertifikat x.509 publik terbaru dari IdP dan perbarui melalui endpoint `POST /auth/sso/config/{org_slug}` atau update kolom `idp_certificate_enc`. |
| **`Invalid token issuer or audience`** (OIDC) | Klaim `iss` (issuer) atau `aud` (audience) pada ID Token OIDC yang dikirim IdP tidak sesuai dengan `issuer_or_entity_id` atau `client_id` yang terdaftar di konfigurasi ARES. | Periksa kembali apakah nilai `client_id` dan `issuer_or_entity_id` di konfigurasi SSO ARES sudah sama persis dengan yang tertera di konsol IdP Anda. |
| **`SSO configuration not found for organization`** | Organisasi yang diminta tidak memiliki konfigurasi SSO aktif, atau organisasi tersebut berstatus dinonaktifkan (`is_active = 0`). | Pastikan organisasi aktif di tabel `organizations` dan memiliki konfigurasi di tabel `sso_configurations` dengan `is_enabled = 1`. |
