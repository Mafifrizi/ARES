# SUCCESS_MECHANISM_AUDIT.md
# ARES Success Mechanism & Finding Validation Audit
**Auditor**: Principal Security Reviewer & QA Auditor  
**Date**: September 2026  
**Scope**: Module Base Classes (`BaseModule`, `BaseLateralModule`), Execution Engine (`ares/core/engine.py`), Validation Pipeline (`ares/core/validator.py`), Attack Chain & Strategy Planners (`ares/core/chain/chain.py`, `ares/strategy/engine.py`, `ares/modules/ai/autonomous_planner.py`).  
**Status**: DOKUMENTASI ARSITEKTUR & TEMUAN (Honesty Gates belum diimplementasikan di sesi ini sesuai batasan).

---

## EXECUTIVE SUMMARY

Audit mendalam terhadap mekanisme publikasi finding dan evaluasi kesuksesan di ARES mengungkapkan adanya **kesenjangan validasi fundamental (Validation Blindspot)**:
1. **Unvalidated Finding Pipeline**: `BaseModule.finding()` menerbitkan finding tanpa verifikasi bukti target.
2. **Ignored Engine Validator**: `ares/core/engine.py` menjalankan `self.validator.validate()`, namun hasilnya **sama sekali diabaikan**—semua finding yang dikembalikan modul langsung dicap `validated = True` dan dimasukkan ke `confirmed`.
3. **Default Success Paths**: Error/timeout jaringan pada modul seperti `lateral.rdp` ditangkap dan justru dijadikan indikator "sukses" (`result.success = True`), memicu finding `Severity.CRITICAL` tanpa otentikasi maupun eksekusi perintah nyata.
4. **Autonomous Cascading Risk**: Finding palsu ini secara otomatis dibaca oleh `ChainAdvisor`, `AutonomousPlanner`, dan `StrategyEngine`, memicu chain serangan lanjutan yang agresif dan berisiko tinggi terhadap target, atau secara keliru mengklaim bahwa tujuan engagement (`goal_achieved`) telah tercapai.

---

## PERTANYAAN 1: Apa yang Harus Benar Agar Finding CRITICAL/HIGH Bisa Diterbitkan?

### 1. Alur Eksekusi: Dari `run()` ke `self.finding()`
- **Kontrak Base Class**: Di `ares/modules/base.py:431-447`, method `BaseModule.run()` didefinisikan dengan docstring eksplisit:
  ```python
  # ares/modules/base.py:435-437
  Returns:
      findings  - list of Finding objects (unvalidated)
      raw       - raw output dict (evidence, debug info)
  ```
  Base class sendiri mengakui bahwa list `Finding` yang dikembalikan adalah **unvalidated**.
- **Metode Pembuatan Finding**: Di `ares/modules/base.py:532-568`:
  ```python
  # ares/modules/base.py:545-558
  f = Finding(
      id              = str(uuid.uuid4()),
      title           = title,
      description     = description,
      severity        = severity,
      mitre_technique = mitre_technique,
      mitre_tactic    = mitre_tactic,
      evidence        = evidence or {},
      remediation     = remediation,
      host            = host,
      confidence      = confidence,
      module_id       = self.MODULE_ID,
  )
  self._findings.append(f)
  return f
  ```
  Tidak ada gate atau filter apa pun di dalam `self.finding()`. Setiap modul bebas memanggil `self.finding(..., severity=Severity.CRITICAL, confidence=1.0)` kapan saja, bahkan tanpa bukti koneksi target sama sekali.

### 2. Apakah Ada Gate Pembuktian di Level Engine?
- **Pemeriksaan di `ares/core/engine.py:776-800`**:
  ```python
  # ares/core/engine.py:776-781
  validation_results: list[ValidationResult] = []
  if not skip_validation:
      # Run all validations in parallel too
      validation_results = list(
          await asyncio.gather(*[self.validator.validate(f, raw) for f in findings])
      )

  # ares/core/engine.py:791-799
  for f in findings:
      if not f.false_positive:
          f.validated = True
          f.module_id = f.module_id or module_id
          enrich_finding_with_cvss(f)
          if trace_id:
              f.trace_id = trace_id
          confirmed.append(f)
  ```
- **Bukti Kritis**:
  Meskipun `self.validator.validate(f, raw)` dipanggil di baris 780, **hasil `validation_results` tidak pernah diinspeksi untuk memfilter `findings`!**
  Di baris 791, engine hanya mengecek `if not f.false_positive`. Karena atribut `false_positive` pada model `Finding` (`ares/core/campaign.py:50`) secara default bernilai `False`, seluruh finding tanpa kecuali langsung diubah statusnya menjadi `f.validated = True` dan dimasukkan ke dalam daftar `confirmed`.

### 3. Kelemahan di Dalam `FindingValidator` Sendiri
Bahkan jika hasil validator diperiksa, implementasi `FindingValidator` memiliki celah besar:
- **Default Permissive**: Di `ares/core/validator.py:70-79`, jika sebuah modul tidak memiliki check terdaftar di registry, validator mengembalikan:
  `passed=True`, `confidence=0.6`, `notes=["No validators registered - manual review recommended"]`.
- **Tautological Check**: Di `ares/core/validator.py:264-276` (`_check_lateral_evidence`):
  ```python
  if target:
      account_str = f" as '{user}'" if user else ""
      return True, 1.0, f"Lateral movement to {target}{account_str} verified via {tech} ({privilege} privilege)"
  return False, 0.0, "Missing target host evidence in lateral movement finding"
  ```
  Pemeriksaan lateral movement hanya mengecek apakah field `target` ada/tidak kosong! Jika ada, check mengembalikan `passed=True, score=1.0`.

**Kesimpulan Pertanyaan 1**: Tidak ada gate pembuktian nyata. Finding severity CRITICAL/HIGH dapat diterbitkan hanya berdasarkan kemauan penulis modul tanpa verifikasi respon target nyata.

---

## PERTANYAAN 2: Apakah Ada Default Success Path Tanpa Bukti?

Ya, ditemukan beberapa pola konkret di mana kegagalan jaringan atau ketiadaan bukti di-interpretasikan sebagai sukses:

### 1. Exception di-Catch Lalu Fallback ke Success (Kasus `lateral.rdp`)
- **Path & Baris**: `ares/modules/lateral/modules.py:1483-1492`
  ```python
  banner = sock.recv(64)
  sock.close()
  if banner and banner[0] == 0x03:
      return True, "rdp_port_open", ""
  return False, "", "Unexpected banner response"
  except (OSError, socket.timeout):
      sock.close()
      # Port open but no valid response - still likely RDP
      return True, "rdp_port_open", ""
  ```
- **Dampak**: Jika socket port 3389 terbuka tetapi terjadi timeout saat membaca banner, exception ditangkap dan fungsi mengembalikan `True` dengan privilege `"rdp_port_open"`.
- Lalu di `ares/modules/lateral/modules.py:466-506`:
  ```python
  if result.success:
      findings.append(self.finding(
          title       = f"Lateral Movement: {self.MODULE_NAME} → {target}",
          description = f"Successfully moved laterally to {target} as {account_label} via {result.technique.value}. Privilege: {result.privilege or 'unknown'}.",
          severity    = Severity.CRITICAL,
          confidence  = 1.0,
      ))
  ```
  Modul menerbitkan finding **Severity.CRITICAL** dengan klaim "Successfully moved laterally" dan confidence 1.0, padahal yang terjadi hanyalah port 3389 terbuka tanpa otentikasi maupun eksekusi perintah (MOD-021).

### 2. Fallback Dummy / Phantom Active Saat Backend Absen
- **Path & Baris**: `ares/modules/lateral/infrastructure.py:260-265, 368-370` (MOD-019)
  Jika library backend `asyncssh` tidak terpasang, modul menandai tunnel status sebagai `ACTIVE` dan menerbitkan status sukses.
- **Path & Baris**: `ares/modules/lateral/modules.py:1332-1356` (MOD-020)
  `SSHPivot.establish_socks5` mengembalikan dictionary proxy aktif, padahal method `move()` di bawahnya tidak membuka port forwarding nyata.

### 3. Local Calculation Tanpa I/O Diklaim Eksploitasi Nyata
- **Path & Baris**: `ares/modules/ad/ghost_forge.py:165-201` (MOD-005)
  Melakukan kalkulasi MD4/HMAC lokal, tidak pernah menyentuh socket/jaringan, namun menerbitkan finding CRITICAL "Golden/Silver Ticket Forged" dan menyuntikkan tiket fiktif ke Credential Vault.

### 4. Permissive Module Status di Engine
- **Path & Baris**: `ares/modules/base.py:341-347`
  ```python
  findings, raw = await self.run(**kwargs)
  return ModuleResult(
      status = "success" if findings or raw else "partial",
      ...
  )
  ```
  Bahkan jika modul hanya mengembalikan dictionary `raw` berisi string error, status yang diberikan adalah `"success"`. Dan di `ares/core/engine.py:66-74`, status `"partial"` maupun `"success"` keduanya tergolong `_SUCCESSFUL_MODULE_OUTCOMES`.

---

## PERTANYAAN 3: Apakah Finding CRITICAL Otomatis Memicu Chain Eksekusi?

**YA, SEPENUHNYA TERBUKTI.**
Finding severity CRITICAL dan data palsu yang dihasilkannya otomatis memicu chain eksekusi berikutnya pada minimal 3 komponen otonom ARES:

### 1. ChainAdvisor Rule Engine (`ares/core/chain/chain.py`)
Di `ares/core/chain/chain.py:306-375`, `ChainAdvisor.suggest()` menganalisis confirmed findings untuk menentukan modul berikutnya:
```python
# ares/core/chain/chain.py:343-345
(
    "critical" in severities,
    Suggestion("ad.enum_acl", "Critical findings present - check for ACL abuse paths", 0.75, 2),
),
# ares/core/chain/chain.py:323-326
(
    any("writedacl" in t or "genericall" in t or "dcsync right" in t for t in titles),
    Suggestion("ad.dcsync", "Dangerous ACL grants DCSync capability", 0.90, 2),
),
```
Jika modul menghasilkan finding CRITICAL atau judul finding mengandung keyword tertentu (misal DCSync right), `ChainAdvisor` langsung menyarankan eksekusi modul berbahaya seperti `ad.dcsync` atau `ad.enum_acl`.

### 2. Autonomous Planner Context Injection (`ares/modules/ai/autonomous_planner.py`)
Di `ares/modules/ai/autonomous_planner.py:163-176`, seluruh finding diekstraksi ke prompt LLM:
```python
ctx["findings_summary"].append({"severity": str(sev), "title": title, "module": mid})
```
Dan di `_format_credentials_actionable` (baris 116-144), jika ada kredensial di vault (seperti kredensial fiktif yang disuntikkan MOD-005):
- Tipe `NTLM` / `plaintext` $\rightarrow$ merekomendasikan `lateral.psexec`, `lateral.wmiexec`, `lateral.winrm`.
- Privilege `domain_admin` $\rightarrow$ merekomendasikan `ad.dcsync`, `credential.golden_ticket`.

### 3. StrategyEngine Autonomous Loop (`ares/strategy/engine.py`)
Di `ares/strategy/engine.py:390-570`, engine menjalankan multi-round engagement secara otonom:
1. `_run_ai_planner()` membuat `execution_plan` berdasarkan findings summary.
2. `ConstitutionEnforcer` hanya memfilter modul yang dilarang eksplisit (`forbidden_modules`), bukan memeriksa keabsahan bukti.
3. Modul-modul hasil rencana LLM dieksekusi secara otomatis via `self._run_single_module()`.
4. **Pengecekan Sasaran (Goal Achieved)** di `ares/strategy/engine.py:894-913`:
   ```python
   def _check_goal_achieved(self, campaign: "Any", goal: str) -> bool:
       findings = getattr(campaign, "findings", [])
       goal_indicators = {
           "domain_admin":     ["DCSync", "Domain Admin", "krbtgt", "ntlm_hash"],
           ...
       }
       ...
       for finding in findings:
           title = getattr(finding, "title", "")
           if any(ind.lower() in title.lower() for ind in indicators):
               return True
       return False
   ```
   Jika finding CRITICAL palsu (seperti dari MOD-005 atau MOD-021) memuat judul "Domain Admin" atau "ntlm_hash", engine langsung menyimpulkan bahwa sasaran campaign **SELESAI (`goal_achieved = True`)**, memicu laporan kemenangan palsu dan menghentikan pengujian sesungguhnya.
   Sebaliknya, jika campaign belum berhenti, false-positive CRITICAL lateral movement (MOD-021) akan menyebabkan AI Planner melancarkan modul post-exploitation bising (misal `lsass_dump`, DCSync) ke host yang sama sekali belum berhasil dikompromikan, memicu alarm EDR/SOC klien.

---

## DAFTAR HONESTY GATES YANG HILANG

Berikut adalah 5 arsitektur gerbang integritas (Honesty Gates) yang wajib diimplementasikan di masa depan untuk mencegah keterulangan bug integritas bukti:

### Gate 1: Network Evidence Verification Gate (Physical I/O Proof)
- **Lokasi Rencana**: `ares/core/engine.py:780-805` & `ares/modules/base.py:532-568`
- **Kondisi yang Dicek**: Setiap finding dengan `severity in (CRITICAL, HIGH)` harus memiliki bukti target fisik dalam `evidence` yang merefleksikan respon I/O jaringan nyata (misal: socket byte stream, NTLM challenge-response valid, Kerberos ticket session key dari KDC). Modul lokal tanpa I/O target dilarang keras menerbitkan finding di atas `Severity.LOW` / `Severity.INFO`.
- **Jika Gagal**: Turunkan severity ke `Severity.INFO` / `LOCAL_CALCULATION`, set `finding.validated = False`, `finding.false_positive = True`, dan tolak registrasi ke `confirmed`.
- **Modul yang Dicegah**: **MOD-005** (`ad.ghost_forge`), **MOD-019** (`network.pivot`).

### Gate 2: Lateral Movement Proof-of-Execution Gate (Lateral Honesty Gate)
- **Lokasi Rencana**: `ares/modules/lateral/modules.py:464-506` & `ares/core/validator.py:264-276`
- **Kondisi yang Dicek**: Untuk menerbitkan finding "Lateral Movement", `result.success` tidak cukup hanya dari status port terbuka (`rdp_port_open`, `smb_open`). Wajib ada bukti **otentikasi berhasil** DAN **eksekusi perintah nyata** (misal: stdout dari `whoami`, token user privilege terverifikasi, atau session ID RDP interaktif yang terjalin).
- **Jika Gagal**: Pisahkan hasil: laporkan sebagai `network.service_detect` / `open_port` (Severity.LOW / INFO), bukan `Lateral Movement` (Severity.CRITICAL). `result.success` untuk perpindahan lateral di-set `False`.
- **Modul yang Dicegah**: **MOD-021** (`lateral.rdp`), **MOD-020** (`lateral.ssh_pivot`).

### Gate 3: Engine Validator Enforcement Gate (Active Gatekeeper)
- **Lokasi Rencana**: `ares/core/engine.py:776-805`
- **Kondisi yang Dicek**: Hasil `validation_results` dari `self.validator.validate(f, raw)` wajib diperiksa secara fail-closed:
  ```python
  if not validation_res.should_report:
      f.false_positive = True
      f.validated = False
      # Jangan masukkan ke confirmed
  ```
- **Jika Gagal**: Finding ditolak dari daftar `confirmed`, tidak disimpan ke database temuan aktif, dan tidak diumpankan ke planner.
- **Modul yang Dicegah**: Mencegah seluruh modul dari lolosnya unverified finding ke laporan akhir dan pipeline chain.

### Gate 4: Kerberos Ticket & S4U Identity Verification Gate
- **Lokasi Rencana**: `ares/core/validator.py` & `ares/modules/lateral/ntlm_relay.py:944-965`
- **Kondisi yang Dicek**: Modul yang mengklaim impersonasi identitas istimewa (misal Domain Admin via S4U2self/S4U2proxy) wajib memverifikasi bahwa tiket ccache yang diterima memiliki Client Principal sesuai target klaim (bukan sekadar tiket akun mesin lokal).
- **Jika Gagal**: Batalkan klaim CRITICAL Administrator impersonation, ubah menjadi MEDIUM (Machine Account TGS captured).
- **Modul yang Dicegah**: **MOD-013** (`lateral.ntlm_relay`).

### Gate 5: Goal Indicator Cryptographic Verifier Gate
- **Lokasi Rencana**: `ares/strategy/engine.py:894-913` (`_check_goal_achieved`)
- **Kondisi yang Dicek**: `_check_goal_achieved()` tidak boleh hanya melakukan pencarian substring judul ("DCSync", "Domain Admin"). Goal "Domain Admin" hanya boleh dinyatakan tercapai jika ada kredensial domain admin terverifikasi di Vault DAN finding yang melandasinya telah lulus `Gate 1` dan `Gate 3`.
- **Jika Gagal**: `goal_achieved = False`; autonomous engine tidak tertipu oleh false positive.
- **Modul yang Dicegah**: Mencegah false termination dan false victory pada **MOD-005**, **MOD-013**, **MOD-021**.

---

*(Catatan: Sesuai batasan operasional, implementasi gerbang-gerbang di atas ditunda untuk review owner dan sesi refactoring arsitektur berikutnya).*
