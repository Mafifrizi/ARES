# ARES Autonomous Patching Progress

Tracking file for verified findings, reproduction tests, applied fixes, test suite outcomes, and residual risks.

| ID | Item | Status | Test Result | Changed Files | Notes |
|---|---|---|---|---|---|
| NEW-01 | SSO Local Account Takeover | FIXED | PASSED (15/15 SSO tests) | `ares/db/database.py`, `ares/db/postgres.py`, `ares/api/server.py`, `tests/unit/test_sso_account_takeover.py` | Isolated SSO JIT provisioning by auth_provider & org_id, blocked takeover of local users |
| ID-001 | Persistence Pipeline C-LIVE Non-Debug | GUGUR (FALSE POSITIVE) | Tidak terbukti / non-reproducible | - | `_finalize_committed_module_result` menangani persistensi findings, loot, runs, dan audit secara komprehensif |
| NEW-03 | Scope Contamination on upsert_host | FIXED | PASSED (2/2 unit tests) | `ares/api/server.py`, `ares/core/engine.py`, `tests/unit/test_scope_contamination.py` | Menambahkan validasi `campaign.is_in_scope()` sebelum `db.upsert_host` di auto-upsert dan `_persist_runtime_hosts` |
| NEW-02 | WebSocket Expiry at T+15min | FIXED | PASSED (Unit repro + 46/46 WS tests) | `ares/db/database.py`, `ares/db/postgres.py`, `tests/unit/test_api_endpoints.py`, `tests/unit/test_websocket_ticket_lifecycle.py`, `tests/unit/test_websocket_expiry_repro.py` | Validasi authority sesi aktif (`refresh_token_families`) tanpa memutus paksa WebSocket saat masa 15 menit access token terlewati |
| ID-004 | Campaign Lifecycle valid_uuid | FIXED | PASSED (Unit repro + lifecycle tests) | `ares/db/database.py`, `ares/db/postgres.py`, `tests/unit/test_campaign_lifecycle_slug.py` | Symmetrical SHA-256 target UUID derivation for slug campaigns, unblocking clean deletion across SQLite and Postgres |
| NEW-04 | Plan Children decision_ordinal | GUGUR (FALSE POSITIVE) | Tidak terbukti / non-reproducible | - | Tuple derivasi UUID attempt dijamin unik oleh `stage_ordinal`, `module_ordinal`, dan `occurrence` |
| NEW-05 | GoalEngine SDK Quickstart Reference | RESOLVED | PASSED (Clean docs/import) | `ares/__init__.py` | Updated quickstart docstring to reference active AresEngine instead of legacy GoalEngine |
| ID-013 | Substring Matching SSO Role Mapping | GUGUR (FALSE POSITIVE) | Tidak terbukti / non-reproducible | - | Pengecekan `frozenset` adalah exact equality, bukan substring matching |
| ID-014 | Timing Attack Token/Signature Digest | GUGUR (FALSE POSITIVE) | Tidak terbukti / non-reproducible | - | Seluruh pembandingan token dan digest kriptografis menggunakan `hmac.compare_digest` |
| MOD-005 | Fictitious Implementation & Vault Contamination on ad.ghost_forge | MITIGATED (disabled) - keputusan final pending | PASSED (Unit repro + API & staged tests) | `ares/modules/ad/ghost_forge.py`, `ares/modules/base.py`, `ares/core/plugin/loader.py`, `ares/core/engine.py`, `ares/cli/typer_main.py`, `ares/api/server.py`, `ares/core/execution_chains.py`, `tests/unit/test_staged_modules.py`, `tests/unit/test_api_endpoints.py` | Dinonaktifkan sementara dari pipeline produksi (`ENABLED = False`). Disaring keluar dari katalog `ModuleRegistry` (`list_metadata`, `all`, `by_category`), endpoint API `/modules`, CLI `ares module list`, dan production execution chains. Invokasi langsung via class, engine (`run_module`), atau HTTP API gagal deterministik dengan pesan error eksplisit "module disabled: implementation incomplete, see MOD-005" tanpa koneksi jaringan, tanpa finding, dan tanpa kontaminasi vault. |
| MOD-004 | ad.coerce listener_ip unvalidated against scope | DIKONFIRMASI VALID (TERBUKTI) | Audit verified (Zero scope guard on listener_ip) | Menunggu remedi | Engine `_extract_all_targets` hanya mengekstrak `_TARGET_KEYS` yang tidak memuat `listener_ip` atau `listener`. Potensi pemaksaan otentikasi ke listener luar scope. |
| MOD-006 | Key mismatch ArtifactNormalizer vs hashes | FIXED (Dual-Read Fallback) | PASSED (17/17 pipeline tests) | `ares/normalize/artifacts.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Implementasi Dual-Read Fallback di `ArtifactNormalizer` (`_normalize_*`) dan 5 handler P0 (`cleartext_credentials`, `cracked_credentials`, `laps_passwords`, `kerberos_tickets`, `open_ports`). Memulihkan 70% data loss tanpa breaking change pada modul. |
| MOD-009 | ad.adcs scope bypass on CA HTTP enrollment | TERBUKTI (HIGH) | Audit verified (`adcs.py:1111`) | Menunggu remedi | `_submit_csr_to_ca` menghubungi `ca_host` via HTTP tanpa `before_request(ca_host)`. |
| MOD-010 | ad.sccm scope bypass on DCOM & PXE port probe | TERBUKTI (HIGH) | Audit verified (`sccm.py:477, 561`) | Menunggu remedi | Query WMI ke site server dan probe port 4011/67 ke distribution points dilakukan tanpa `before_request`. |
| MOD-011 | lateral.ntlm_relay mass out-of-scope port probe | TERBUKTI (CRITICAL) | Audit verified (`ntlm_relay.py:486`) | Menunggu remedi | Loop `_check_relay_targets` membuka socket port 445 ke 50 host AD tanpa memeriksa apakah host berada dalam scope. |
| MOD-012 | lateral.ntlm_relay persistent machine account & DACL without teardown | TERBUKTI (CRITICAL) | Audit verified (`ntlm_relay.py:782-848`) | Menunggu remedi | Akun mesin `ARESXXXXXX$` dan DACL RBCD dibuat di AD tanpa handler cleanup/finally, meninggalkan backdoor permanen di domain target (melanggar Rule 4). |
| MOD-013 | lateral.ntlm_relay fictitious S4U impersonation claim | TERBUKTI (HIGH) | Audit verified (`ntlm_relay.py:944-965`) | Menunggu remedi | Mengklaim S4U impersonasi Administrator, padahal hanya meminta TGS biasa untuk akun mesin dan menyimpan tiket mesin sebagai `administrator@target.ccache` (melanggar Rule 1). |
| MOD-014 | lateral.mssql scope bypass on UNC coercion listener & linked server | TERBUKTI (HIGH) | Audit verified (`mssql.py:321, 485`) | Menunggu remedi | `listener_ip` pada `xp_dirtree` dan `linked_server` pada dynamic SQL execution tidak divalidasi terhadap scope campaign. |
| MOD-015 | lateral.smb_relay omission scope check on primary loop | TERBUKTI (MEDIUM) | Audit verified (`smb_relay.py:343`) | Menunggu remedi | Loop SMB audit mengirim negotiate packet tanpa memanggil `await self.before_request(target, "smb")`. |
| MOD-016 | ad.sccm cleartext credential evaporation & DPAPI misleading | TERBUKTI (HIGH) | Audit verified (`sccm.py:300, 521`) | Menunggu remedi | NAA DPAPI encrypted blob dilaporkan sebagai `cleartext_credentials`, tidak ada normalizer handler, dan tidak disimpan ke vault. |
| MOD-017 | network.pivot scope bypass on remote_host & subnets | TERBUKTI (HIGH) | Audit verified (`infrastructure.py:283-376`) | Menunggu remedi | `establish_local_forward` tidak memvalidasi `remote_host` atau `reachable_subnets` terhadap `campaign.is_in_scope()`. |
| MOD-018 | network.pivot teardown omission on background SSH processes | TERBUKTI (HIGH) | Audit verified (`pivot.py:343-359`) | Menunggu remedi | `PivotModule.teardown()` tidak pernah dipanggil di engine lifecycle, meninggalkan proses tunnel background yatim (melanggar Rule 4). |
| MOD-019 | network.pivot fictitious implementation & phantom active status | TERBUKTI (HIGH) | Audit verified (`infrastructure.py:260-265, 368-370`) | Menunggu remedi | Jika backend asyncssh/ssh tidak ada, tunnel ditandai ACTIVE dan finding palsu diterbitkan (melanggar Rule 1). |
| MOD-020 | lateral.ssh_pivot fictitious SOCKS5 proxy implementation | TERBUKTI (HIGH) | Audit verified (`modules.py:1332-1356`) | Menunggu remedi | `establish_socks5` mengembalikan dict proxy padahal `move()` mengabaikan port dan menutup koneksi (melanggar Rule 1). |
| MOD-021 | lateral.rdp false-positive execution claim on open port | TERBUKTI (CRITICAL) | Audit verified (`modules.py:1448-1517`) | Menunggu remedi | Port 3389 terbuka memicu status success dan finding CRITICAL lateral movement berhasil tanpa otentikasi (melanggar Rule 1). |
| MOD-022 | exfil.staged_collection workstation egress disruption & false target attribution | TERBUKTI (HIGH) | Audit verified (`staged_collection.py:44-89, 356-378`) | Menunggu remedi | Mengirim HTTP HEAD dari workstation operator ke cloud publik tanpa scope guard dan mengatribusikannya ke target host. |
| MOD-023 | exfil.staged_collection phantom staging pipeline & 100% data loss | TERBUKTI (MEDIUM) | Audit verified (`staged_collection.py:388-389`) | Menunggu remedi | Parameter `destination` wajib tapi tidak pernah dipakai; `files_staged` tidak pernah diisi sehingga output file kosong. |
| MOD-024 | network.port_scan CIDR parsing incompatibility & socket failure | TERBUKTI (MEDIUM) | Audit verified (`port_scan.py:324, 271`) | Menunggu remedi | Mengklaim mendukung CIDR namun passing CIDR langsung ke `asyncio.open_connection` memicu `getaddrinfo` error. |
| MOD-025 | windows.lsass_dump teardown omission on transfer exception & orphaned files | TERBUKTI (HIGH) | Audit verified (`lsass_dump.py:655-688, 700-720`) | Menunggu remedi | Kegagalan transfer SMB meninggalkan file lokal tanpa secure cleanup; login failure pada tasklist meninggalkan `ARESPID*.txt` di target (melanggar Rule 4). |
| MOD-026 | windows.lsass_dump phantom capability claim & incomplete ticket extraction | TERBUKTI (MEDIUM) | Audit verified (`lsass_dump.py:77, 463, 782-805`) | Menunggu remedi | Mengklaim capability `kerberos_tickets` namun parser pypykatz hanya membaca NTLM dan hardcode tickets kosong `[]` (melanggar Rule 1). |
| MOD-027 | windows.lsa_secrets plaintext unredacted NTLM & DCC2 hashes in evidence | TERBUKTI (MEDIUM) | Audit verified (`lsa_secrets.py:383, 431`) | Menunggu remedi | Raw password hashes disimpan unredacted di `Finding.evidence["hashes"]` memicu kebocoran hash di log audit (pola MOD-007). |
| MOD-028 | windows.lsa_secrets LSA secrets & cached creds pipeline evaporation (100% data loss) | FIXED | PASSED (20/20 pipeline tests) | `ares/normalize/artifacts.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Menambahkan handler `_normalize_lsa_secrets` (CredentialArtifact `lsa_secret`) dan `_normalize_cached_domain_credentials` (CredentialArtifact `cached_domain`, `cracked=False`) di `ArtifactNormalizer`. Routing untuk capability `lsa_secrets`, `windows.lsa_secrets`, `cached_credentials`, `cached_domain_credentials`. Data loss teratasi. |
| MOD-029 | windows.dpapi fictitious cleartext decryption & false CRITICAL finding | MITIGATED (disabled) - implementasi real pending | PASSED (Unit repro + staged & feasibility tests) | `ares/modules/windows/dpapi.py`, `tests/unit/test_disabled_modules_batch4.py`, `tests/unit/test_roadmap_modules.py`, `tests/unit/test_staged_modules.py`, `tests/unit/test_defense_feasibility_matrix.py` | Dinonaktifkan dari pipeline produksi (`ENABLED = False`, `DISABLED_REASON`). Guard eksplisit pada `run()`, `execute()`, `validate()`, dan `assess_feasibility()` mencegah kontaminasi vault dan false CRITICAL findings. |
| MOD-030 | windows.token_impersonation fictitious privilege escalation confirmation & heuristic over-claiming | MITIGATED (disabled) - implementasi real pending | PASSED (Unit repro + staged & feasibility tests) | `ares/modules/windows/token_impersonation.py`, `tests/unit/test_disabled_modules_batch4.py`, `tests/unit/test_windows_resilience.py`, `tests/unit/test_staged_modules.py`, `tests/unit/test_defense_feasibility_matrix.py`, `tests/unit/modules/test_safety_remediation.py` | Dinonaktifkan dari pipeline produksi (`ENABLED = False`, `DISABLED_REASON`). Guard eksplisit pada `run()`, `execute()`, `validate()`, dan `assess_feasibility()` mencegah kontaminasi vault dan false CRITICAL findings. |
| MOD-031 | credential.ssh_spray scope guard, rate limiting, and jitter omission | FIXED | PASSED (Unit repro + scope enforcement tests) | `ares/modules/credential/ssh_spray.py`, `tests/unit/modules/test_ssh_spray.py` | Menambahkan `await self.before_request(target, "ssh")` di awal loop koneksi `run()` untuk penegakan scope Layer 1, rate limiting, dan OPSEC jitter. |
| MOD-032 | credential.reuse out-of-scope Microsoft cloud probing & false attribution on RFC1918 targets | TERBUKTI (HIGH) | Audit verified (`reuse.py:35-90, 256-269`) | Menunggu remedi | Mengirim HTTP POST ke `login.microsoftonline.com` sebelum `before_request`. Error 400 dari Microsoft ditafsirkan sebagai "Device Code Flow Permitted" menghasilkan false finding MEDIUM pada target lokal (melanggar Rule 1 dan Rule 4, pola MOD-022). |
| MOD-033 | valid_credentials pipeline evaporation & type incoherence across credential modules | FIXED | PASSED (20/20 pipeline tests) | `ares/modules/credential/pass_spray.py`, `ares/modules/credential/ssh_spray.py`, `ares/modules/credential/pass_the_hash.py`, `ares/modules/credential/reuse.py`, `ares/normalize/artifacts.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Standardisasi output `valid_credentials` ke `list[dict]` dengan field standar (`username`, `password`, `target`, `port`, `method`, `protocol`, `privilege`, `domain`). Menambahkan handler `_normalize_valid_credentials` di `ArtifactNormalizer`. Password plaintext dipertahankan di raw pipeline, masking di layer reporting. |
| MOD-034 | credential.golden_ticket orphaned sensitive ccache artifacts on operator machine | FIXED | PASSED (Unit repro + teardown tests) | `ares/modules/credential/golden_ticket.py`, `tests/unit/modules/test_golden_ticket.py` | Menambahkan blok `finally` dengan `os.unlink(ccache_path)` untuk cleanup ccache. Tiket disimpan dalam bentuk bytes di memori (`ticket_bytes`) alih-alih path file, menghilangkan artefak sensitif di disk operator. |
| MOD-035 | credential.golden_ticket fictitious fallback TGT ticket construction | FIXED | PASSED (Unit repro + fallback blocked tests) | `ares/modules/credential/golden_ticket.py`, `tests/unit/modules/test_golden_ticket.py` | Fallback `CCache.fromKRBCRED` dihapus. Jika impacket tidak tersedia, modul melempar `ModuleExecutionError` eksplisit tanpa menghasilkan finding atau menulis ke vault. Impacket menjadi hard dependency. |
| MOD-036 | credential.ticket_converter output key mismatch & pipeline evaporation | TERBUKTI (MEDIUM) | Audit verified (`ticket_converter.py:66, 274`) | Menunggu remedi | Deklarasi output `converted_ticket` sedangkan output `run()` menghasilkan `converted_ticket_b64`. Tidak ada handler di `ArtifactNormalizer`, data tiket konversi hilang dari pipeline. |
| MOD-037 | SSH connection leak — asyncssh conn never closed across 4 Linux modules | FIXED | PASSED (12/12 asyncssh teardown tests + safety suite) | `ares/modules/linux/privesc.py`, `ares/modules/linux/service_hijack.py`, `ares/modules/linux/ld_preload.py`, `ares/modules/linux/nfs_escape.py`, `tests/unit/modules/test_mod037_ssh_teardown.py` | Koneksi asyncssh dibungkus try/finally dan ditutup via `conn.close()` / `wait_closed()` di seluruh 4 modul Linux (`linux.privesc`, `linux.service_hijack`, `linux.ld_preload`, `linux.nfs_escape`). |
| MOD-038 | linux.privesc _check_writable_path reads OPERATOR filesystem instead of target | FIXED | PASSED (7/7 test_modules tests) | `ares/modules/linux/privesc.py`, `tests/unit/modules/test_modules.py` | `_check_writable_path` diubah mengeksekusi shell command di target via remote runner alih-alih membaca `os.environ`/`os.access` operator. Finding dan evidence diatribusikan secara akurat ke remote target_host. |
| MOD-039 | linux.container weak heuristic for host network namespace detection | TERBUKTI (MEDIUM) | Audit verified (`container.py:332`) | Menunggu remedi | Heuristik `len(lines) > 50` pada `/proc/net/tcp` untuk mendeteksi `--net=host` sangat lemah. Container dengan koneksi banyak (scanning, proxying) memicu false-positive HIGH finding (melanggar Rule 1, pola MOD-021). |
| MOD-040 | linux.container unhandled outputs container_escape_vectors & k8s_rbac_findings | TERBUKTI (MEDIUM) | Audit verified (`container.py:56, 187-188`) | Menunggu remedi (Batch Fix Serentak Normalizer) | Capability `container_escape_vectors` dan `k8s_rbac_findings` tidak memiliki handler di `ArtifactNormalizer`. Data hilang dari `ArtifactStore`. Handler normalizer pending, masuk batch fix serentak normalizer. |
| MOD-041 | linux.samba_secrets unhandled outputs machine_account_hash & samba_secrets | TERBUKTI (HIGH) | Audit verified (`samba_secrets.py:66, 256-264`) | Menunggu remedi (Batch Fix Serentak Normalizer) | Capability `machine_account_hash` dan `samba_secrets` tidak memiliki handler di `ArtifactNormalizer`. Extracted NTLM hashes tidak terserap ke `ArtifactStore`. Handler normalizer pending, masuk batch fix serentak normalizer. |
| MOD-042 | linux.samba_secrets plaintext NTLM hash in Finding.evidence & EvidenceRecord | TERBUKTI (HIGH) | Audit verified (`samba_secrets.py:197, 216`) | Menunggu remedi (Batch Fix Serentak Hash Masking) | NTLM hash unredacted disimpan di `Finding.evidence["ntlm_hash"]` dan `EvidenceRecord.data["ntlm_hash"]`. Masuk batch fix serentak hash masking — pola identik MOD-007 dan MOD-027. |
| MOD-043 | linux.ccache_hunt phantom ticket extraction & empty vault secret injection on Keyring/KCM | TERBUKTI (HIGH) | Audit verified (`ccache_hunt.py:320-366, 167-189`) | Menunggu remedi | Pemindaian `/proc/keys` dan socket KCM tidak mengambil byte tiket nyata, namun modul menerbitkan finding CRITICAL/HIGH dan menyimpan string kosong `""` ke `AresVault` sebagai tiket Kerberos (melanggar Rule 1 dan Rule 4). |
| MOD-044 | linux.keytab_abuse unhandled outputs machine_credentials & kerberos_keys (100% data loss) | TERBUKTI (HIGH) | Audit verified (`keytab_abuse.py:65, 271-280`) | Menunggu remedi | Kunci simetris Kerberos (AES-256, RC4) tidak memiliki handler di `ArtifactNormalizer` dan tidak dicatat ke `ArtifactStore`. Modul juga menuliskan `raw["entries"]` alih-alih nama output yang dideklarasikan. |
| MOD-045 | linux.sssd_harvest SHA-512 crypt hashes inverted to CLEARTEXT & 100% normalizer data loss | FIXED | PASSED (19/19 tradecraft tests) | `ares/modules/linux/sssd_harvest.py`, `ares/credential/vault.py`, `ares/modules/credential/crack.py`, `tests/unit/modules/test_linux_ad_tradecraft.py` | Menambahkan HASH dan KERBEROS ke CredentialType enum. Mengimplementasikan _infer_credential_type di sssd_harvest untuk mengklasifikasikan hash Linux ($6$, $y$, $5$, $2b$, $1$) ke CredentialType.HASH dan dual-write standard output keys (users, domain_users, hashes, cached_hashes, credentials, accounts). |
| MOD-046 | persistence.scheduled_task zero teardown on remote scheduled task & registry run key | TERBUKTI (CRITICAL) | Audit verified (`scheduled_task.py:69-100, 405-435`) | Menunggu remedi (CRITICAL DEFERRED) | Modul mendaftarkan Scheduled Task dan menulis Registry Run Key tanpa method `teardown()` atau cleanup otomatis. Backdoor autorun tertinggal permanen pada host target klien (melanggar Rule 4). |
| MOD-047 | persistence.scheduled_task inverted dry_run=True default & unhandled RPC disconnect | TERBUKTI (HIGH) | Audit verified (`scheduled_task.py:549, 415-435`) | Menunggu remedi (Batch Fix Serentak) | `RegistryRunKeyPersistence.run()` secara default `dry_run=True`, memicu false success finding tanpa eksekusi. `_rrp_set_run_key` tidak memiliki `try/finally` untuk menutup koneksi DCE/RPC saat query gagal. |
| MOD-048 | persistence.wmi_subscription broken binding cleanup & truthy persistence_established on failure | TERBUKTI (HIGH) | Audit verified (`wmi_subscription.py:353, 384-394`) | Menunggu remedi (Batch Fix Serentak) | Fungsi `cleanup()` mengabaikan penghapusan binding WMI (`name_key=None`). `raw["persistence_established"]` diisi nama subskripsi (string truthy) bahkan saat instalasi gagal, memicu false positive. |
| MOD-049 | cloud.phantom_token fictitious PRT hijack implementation, zero network I/O & synthetic vault contamination | MITIGATED (disabled) | PASSED (Unit tests & registry validation) | `ares/modules/cloud/phantom_token.py`, `tests/unit/test_staged_modules.py` | Modul dinonaktifkan (`ENABLED = False`) dengan fail-fast guards di `assess_feasibility()`, `validate()`, `execute()`, dan `run()`, serta excluded dari active engine registry untuk mencegah suntikan kredensial/token PRT fiktif ke `AresVault` (implementasi real pending). |
| MOD-050 | cloud.identity_federation_abuse scope bypass on on-premises ADFS probing via raw HTTP | FIXED | PASSED (Unit tests & before_request integration) | `ares/modules/cloud/identity_federation.py`, `tests/unit/test_strategic_modules.py` | Ekstraksi hostname target dari `adfs_url` via `urlparse` dan pemanggilan `await self.before_request(target_host, "http")` sebelum probing HTTP ADFS untuk mematuhi batasan scope campaign (pola MOD-004). |
| MOD-051 | cloud.identity_federation_abuse unhandled outputs federation_trusts, golden_saml_paths, oauth_tokens, pivot_paths (100% data loss) | DEFERRED | Audit verified (`identity_federation.py:77, 356-358`) | Menunggu remedi (Batch Fix Serentak Normalizer) | Keempat capability output yang dideklarasikan tidak memiliki handler di `ArtifactNormalizer`. Data pemetaan trust federasi dan Golden SAML hilang permanen dari `ArtifactStore`. |
| MOD-052 | cloud.aws_privesc type confusion mismatch: aws_findings with list[Finding] overwrites S3 normalizer | FIXED | PASSED (Unit tests & pipeline separation) | `ares/modules/cloud/aws_privesc.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Key output diubah dari `raw["aws_findings"]` menjadi `raw["iam_privesc_paths"]` dan deklarasi diperbarui ke `OUTPUTS = ["aws_privesc_paths", "iam_privesc_paths"]`. Output tidak lagi menimpa dictionary S3 `cloud.aws` dan mencegah kontaminasi type confusion. |
| MOD-053 | cloud.aws_privesc & cloud.identity_federation_abuse unvalidated AWS account/tenant scope & generic host attribution | DEFERRED | Audit verified (`aws_privesc.py:331`, `identity_federation.py:1046, 1074`) | Menunggu keputusan arsitektur (Architectural Gap) | ScopeGuard saat ini hanya memvalidasi IP/CIDR/DNS, tidak mengenali cloud identifiers (tenant_id, aws_account_id, subscription_id). Butuh perancangan CloudScopeGuard / ScopeGuard extension. |
| MOD-054 | ad.enum_spn internal key mismatch (spn_list vs spns) causing 100% SPN list evaporation | FIXED | PASSED (Unit tests & normalizer pipeline) | `ares/modules/ad/enum_spn.py`, `ares/normalize/artifacts.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Internal key disinkronkan ke `spns` & alias `spn_list`. Normalizer dual-read fallback. |
| MOD-055 | ad.laps_enum output type confusion on valid_credentials & secret evaporation in normalizer | FIXED | PASSED (Unit tests & pipeline separation) | `ares/core/context.py`, `ares/modules/ad/laps_enum.py`, `ares/normalize/artifacts.py`, `tests/unit/test_artifact_normalizer_pipeline.py` | Password LAPS ditulis langsung ke vault (Gate 6 validated). `raw["entries"]` dan `raw["laps_passwords"]` OPSEC-safe (`has_password: True`). |
| MOD-056 | ad.enum_users unhandled output telemetry password_policy & dual-write omission | PARTIALLY FIXED | PASSED (Unit tests) | `ares/modules/ad/enum_users.py`, `NORMALIZER_CONTRACT_AUDIT.md`, `tests/unit/test_artifact_normalizer_pipeline.py` | Dual-write `users` key ke `raw`. Handler `password_policy` ditunda ke batch fix serentak. |
| MOD-057 | ad.enum_acl & ad.laps_enum inconsistent LDAP bind authentication formatting (bypassing build_ad_bind_plan) | DEFERRED | Audit verified (`enum_acl.py:234`, `laps_enum.py:297`) | Menunggu remedi (Batch Fix Serentak) | Migrasi raw string binding ke `build_ad_bind_plan()` ditunda ke batch fix serentak. |
| MOD-058 | network.dns_enum out-of-scope AXFR zone transfer probing on discovered nameservers | DEFERRED | Audit verified (`dns_enum.py:269-272`) | Menunggu remedi (Batch Fix Serentak - Grup D) | `_try_axfr` menghubungi nameserver eksternal hasil enumerasi NS tanpa validasi `before_request(ns_clean)`. |
| MOD-059 | network.http_fingerprint unbounded HTTP redirect traversal on external hosts via follow_redirects=True | DEFERRED | Audit verified (`http_fingerprint.py:252-255`) | Menunggu remedi (Batch Fix Serentak - Grup D) | `httpx.AsyncClient` otomatis mengikuti redirect 301/302 ke host eksternal di luar scope campaign. |
| MOD-060 | network.service_detect asyncio TCP writer handle leak on read timeout in _grab_banner | DEFERRED | Audit verified (`service_detect.py:108-129`) | Menunggu remedi (Batch Fix Serentak - Grup C) | `reader.read()` tidak dibungkus `try ... finally: writer.close()`, memicu socket leak saat timeout. |
| MOD-061 | network.snmp_enum discovered SNMP community strings evaporation from vault & standard pipeline | FIXED | PASSED (Unit tests & vault integration) | `ares/modules/network/snmp_enum.py` | Direct vault writing added for valid community strings (CredentialType.CLEARTEXT, Gate 6 compliant), valid_credentials standardized to list[dict], raw snmp_findings serialized to dicts (commit `5635362`). |
| MOD-062 | network.* & recon.fingerprint 100% unhandled reconnaissance capabilities in ArtifactNormalizer | DEFERRED | Audit verified (`fingerprint.py:72`, `dns_enum.py:82`, `http_fingerprint.py:99`, `service_detect.py:159`, `snmp_enum.py:165`) | Menunggu remedi (Batch Fix Serentak - Grup A) | 9 capability recon tidak memiliki handler di `ArtifactNormalizer`. Data host, subdomain, service, dan web target gagal memperbarui `HostArtifact`. |
| MOD-063 | cloud.* unscoped cloud account/tenant execution via ambient credentials | DEFERRED | Audit verified (`aws.py:190`, `azure.py:211`, `azure_ad.py:231`, `gcp.py:134`) | Menunggu remedi (Batch Fix Serentak - Grup D) | Target cloud account/subscription/project ID tidak divalidasi terhadap scope campaign. Ambient credentials dapat mengeksekusi di luar otorisasi. |
| MOD-064 | cloud.aws & cloud.gcp operator workstation link-local metadata SSRF probe | FIXED | PASSED (Unit tests) | `ares/modules/cloud/aws.py`, `ares/modules/cloud/gcp.py` | Probing metadata link-local dari workstation operator (169.254.169.254 & metadata.google.internal) dihapus dari modul discovery remote (commit `d86750b`). |
| MOD-065 | cloud.* missing pre-flight SDK dependency validation in validate() | DEFERRED | Audit verified (`aws.py:91`, `azure.py:100`, `azure_ad.py:90`, `gcp.py:91`) | Menunggu remedi (Batch Fix Serentak - Grup E) | validate() tidak memverifikasi import SDK cloud (boto3, azure-identity, azure-mgmt, msal, google-auth), gagal di runtime saat dependensi belum terpasang. |
| MOD-066 | cloud.azure & cloud.azure_ad 100% normalizer data loss on azure_findings, azure_ad_findings, access_tokens | DEFERRED | Audit verified (`azure.py:238`, `azure_ad.py:282-283`) | Menunggu remedi (Batch Fix Serentak - Grup A) | Tidak ada handler normalizer untuk azure_findings, azure_ad_findings, atau access_tokens. Seluruh hasil enumerasi Azure dan Entra ID hilang dari ArtifactStore. |
| MOD-067 | cloud.azure_ad indentation defect causing UnboundLocalError & 100% unreachable Graph API dead code | FIXED | PASSED (Unit tests) | `ares/modules/cloud/azure_ad.py` | Indentasi blok return device_code diperbaiki, inisialisasi raw di awal run(), Graph API enumeration restored (commit `bd2c9b4`). |
| MOD-068 | cloud.gcp 100% normalizer data loss on gcp_findings in ArtifactNormalizer | DEFERRED | Audit verified (`gcp.py:87`, `134`) | Menunggu remedi (Batch Fix Serentak - Grup A) | Output gcp_findings tidak memiliki handler di ArtifactNormalizer. Seluruh temuan GCS buckets publik, IAM project bindings, dan SA keys menguap dari ArtifactStore. |
| MOD-069 | windows.registry_enum & windows.scheduled_tasks_enum pre-flight validation asymmetry | DEFERRED | Audit verified (`registry_enum.py:220`, `scheduled_tasks_enum.py:180`) | Menunggu remedi (Batch Fix Serentak - Grup E) | `validate()` meloloskan eksekusi tanpa `username`, namun `run()` melakukan abort diam-diam saat kredensial kosong alih-alih melempar ModuleValidationError. |
| MOD-070 | windows.* & linux.kernel_suggester domain object bleed & 100% normalizer data loss | DEFERRED | Audit verified (`registry_enum.py:735`, `scheduled_tasks_enum.py:521`, `kernel_suggester.py:306`) | Menunggu remedi (Batch Fix Serentak - Grup A) | Domain object `Finding` di-assign langsung ke raw output keys (`cleartext_credentials`, `credential_hints`, `scheduled_tasks`, `privesc_vectors`) tanpa handler normalizer di `ArtifactNormalizer`. |
| MOD-071 | linux.kernel_suggester userspace CVE false positives on kernel versions | DEFERRED | Audit verified (`kernel_suggester.py:34-35`) | Menunggu remedi (Batch Fix Serentak - Grup E) | Regex `r"[345]\.[0-9]+"` mencocokkan CVE userspace (PwnKit CVE-2021-4034, Baron Samedit CVE-2021-3156) ke versi kernel, memicu false positive CRITICAL pada hampir semua Linux host. |
| MOD-072 | linux._parsers pseudo-parser in KirbiASN1Codec.decode_kirbi corrupting tickets | DEFERRED | Audit verified (`_parsers.py:660-695`) | Menunggu remedi (Batch Fix Serentak - Grup E) | `decode_kirbi()` tidak mem-parsing ASN.1 DER dan hardcode kunci sesi ke 32 byte nol (`0000...`), merusak seluruh tiket hasil konversi ticket_converter. |
| MOD-073 | exfil.secrets_scan & exfil.smb_shares scope protocol defaulting & pre-flight credential omission | DEFERRED | Audit verified (`secrets_scan.py:406, 608`, `smb_shares.py:106, 256`) | Menunggu remedi (Batch Fix Serentak - Grup E) | `before_request(target, "default")` membypass profile rate limit protokol ("ssh"/"smb"), dan `validate()` tidak memvalidasi kredensial username untuk eksekusi non-dry-run. |
| MOD-074 | exfil.secrets_scan & exfil.smb_shares 100% normalizer data loss on exfiltration outputs | DEFERRED | Audit verified (`secrets_scan.py:647-652`, `smb_shares.py:326-331`) | Menunggu remedi (Batch Fix Serentak - Grup A) | Tidak ada handler normalizer untuk `credential_list`, `discovered_secrets`, `sensitive_data_found`, `file_share_list`, atau `sensitive_file_paths`. |

---

## CRITICAL DEFERRED — BUTUH FIX SEBELUM PRODUCTION USE

### [MOD-012] Persistent Backdoor Machine Account & DACL Injection on `lateral.ntlm_relay`
- **Severity**: **CRITICAL**
- **Status Keputusan**: **DEFERRED (Tercatat, remedi dilakukan serentak pasca-audit seluruh batch)**
- **Operasional Policy Flag**: 
  > ⚠️ **PERINGATAN OPERATOR**: **JANGAN gunakan `lateral.ntlm_relay` di engagement produksi sampai MOD-012 diperbaiki.**
- **Ringkasan Teknis**:
  Pada method `_rbcd_attack()` (`ares/modules/lateral/ntlm_relay.py:782-848`), modul membuat akun mesin baru di domain target (`ARESXXXXXX$`) via LDAP dan menimpa atribut `msDS-AllowedToActOnBehalfOfOtherIdentity` pada objek komputer target untuk memberikan hak delegasi Resource-Based Constrained Delegation (RBCD). Seluruh proses penulisan objek Active Directory ini dilakukan **tanpa blok `finally` atau handler cleanup/teardown**.
- **Skenario Bahaya Konkret (Engagement Risk)**:
  Bila modul ini dieksekusi dalam engagement nyata terhadap Active Directory klien:
  1. Jika eksekusi gagal pada fase S4U, terjadi timeout jaringan, koneksi KDC terputus, atau operator meng-cancel campaign di tengah jalan, akun mesin `ARESXXXXXX$` dan atribut DACL delegasi RBCD akan **tertinggal permanen di database Active Directory klien**.
  2. Akun mesin liar ini menjadi persistent backdoor yang tidak terkelola, memicu alert compliance audit domain klien, dan secara langsung melanggar SLA engagement serta **Rule 4 ARES (Zero Collateral & Guaranteed Teardown)**.
  3. Pembersihan hanya dapat dilakukan melalui intervensi manual oleh Domain Admin klien.
- **Estimasi Scope Perbaikan**:
  1. Baca dan simpan nilai asli `msDS-AllowedToActOnBehalfOfOtherIdentity` sebelum melakukan modifikasi LDAP.
  2. Bungkus rantai eksekusi RBCD dalam blok `try ... finally`.
  3. Di dalam blok `finally`:
     - Pulihkan atribut `msDS-AllowedToActOnBehalfOfOtherIdentity` ke nilai semula (atau kosongkan jika sebelumnya tidak ada).
     - Hapus akun mesin yang dibuat (`conn.delete(machine_dn)`).
     - Tangani logging error cleanup secara defensif agar tidak menutupi exception asli.

### [MOD-046] Zero Teardown on Remote Scheduled Task & Registry Run Key Persistence on `persistence.scheduled_task`
- **Severity**: **CRITICAL**
- **Status Keputusan**: **DEFERRED — fix setelah semua batch selesai**
- **Operasional Policy Flag**:
  > ⚠️ **PERINGATAN OPERATOR**: **JANGAN gunakan `persistence.scheduled_task` dan `persistence.wmi_subscription` di engagement produksi sampai teardown diperbaiki.**  
  > Eksekusi modul ini akan meninggalkan Scheduled Task Windows, Registry Run Key, dan WMI subscription secara permanen di host target tanpa kemampuan cleanup via ARES.
- **Ringkasan Teknis**:
  Modul mendaftarkan task scheduler via RPC (`_tsch_register_sync`) dan menulis autorun registry (`_rrp_set_run_key`) tanpa menyediakan method `teardown()` atau fail-safe cleanup context manager. Backdoor eksekusi otomatis tertinggal secara permanen di sistem target klien.
- **Scope Fix yang Diperlukan**:
  1. `persistence.scheduled_task`: implementasi `teardown()` yang menghapus scheduled task (`hSchRpcDeleteTask`) dan registry run key (`hBaseRegDeleteValue`) via WMI/RPC yang sama.
  2. `persistence.wmi_subscription`: fix `cleanup()` tuple bug (MOD-048) dan verifikasi `__FilterToConsumerBinding` benar-benar dihapus.
  3. Kedua modul perlu menyimpan identifier artifact yang dibuat (task name, key path, subscription name) ke raw output dan vault supaya `teardown()` bisa menemukan dan menghapusnya.

---

## MILESTONE: KEY CONVENTION STANDARDIZATION COMPLETED

- **Dokumen Referensi**: [`KEY_CONVENTION_STANDARD.md`](file:///c:/Users/ASUS/Desktop/ARES/KEY_CONVENTION_STANDARD.md)
- **Status**: **STANDARD ESTABLISHED & READY FOR SIMULTANEOUS FIX EXECUTION**
- **Ringkasan Keputusan Arsitektural**:
  1. Standar kanonikal tunggal ditetapkan untuk seluruh 9 capability normalizer dan 15 modul terdampak (misal `hashes`, `users`, `computers`, `spns`, `target`, `misconfigs`).
  2. Kebijakan **Dual-Write Policy** ditetapkan pada modul dan **Dual-Read Fallback** pada normalizer untuk menjamin **Zero Breaking Change** terhadap API eksternal dan UI dashboard.
  3. Kategori unhandled outputs telah dipetakan dengan prioritas [P0] HARUS ADA (5 capability kritis: `cleartext_credentials`, `cracked_credentials`, `laps_passwords`, `kerberos_ticket`, `open_ports`), [P1] SEBAIKNYA ADA, dan [P2] BISA DITUNDA.
  4. Strategi eksekusi **Opsi A (Normalizer Dual-Read First)** dipilih sebagai alur implementasi resmi yang aman tanpa risiko regresi.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 6)

### [MOD-040] Unhandled Outputs `container_escape_vectors` & `k8s_rbac_findings` on `linux.container`
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED (Masuk batch fix serentak normalizer)**
- **Catatan**: Output capability tidak memiliki handler di `ArtifactNormalizer`. Terdaftar di `NORMALIZER_CONTRACT_AUDIT.md`. Akan difix serentak bersama capability normalizer pending lainnya.

### [MOD-041] Unhandled Outputs `machine_account_hash` & `samba_secrets` on `linux.samba_secrets`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak normalizer)**
- **Catatan**: Machine account hash dan secrets TDB tidak terserap ke `ArtifactStore`. Terdaftar di `NORMALIZER_CONTRACT_AUDIT.md`. Akan difix serentak bersama normalizer hash ingestion.

### [MOD-042] Plaintext NTLM Hash in Finding.evidence & EvidenceRecord on `linux.samba_secrets`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak hash masking)**
- **Catatan**: Pola identik dengan MOD-007 (`ad.kerberoast`) dan MOD-027 (`windows.lsa_secrets`). Hash NTLM diekspos unredacted di `evidence`. Akan difix serentak dengan pola masking kanonikal di seluruh layer reporting/evidence.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 7)

### [MOD-043] Phantom Ticket Extraction & Empty Vault Secret Injection on `linux.ccache_hunt`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak)**
- **Catatan**: Scanning `/proc/keys` dan socket KCM menghasilkan finding dan menyimpan empty string `""` ke `AresVault`. Akan difix serentak pasca-audit.

### [MOD-044] Unhandled Outputs `machine_credentials` & `kerberos_keys` on `linux.keytab_abuse`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak normalizer)**
- **Catatan**: Terdaftar di `NORMALIZER_CONTRACT_AUDIT.md`. Modul menghasilkan `raw["entries"]` dan `raw["silver_tickets"]`. Handler normalizer pending.

### [MOD-047] Inverted `dry_run=True` Default & Unhandled RPC Disconnect on `persistence.scheduled_task`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak)**
- **Catatan**: Default `dry_run=True` pada `RegistryRunKeyPersistence` dan unhandled `dce.disconnect()` pada `_rrp_set_run_key`. Akan difix serentak bersama teardown MOD-046.

### [MOD-048] Broken `__FilterToConsumerBinding` Cleanup & Truthy `persistence_established` on `persistence.wmi_subscription`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak)**
- **Catatan**: Tuple cleanup `("__FilterToConsumerBinding", None)` menyebabkan binding tidak terhapus, dan `raw["persistence_established"]` truthy pada status kegagalan. Akan difix serentak bersama MOD-046.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 8)

### [MOD-051] Unhandled Outputs `federation_trusts`, `golden_saml_paths`, `oauth_tokens`, `pivot_paths` on `cloud.identity_federation_abuse`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak normalizer)**
- **Catatan**: Keempat capability output yang dideklarasikan tidak memiliki handler di `ArtifactNormalizer`. Terdaftar di `NORMALIZER_CONTRACT_AUDIT.md`. Akan difix serentak bersama capability normalizer pending lainnya.

### [MOD-053] Cloud Scope Gap (ARCHITECTURAL GAP)
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED — butuh keputusan desain lebih besar**
- **Temuan**: ScopeGuard hanya memvalidasi IP/CIDR/DNS. Identifier cloud (`tenant_id`, `aws_account_id`, `subscription_id`) tidak dikenali.
- **Opsi yang perlu dievaluasi**:
  A. Extend `ScopeGuard` dengan `CloudScope` validator terpisah
  B. Buat `CloudScopeGuard` class baru dengan interface yang sama
  C. Validasi cloud identifier di layer campaign configuration
- **Catatan**: Keputusan ini mempengaruhi semua cloud modules (Batch 8+) dan butuh review owner sebelum diimplementasikan.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 9)

### [MOD-054] Internal Key Mismatch (`spn_list` vs `spns`) on `ad.enum_spn`
- **Severity**: **HIGH**
- **Status**: **FIXED** (commit `f0825df`)
- **Catatan**: Internal key disinkronkan: `_fetch_spns_sync` menulis `spns` dan alias `spn_list`. `ArtifactNormalizer._normalize_spns` dual-read fallback. `UserArtifact.spns` terisi penuh.

### [MOD-055] LAPS Password Pipeline vs OPSEC on `ad.laps_enum`
- **Severity**: **HIGH**
- **Status**: **FIXED** (commit `4bbf61d`)
- **Catatan**: Password LAPS ditulis langsung ke vault (`_vault.store()` / `ctx.record_credential()` dengan validasi Gate 6). `raw["entries"]` dan `raw["laps_passwords"]` aman secara OPSEC tanpa password (`has_password: True`). `CredentialArtifact` dibuat dengan note "password stored in vault".

### [MOD-056] Internal Key Mismatch & Unhandled Telemetry on `ad.enum_users`
- **Severity**: **MEDIUM**
- **Status**: **PARTIALLY FIXED (users dual-write: FIXED; password_policy: DEFERRED)** (commit `bc8c830`)
- **Catatan**: Dual-write `raw["users"] = users` dan `raw["user_list"] = users` telah diimplementasikan. Normalizer `_normalize_users` membaca key kanonikal. Handler `password_policy` ditunda ke batch fix serentak.

### [MOD-057] Inconsistent LDAP Bind Authentication Formatting on `ad.enum_acl` & `ad.laps_enum`
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED (Masuk batch fix serentak)**
- **Catatan**: Migrasi raw string binding ke `build_ad_bind_plan()` untuk menjamin kompatibilitas format UPN (`user@domain.local`) pada seluruh modul Active Directory.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 10)

### [MOD-058] Out-of-Scope AXFR Zone Transfer Probing on Discovered Nameservers on `network.dns_enum`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup D: Scope Bypass)**
- **Catatan**: Loop AXFR zone transfer `_try_axfr(ns_clean)` menghubungi nameserver eksternal hasil enumerasi NS via TCP 53 tanpa memanggil `await self.before_request(ns_clean, "dns")`. Wajib difilter/diperiksa dengan scope check sebelum koneksi probe zone transfer.

### [MOD-059] Unbounded HTTP Redirect Traversal on External Hosts via `follow_redirects=True` on `network.http_fingerprint`
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup D: Scope Bypass)**
- **Catatan**: `httpx.AsyncClient` dengan `follow_redirects=True` berisiko mengejar redirect HTTP 301/302 ke domain/host eksternal tanpa validasi scope campaign. Perlu custom redirect hook atau `follow_redirects=False` dengan pengecekan `campaign.is_in_scope()` pada target redirect.

### [MOD-060] Asyncio TCP Writer Handle Leak on Read Timeout in `_grab_banner` on `network.service_detect`
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup C: Teardown & Resource Cleanup)**
- **Catatan**: Pemanggilan `await asyncio.wait_for(reader.read(2048), timeout=timeout)` tidak dibungkus dalam blok `try ... finally: writer.close()`. Perlu try/finally untuk mencegah kebocoran file descriptor socket TCP.

### [MOD-061] Discovered SNMP Community Strings Evaporation from Vault & Standard Pipeline on `network.snmp_enum`
- **Severity**: **HIGH**
- **Status**: **FIXED** (commit `5635362`)
- **Catatan**: Community string valid sekarang ditulis langsung ke `AresVault` (`_vault.store(cred, community)` dengan `CredentialType.CLEARTEXT` dan verifikasi Gate 6). Output `raw["valid_credentials"]` distandardisasi ke `list[dict]` (MOD-033), dan objek `Finding` di `raw["snmp_findings"]` diserialisasi ke plain dicts.

### [MOD-062] 100% Unhandled Reconnaissance Capabilities in `ArtifactNormalizer` on `network.*` & `recon.fingerprint`
- **Severity**: **MEDIUM**
- **Status**: **PARTIALLY FIXED / DEFERRED (7 Handlers implemented in commit `5635362`)**
- **Catatan**: 7 handler normalizer P0/P1 ditambahkan di `ares/normalize/artifacts.py` (`dns_records`, `subdomains`, `service_versions`, `vulnerable_services`, `web_fingerprint`, `admin_interfaces`, dll.). Sisa capability recon ditunda ke batch fix serentak.

---

## BATCH FIX SERENTAK DEFERRED NOTES (Batch 11)

### [MOD-063] Unscoped Cloud Account/Tenant Execution via Ambient Credentials on `cloud.*`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup D: Scope Bypass)**
- **Catatan**: Seluruh 4 modul cloud (`cloud.aws`, `cloud.azure`, `cloud.azure_ad`, `cloud.gcp`) tidak memvalidasi cloud target identifier (`Account` dari STS caller identity, `subscription_id`, `tenant_id`, `project_id`) terhadap batasan `campaign.scope`. Ambient developer credentials (`~/.aws/credentials`, `az login`, `GOOGLE_APPLICATION_CREDENTIALS`) dapat mengeksekusi scanning di luar otorisasi engagement.

### [MOD-064] Operator Workstation Link-Local Metadata SSRF Probe & Token Leak on `cloud.aws` & `cloud.gcp`
- **Severity**: **HIGH**
- **Status**: **FIXED** (commit `d86750b`)
- **Catatan**: Probing metadata link-local dari workstation operator (`http://169.254.169.254` dan `http://metadata.google.internal`) telah dihapus sepenuhnya dari `cloud.aws` dan `cloud.gcp`. Tidak ada lagi risiko kebocoran IAM credentials operator atau false finding atribusi target.

### [MOD-065] Missing Pre-Flight SDK Dependency Validation in `validate()` on `cloud.*`
- **Severity**: **MEDIUM**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup E: Robustness & Pre-flight)**
- **Catatan**: `validate()` tidak memeriksa kelengkapan modul eksternal (`boto3`, `azure-identity`, `azure-mgmt-*`, `msal`, `google-auth`), sehingga modul lulus scheduling tapi crash unhandled di runtime saat library belum terpasang. Estimasi fix: S (4 file, pola identik).

### [MOD-066] 100% Normalizer Data Loss on `azure_findings`, `azure_ad_findings`, `access_tokens` on `cloud.azure` & `cloud.azure_ad`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup A: Normalizer Handlers Missing)**
- **Catatan**: `OUTPUTS = ["azure_findings"]` dan `OUTPUTS = ["azure_ad_findings", "access_tokens"]` tidak memiliki handler di `ArtifactNormalizer`. Seluruh telemetry storage container, RBAC assignments, NSG rules, guest users, dan OAuth access tokens hilang 100% dari `ArtifactStore`.

### [MOD-067] Indentation Defect Causing `UnboundLocalError` & 100% Unreachable Graph API Dead Code on `cloud.azure_ad`
- **Severity**: **CRITICAL**
- **Status**: **FIXED** (commit `bd2c9b4`)
- **Catatan**: Indentasi blok return device_code telah diperbaiki di dalam `if technique == "device_code":`, variabel `raw` diinisialisasi di awal method `run()`, dan jalur eksekusi Graph API enumeration (`_enumerate_tenant`) untuk users, guests, dan privileged service principals telah dipulihkan sepenuhnya. Output `raw["azure_ad_findings"]` dijamin selalu ada.

### [MOD-068] 100% Normalizer Data Loss on `gcp_findings` in `ArtifactNormalizer` on `cloud.gcp`
- **Severity**: **HIGH**
- **Status**: **DEFERRED (Masuk batch fix serentak - Grup A: Normalizer Handlers Missing)**
- **Catatan**: `OUTPUTS = ["gcp_findings"]` tidak terdaftar di `ArtifactNormalizer.handlers`. Seluruh temuan enumerasi GCS public buckets, project IAM owner roles, dan service account keys menguap dari `ArtifactStore`.








