"""
tests/unit/test_artifact_normalizer_pipeline.py
End-to-End integration test suite for ArtifactNormalizer pipeline and dual-read fallback.

Validates that real-world raw outputs from offensive modules (using legacy key conventions)
successfully populate ArtifactStore without 70% data evaporation.
"""
from __future__ import annotations

import pytest

from ares.normalize.artifacts import (
    ArtifactNormalizer,
    ArtifactStore,
    ArtifactType,
    CredentialArtifact,
    HashArtifact,
    HostArtifact,
    UserArtifact,
)


@pytest.fixture
def store() -> ArtifactStore:
    return ArtifactStore()


@pytest.fixture
def normalizer() -> ArtifactNormalizer:
    return ArtifactNormalizer()


# ── Batch of Mismatched Handlers (Langkah 2A) ─────────────────────────────────

def test_kerberoast_pipeline_recovers_hashes(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.kerberoast writes raw['kerberos_hashes']; normalizer must ingest via fallback."""
    raw = {
        "kerberos_hashes": ["$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01*1234567890abcdef..."],
        "accounts": ["svc_sql"],
    }
    added = normalizer.normalize("ad.kerberoast", ["kerberos_hashes"], raw, store)
    assert added == 1
    hashes = store.hashes()
    assert len(hashes) == 1
    assert hashes[0].username == "svc_sql"
    assert hashes[0].hash_type == "krb5tgs"
    assert hashes[0].hashcat_mode == 13100


def test_asreproast_pipeline_recovers_hashes(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.asreproast writes raw['asrep_hashes']; normalizer must ingest via fallback."""
    raw = {
        "asrep_hashes": ["$krb5asrep$23$target_user@CORP.LOCAL:1234567890abcdef..."],
        "vulnerable_accounts": ["target_user"],
    }
    added = normalizer.normalize("ad.asreproast", ["asrep_hashes"], raw, store)
    assert added == 1
    hashes = store.hashes()
    assert len(hashes) == 1
    assert hashes[0].username == "target_user"
    assert hashes[0].hash_type == "krb5asrep"
    assert hashes[0].hashcat_mode == 18200


def test_dcsync_pipeline_recovers_ntlm_hashes(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.dcsync writes raw['ntlm_hashes']; normalizer must ingest via fallback."""
    raw = {
        "ntlm_hashes": [
            {"username": "Administrator", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"}
        ],
        "target": "Administrator",
    }
    added = normalizer.normalize("ad.dcsync", ["ntlm_hashes"], raw, store)
    assert added == 1
    hashes = store.hashes()
    assert len(hashes) == 1
    assert hashes[0].username == "Administrator"
    assert hashes[0].hash_type == "ntlm"
    assert hashes[0].hash_value == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_enum_users_pipeline_recovers_users(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.enum_users writes raw['user_list']; normalizer must ingest via fallback."""
    raw = {
        "user_list": [
            {
                "samAccountName": "jdoe",
                "domain": "CORP",
                "enabled": True,
                "adminCount": 1,
            }
        ]
    }
    added = normalizer.normalize("ad.enum_users", ["user_list"], raw, store)
    assert added == 1
    users = store.users()
    assert len(users) == 1
    assert users[0].username == "jdoe"
    assert users[0].domain == "CORP"
    assert users[0].is_admin is True


@pytest.mark.asyncio
async def test_enum_users_dual_write_users_key_mod_056(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """
    MOD-056: ad.enum_users dual-writes raw['users'] and raw['user_list'].
    Normalizer ingests both keys successfully into UserArtifact.
    """
    from unittest.mock import patch
    from tests.unit.modules.test_modules import _make_module
    from ares.modules.ad.enum_users import ADEnumUsersModule

    mod, _ = _make_module(ADEnumUsersModule)
    mock_users = [
        {
            "samAccountName": "alice",
            "enabled": True,
            "noExpiry": False,
            "noPreauth": True,
            "isAdmin": True,
            "badPwdCount": 0,
            "days_since_login": 10,
            "days_since_pwd": 20,
        }
    ]
    mock_policy = {"minPwdLength": 8, "pwdHistoryLength": 5, "lockoutThreshold": 5}

    with patch.object(mod, "_ldap_query_sync", return_value=(mock_users, mock_policy)):
        findings, raw = await mod.run(
            dc="10.0.0.1",
            username="analyst",
            password="fake_password",
            domain="corp.local",
        )

    # Verify dual-write in module raw output
    assert "users" in raw
    assert "user_list" in raw
    assert raw["users"] == mock_users
    assert raw["user_list"] == mock_users

    # Verify normalizer reads "users"
    added = normalizer.normalize("ad.enum_users", ["users"], raw, store)
    assert added == 1
    users = store.users()
    assert len(users) == 1
    assert users[0].username == "alice"
    assert users[0].is_admin is True
    assert users[0].no_preauth is True



def test_enum_computers_pipeline_recovers_computers(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.enum_computers writes raw['computer_list']; normalizer must ingest via fallback."""
    raw = {
        "computer_list": [
            {
                "name": "DC01",
                "dns_name": "dc01.corp.local",
                "os": "Windows Server 2022",
                "is_dc": True,
                "ip": "10.0.0.1",
            }
        ]
    }
    added = normalizer.normalize("ad.enum_computers", ["computer_list"], raw, store)
    assert added == 1
    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0].hostname in ("dc01.corp.local", "DC01")
    assert hosts[0].is_dc is True


def test_enum_spn_pipeline_recovers_spns(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.enum_spn writes raw['spn_list']; normalizer must ingest via fallback."""
    raw = {
        "spn_list": [
            {
                "samAccountName": "svc_web",
                "spns": ["HTTP/web.corp.local"],
                "enabled": True,
                "is_admin": False,
            }
        ]
    }
    added = normalizer.normalize("ad.enum_spn", ["spn_list"], raw, store)
    assert added == 1
    users = store.users()
    assert len(users) == 1
    assert users[0].username == "svc_web"
    assert users[0].is_kerberoastable is True


def test_enum_spn_internal_key_sync_mod_054(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-054: ad.enum_spn writes spns & spn_list with non-empty SPNs inside entries."""
    from ares.modules.ad.enum_spn import ADEnumSPNModule

    assert "spns" in ADEnumSPNModule.OUTPUTS
    assert "spn_list" in ADEnumSPNModule.OUTPUTS

    # Format produced by _fetch_spns_sync after fix:
    spn_entries = [
        {
            "name": "svc_sql",
            "samAccountName": "svc_sql",
            "spns": ["MSSQLSvc/sql01.corp.local:1433"],
            "spn_list": ["MSSQLSvc/sql01.corp.local:1433"],
            "is_admin": True,
            "uses_rc4": True,
            "days_since_pwd": 45,
            "enabled": True,
        }
    ]
    raw = {
        "spns": spn_entries,
        "spn_list": spn_entries,
        "outcome_category": "confirmed_findings",
        "outcome_message": "Found 1 service principal candidate(s).",
    }

    added = normalizer.normalize("ad.enum_spn", ["spns"], raw, store)
    assert added == 1
    users = store.users()
    assert len(users) == 1
    assert users[0].username == "svc_sql"
    assert users[0].spns == ["MSSQLSvc/sql01.corp.local:1433"]
    assert users[0].is_kerberoastable is True

    # Test backward-compat fallback when inner dict only has spn_list:
    store2 = ArtifactStore()
    raw_compat = {
        "spn_list": [
            {
                "name": "svc_iis",
                "spn_list": ["HTTP/iis.corp.local"],
                "enabled": True,
            }
        ]
    }
    added2 = normalizer.normalize("ad.enum_spn", ["spn_list"], raw_compat, store2)
    assert added2 == 1
    users2 = store2.users()
    assert len(users2) == 1
    assert users2[0].username == "svc_iis"
    assert users2[0].spns == ["HTTP/iis.corp.local"]


def test_host_vuln_pipeline_recovers_target(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """linux.privesc writes raw['target']; normalizer must ingest via fallback."""
    raw = {
        "target": "10.0.0.55",
        "privesc_vectors": ["cve-2021-4034"],
    }
    added = normalizer.normalize("linux.privesc", ["privesc_vectors"], raw, store)
    assert added == 1
    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0].ip_address == "10.0.0.55"


def test_aws_privesc_pipeline_recovers_paths(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """cloud.aws_privesc writes raw['privesc_paths']; normalizer must ingest without dropping."""
    raw = {
        "privesc_paths": [
            {"role_arn": "arn:aws:iam::123456789012:role/AdminEscalationRole", "action": "iam:PassRole"}
        ],
        "region": "us-east-1",
    }
    added = normalizer.normalize("cloud.aws_privesc", ["aws_findings"], raw, store)
    assert added == 1
    cloud_res = store.get(ArtifactType.CLOUD_RESOURCE)
    assert len(cloud_res) == 1
    assert "AdminEscalationRole" in cloud_res[0].resource_id


def test_aws_privesc_output_key_separation(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-052: aws_privesc must use iam_privesc_paths and not overwrite aws_findings."""
    from unittest.mock import MagicMock
    from ares.modules.cloud.aws_privesc import AWSPrivescModule
    assert "iam_privesc_paths" in AWSPrivescModule.OUTPUTS
    assert "aws_findings" not in AWSPrivescModule.OUTPUTS

    # Simulate existing cloud.aws findings in raw
    cloud_aws_findings = {
        "s3": {
            "public_buckets": [{"name": "confidential-backup"}]
        },
        "region": "us-east-1",
    }
    raw = {
        "aws_findings": cloud_aws_findings,
        "s3": cloud_aws_findings["s3"],
        "region": "us-east-1",
    }

    # aws_privesc populates raw
    mod = AWSPrivescModule(MagicMock(), MagicMock(), MagicMock())
    mod._findings = ["privesc_found"]
    raw["aws_privesc_paths"] = mod._findings
    raw["iam_privesc_paths"] = mod._findings

    # aws_findings must not be overwritten by list[Finding]
    assert raw["aws_findings"] == cloud_aws_findings
    assert isinstance(raw["aws_findings"], dict)
    assert raw["iam_privesc_paths"] == ["privesc_found"]

    # Verify cloud.aws S3 normalization still succeeds
    added = normalizer.normalize("cloud.aws", ["aws_findings"], raw, store)
    assert added >= 1
    buckets = [r for r in store.get(ArtifactType.CLOUD_RESOURCE) if r.resource_type == "s3_bucket"]
    assert any(b.resource_id == "confidential-backup" for b in buckets)


# ── Batch of P0 Handlers (Langkah 2B) ─────────────────────────────────────────

def test_cleartext_credentials_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.sccm and windows.dpapi write cleartext_credentials; normalizer must create CredentialArtifact."""
    raw = {
        "cleartext_credentials": [
            {
                "username": "sccm_naa",
                "password": "PasswordNAA123!",
                "domain": "CORP",
                "host": "10.0.0.10",
            }
        ]
    }
    added = normalizer.normalize("ad.sccm", ["cleartext_credentials"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "sccm_naa"
    assert creds[0].domain == "CORP"
    assert creds[0].cred_type == "cleartext"
    assert creds[0].secret == "PasswordNAA123!"
    assert creds[0].source_host == "10.0.0.10"


def test_cracked_credentials_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """credential.crack writes cracked_credentials; normalizer must create CredentialArtifact(cracked=True)."""
    raw = {
        "cracked_credentials": [
            {
                "username": "svc_sql",
                "domain": "CORP",
                "plaintext": "Winter2024!",
                "hash_type": "krb5tgs",
            }
        ]
    }
    added = normalizer.normalize("credential.crack", ["cracked_credentials"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "svc_sql"
    assert creds[0].domain == "CORP"
    assert creds[0].cracked is True
    assert creds[0].secret == "Winter2024!"


def test_laps_passwords_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.laps_enum writes laps_passwords; normalizer must create CredentialArtifact(cred_type='laps')."""
    raw = {
        "laps_passwords": [
            {
                "computer": "WORKSTATION-01",
                "password": "LapsSecretAdminPwd!",
            }
        ]
    }
    added = normalizer.normalize("ad.laps_enum", ["laps_passwords"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "Administrator"
    assert creds[0].cred_type == "laps"
    assert creds[0].secret == "LapsSecretAdminPwd!"
    assert creds[0].source_host == "WORKSTATION-01"
    assert creds[0].privilege == "local_admin"


@pytest.mark.asyncio
async def test_laps_opsec_direct_vault_pipeline_mod_055(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """
    MOD-055: LAPS module writes passwords directly to vault (Gate 6 validated),
    while raw output omits password for OPSEC and sets has_password=True.
    Normalizer ingests has_password=True and creates CredentialArtifact with secret="" and note.
    """
    from unittest.mock import patch
    from tests.unit.modules.test_modules import _make_module
    from ares.modules.ad.laps_enum import LAPSEnumModule
    from ares.credential.vault import CredentialVault
    from ares.core.context import ExecutionContext

    mod, _ = _make_module(LAPSEnumModule)
    vault = CredentialVault(encryption_key=None)
    ctx = ExecutionContext(
        target="10.0.0.1",
        domain="corp.local",
        vault=vault,
        network_io_occurred=True,
    )

    mock_entries = [
        {"computer": "PC-FINANCE-01", "password": "RealSecretLapsPassword123!", "version": "v1", "expiry": ""},
    ]

    with patch.object(mod, "_query_laps_sync", return_value=mock_entries):
        findings, raw = await mod.run(
            dc="10.0.0.1",
            domain="corp.local",
            username="analyst",
            password="fake_login_pwd",
            vault=vault,
            ctx=ctx,
        )

    # 1. raw output does NOT contain plaintext password (OPSEC safe)
    assert raw["entries"][0].get("has_password") is True
    assert "password" not in raw["entries"][0]
    assert "password" not in raw["laps_passwords"][0]

    # 2. Vault contains full password (Gate 6 passed valid CLEARTEXT)
    stored_creds = [c for c in vault._store.values() if "PC-FINANCE-01" in getattr(c, "domain", "") or "PC-FINANCE-01" in getattr(c, "target_host", "")]
    assert len(stored_creds) >= 1
    cred_id = stored_creds[0].id
    revealed_secret = vault.reveal(cred_id)
    assert revealed_secret == "RealSecretLapsPassword123!"

    # 3. Normalizer creates CredentialArtifact with has_password=True and note
    added = normalizer.normalize("ad.laps_enum", ["laps_passwords"], raw, store)
    assert added == 1
    artifacts = store.credentials()
    assert len(artifacts) == 1
    assert artifacts[0].username == "Administrator"
    assert artifacts[0].source_host == "PC-FINANCE-01"
    assert artifacts[0].secret == ""
    assert artifacts[0].has_password is True
    assert artifacts[0].note == "password stored in vault"



def test_kerberos_tickets_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """lateral.ntlm_relay / linux.ccache_hunt write tickets; normalizer must create CredentialArtifact."""
    raw = {
        "kerberos_tickets": [
            {
                "client": "Administrator@CORP.LOCAL",
                "ticket_path": "/tmp/admin_ticket.ccache",
                "target": "10.0.0.2",
            }
        ]
    }
    added = normalizer.normalize("linux.ccache_hunt", ["kerberos_tickets"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "Administrator"
    assert creds[0].domain == "CORP.LOCAL"
    assert creds[0].cred_type == "kerberos_ticket"
    assert creds[0].secret == "/tmp/admin_ticket.ccache"


def test_open_ports_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """network.port_scan writes open_ports; normalizer must populate HostArtifact.open_ports."""
    raw = {
        "target": "10.0.0.25",
        "open_ports": [22, 80, 445],
        "service_map": {22: "ssh", 80: "http", 445: "smb"},
    }
    added = normalizer.normalize("network.port_scan", ["open_ports"], raw, store)
    assert added >= 1
    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0].ip_address == "10.0.0.25"
    assert hosts[0].open_ports == [22, 80, 445]


def test_open_ports_updates_existing_host(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """Scanning existing host updates open_ports without creating duplicate host."""
    store.add(HostArtifact(ip="10.0.0.30", hostname="10.0.0.30", open_ports=[80]))
    raw = {
        "target": "10.0.0.30",
        "open_ports": [443, 8080],
    }
    added = normalizer.normalize("network.port_scan", ["open_ports"], raw, store)
    assert added == 1
    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0].open_ports == [80, 443, 8080]


# ── Canonical Standard Key Tests (Dual-Read Verification) ─────────────────────

def test_canonical_standard_keys_accepted(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """Verify that newly standardized keys ('hashes', 'users', 'computers', 'spns', 'target') work seamlessly."""
    raw_users = {"users": [{"username": "alice", "domain": "CORP"}]}
    assert normalizer.normalize("ad.enum_users", ["user_list"], raw_users, store) == 1

    raw_comp = {"computers": [{"name": "FS01", "os": "Linux", "ip": "10.0.0.2"}]}
    assert normalizer.normalize("ad.enum_computers", ["computer_list"], raw_comp, store) == 1

    raw_hashes = {"hashes": [{"username": "bob", "nt_hash": "aabbccddeeff00112233445566778899"}]}
    assert normalizer.normalize("windows.lsass_dump", ["ntlm_hashes"], raw_hashes, store) == 1

    raw_spns = {"spns": [{"name": "svc_crm", "spns": ["HTTP/crm.corp.local"]}]}
    assert normalizer.normalize("ad.enum_spn", ["spn_list"], raw_spns, store) == 1

    assert len(store.users()) == 2
    assert len(store.hosts()) == 1
    assert len(store.hashes()) == 1


def test_kerberos_ticket_string_path(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """Verify that a single string path for kerberos_ticket is normalized into CredentialArtifact."""
    raw = {"kerberos_ticket": "/tmp/golden.ccache"}
    added = normalizer.normalize("credential.golden_ticket", ["kerberos_ticket"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].secret == "/tmp/golden.ccache"
    assert creds[0].cred_type == "kerberos_ticket"


def test_acl_findings_permissions_pipeline(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """ad.enum_acl writes misconfigs; normalizer must ingest into PermissionArtifact."""
    raw = {
        "misconfigs": [
            {
                "trustee_sid": "S-1-5-21-12345-500",
                "target": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                "right": "GenericAll",
            }
        ]
    }
    added = normalizer.normalize("ad.enum_acl", ["acl_findings"], raw, store)
    assert added == 1
    perms = store.permissions()
    assert len(perms) == 1
    assert perms[0].is_dangerous is True
    assert perms[0].right == "GenericAll"


def test_lsa_secrets_pipeline_recovers_credentials(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """windows.lsa_secrets writes raw['lsa_secrets']; normalizer must ingest into CredentialArtifact(cred_type='lsa_secret')."""
    raw = {
        "target": "10.0.0.15",
        "domain": "CORP.LOCAL",
        "sam_hashes": ["Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"],
        "lsa_secrets": [
            "$MACHINE.ACC: plain_password_hex_31323334",
            "_SC_MSSQLSERVER: ComplexServicePassword!2024",
            "DPAPI_SYSTEM: 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000",
        ],
        "cached_credentials": [],
        "errors": [],
    }
    added = normalizer.normalize("windows.lsa_secrets", ["lsa_secrets"], raw, store)
    assert added == 3
    creds = store.credentials()
    assert len(creds) == 3

    assert creds[0].username == "$MACHINE.ACC"
    assert creds[0].cred_type == "lsa_secret"
    assert creds[0].secret == "plain_password_hex_31323334"
    assert creds[0].source_host == "10.0.0.15"
    assert creds[0].cracked is False

    assert creds[1].username == "_SC_MSSQLSERVER"
    assert creds[1].secret == "ComplexServicePassword!2024"
    assert creds[1].privilege == "service_account"

    assert creds[2].username == "DPAPI_SYSTEM"
    assert creds[2].cred_type == "lsa_secret"


def test_cached_domain_credentials_pipeline_recovers_credentials(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """windows.lsa_secrets writes raw['cached_credentials']; normalizer must ingest into CredentialArtifact(cred_type='cached_domain', cracked=False)."""
    raw = {
        "target": "10.0.0.15",
        "domain": "CORP.LOCAL",
        "sam_hashes": [],
        "lsa_secrets": [],
        "cached_credentials": [
            "CORP.LOCAL\\jdoe:$DCC2$10240#jdoe#5f4dcc3b5aa765d61d8327deb882cf99",
            "$DCC2$10240#admin_ops#8b1a9953c4611296a827abf8c47804d7",
        ],
        "errors": [],
    }
    added = normalizer.normalize("windows.lsa_secrets", ["cached_credentials"], raw, store)
    assert added == 2
    creds = store.credentials()
    assert len(creds) == 2

    assert creds[0].username == "jdoe"
    assert creds[0].domain == "CORP.LOCAL"
    assert creds[0].cred_type == "cached_domain"
    assert creds[0].cracked is False
    assert creds[0].secret == "$DCC2$10240#jdoe#5f4dcc3b5aa765d61d8327deb882cf99"
    assert creds[0].source_host == "10.0.0.15"

    assert creds[1].username == "admin_ops"
    assert creds[1].cred_type == "cached_domain"
    assert creds[1].cracked is False


def test_lsa_secrets_and_cached_creds_dict_structure(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """Test structured dictionary input for lsa_secrets and cached_creds fallback."""
    raw = {
        "target": "10.0.0.20",
        "lsa_secrets": [
            {"username": "svc_backup", "domain": "CORP", "secret": "BackupPass123!", "privilege": "service_account"}
        ],
        "cached_creds": [
            {"username": "d_admin", "domain": "CORP", "hash": "dcc2_hash_value", "privilege": "domain_admin"}
        ],
    }
    added_lsa = normalizer.normalize("windows.lsa_secrets", ["lsa_secrets"], raw, store)
    assert added_lsa == 1

    added_cached = normalizer.normalize("windows.lsa_secrets", ["cached_credentials"], raw, store)
    assert added_cached == 1

    creds = store.credentials()
    assert len(creds) == 2

    lsa_cred = next(c for c in creds if c.cred_type == "lsa_secret")
    assert lsa_cred.username == "svc_backup"
    assert lsa_cred.secret == "BackupPass123!"

    cached_cred = next(c for c in creds if c.cred_type == "cached_domain")
    assert cached_cred.username == "d_admin"
    assert cached_cred.secret == "dcc2_hash_value"
    assert cached_cred.cracked is False


def test_valid_credentials_pipeline_normalizes_to_artifact_store(
    normalizer: ArtifactNormalizer, store: ArtifactStore
):
    """MOD-033: valid_credentials standard contract normalizes into CredentialArtifact."""
    raw = {
        "valid_credentials": [
            {
                "username": "admin",
                "password": "SecretPassword123!",
                "target": "10.0.0.50",
                "port": 22,
                "method": "password",
                "protocol": "ssh",
                "privilege": "admin",
                "domain": None,
            },
            {
                "username": "svc_sql",
                "password": "0123456789abcdef0123456789abcdef",
                "target": "10.0.0.51",
                "port": 445,
                "method": "hash",
                "protocol": "smb",
                "privilege": "user",
                "domain": "CORP",
            },
        ]
    }
    added = normalizer.normalize("credential.ssh_spray", ["valid_credentials"], raw, store)
    assert added == 2
    creds = store.credentials()
    assert len(creds) == 2

    c1 = next(c for c in creds if c.username == "admin")
    assert c1.secret == "SecretPassword123!"
    assert c1.source_host == "10.0.0.50"
    assert c1.target == "10.0.0.50"
    assert c1.protocol == "ssh"
    assert c1.cred_type == "password"
    assert c1.privilege == "admin"
    assert c1.cracked is False

    c2 = next(c for c in creds if c.username == "svc_sql")
    assert c2.secret == "0123456789abcdef0123456789abcdef"
    assert c2.source_host == "10.0.0.51"
    assert c2.protocol == "smb"
    assert c2.cred_type == "hash"
    assert c2.privilege == "user"
    assert c2.domain == "CORP"
    assert c2.cracked is False


def test_valid_credentials_skips_invalid_non_dict_entries(
    normalizer: ArtifactNormalizer, store: ArtifactStore
):
    """MOD-033: Non-dict entries in valid_credentials are safely skipped."""
    raw = {
        "valid_credentials": [
            "invalid_string_id",
            12345,
            {
                "username": "valid_user",
                "password": "valid_password",
                "target": "10.0.0.60",
                "port": 445,
                "method": "password",
                "protocol": "smb",
                "privilege": "user",
                "domain": "CORP",
            },
        ]
    }
    added = normalizer.normalize("credential.reuse", ["valid_credentials"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "valid_user"
    assert creds[0].secret == "valid_password"


@pytest.mark.asyncio
async def test_snmp_enum_vault_and_valid_credentials_mod_061(
    normalizer: ArtifactNormalizer, store: ArtifactStore
):
    """
    MOD-061: snmp_enum writes valid community strings to AresVault (Gate 6 compliant),
    produces standardized valid_credentials output, and serializes snmp_findings.
    """
    from unittest.mock import patch
    from tests.unit.modules.test_modules import _make_module
    from ares.modules.network.snmp_enum import SnmpEnumModule
    from ares.credential.vault import CredentialVault
    from ares.core.context import ExecutionContext

    mod, _ = _make_module(SnmpEnumModule)
    vault = CredentialVault(encryption_key=None)
    ctx = ExecutionContext(
        target="10.0.0.100",
        vault=vault,
        network_io_occurred=True,
    )

    fake_sys_info = {
        "sysDescr": "Linux router 5.15.0",
        "sysName": "edge-router-01",
    }

    # Mock low-level sync SNMP calls so no real network traffic occurs
    with patch("ares.modules.network.snmp_enum._snmp_get_sync", return_value=fake_sys_info), \
         patch("ares.modules.network.snmp_enum._snmp_walk_sync", return_value=[]):
        findings, raw = await mod.run(
            target="10.0.0.100",
            port=161,
            communities=["public"],
            walk=False,
            vault=vault,
            ctx=ctx,
        )

    # 1. Community string stored directly into vault (Gate 6 passed)
    stored_creds = list(vault._store.values())
    assert len(stored_creds) == 1
    revealed = vault.reveal(stored_creds[0].id)
    assert revealed == "public"

    # 2. raw output has standardized valid_credentials contract
    assert "valid_credentials" in raw
    assert len(raw["valid_credentials"]) == 1
    assert raw["valid_credentials"][0]["username"] == "snmp"
    assert raw["valid_credentials"][0]["password"] == "public"
    assert raw["valid_credentials"][0]["method"] == "snmp_community"
    assert raw["valid_credentials"][0]["protocol"] == "snmp"

    # 3. snmp_findings is serialized (list of dicts, not raw Finding objects)
    assert isinstance(raw["snmp_findings"], list)
    assert len(raw["snmp_findings"]) >= 1
    assert isinstance(raw["snmp_findings"][0], dict)

    # 4. Normalizer pipeline creates CredentialArtifact with cred_type="snmp_community"
    added = normalizer.normalize("network.snmp_enum", ["valid_credentials"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "snmp"
    assert creds[0].secret == "public"
    assert creds[0].cred_type == "snmp_community"
    assert creds[0].protocol == "snmp"
    assert creds[0].target == "10.0.0.100"


def test_converted_ticket_pipeline_mod_036(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-036: Converted ticket base64 is ingested into CredentialArtifact."""
    raw = {
        "target": "corp.local",
        "converted_ticket_b64": "Y2NhY2hlLXRlc3QtZGF0YQ==",
        "metadata": {
            "client": "admin@CORP.LOCAL",
            "server": "krbtgt/CORP.LOCAL",
            "is_tgt": True,
        },
    }
    added = normalizer.normalize("credential.ticket_converter", ["converted_ticket"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "admin@CORP.LOCAL"
    assert creds[0].domain == "corp.local"
    assert creds[0].cred_type == "tgt"
    assert creds[0].privilege == "domain_admin"
    assert creds[0].secret == "Y2NhY2hlLXRlc3QtZGF0YQ=="


def test_samba_secrets_pipeline_mod_041(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-041: Samba secrets are converted to HashArtifact and CredentialArtifact."""
    raw = {
        "target": "fileserver01",
        "samba_secrets": [
            {
                "account_name": "FILESERVER01$",
                "domain": "CORP",
                "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "plaintext": "SecretMachinePass123!",
            }
        ],
    }
    added = normalizer.normalize("linux.samba_secrets", ["samba_secrets"], raw, store)
    assert added == 2
    hashes = store.hashes()
    assert len(hashes) == 1
    assert hashes[0].username == "FILESERVER01$"
    assert hashes[0].hash_type == "ntlm"
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in hashes[0].hash_value

    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "FILESERVER01$"
    assert creds[0].secret == "SecretMachinePass123!"


def test_keytab_keys_pipeline_mod_044(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-044: Kerberos keytab keys are converted to CredentialArtifact with enctype note."""
    raw = {
        "target": "linux01",
        "kerberos_keys": [
            {
                "principal": "host/linux01.corp.local@CORP.LOCAL",
                "realm": "CORP.LOCAL",
                "key_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "enctype": 18,
                "kvno": 2,
            }
        ],
    }
    added = normalizer.normalize("linux.keytab_abuse", ["kerberos_keys"], raw, store)
    assert added == 1
    creds = store.credentials()
    assert len(creds) == 1
    assert creds[0].username == "host/linux01.corp.local@CORP.LOCAL"
    assert creds[0].cred_type == "keytab_key"
    assert creds[0].secret.startswith("12345678")
    assert "enctype=18" in creds[0].note


def test_iam_privesc_pipeline_mod_052(normalizer: ArtifactNormalizer, store: ArtifactStore):
    """MOD-052: AWS IAM privilege escalation paths normalized to PermissionArtifact."""
    raw = {
        "account_id": "123456789012",
        "iam_privesc_paths": [
            {
                "principal": "arn:aws:iam::123456789012:user/dev",
                "action": "iam:PassRole",
                "target": "arn:aws:iam::123456789012:role/AdminRole",
                "technique": "T1548",
            }
        ],
    }
    added = normalizer.normalize("cloud.aws_privesc", ["iam_privesc_paths"], raw, store)
    assert added == 1
    perms = store.permissions()
    assert len(perms) == 1
    assert perms[0].principal == "arn:aws:iam::123456789012:user/dev"
    assert perms[0].target == "arn:aws:iam::123456789012:role/AdminRole"
    assert perms[0].right == "iam:PassRole"
    assert perms[0].is_dangerous is True


def test_dns_records_and_subdomains_pipeline_mod_062(
    normalizer: ArtifactNormalizer, store: ArtifactStore
):
    """MOD-062: DNS subdomains and A-records normalized to HostArtifact."""
    raw = {
        "domain": "target.corp",
        "subdomains": [
            {"fqdn": "vpn.target.corp", "ips": ["10.10.1.5"]},
            "mail.target.corp",
        ],
        "dns_records": {
            "A": ["10.10.1.1", "10.10.1.2"],
        },
    }
    added = normalizer.normalize("network.dns_enum", ["subdomains", "dns_records"], raw, store)
    assert added >= 4
    hosts = store.hosts()
    hostnames = {h.hostname for h in hosts}
    assert "vpn.target.corp" in hostnames
    assert "mail.target.corp" in hostnames
    assert "target.corp" in hostnames


def test_service_versions_and_web_fingerprint_pipeline_mod_062(
    normalizer: ArtifactNormalizer, store: ArtifactStore
):
    """MOD-062: Service versions and web fingerprint update HostArtifact."""
    raw_service = {
        "target": "10.10.1.50",
        "service_versions": {
            "80": {"service": "http", "version": "nginx 1.18"},
            "443": {"service": "https", "version": "nginx 1.18"},
        },
        "os": "Ubuntu Linux",
    }
    added_svc = normalizer.normalize("network.service_detect", ["service_versions"], raw_service, store)
    assert added_svc == 1

    hosts = store.hosts()
    assert len(hosts) == 1
    assert hosts[0].ip_address == "10.10.1.50"
    assert hosts[0].open_ports == [80, 443]
    assert hosts[0].os == "Ubuntu Linux"

    raw_web = {
        "target": "10.10.1.50",
        "web_fingerprint": {"server": "nginx/1.18.0 (Ubuntu)"},
    }
    added_web = normalizer.normalize("network.http_fingerprint", ["web_fingerprint"], raw_web, store)
    assert added_web == 1
    # Existing host updated, no duplicate created
    assert len(store.hosts()) == 1
    assert store.hosts()[0].os == "Ubuntu Linux"




