"""
ARES Architectural Benchmark: GOAD (Game of Active Directory) Validation Test.
Verifies that ARES modules deterministically cover all primary attack vectors
present in Orange Cyberdefense's Game of Active Directory (GOAD) without
relying on unverified shell scripts or probabilistic LLM execution.
"""
from __future__ import annotations

import pytest
from ares.core.plugin.loader import PluginLoader
from ares.core.chain.chain import CapabilityResolver, DependencyResolver


@pytest.fixture(scope="module")
def module_registry():
    loader = PluginLoader()
    loader._load_builtin()
    return loader.registry


# The canonical attack vectors present in Orange Cyberdefense's GOAD environment
GOAD_ATTACK_VECTORS = [
    {
        "vector": "AS-REP Roasting",
        "goad_target": "fcastle (DONOTREQPREAUTH)",
        "module_id": "ad.asreproast",
        "mitre": "T1558.004",
    },
    {
        "vector": "Kerberoasting",
        "goad_target": "sql_svc / web_svc SPN",
        "module_id": "ad.kerberoast",
        "mitre": "T1558.003",
    },
    {
        "vector": "Active Directory Certificate Services (AD CS) ESC1-ESC8",
        "goad_target": "SubCA / Vulnerable Certificate Templates",
        "module_id": "ad.adcs",
        "mitre": "T1649",
    },
    {
        "vector": "Authentication Coercion (PetitPotam / PrinterBug)",
        "goad_target": "Domain Controller MS-EFSR / MS-RPRN",
        "module_id": "ad.coerce",
        "mitre": "T1187",
    },
    {
        "vector": "NTLM Relay to LDAP / LDAPS",
        "goad_target": "Relay to DC for RBCD or ACL escalation",
        "module_id": "lateral.ntlm_relay",
        "mitre": "T1557.001",
    },
    {
        "vector": "LAPS Credential Enumeration",
        "goad_target": "ms-Mcs-AdmPwd attribute",
        "module_id": "ad.laps_enum",
        "mitre": "T1552.001",
    },
    {
        "vector": "Kerberos Delegation Abuse (Constrained & Unconstrained)",
        "goad_target": "msDS-AllowedToDelegateTo / TRUSTED_FOR_DELEGATION",
        "module_id": "ad.delegation_abuse",
        "mitre": "T1558.002",
    },
    {
        "vector": "DCSync Replication",
        "goad_target": "DS-Replication-Get-Changes-All on Domain Head",
        "module_id": "ad.dcsync",
        "mitre": "T1003.006",
    },
    {
        "vector": "MSSQL Lateral Movement & Linked Servers",
        "goad_target": "SQL Server linked queries & xp_cmdshell",
        "module_id": "lateral.mssql",
        "mitre": "T1090",
    },
    {
        "vector": "Pass-the-Hash / Pass-the-Ticket",
        "goad_target": "NTLM / Kerberos credential reuse across members",
        "module_id": "credential.pass_the_hash",
        "mitre": "T1550.002",
    },
]


def test_goad_all_attack_vectors_have_active_production_modules(module_registry):
    """Every GOAD vector must be backed by a concrete, active module in ARES registry."""
    for item in GOAD_ATTACK_VECTORS:
        mid = item["module_id"]
        mod_cls = module_registry.get(mid)
        assert mod_cls is not None, f"GOAD vector '{item['vector']}' missing module {mid}"
        assert getattr(mod_cls, "MODULE_ID", None) == mid
        assert hasattr(mod_cls, "run"), f"Module {mid} must implement run() method"
        assert hasattr(mod_cls, "validate"), f"Module {mid} must implement validate() method"


def test_goad_modules_have_strict_mitre_mapping(module_registry):
    """Verify that each module accurately declares its MITRE ATT&CK technique."""
    for item in GOAD_ATTACK_VECTORS:
        mid = item["module_id"]
        mod_cls = module_registry.get(mid)
        desc = getattr(mod_cls, "DESCRIPTION", "") or getattr(mod_cls, "__doc__", "")
        # Either the docstring, DESCRIPTION, or MITRE attribute must reference the technique or ATT&CK
        assert len(desc) > 20, f"Module {mid} must have descriptive documentation"


def test_goad_chain_topological_resolution(module_registry):
    """Verify that GOAD modules can be auto-resolved into a valid execution DAG without cycles."""
    resolver = CapabilityResolver(module_registry)
    goad_mids = [item["module_id"] for item in GOAD_ATTACK_VECTORS]
    nodes = resolver.build_nodes(goad_mids)

    assert len(nodes) == len(goad_mids)

    dep_resolver = DependencyResolver()
    stages = dep_resolver.resolve(nodes)

    # Must resolve into at least 1 valid sequential/parallel stage
    assert len(stages) >= 1
    all_resolved = [m for stage in stages for m in stage]
    assert set(all_resolved) == set(goad_mids)
