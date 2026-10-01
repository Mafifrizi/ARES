import json
import zipfile
import pytest
from pathlib import Path
from ares.graph.attack_graph import AttackGraph


@pytest.fixture
def sample_bloodhound_data():
    """Generates standard BloodHound CE (v5) / legacy compatible data dictionary."""
    domain_sid = "S-1-5-21-1111111111-2222222222-3333333333"
    attacker_sid = f"{domain_sid}-1101"
    victim_sid = f"{domain_sid}-1102"
    da_group_sid = f"{domain_sid}-512"
    dc_sid = f"{domain_sid}-1000"
    ws_sid = f"{domain_sid}-1001"

    users_data = {
        "meta": {"type": "users", "count": 2},
        "data": [
            {
                "ObjectIdentifier": attacker_sid,
                "Properties": {
                    "name": "ATTACKER@CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                    "domainsid": domain_sid,
                    "admincount": False,
                    "enabled": True,
                },
                "Aces": [],
            },
            {
                "ObjectIdentifier": victim_sid,
                "Properties": {
                    "name": "VICTIM@CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                    "domainsid": domain_sid,
                    "admincount": False,
                    "enabled": True,
                },
                "Aces": [
                    {
                        "PrincipalSID": attacker_sid,
                        "PrincipalType": "User",
                        "RightName": "GenericAll",
                        "IsInherited": False,
                    }
                ],
            },
        ],
    }

    groups_data = {
        "meta": {"type": "groups", "count": 1},
        "data": [
            {
                "ObjectIdentifier": da_group_sid,
                "Properties": {
                    "name": "DOMAIN ADMINS@CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                    "domainsid": domain_sid,
                    "admincount": True,
                },
                "Members": [
                    {
                        "MemberId": victim_sid,
                        "MemberType": "User",
                    }
                ],
                "Aces": [],
            }
        ],
    }

    computers_data = {
        "meta": {"type": "computers", "count": 2},
        "data": [
            {
                "ObjectIdentifier": dc_sid,
                "Properties": {
                    "name": "DC01.CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                    "domainsid": domain_sid,
                    "isdc": True,
                    "enabled": True,
                },
                "Aces": [
                    {
                        "PrincipalSID": da_group_sid,
                        "PrincipalType": "Group",
                        "RightName": "GenericAll",
                        "IsInherited": False,
                    }
                ],
            },
            {
                "ObjectIdentifier": ws_sid,
                "Properties": {
                    "name": "WS01.CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                    "domainsid": domain_sid,
                    "isdc": False,
                    "enabled": True,
                },
                "LocalAdmins": {
                    "Collected": True,
                    "FailureReason": None,
                    "Results": [
                        {
                            "ObjectIdentifier": attacker_sid,
                            "ObjectType": "User",
                        }
                    ],
                },
                "Sessions": {
                    "Collected": True,
                    "FailureReason": None,
                    "Results": [
                        {
                            "UserId": victim_sid,
                            "ComputerId": ws_sid,
                        }
                    ],
                },
                "Aces": [],
            },
        ],
    }

    domains_data = {
        "meta": {"type": "domains", "count": 1},
        "data": [
            {
                "ObjectIdentifier": domain_sid,
                "Properties": {
                    "name": "CORP.LOCAL",
                    "domain": "CORP.LOCAL",
                },
                "Aces": [
                    {
                        "PrincipalSID": victim_sid,
                        "PrincipalType": "User",
                        "RightName": "DCSync",
                        "IsInherited": False,
                    }
                ],
            }
        ],
    }

    return {
        "users": users_data,
        "groups": groups_data,
        "computers": computers_data,
        "domains": domains_data,
    }


def test_bloodhound_ingest_sid_resolution_attack_path(tmp_path, sample_bloodhound_data):
    """
    Empirically verifies that BloodHound ACEs referencing SIDs resolve
    to canonical user/group nodes, correctly forming the attack path to DA.
    """
    u_file = tmp_path / "users.json"
    g_file = tmp_path / "groups.json"
    u_file.write_text(json.dumps(sample_bloodhound_data["users"]), encoding="utf-8")
    g_file.write_text(json.dumps(sample_bloodhound_data["groups"]), encoding="utf-8")

    ag = AttackGraph()
    res = ag.ingest_bloodhound(str(tmp_path))
    assert res["nodes_added"] > 0
    assert res["edges_added"] > 0

    # Shortest path from ATTACKER to Domain Admins must succeed
    path = ag.shortest_path_to_da("user:ATTACKER@CORP.LOCAL")
    assert path is not None
    assert path["path_length"] == 3
    assert path["start"] == "ATTACKER@CORP.LOCAL"
    assert path["end"] == "DOMAIN ADMINS@CORP.LOCAL"
    # Ensure steps detail the hops accurately
    assert path["steps"][0]["from"] == "ATTACKER@CORP.LOCAL"
    assert path["steps"][0]["to"] == "VICTIM@CORP.LOCAL"
    assert path["steps"][1]["from"] == "VICTIM@CORP.LOCAL"
    assert path["steps"][1]["to"] == "DOMAIN ADMINS@CORP.LOCAL"


def test_bloodhound_ingest_sessions_and_local_admins(tmp_path, sample_bloodhound_data):
    """
    Verifies that LocalAdmins (AdminTo) and active sessions (HasSession)
    are ingested and allow path traversal from compromised workstation to DA.
    """
    for name, data in sample_bloodhound_data.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")

    ag = AttackGraph()
    res = ag.ingest_bloodhound(str(tmp_path))
    assert res["nodes_added"] > 0
    assert res["edges_added"] > 0

    # WS01 should have admin_to edge from ATTACKER
    attacker_node = "user:ATTACKER@CORP.LOCAL"
    ws_node = "computer:WS01.CORP.LOCAL"
    victim_node = "user:VICTIM@CORP.LOCAL"

    assert ag._g.has_edge(attacker_node, ws_node)
    edge_data = ag._g.get_edge_data(attacker_node, ws_node)
    assert edge_data.get("label") == "admin_to"

    # WS01 should have has_session edge to VICTIM
    assert ag._g.has_edge(ws_node, victim_node)
    session_edge = ag._g.get_edge_data(ws_node, victim_node)
    assert session_edge.get("label") == "has_session"


def test_bloodhound_zip_archive_ingestion(tmp_path, sample_bloodhound_data):
    """
    Verifies that a SharpHound .zip archive is transparently ingested without extraction.
    """
    zip_path = tmp_path / "bloodhound_collection.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sample_bloodhound_data.items():
            zf.writestr(f"{name}.json", json.dumps(data))

    ag = AttackGraph()
    res = ag.ingest_bloodhound(str(zip_path))
    assert res["nodes_added"] > 0
    assert res["edges_added"] > 0
    assert res["file_count"] == 4

    path = ag.shortest_path_to_da("user:ATTACKER@CORP.LOCAL")
    assert path is not None
    assert path["end"] == "DOMAIN ADMINS@CORP.LOCAL"


def test_bloodhound_two_pass_order_independence(tmp_path, sample_bloodhound_data):
    """
    Verifies that file ordering does not break SID resolution:
    groups.json loaded before users.json must still connect perfectly.
    """
    folder = tmp_path / "inverted_order"
    folder.mkdir()
    # Name files so groups sorts first
    (folder / "01_groups.json").write_text(json.dumps(sample_bloodhound_data["groups"]), encoding="utf-8")
    (folder / "02_users.json").write_text(json.dumps(sample_bloodhound_data["users"]), encoding="utf-8")

    ag = AttackGraph()
    res = ag.ingest_bloodhound(str(folder))
    assert res["file_count"] == 2

    path = ag.shortest_path_to_da("user:ATTACKER@CORP.LOCAL")
    assert path is not None
    assert path["start"] == "ATTACKER@CORP.LOCAL"
    assert path["end"] == "DOMAIN ADMINS@CORP.LOCAL"
