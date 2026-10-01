from __future__ import annotations

import json
from ares.worker.cluster import ClusterTask, TaskState


def test_cluster_task_wire_serialization_preserves_credentials():
    task = ClusterTask(
        module_id="ad.kerberoast",
        campaign_id="camp-123",
        params={
            "dc": "10.0.0.1",
            "username": "svc_admin",
            "password": "SecretPassword123!",
            "nt_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        },
        priority=1,
    )

    serialized = task.to_json()
    assert "SecretPassword123!" in serialized
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in serialized

    restored = ClusterTask.from_json(serialized)
    assert restored.params["password"] == "SecretPassword123!"
    assert restored.params["nt_hash"] == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    assert restored.module_id == "ad.kerberoast"


def test_cluster_task_safe_display_redacts_credentials():
    task = ClusterTask(
        module_id="ad.kerberoast",
        campaign_id="camp-123",
        params={
            "dc": "10.0.0.1",
            "username": "svc_admin",
            "password": "SecretPassword123!",
            "nt_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        },
        priority=1,
    )

    safe_dict = task.to_safe_dict()
    assert safe_dict["params"]["password"] == "<REDACTED>"
    assert safe_dict["params"]["nt_hash"] == "<REDACTED>"
    assert safe_dict["params"]["username"] == "svc_admin"
    assert safe_dict["params"]["dc"] == "10.0.0.1"

    safe_json = task.to_safe_json()
    assert "<REDACTED>" in safe_json
    assert "SecretPassword123!" not in safe_json
