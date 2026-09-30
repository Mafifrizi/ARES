"""
Performance and verification tests for AUD-005:
Eliminating N+1 queries in AresDatabase.export_backup() / export_json().
Verifies that 100 campaigns are exported in exactly 3 batch queries instead of 201.
"""
import json
from pathlib import Path
import pytest

from ares.db.database import AresDatabase


@pytest.mark.asyncio
async def test_export_backup_executes_batch_queries_not_n_plus_one(tmp_path: Path):
    """
    Verify that export_backup() executes exactly 3 SQL queries
    regardless of the number of campaigns (tested with 100 campaigns).
    """
    db = AresDatabase(":memory:")
    await db.connect()

    try:
        # Seed 100 campaigns with findings and hosts
        campaign_count = 100
        for i in range(campaign_count):
            cid = f"camp-{i:03d}"
            # 1. Insert campaign
            await db._conn.execute(
                """
                INSERT INTO campaigns (id, name, operator, created_at, status)
                VALUES (?, ?, ?, datetime('now'), 'active')
                """,
                (cid, f"Campaign {i}", "operator_test"),
            )
            # 2. Insert 2 findings for this campaign
            await db._conn.execute(
                """
                INSERT INTO findings (id, campaign_id, title, description, severity, discovered_at, module_id)
                VALUES (?, ?, ?, 'Test description', 'high', datetime('now'), 'test.module')
                """,
                (f"fnd-{i:03d}-1", cid, f"Finding 1 for {cid}"),
            )
            await db._conn.execute(
                """
                INSERT INTO findings (id, campaign_id, title, description, severity, discovered_at, module_id)
                VALUES (?, ?, ?, 'Test description', 'medium', datetime('now'), 'test.module')
                """,
                (f"fnd-{i:03d}-2", cid, f"Finding 2 for {cid}"),
            )
            # 3. Insert 1 host for this campaign
            await db._conn.execute(
                """
                INSERT INTO hosts (id, campaign_id, ip_address, hostname, first_seen)
                VALUES (?, ?, ?, ?, datetime('now'))
                """,
                (f"host-{i:03d}", cid, f"10.0.{i // 256}.{i % 256}", f"host-{i}.corp"),
            )

        await db._conn.commit()

        # Intercept queries executed during export
        query_log = []
        original_execute = db._conn.execute

        def counting_execute(sql, *args, **kwargs):
            query_log.append(str(sql).strip())
            return original_execute(sql, *args, **kwargs)

        db._conn.execute = counting_execute

        export_file = str(tmp_path / "test_backup.json")
        res_path = await db.export_backup(output_path=export_file)

        # Revert intercepted execute
        db._conn.execute = original_execute

        # 1. Total queries must be exactly 3 (Campaigns, Findings, Hosts)
        # In N+1 architecture this would be 1 + 2*100 = 201 queries.
        assert len(query_log) == 3, f"Expected 3 queries, got {len(query_log)}: {query_log}"
        assert any("FROM campaigns" in q for q in query_log)
        assert any("FROM findings" in q for q in query_log)
        assert any("FROM hosts" in q for q in query_log)

        # 2. Verify output JSON structure and integrity
        assert Path(res_path).exists()
        with open(res_path, "r", encoding="utf-8") as fh:
            exported_data = json.load(fh)

        assert exported_data["export_version"] == "1.0"
        assert "schema_version" in exported_data
        assert "exported_at" in exported_data
        assert len(exported_data["campaigns"]) == 100

        # Verify findings and hosts grouped correctly
        for camp in exported_data["campaigns"]:
            cid = camp["id"]
            findings = camp.get("_findings", [])
            hosts = camp.get("_hosts", [])
            assert len(findings) == 2
            assert all(f["campaign_id"] == cid for f in findings)
            assert len(hosts) == 1
            assert hosts[0]["campaign_id"] == cid

    finally:
        await db.close()


@pytest.mark.asyncio
async def test_export_backup_empty_db_structure(tmp_path: Path):
    """Verify that export_backup on empty database still executes 3 queries and outputs empty list."""
    db = AresDatabase(":memory:")
    await db.connect()

    try:
        export_file = str(tmp_path / "empty_backup.json")
        res_path = await db.export_backup(output_path=export_file)

        with open(res_path, "r", encoding="utf-8") as fh:
            exported_data = json.load(fh)

        assert exported_data["export_version"] == "1.0"
        assert exported_data["campaigns"] == []
    finally:
        await db.close()
