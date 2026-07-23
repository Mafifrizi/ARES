"""
ARES Database — PostgreSQL async backend via asyncpg.

Used when ARES_DATABASE_URL starts with postgresql+asyncpg:// or postgresql://.

Install:
    pip install ares-redteam[postgres]      # adds asyncpg>=0.29
    # or:
    pip install asyncpg

Configuration (.env):
    ARES_DATABASE_URL=postgresql+asyncpg://ares_user:strong_password@db:5432/ares_db
    ARES_ENCRYPTION_KEY=<fernet-key>

Design:
  - Same public API as AresDatabase (SQLite) — zero changes to server.py or engine.py
  - asyncpg connection pool (min=2, max=10)
  - All credential/token content encrypted at rest via Fernet (same as SQLite backend)
  - Alembic-managed migrations: `alembic -x db_url=<url> upgrade head`
  - Parameterized queries throughout — no string interpolation

Production checklist:
  □ Create ares_user with CREATEDB privilege or pre-create ares_db
  □ Set ARES_DATABASE_URL in .env (never commit)
  □ Run alembic upgrade head before first start
  □ Set max_connections in postgresql.conf to > (max_workers × pool_max + 5)
"""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from ares.core.logger import get_logger
from ares.core.security import DataEncryptor, hash_password, verify_password

logger = get_logger("ares.db.postgres")


# ── Postgres schema DDL ────────────────────────────────────────────────────────
# Equivalent to schema.py but for PostgreSQL syntax.
# Alembic handles migrations; this DDL is the "create if not exists" fallback.

_PG_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS campaigns (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    client          TEXT NOT NULL DEFAULT 'Internal',
    operator        TEXT NOT NULL DEFAULT 'unknown',
    noise_profile   TEXT NOT NULL DEFAULT 'stealth',
    status          TEXT NOT NULL DEFAULT 'created',
    scope_json      TEXT NOT NULL DEFAULT '[]',
    targets_json    TEXT NOT NULL DEFAULT '[]',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS module_runs (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    success         INTEGER NOT NULL DEFAULT 0,
    duration_ms     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    completed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_module_runs_campaign ON module_runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_module_runs_completed ON module_runs(completed_at);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      FLOAT NOT NULL DEFAULT 1.0,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    cvss_score      FLOAT NOT NULL DEFAULT 0.0,
    cvss_vector     TEXT NOT NULL DEFAULT '',
    trace_id        TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    remediation     TEXT DEFAULT '',
    host            TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_findings_campaign  ON findings(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_pg_findings_fp        ON findings(false_positive);

CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    fqdn            TEXT,
    os              TEXT,
    os_version      TEXT,
    domain          TEXT,
    is_dc           INTEGER NOT NULL DEFAULT 0,
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    tags_json       TEXT NOT NULL DEFAULT '[]',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(campaign_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_pg_hosts_campaign ON hosts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_pg_hosts_ip       ON hosts(ip_address);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    host_id         TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    username        TEXT NOT NULL,
    secret_enc      TEXT,
    cred_type       TEXT NOT NULL,
    domain          TEXT,
    source_module   TEXT,
    notes           TEXT DEFAULT '',
    cracked         INTEGER NOT NULL DEFAULT 0,
    cracked_value_enc TEXT,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_creds_campaign ON credentials(campaign_id);

CREATE TABLE IF NOT EXISTS loot (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    host_id         TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    loot_type       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    content_enc     TEXT,
    size_bytes      INTEGER DEFAULT 0,
    path_on_target  TEXT,
    source_module   TEXT,
    tags_json       TEXT NOT NULL DEFAULT '[]',
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    actor           TEXT NOT NULL DEFAULT 'system',
    action          TEXT NOT NULL,
    detail          TEXT DEFAULT '',
    module_id       TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_audit_campaign ON audit_log(campaign_id);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'reporter',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_users_username ON users(username);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT 'read',
    is_active   INTEGER NOT NULL DEFAULT 1,
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pg_apikeys_user   ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_pg_apikeys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_revoked  INTEGER NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pg_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pg_refresh_exp  ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_rat_expires ON revoked_access_tokens(expires_at);
"""


class PostgresDatabase:
    """
    Async PostgreSQL database backend via asyncpg.
    Public API is identical to AresDatabase (SQLite) — drop-in replacement.

    Usage:
        db = await PostgresDatabase.create(
            dsn            = "postgresql+asyncpg://user:pass@host/db",
            encryption_key = settings.encryption_key_value,
        )
        app.state.db = db
    """

    def __init__(
        self,
        dsn:            str,
        encryption_key: str | None = None,
        pool_min:       int = 2,
        pool_max:       int = 10,
    ) -> None:
        # Strip SQLAlchemy dialect prefix — asyncpg uses plain postgres:// DSN
        self._dsn = (
            dsn
            .replace("postgresql+asyncpg://", "postgresql://")
            .replace("postgres+asyncpg://",   "postgres://")
        )
        self._enc: DataEncryptor | None = DataEncryptor(encryption_key) if encryption_key else None
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: Any = None   # asyncpg.Pool

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def connect(self) -> "PostgresDatabase":
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "asyncpg is required for PostgreSQL support. "
                "Install: pip install ares-redteam[postgres]"
            ) from exc
        self._pool = await asyncpg.create_pool(
            self._dsn,
            min_size=self._pool_min,
            max_size=self._pool_max,
            command_timeout=30,
        )
        await self._init_schema()
        logger.info("pg_db_ready", dsn=self._dsn[:40] + "…")
        return self

    async def __aenter__(self) -> "PostgresDatabase":
        return await self.connect()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @classmethod
    async def create(
        cls,
        dsn:            str,
        encryption_key: str | None = None,
    ) -> "PostgresDatabase":
        db = cls(dsn, encryption_key)
        return await db.connect()

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def _init_schema(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(_PG_CREATE_TABLES)
        logger.info("pg_schema_ready")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _enc_val(self, v: str | None) -> str | None:
        return self._enc.encrypt(v) if self._enc and v else v

    def _dec_val(self, v: str | None) -> str | None:
        return self._enc.decrypt(v) if self._enc and v else v

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        """Convert asyncpg Record to plain dict; convert datetime → ISO string."""
        if row is None:
            return {}
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d

    # ── Campaigns ──────────────────────────────────────────────────────────────

    async def save_campaign(self, c: Any) -> None:
        from ares.core.campaign import Campaign
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO campaigns(id,name,client,operator,noise_profile,status,scope_json,targets_json,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO UPDATE SET
                  name=EXCLUDED.name, client=EXCLUDED.client, operator=EXCLUDED.operator,
                  noise_profile=EXCLUDED.noise_profile, status=EXCLUDED.status,
                  scope_json=EXCLUDED.scope_json, targets_json=EXCLUDED.targets_json,
                  notes=EXCLUDED.notes,
                  updated_at=now()
            """, c.id, c.name, c.client, c.operator,
                c.noise_profile.value if hasattr(c.noise_profile, "value") else str(c.noise_profile),
                c.status.value if hasattr(c.status, "value") else str(c.status),
                json.dumps([s.model_dump() for s in c.scope]),
                json.dumps(c.targets), c.notes)

    async def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_id)
        return self._row_to_dict(row) if row else None

    async def list_campaigns(
        self, page: int = 1, per_page: int = 50, operator: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        offset = (page - 1) * per_page
        where  = "WHERE operator=$1" if operator else ""
        params = [operator] if operator else []

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM campaigns {where}", *params
            )
            rows = await conn.fetch(
                f"SELECT * FROM campaigns {where} ORDER BY created_at DESC LIMIT ${ len(params)+1 } OFFSET ${ len(params)+2 }",
                *params, per_page, offset,
            )
        return [self._row_to_dict(r) for r in rows], total or 0

    async def delete_campaign(self, campaign_id: str) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for statement in (
                    "DELETE FROM loot WHERE campaign_id=$1",
                    "DELETE FROM credentials WHERE campaign_id=$1",
                    "DELETE FROM hosts WHERE campaign_id=$1",
                    "DELETE FROM findings WHERE campaign_id=$1",
                ):
                    await conn.execute(statement, campaign_id)
                result = await conn.execute(
                    "DELETE FROM campaigns WHERE id=$1", campaign_id
                )
        return result == "DELETE 1"

    # ── Findings ───────────────────────────────────────────────────────────────

    async def save_finding(self, campaign_id: str, f: Any, module_id: str = "") -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO findings
                (id,campaign_id,module_id,title,description,severity,cvss_score,cvss_vector,
                 confidence,mitre_technique,mitre_tactic,evidence_json,remediation,host,trace_id,
                 validated,false_positive)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                ON CONFLICT(id) DO UPDATE SET
                  title=EXCLUDED.title, description=EXCLUDED.description,
                  severity=EXCLUDED.severity, evidence_json=EXCLUDED.evidence_json,
                  validated=EXCLUDED.validated, false_positive=EXCLUDED.false_positive
            """, f.id, campaign_id, module_id or getattr(f, "module_id", ""),
                f.title, f.description,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                getattr(f, "cvss_score", 0.0), getattr(f, "cvss_vector", ""),
                f.confidence, f.mitre_technique, f.mitre_tactic,
                json.dumps(f.evidence), f.remediation, f.host,
                getattr(f, "trace_id", ""),
                int(bool(getattr(f, "validated", False))),
                int(bool(getattr(f, "false_positive", False))))

    async def list_findings(
        self,
        campaign_id:    str,
        page:           int = 1,
        per_page:       int = 50,
        severity:       str | None = None,
        false_positive: bool | None = None,
        validated:      bool | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conditions = ["campaign_id=$1"]
        params: list[Any] = [campaign_id]

        if severity:
            params.append(severity);        conditions.append(f"severity=${len(params)}")
        if false_positive is not None:
            params.append(int(false_positive)); conditions.append(f"false_positive=${len(params)}")
        if validated is not None:
            params.append(int(validated));  conditions.append(f"validated=${len(params)}")

        where  = " AND ".join(conditions)
        offset = (page - 1) * per_page

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(f"SELECT COUNT(*) FROM findings WHERE {where}", *params)
            params_page = params + [per_page, offset]
            rows = await conn.fetch(
                f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC"
                f" LIMIT ${len(params)+1} OFFSET ${len(params)+2}",
                *params_page,
            )
        return [self._row_to_dict(r) for r in rows], total or 0

    async def get_findings(self, campaign_id: str, confirmed_only: bool = False) -> list[dict]:
        where = (
            "campaign_id=$1 AND validated=1 AND false_positive=0"
            if confirmed_only
            else "campaign_id=$1"
        )
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC",
                campaign_id,
            )
        return [self._row_to_dict(r) for r in rows]

    async def get_finding_stats(self, campaign_id: str) -> dict[str, Any]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT severity, COUNT(*) as n FROM findings WHERE campaign_id=$1 GROUP BY severity",
                campaign_id,
            )
        stats: dict[str, Any] = {"total": 0, "critical":0,"high":0,"medium":0,"low":0,"info":0}
        for r in rows:
            stats[r["severity"]] = r["n"]
            stats["total"] += r["n"]
        return stats

    async def get_monthly_confirmed_finding_stats(self) -> dict[str, Any]:
        """Return confirmed findings grouped by day in the current UTC month."""
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if period_start.month == 12:
            next_month = period_start.replace(year=period_start.year + 1, month=1)
        else:
            next_month = period_start.replace(month=period_start.month + 1)
        period = period_start.strftime("%Y-%m")
        async with self._pool.acquire() as conn:
            confirmed_findings = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE validated=1
                  AND false_positive=0
                """
            )
            rows = await conn.fetch(
                """
                SELECT (discovered_at AT TIME ZONE 'UTC')::date AS finding_date,
                       COUNT(*) AS n
                FROM findings
                WHERE validated=1
                  AND false_positive=0
                  AND discovered_at >= $1
                  AND discovered_at < $2
                GROUP BY 1
                ORDER BY 1
                """,
                period_start,
                next_month,
            )
        series = [
            {"date": row["finding_date"].isoformat(), "count": int(row["n"])}
            for row in rows
        ]
        return {
            "period": period,
            "label": "Security signals this cycle",
            "total": sum(item["count"] for item in series),
            "confirmed_findings": int(confirmed_findings or 0),
            "series": series,
        }

    # ── Hosts ──────────────────────────────────────────────────────────────────

    async def record_module_run(
        self,
        campaign_id: str,
        module_id: str,
        outcome: str,
        success: bool,
        duration_ms: float,
    ) -> None:
        """Persist non-sensitive execution metadata for restart-safe telemetry."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO module_runs
                    (id, campaign_id, module_id, outcome, success, duration_ms, completed_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                str(uuid.uuid4()),
                campaign_id,
                module_id,
                outcome,
                int(bool(success)),
                max(0.0, float(duration_ms or 0.0)),
                datetime.now(timezone.utc),
            )

    async def get_telemetry_stats(self) -> dict[str, Any]:
        """Aggregate persisted execution, finding, and discovered-host telemetry."""
        async with self._pool.acquire() as conn:
            run_rows = await conn.fetch(
                "SELECT success, duration_ms, completed_at FROM module_runs ORDER BY completed_at"
            )
            confirmed_findings = int(
                await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM findings
                    WHERE validated=1 AND false_positive=0
                    """
                )
                or 0
            )
            discovered_hosts = int(await conn.fetchval("SELECT COUNT(*) FROM hosts") or 0)

        total = len(run_rows)
        success = sum(int(row["success"]) for row in run_rows)
        failed = total - success
        durations = sorted(float(row["duration_ms"] or 0.0) for row in run_rows)

        def percentile(fraction: float) -> float | None:
            if not durations:
                return None
            index = max(0, min(len(durations) - 1, int(len(durations) * fraction + 0.999999) - 1))
            return round(durations[index], 1)

        recent_cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        recent_runs = sum(
            1
            for row in run_rows
            if row["completed_at"] is not None and row["completed_at"] >= recent_cutoff
        )
        return {
            "modules": {
                "total": total,
                "success": success,
                "failed": failed,
                "error_rate": failed / total if total else 0.0,
            },
            "findings": confirmed_findings,
            "latency_ms": {
                "p50": percentile(0.50),
                "p95": percentile(0.95),
                "p99": percentile(0.99),
            },
            "throughput": {
                "tasks_per_min": float(recent_runs) if recent_runs else None,
            },
            "hosts": {
                "available": False,
                "discovered": discovered_hosts,
                "owned": None,
            },
        }

    async def upsert_host(self, h: Any) -> str:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO hosts(id,campaign_id,ip_address,hostname,fqdn,os,os_version,
                    domain,is_dc,open_ports_json,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT(campaign_id,ip_address) DO UPDATE SET
                  hostname=EXCLUDED.hostname, os=EXCLUDED.os, is_dc=EXCLUDED.is_dc,
                  open_ports_json=EXCLUDED.open_ports_json, last_seen=now()
            """, h.id, h.campaign_id, h.ip_address, h.hostname, h.fqdn,
                h.os, h.os_version, h.domain, int(h.is_dc),
                json.dumps(h.open_ports), json.dumps(h.tags))
        return h.id

    async def get_hosts(self, campaign_id: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM hosts WHERE campaign_id=$1 ORDER BY first_seen", campaign_id
            )
        return [self._row_to_dict(r) for r in rows]

    # ── Credentials ────────────────────────────────────────────────────────────

    async def save_credential(self, c: Any) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO credentials
                (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO NOTHING
            """, c.id, c.campaign_id, c.host_id, c.username,
                self._enc_val(c.secret), c.cred_type, c.domain, c.source_module, c.notes)

    async def get_credentials(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM credentials WHERE campaign_id=$1 ORDER BY captured_at", campaign_id
            )
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            d["secret"] = self._dec_val(d.get("secret_enc")) if decrypt else None
            result.append(d)
        return result

    async def save_credential_preencrypted(self, cred: Any) -> None:
        """
        Persist a credential whose secret is ALREADY Fernet-encrypted by
        CredentialVault. Skips _enc_val() to prevent double-encryption.
        Mirrors database.py implementation — required by engine._persist_vault_credentials().
        """
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO credentials
                    (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT(id) DO UPDATE SET
                    secret_enc    = EXCLUDED.secret_enc,
                    source_module = EXCLUDED.source_module,
                    notes         = EXCLUDED.notes
            """, cred.id, cred.campaign_id, cred.host_id, cred.username,
                cred.secret,   # already vault-encrypted — store verbatim, no _enc_val()
                cred.cred_type, cred.domain, cred.source_module, cred.notes)

    async def load_credentials_raw(self, campaign_id: str) -> list[dict]:
        """
        Load all credentials for a campaign as raw dicts.
        Secrets returned as-is (Fernet-encrypted by CredentialVault) —
        use CredentialVault.restore_from_db_records() to re-hydrate.
        Required by server.py POST /campaigns/{id}/restore-vault endpoint.
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM credentials WHERE campaign_id=$1 ORDER BY captured_at DESC",
                campaign_id,
            )
        return [self._row_to_dict(r) for r in rows]

    # ── Loot ───────────────────────────────────────────────────────────────────

    async def save_loot(self, l: Any) -> None:
        content_str = json.dumps(l.content) if isinstance(l.content, (dict, list)) else l.content
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO loot
                (id,campaign_id,host_id,loot_type,name,description,content_enc,
                 path_on_target,source_module,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                ON CONFLICT(id) DO NOTHING
            """, l.id, l.campaign_id, l.host_id, l.loot_type, l.name, l.description,
                self._enc_val(content_str), l.path_on_target, l.source_module,
                json.dumps(l.tags))

    async def get_loot(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM loot WHERE campaign_id=$1 ORDER BY captured_at", campaign_id
            )
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            d["content"] = self._dec_val(d.get("content_enc")) if decrypt else None
            result.append(d)
        return result

    async def save_campaign_graph(self, campaign_id: str, graph: dict[str, Any]) -> None:
        """Persist a sanitized graph snapshot in the existing encrypted loot store."""
        graph_id = f"campaign_graph:{campaign_id}"
        payload = json.dumps(graph, separators=(",", ":"))
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO loot
                    (id,campaign_id,loot_type,name,description,content_enc,source_module,tags_json)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                ON CONFLICT(id) DO UPDATE SET
                  description=EXCLUDED.description,
                  content_enc=EXCLUDED.content_enc,
                  source_module=EXCLUDED.source_module,
                  tags_json=EXCLUDED.tags_json,
                  captured_at=now()
                """,
                graph_id,
                campaign_id,
                "campaign_graph",
                "durable_attack_graph",
                "Sanitized artifact and BloodHound graph snapshot",
                self._enc_val(payload),
                "core.graph",
                json.dumps(["runtime", "safe-metadata"]),
            )

    async def get_campaign_graph(self, campaign_id: str) -> dict[str, Any] | None:
        """Load the safe graph snapshot without returning general decrypted loot."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT content_enc FROM loot
                WHERE id=$1 AND campaign_id=$2 AND loot_type='campaign_graph'
                """,
                f"campaign_graph:{campaign_id}",
                campaign_id,
            )
        if not row or not row["content_enc"]:
            return None
        try:
            decoded = self._dec_val(row["content_enc"])
            parsed = json.loads(decoded) if decoded else None
            return parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            logger.warning("campaign_graph_snapshot_invalid", campaign_id=campaign_id[:8])
            return None

    async def campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        findings = await self.get_findings(campaign_id)
        hosts    = await self.get_hosts(campaign_id)
        creds    = await self.get_credentials(campaign_id)
        loot     = await self.get_loot(campaign_id)
        return {
            "campaign_id":      campaign_id,
            "findings":         findings,
            "finding_count":    len(findings),
            "host_count":       len(hosts),
            "credential_count": len(creds),
            "loot_count":       len(loot),
        }

    # ── Audit ──────────────────────────────────────────────────────────────────

    async def audit(self, actor: str, action: str, detail: str = "",
                    campaign_id: str | None = None, module_id: str | None = None) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_log(campaign_id,actor,action,detail,module_id) VALUES($1,$2,$3,$4,$5)",
                campaign_id, actor, action, detail, module_id,
            )

    # ── Users ──────────────────────────────────────────────────────────────────

    async def create_user(self, username: str, password: str, role: str,
                          created_by: str = "system") -> str:
        user_id = str(uuid.uuid4())
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES($1,$2,$3,$4,$5)",
                user_id, username, hash_password(password), role, created_by,
            )
        logger.info("user_created", username=username, role=role)
        return user_id

    async def get_user(self, username: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE username=$1 AND is_active=1", username
            )
        return self._row_to_dict(row) if row else None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM users WHERE id=$1 AND is_active=1", user_id
            )
        return self._row_to_dict(row) if row else None

    async def verify_user(self, username: str, password: str) -> dict[str, Any] | None:
        user = await self.get_user(username)
        _DUMMY = "$2b$12$notarealthashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        candidate = user["hashed_password"] if user else _DUMMY
        if not user or not verify_password(password, candidate):
            return None
        async with self._pool.acquire() as conn:
            await conn.execute("UPDATE users SET last_login=now() WHERE id=$1", user["id"])
        return user

    async def user_exists(self, username: str) -> bool:
        async with self._pool.acquire() as conn:
            return bool(await conn.fetchval(
                "SELECT 1 FROM users WHERE username=$1", username
            ))

    async def update_password(self, user_id: str, new_hash: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET hashed_password=$1 WHERE id=$2", new_hash, user_id
            )

    async def list_users(self) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id,username,role,is_active,created_at,last_login FROM users ORDER BY created_at"
            )
        return [self._row_to_dict(r) for r in rows]

    async def ensure_default_admin(self, admin_password: str) -> bool:
        async with self._pool.acquire() as conn:
            n = await conn.fetchval("SELECT COUNT(*) FROM users")
        if n == 0:
            await self.create_user("admin", admin_password, "team_lead", "bootstrap")
            logger.warning("default_admin_created",
                           msg="CHANGE password immediately: POST /auth/change-password")
            return True
        return False

    # ── API Keys ───────────────────────────────────────────────────────────────

    async def create_api_key(self, user_id: str, name: str, scopes: str = "read",
                             expires_days: int | None = None) -> tuple[str, str]:
        raw_key    = "ares_" + secrets.token_urlsafe(40)
        key_prefix = raw_key[:12]
        key_id     = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat() \
                     if expires_days else None
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,scopes,expires_at) "
                "VALUES($1,$2,$3,$4,$5,$6,$7)",
                key_id, user_id, name, hash_password(raw_key), key_prefix, scopes, expires_at,
            )
        return key_id, raw_key

    async def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        if not raw_key.startswith("ares_"):
            return None
        prefix = raw_key[:12]
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT ak.*, u.username, u.role
                   FROM api_keys ak JOIN users u ON ak.user_id=u.id
                   WHERE ak.key_prefix=$1 AND ak.is_active=1
                   AND (ak.expires_at IS NULL OR ak.expires_at > now())""",
                prefix,
            )
        for row in rows:
            d = self._row_to_dict(row)
            if verify_password(raw_key, d["key_hash"]):
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE api_keys SET last_used=now() WHERE id=$1", d["id"]
                    )
                return {
                    "username": d["username"],
                    "role": d["role"],
                    "auth_type": "api_key",
                    "key_id": d["id"],
                    "scopes": [d["scopes"]] if d.get("scopes") else [],
                }
        return None

    async def list_api_keys(self, user_id: str) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id,name,key_prefix,scopes,is_active,last_used,expires_at,created_at "
                "FROM api_keys WHERE user_id=$1 AND is_active=1 ORDER BY created_at DESC", user_id,
            )
        return [self._row_to_dict(r) for r in rows]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET is_active=0 WHERE id=$1 AND user_id=$2", key_id, user_id
            )
        return True

    # ── Refresh Tokens ─────────────────────────────────────────────────────────

    async def create_refresh_token(self, user_id: str, expires_days: int = 30) -> str:
        import hashlib, secrets
        raw_token  = secrets.token_urlsafe(48)                          # returned to client
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()     # stored in DB
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES($1,$2,$3)",
                token_hash, user_id, expires_at,   # store hash, not raw
            )
        return raw_token   # client gets raw token; DB stores only SHA-256 hash

    async def rotate_refresh_token(self, old_token: str) -> tuple[dict | None, str | None]:
        import hashlib, secrets
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()   # look up by hash
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT rt.*, u.username, u.role, u.id as uid
                   FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id
                   WHERE rt.id=$1 AND rt.is_revoked=0 AND rt.expires_at > now()""",
                old_hash,
            )
            if not row:
                return None, None
            d = self._row_to_dict(row)
            await conn.execute(
                "UPDATE refresh_tokens SET is_revoked=1, used_at=now() WHERE id=$1", old_hash
            )
            new_raw   = secrets.token_urlsafe(48)
            new_hash  = hashlib.sha256(new_raw.encode()).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            await conn.execute(
                "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES($1,$2,$3)",
                new_hash, d["uid"], expires_at,   # store hash
            )
        user = {"id": d["uid"], "username": d["username"], "role": d["role"]}
        return user, new_raw   # return raw to client

    async def revoke_access_token(self, jti: str, user_id: str, expires_at: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO revoked_access_tokens(jti,user_id,expires_at) VALUES($1,$2,$3) "
                "ON CONFLICT(jti) DO NOTHING",
                jti, user_id, expires_at,
            )
            await conn.execute(
                "DELETE FROM revoked_access_tokens WHERE expires_at < now()"
            )

    async def is_access_token_revoked(self, jti: str) -> bool:
        async with self._pool.acquire() as conn:
            return bool(await conn.fetchval(
                "SELECT 1 FROM revoked_access_tokens WHERE jti=$1", jti
            ))

    async def revoke_all_refresh_tokens(self, user_id: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET is_revoked=1 WHERE user_id=$1", user_id
            )

    async def purge_expired_tokens(self) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM refresh_tokens WHERE is_revoked=1 OR expires_at < now() - interval '7 days'"
            )
        # asyncpg returns "DELETE N" as a string
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    # ── Bypass outcome tracking (cross-session EDR learning) ──────────────

    async def save_bypass_outcome(
        self,
        technique_id: str,
        edr_vendor:   str,
        edr_version:  str,
        success:      bool,
        campaign_id:  str,
        notes:        str = "",
    ) -> None:
        """Persist bypass technique outcome for cross-session learning."""
        import time as _time
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO bypass_outcomes
                       (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                    technique_id, edr_vendor, edr_version,
                    int(success), campaign_id, notes[:500], _time.time(),
                )
        except Exception:
            await self._ensure_bypass_outcomes_table()
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO bypass_outcomes
                       (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                    technique_id, edr_vendor, edr_version,
                    int(success), campaign_id, notes[:500], _time.time(),
                )

    async def get_bypass_success_rate(
        self,
        technique_id: str,
        edr_vendor:   str,
        min_samples:  int = 3,
    ) -> float | None:
        """Return historical success rate for a bypass technique against an EDR vendor."""
        import time as _time
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """SELECT COUNT(*) as total, COALESCE(SUM(success), 0) as successes
                       FROM bypass_outcomes
                       WHERE technique_id = $1 AND edr_vendor = $2
                       AND ts > $3""",
                    technique_id, edr_vendor, _time.time() - 7_776_000,
                )
            if not row or row["total"] < min_samples:
                return None
            return round(row["successes"] / row["total"], 3)
        except Exception:
            return None

    async def _ensure_bypass_outcomes_table(self) -> None:
        """Create bypass_outcomes table if it doesn't exist."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """CREATE TABLE IF NOT EXISTS bypass_outcomes (
                   id           SERIAL PRIMARY KEY,
                   technique_id TEXT    NOT NULL,
                   edr_vendor   TEXT    NOT NULL,
                   edr_version  TEXT    DEFAULT '',
                   success      INTEGER NOT NULL,
                   campaign_id  TEXT    DEFAULT '',
                   notes        TEXT    DEFAULT '',
                   ts           DOUBLE PRECISION NOT NULL
                )"""
            )

    async def checkpoint_wal(self) -> None:
        """No-op for PostgreSQL — WAL is managed by the server."""

    async def export_json(self, output_path: str | None = None) -> str:
        """Export all campaigns + findings to JSON (same interface as SQLite backend)."""
        import json as _json
        from pathlib import Path
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not output_path:
            backup_dir = Path.home() / ".ares" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(backup_dir / f"ares_export_{ts}.json")

        async with self._pool.acquire() as conn:
            campaigns = [self._row_to_dict(r)
                         for r in await conn.fetch("SELECT * FROM campaigns ORDER BY created_at DESC")]
        for c in campaigns:
            cid = c["id"]
            async with self._pool.acquire() as conn:
                c["_findings"] = [self._row_to_dict(r)
                                  for r in await conn.fetch(
                                      "SELECT * FROM findings WHERE campaign_id=$1 ORDER BY discovered_at DESC",
                                      cid)]
                c["_hosts"]    = [self._row_to_dict(r)
                                  for r in await conn.fetch(
                                      "SELECT * FROM hosts WHERE campaign_id=$1 ORDER BY first_seen", cid)]

        export = {"export_version": "1.0", "exported_at": ts, "campaigns": campaigns}
        with open(output_path, "w") as fh:
            _json.dump(export, fh, indent=2, default=str)
        logger.info("pg_export_complete", path=output_path, campaigns=len(campaigns))
        return output_path
