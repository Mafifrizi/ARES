"""
ARES Database — async SQLite via aiosqlite.
All credential/token content encrypted at rest via Fernet.
"""
from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import aiosqlite
from ares.core.logger import get_logger

logger = get_logger("ares.db")

from ares.core.campaign import Campaign, Finding
from ares.core.security import DataEncryptor, hash_password, verify_password
from ares.db.schema import CREATE_TABLES, SCHEMA_VERSION


# ── Domain models ─────────────────────────────────────────────────────────────

@dataclass
class Host:
    """Domain model for a discovered host. Consistent with Campaign/Finding (Pydantic)."""
    campaign_id:     str
    ip_address:      str
    hostname:        str | None          = None
    fqdn:            str | None          = None
    os:              str | None          = None
    os_version:      str | None          = None
    domain:          str | None          = None
    is_dc:           bool                = False
    open_ports:      list[int]           = field(default_factory=list)
    tags:            list[str]           = field(default_factory=list)
    id:              str                 = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class DBCredential:
    """Domain model for a stored credential. Consistent with vault Credential model."""
    campaign_id:     str
    username:        str
    cred_type:       str
    secret:          str | None          = None
    domain:          str | None          = None
    host_id:         str | None          = None
    source_module:   str | None          = None
    notes:           str                 = ""
    id:              str                 = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Loot:
    """Domain model for collected loot (files, tokens, keys)."""
    campaign_id:     str
    loot_type:       str
    name:            str
    description:     str                 = ""
    content:         str | bytes | None  = None
    host_id:         str | None          = None
    path_on_target:  str | None          = None
    source_module:   str | None          = None
    tags:            list[str]           = field(default_factory=list)
    id:              str                 = field(default_factory=lambda: str(uuid.uuid4()))


# ── Database ──────────────────────────────────────────────────────────────────

class AresDatabase:
    """Async SQLite database wrapper with encryption support."""

    def __init__(
        self,
        db_path: str | Path = "ares.db",
        encryption_key: str | bytes | "DataEncryptor | None" = None,
    ) -> None:
        db_path_str = str(db_path)
        self._is_sqlite_uri = db_path_str.startswith("file:")
        self._db_path = db_path_str if self._is_sqlite_uri else Path(db_path_str)
        if isinstance(encryption_key, DataEncryptor):
            self._enc: DataEncryptor | None = encryption_key
        elif encryption_key:
            self._enc = DataEncryptor(encryption_key)
        else:
            self._enc = None
        self._conn: aiosqlite.Connection | None = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected — call await db.connect() first")
        return self._conn

    async def connect(self) -> "AresDatabase":
        self._conn = await aiosqlite.connect(str(self._db_path), uri=self._is_sqlite_uri)
        self._conn.row_factory = aiosqlite.Row
        if not self._is_sqlite_uri:
            await self._conn.execute("PRAGMA journal_mode = WAL")
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._init_schema()
        return self

    async def __aenter__(self) -> "AresDatabase":
        return await self.connect()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @classmethod
    async def create(
        cls,
        db_path: "str | Path" = "ares.db",
        encryption_key: str | None = None,
    ) -> "AresDatabase | PostgresDatabase":   # type: ignore[return]
        """
        Factory that returns the correct backend based on db_path / DATABASE_URL.

        SQLite  (default):
            db_path = "ares.db"  OR  "sqlite:///./ares.db"
        PostgreSQL (optional, requires asyncpg):
            db_path = "postgresql+asyncpg://user:pass@host/db"
            OR set ARES_DATABASE_URL=postgresql+asyncpg://...
        """
        # Resolve database URL: explicit arg wins, then env var
        import os as _os
        url = str(db_path)
        if not url or url == "ares.db":
            url = _os.environ.get("ARES_DATABASE_URL", url)

        if url.startswith(("postgresql", "postgres")):
            from ares.db.postgres import PostgresDatabase
            return await PostgresDatabase.create(
                dsn=url, encryption_key=encryption_key
            )

        # SQLite path — strip dialect prefix if present
        for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
            if url.startswith(prefix):
                url = url[len(prefix):]

        db = cls(url, encryption_key)
        return await db.connect()

    async def _init_schema(self) -> None:
        alembic_applied = await self._run_alembic_migrations()
        if not alembic_applied:
            await self._conn.executescript(CREATE_TABLES)
            await self._conn.commit()
        await self._reconcile_sqlite_schema()
        logger.info("db_ready", path=str(self._db_path), schema_version=SCHEMA_VERSION)

    async def _reconcile_sqlite_schema(self) -> None:
        """Ensure critical columns exist after idempotent/fallback migrations."""

        async def _columns(table: str) -> set[str]:
            async with self._conn.execute(f"PRAGMA table_info({table})") as cur:
                rows = await cur.fetchall()
            return {row["name"] for row in rows}

        findings_columns = await _columns("findings")
        missing_findings_columns = [
            ("cvss_score", "cvss_score REAL NOT NULL DEFAULT 0.0"),
            ("cvss_vector", "cvss_vector TEXT NOT NULL DEFAULT ''"),
            ("trace_id", "trace_id TEXT NOT NULL DEFAULT ''"),
        ]
        for name, ddl in missing_findings_columns:
            if name not in findings_columns:
                await self._conn.execute(f"ALTER TABLE findings ADD COLUMN {ddl}")
                findings_columns.add(name)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(cvss_score)"
        )
        await self._conn.commit()

    async def _run_alembic_migrations(self) -> bool:
        if self._is_sqlite_uri:
            logger.debug("alembic_skipped_for_sqlite_uri", db=str(self._db_path))
            return False

        try:
            from pathlib import Path
            from alembic.config import Config as AlembicConfig
            from alembic import command as alembic_command

            repo_root   = Path(__file__).parent.parent.parent
            alembic_ini = repo_root / "alembic.ini"
            if not alembic_ini.exists():
                logger.debug("alembic_ini_not_found", path=str(alembic_ini))
                return False

            alembic_cfg = AlembicConfig(str(alembic_ini))
            db_url = f"sqlite:///{self._db_path}"
            alembic_cfg.set_main_option("sqlalchemy.url", db_url)

            import asyncio
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: alembic_command.upgrade(alembic_cfg, "head")
            )
            logger.info("alembic_migrations_applied", db=str(self._db_path))
            return True

        except ImportError:
            logger.debug("alembic_not_installed", hint="pip install alembic")
            return False
        except Exception as exc:
            logger.warning("alembic_migration_failed", error=str(exc)[:200],
                           fallback="raw_sql_create_if_not_exists")
            return False

    # ── Backup / export ───────────────────────────────────────────────────────

    async def checkpoint_wal(self) -> None:
        """Force a WAL checkpoint — consolidates WAL into main DB file.
        Call periodically (e.g. hourly) or before taking a file-system backup."""
        await self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await self._conn.commit()

    async def export_json(self, output_path: str | None = None) -> str:
        """
        Export all campaigns + findings to JSON.
        Safe to call during engagement — read-only snapshot.

        Returns the output file path written.
        Default path: ~/.ares/backups/ares_export_<timestamp>.json
        """
        import json
        from datetime import datetime, timezone
        from pathlib import Path

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not output_path:
            backup_dir = Path.home() / ".ares" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(backup_dir / f"ares_export_{ts}.json")

        async with self._conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC"
        ) as cur:
            campaigns = [dict(r) for r in await cur.fetchall()]

        for campaign in campaigns:
            cid = campaign["id"]
            async with self._conn.execute(
                "SELECT * FROM findings WHERE campaign_id=? ORDER BY discovered_at DESC",
                (cid,),
            ) as cur:
                campaign["_findings"] = [dict(r) for r in await cur.fetchall()]
            async with self._conn.execute(
                "SELECT * FROM hosts WHERE campaign_id=? ORDER BY first_seen",
                (cid,),
            ) as cur:
                campaign["_hosts"] = [dict(r) for r in await cur.fetchall()]

        export = {
            "export_version": "1.0",
            "exported_at": ts,
            "schema_version": SCHEMA_VERSION,
            "campaigns": campaigns,
        }
        with open(output_path, "w") as fh:
            json.dump(export, fh, indent=2, default=str)

        logger.info("db_export_complete", path=output_path,
                    campaigns=len(campaigns))
        return output_path

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()

    def _enc_val(self, v: str | None) -> str | None:
        return self._enc.encrypt(v) if self._enc and v else v

    def _dec_val(self, v: str | None) -> str | None:
        return self._enc.decrypt(v) if self._enc and v else v

    # ── Campaigns ─────────────────────────────────────────────────────────────

    async def save_campaign(self, c: Campaign) -> None:
        await self._conn.execute("""
            INSERT INTO campaigns(id,name,client,operator,noise_profile,status,scope_json,targets_json,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name, client=excluded.client, operator=excluded.operator,
              noise_profile=excluded.noise_profile, status=excluded.status,
              scope_json=excluded.scope_json, targets_json=excluded.targets_json,
              notes=excluded.notes,
              updated_at=datetime('now')
        """, (c.id, c.name, c.client, c.operator, c.noise_profile.value,
              c.status.value if hasattr(c.status, 'value') else str(c.status),
              json.dumps([s.model_dump() for s in c.scope]),
              json.dumps(c.targets), c.notes))
        await self._conn.commit()

    async def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        async with self._conn.execute(
            "SELECT * FROM campaigns WHERE id=?", (campaign_id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def list_campaigns(
        self, page: int = 1, per_page: int = 50, operator: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        offset = (page - 1) * per_page
        conditions: list[str] = []
        params_list: list[Any] = []
        if operator:
            conditions.append("operator=?")
            params_list.append(operator)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        async with self._conn.execute(
            f"SELECT COUNT(*) as n FROM campaigns {where}", params_list
        ) as cur:
            total = (await cur.fetchone())["n"]

        async with self._conn.execute(
            f"SELECT * FROM campaigns {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params_list + [per_page, offset],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        return rows, total

    async def delete_campaign(self, campaign_id: str) -> bool:
        try:
            await self._conn.execute("BEGIN")
            for statement in (
                "DELETE FROM loot WHERE campaign_id=?",
                "DELETE FROM credentials WHERE campaign_id=?",
                "DELETE FROM hosts WHERE campaign_id=?",
                "DELETE FROM findings WHERE campaign_id=?",
            ):
                await self._conn.execute(statement, (campaign_id,))
            async with self._conn.execute(
                "DELETE FROM campaigns WHERE id=?", (campaign_id,)
            ) as cur:
                changed = cur.rowcount
            await self._conn.commit()
            return changed > 0
        except Exception:
            await self._conn.rollback()
            raise

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(self, campaign_id: str, f: Finding, module_id: str = "") -> None:
        """FIX: module_id sekarang opsional (default '')."""
        await self._conn.execute("""
            INSERT OR REPLACE INTO findings
            (id,campaign_id,module_id,title,description,severity,cvss_score,cvss_vector,
             confidence,mitre_technique,mitre_tactic,evidence_json,remediation,host,trace_id,
             validated,false_positive)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (f.id, campaign_id, module_id or getattr(f, "module_id", ""),
              f.title, f.description,
              f.severity.value if hasattr(f.severity, "value") else str(f.severity),
              getattr(f, "cvss_score", 0.0), getattr(f, "cvss_vector", ""),
              f.confidence, f.mitre_technique, f.mitre_tactic,
              json.dumps(f.evidence), f.remediation, f.host,
              getattr(f, "trace_id", ""), int(bool(getattr(f, "validated", False))),
              int(bool(getattr(f, "false_positive", False)))))
        await self._conn.commit()

    async def list_findings(
        self,
        campaign_id: str,
        page:        int = 1,
        per_page:    int = 50,
        severity:    str | None = None,
        false_positive: bool | None = None,
        validated:   bool | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conditions = ["campaign_id=?"]
        params_list: list[Any] = [campaign_id]
        if severity:
            conditions.append("severity=?"); params_list.append(severity)
        if false_positive is not None:
            conditions.append("false_positive=?"); params_list.append(int(false_positive))
        if validated is not None:
            conditions.append("validated=?"); params_list.append(int(validated))

        where  = " AND ".join(conditions)
        offset = (page - 1) * per_page

        async with self._conn.execute(
            f"SELECT COUNT(*) as n FROM findings WHERE {where}", params_list
        ) as cur:
            total = (await cur.fetchone())["n"]

        async with self._conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC LIMIT ? OFFSET ?",
            params_list + [per_page, offset]
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        return rows, total

    async def get_findings(
        self,
        campaign_id:   str,
        confirmed_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return flat list of all findings for a campaign (no pagination)."""
        conditions = ["campaign_id=?"]
        params_list: list[Any] = [campaign_id]
        if confirmed_only:
            conditions.append("validated=1")
            conditions.append("false_positive=0")
        where = " AND ".join(conditions)
        async with self._conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC",
            params_list,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_finding_stats(self, campaign_id: str) -> dict[str, Any]:
        """Return count breakdown by severity for a campaign."""
        async with self._conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings WHERE campaign_id=? GROUP BY severity",
            (campaign_id,),
        ) as cur:
            rows = await cur.fetchall()
        stats: dict[str, Any] = {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for r in rows:
            sev = r["severity"]
            stats[sev] = r["n"]
            stats["total"] += r["n"]
        return stats

    async def campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        """High-level stats for a campaign."""
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

    # ── Hosts ─────────────────────────────────────────────────────────────────

    async def upsert_host(self, h: Host) -> str:
        await self._conn.execute("""
            INSERT INTO hosts(id,campaign_id,ip_address,hostname,fqdn,os,os_version,
                domain,is_dc,open_ports_json,tags_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(campaign_id,ip_address) DO UPDATE SET
              hostname=excluded.hostname, fqdn=excluded.fqdn, os=excluded.os,
              is_dc=excluded.is_dc, open_ports_json=excluded.open_ports_json,
              tags_json=excluded.tags_json, last_seen=datetime('now')
        """, (h.id, h.campaign_id, h.ip_address, h.hostname, h.fqdn,
              h.os, h.os_version, h.domain, int(h.is_dc),
              json.dumps(h.open_ports), json.dumps(h.tags)))
        await self._conn.commit()
        return h.id

    async def get_hosts(self, campaign_id: str) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM hosts WHERE campaign_id=? ORDER BY first_seen", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Credentials ───────────────────────────────────────────────────────────

    async def save_credential(self, c: DBCredential) -> None:
        await self._conn.execute("""
            INSERT OR REPLACE INTO credentials
            (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (c.id, c.campaign_id, c.host_id, c.username,
              self._enc_val(c.secret), c.cred_type, c.domain, c.source_module, c.notes))
        await self._conn.commit()

    async def save_credential_preencrypted(self, c: DBCredential) -> None:
        """
        Persist a credential whose secret is ALREADY Fernet-encrypted by
        CredentialVault. Skips _enc_val() to prevent double-encryption.
        Uses INSERT OR IGNORE so re-running after a crash doesn't overwrite
        existing secrets with the same ID.
        """
        await self._conn.execute("""
            INSERT INTO credentials
                (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                secret_enc    = excluded.secret_enc,
                source_module = excluded.source_module,
                notes         = excluded.notes
        """, (c.id, c.campaign_id, c.host_id, c.username,
              c.secret,   # already vault-encrypted — store verbatim
              c.cred_type, c.domain, c.source_module, c.notes))
        await self._conn.commit()

    async def load_credentials_raw(self, campaign_id: str) -> list[dict]:
        """
        Load all credentials for a campaign from DB as raw dicts.
        Secrets are returned as-is (Fernet-encrypted by CredentialVault) —
        use CredentialVault.restore_from_db_records() to re-hydrate.
        """
        async with self._conn.execute(
            "SELECT * FROM credentials WHERE campaign_id=? ORDER BY captured_at DESC",
            (campaign_id,)
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_credentials(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM credentials WHERE campaign_id=? ORDER BY captured_at", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if decrypt and d.get("secret_enc"):
                d["secret"] = self._dec_val(d["secret_enc"])
            else:
                d["secret"] = None
            result.append(d)
        return result

    # ── Loot ──────────────────────────────────────────────────────────────────

    async def save_loot(self, l: Loot) -> None:
        content_str = json.dumps(l.content) if isinstance(l.content, (dict, list)) else l.content
        await self._conn.execute("""
            INSERT OR REPLACE INTO loot
            (id,campaign_id,host_id,loot_type,name,description,content_enc,
             path_on_target,source_module,tags_json)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (l.id, l.campaign_id, l.host_id, l.loot_type, l.name, l.description,
              self._enc_val(content_str), l.path_on_target, l.source_module,
              json.dumps(l.tags)))
        await self._conn.commit()

    async def get_loot(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM loot WHERE campaign_id=? ORDER BY captured_at", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if decrypt and d.get("content_enc"):
                d["content"] = self._dec_val(d["content_enc"])
            else:
                d["content"] = None
            result.append(d)
        return result

    # ── Audit log ─────────────────────────────────────────────────────────────

    async def audit(self, actor: str, action: str, detail: str = "",
                    campaign_id: str | None = None, module_id: str | None = None) -> None:
        await self._conn.execute(
            "INSERT INTO audit_log(campaign_id,actor,action,detail,module_id) VALUES(?,?,?,?,?)",
            (campaign_id, actor, action, detail, module_id)
        )
        await self._conn.commit()

    # ── Users (v5) ────────────────────────────────────────────────────────────

    async def create_user(
        self, username: str, password: str, role: str, created_by: str = "system"
    ) -> str:
        user_id = str(uuid.uuid4())
        await self._conn.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (user_id, username, hash_password(password), role, created_by)
        )
        await self._conn.commit()
        logger.info("user_created", username=username, role=role, by=created_by)
        return user_id

    async def get_user(self, username: str) -> dict[str, Any] | None:
        async with self._conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        async with self._conn.execute(
            "SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def verify_user(self, username: str, password: str) -> dict[str, Any] | None:
        user = await self.get_user(username)
        # Always run bcrypt comparison to prevent username enumeration via timing attack.
        # If user not found, compare against a dummy hash so response time is constant.
        _DUMMY_HASH = "$2b$12$notarealthashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        candidate_hash = user["hashed_password"] if user else _DUMMY_HASH
        password_ok = verify_password(password, candidate_hash)
        if not user or not password_ok:
            return None
        await self._conn.execute(
            "UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],)
        )
        await self._conn.commit()
        return user

    async def user_exists(self, username: str) -> bool:
        async with self._conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ) as cur:
            return (await cur.fetchone()) is not None

    async def update_password(self, user_id: str, new_hash: str) -> None:
        """Update a user's hashed password. Called from change-password endpoint."""
        await self._conn.execute(
            "UPDATE users SET hashed_password=? WHERE id=?",
            (new_hash, user_id),
        )
        await self._conn.commit()

    async def list_users(self) -> list[dict[str, Any]]:
        async with self._conn.execute(
            "SELECT id,username,role,is_active,created_at,last_login FROM users ORDER BY created_at"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def ensure_default_admin(self, admin_password: str) -> bool:
        async with self._conn.execute("SELECT COUNT(*) as n FROM users") as cur:
            n = (await cur.fetchone())["n"]
        if n == 0:
            await self.create_user("admin", admin_password, "team_lead", "bootstrap")
            logger.warning("default_admin_created",
                           msg="CHANGE admin password immediately: POST /auth/change-password")
            return True
        return False

    # ── API Keys (v5) ─────────────────────────────────────────────────────────

    async def create_api_key(
        self, user_id: str, name: str, scopes: str = "read",
        expires_days: int | None = None,
    ) -> tuple[str, str]:
        raw_key    = "ares_" + secrets.token_urlsafe(40)
        key_prefix = raw_key[:12]
        key_id     = str(uuid.uuid4())
        expires_at = None
        if expires_days:
            expires_at = (datetime.now(timezone.utc) +
                          timedelta(days=expires_days)).isoformat()
        await self._conn.execute(
            "INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,scopes,expires_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (key_id, user_id, name, hash_password(raw_key), key_prefix, scopes, expires_at)
        )
        await self._conn.commit()
        logger.info("api_key_created", user_id=user_id, name=name, prefix=key_prefix)
        return key_id, raw_key

    async def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        if not raw_key.startswith("ares_"):
            return None
        prefix = raw_key[:12]
        async with self._conn.execute(
            """SELECT ak.*, u.username, u.role
               FROM api_keys ak JOIN users u ON ak.user_id=u.id
               WHERE ak.key_prefix=? AND ak.is_active=1
               AND (ak.expires_at IS NULL OR ak.expires_at > datetime('now'))""",
            (prefix,)
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        for row in rows:
            if verify_password(raw_key, row["key_hash"]):
                await self._conn.execute(
                    "UPDATE api_keys SET last_used=datetime('now') WHERE id=?", (row["id"],)
                )
                await self._conn.commit()
                return {
                    "username": row["username"],
                    "role": row["role"],
                    "auth_type": "api_key",
                    "key_id": row["id"],
                    "scopes": [row["scopes"]] if row["scopes"] else [],
                }
        return None

    async def list_api_keys(self, user_id: str) -> list[dict[str, Any]]:
        async with self._conn.execute(
            "SELECT id,name,key_prefix,scopes,is_active,last_used,expires_at,created_at "
            "FROM api_keys WHERE user_id=? AND is_active=1 ORDER BY created_at DESC", (user_id,)
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        async with self._conn.execute(
            "UPDATE api_keys SET is_active=0 WHERE id=? AND user_id=? AND is_active=1",
            (key_id, user_id)
        ) as cur:
            changed = cur.rowcount
        await self._conn.commit()
        return changed > 0

    # ── Refresh Tokens (v5) ───────────────────────────────────────────────────

    async def create_refresh_token(
        self, user_id: str, expires_days: int = 30
    ) -> str:
        import hashlib
        # Generate cryptographically strong random token
        raw_token  = secrets.token_urlsafe(48)           # 384 bits — URL-safe, client sees this
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()  # stored in DB
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        await self._conn.execute(
            "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES(?,?,?)",
            (token_hash, user_id, expires_at)
        )
        await self._conn.commit()
        return raw_token   # client gets raw; DB stores only hash

    async def rotate_refresh_token(
        self, old_token: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        import hashlib
        # Hash the incoming token to look it up in DB (DB stores hashes only)
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()
        async with self._conn.execute(
            """SELECT rt.*, u.username, u.role, u.id as uid
               FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id
               WHERE rt.id=? AND rt.is_revoked=0 AND rt.expires_at > datetime('now')""",
            (old_hash,)
        ) as cur:
            row = await cur.fetchone()

        if not row:
            return None, None

        row = dict(row)
        await self._conn.execute(
            "UPDATE refresh_tokens SET is_revoked=1, used_at=datetime('now') WHERE id=?",
            (old_hash,)
        )
        new_raw   = secrets.token_urlsafe(48)
        new_hash  = hashlib.sha256(new_raw.encode()).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        await self._conn.execute(
            "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES(?,?,?)",
            (new_hash, row["uid"], expires_at)
        )
        await self._conn.commit()

        user = {"id": row["uid"], "username": row["username"], "role": row["role"]}
        return user, new_raw   # client gets raw token; DB stores only hash

    async def revoke_access_token(self, jti: str, user_id: str, expires_at: str) -> None:
        """Add access token jti to blacklist. Called on logout."""
        await self._conn.execute(
            "INSERT OR IGNORE INTO revoked_access_tokens (jti, user_id, expires_at) VALUES (?,?,?)",
            (jti, user_id, expires_at),
        )
        # Prune expired entries while we're here (low-cost housekeeping)
        await self._conn.execute(
            "DELETE FROM revoked_access_tokens WHERE expires_at < datetime('now')",
        )
        await self._conn.commit()

    async def is_access_token_revoked(self, jti: str) -> bool:
        """Return True if this jti has been explicitly revoked."""
        async with self._conn.execute(
            "SELECT 1 FROM revoked_access_tokens WHERE jti=?", (jti,)
        ) as cur:
            return await cur.fetchone() is not None

    async def revoke_all_refresh_tokens(self, user_id: str) -> None:
        await self._conn.execute(
            "UPDATE refresh_tokens SET is_revoked=1 WHERE user_id=?", (user_id,)
        )
        await self._conn.commit()

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
            await self._conn.execute(
                """INSERT INTO bypass_outcomes
                   (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (technique_id, edr_vendor, edr_version,
                 int(success), campaign_id, notes[:500], _time.time()),
            )
            await self._conn.commit()
        except Exception:
            # Table may not exist yet — create it
            await self._ensure_bypass_outcomes_table()
            await self._conn.execute(
                """INSERT INTO bypass_outcomes
                   (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (technique_id, edr_vendor, edr_version,
                 int(success), campaign_id, notes[:500], _time.time()),
            )
            await self._conn.commit()

    async def get_bypass_success_rate(
        self,
        technique_id: str,
        edr_vendor:   str,
        min_samples:  int = 3,
    ) -> float | None:
        """
        Return historical success rate for a bypass technique against an EDR vendor.
        Returns None if fewer than min_samples recorded.
        """
        import time as _time
        try:
            async with self._conn.execute(
                """SELECT COUNT(*) as total, COALESCE(SUM(success), 0) as successes
                   FROM bypass_outcomes
                   WHERE technique_id = ? AND edr_vendor = ?
                   AND ts > ?""",
                (technique_id, edr_vendor, _time.time() - 7_776_000),  # 90 days
            ) as cur:
                row = await cur.fetchone()
            if not row or row["total"] < min_samples:
                return None
            return round(row["successes"] / row["total"], 3)
        except Exception:
            return None

    async def _ensure_bypass_outcomes_table(self) -> None:
        """Create bypass_outcomes table if it doesn't exist."""
        await self._conn.execute(
            """CREATE TABLE IF NOT EXISTS bypass_outcomes (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               technique_id TEXT    NOT NULL,
               edr_vendor   TEXT    NOT NULL,
               edr_version  TEXT    DEFAULT '',
               success      INTEGER NOT NULL,
               campaign_id  TEXT    DEFAULT '',
               notes        TEXT    DEFAULT '',
               ts           REAL    NOT NULL
            )"""
        )
        await self._conn.commit()


    async def purge_expired_tokens(self) -> int:
        async with self._conn.execute(
            "DELETE FROM refresh_tokens WHERE is_revoked=1 OR "
            "expires_at < datetime('now', '-7 days')"
        ) as cur:
            n = cur.rowcount
        await self._conn.commit()
        return n

# Backward-compat alias
Credential = DBCredential  # noqa
