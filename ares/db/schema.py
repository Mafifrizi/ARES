"""
ARES Database Schema — v5
SQLite WAL mode via aiosqlite. All credential/token content encrypted at rest.

Tables (v5 additions marked ★):
  schema_version  — migration tracking
  campaigns       — engagement metadata
  findings        — vulnerability findings with MITRE mapping
  hosts           — discovered hosts and services
  credentials     — captured attack credentials (encrypted)
  loot            — captured artifacts (hashes, tokens, files)
  audit_log       — append-only action log
  ★ users         — operator accounts (replaces in-memory dict)
  ★ api_keys      — long-lived API keys for CI/CD automation
  ★ refresh_tokens — JWT refresh tokens with expiry tracking
"""
from __future__ import annotations

SCHEMA_VERSION = 7

CREATE_TABLES = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Campaigns ────────────────────────────────────────────────────────────────
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
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Findings ─────────────────────────────────────────────────────────────────
-- Module execution history (non-sensitive telemetry metadata)
CREATE TABLE IF NOT EXISTS module_runs (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    success         INTEGER NOT NULL DEFAULT 0,
    duration_ms     REAL NOT NULL DEFAULT 0.0,
    completed_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_module_runs_campaign ON module_runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_module_runs_completed ON module_runs(completed_at);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 1.0,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    cvss_score      REAL NOT NULL DEFAULT 0.0,
    cvss_vector     TEXT NOT NULL DEFAULT '',
    trace_id        TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    remediation     TEXT DEFAULT '',
    host            TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    discovered_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_campaign   ON findings(campaign_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_fp         ON findings(false_positive);
CREATE INDEX IF NOT EXISTS idx_findings_mitre      ON findings(mitre_technique);

-- ── Hosts ─────────────────────────────────────────────────────────────────────
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
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(campaign_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_hosts_campaign  ON hosts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip        ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_hosts_domain    ON hosts(domain);

-- ── Credentials ──────────────────────────────────────────────────────────────
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
    cracked_value_enc TEXT,              -- Fernet-encrypted cracked plaintext. MUST be encrypted before writing; never store plaintext here.
    captured_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_creds_campaign  ON credentials(campaign_id);
CREATE INDEX IF NOT EXISTS idx_creds_username  ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_creds_type      ON credentials(cred_type);

-- ── Loot ──────────────────────────────────────────────────────────────────────
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
    captured_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_loot_campaign   ON loot(campaign_id);
CREATE INDEX IF NOT EXISTS idx_loot_type       ON loot(loot_type);

-- ── Audit log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id     TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    actor           TEXT NOT NULL DEFAULT 'system',
    action          TEXT NOT NULL,
    detail          TEXT DEFAULT '',
    module_id       TEXT,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_campaign  ON audit_log(campaign_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor     ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action);

-- ── Users (★ v5) ─────────────────────────────────────────────────────────────
-- Replaces in-memory _users dict in server.py.
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'reporter',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL DEFAULT 'system',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role      ON users(role);

-- ── API Keys (★ v5) ──────────────────────────────────────────────────────────
-- Long-lived keys for CI/CD automation (X-API-Key header).
-- key_hash is bcrypt hash of the actual key (only shown once on creation).
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,           -- first 8 chars shown for identification
    scopes          TEXT NOT NULL DEFAULT 'read',  -- read | write | admin
    is_active       INTEGER NOT NULL DEFAULT 1,
    last_used       TEXT,
    expires_at      TEXT,                    -- NULL = never expires
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_apikeys_user    ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_apikeys_prefix  ON api_keys(key_prefix);

-- ── Refresh Tokens (★ v5) ────────────────────────────────────────────────────
-- Opaque tokens stored in DB; rotated on each use (rotation security).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              TEXT PRIMARY KEY,        -- random UUID = the token itself
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_revoked      INTEGER NOT NULL DEFAULT 0,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    used_at         TEXT                     -- NULL = never used
);

CREATE INDEX IF NOT EXISTS idx_refresh_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_exp     ON refresh_tokens(expires_at);

-- Revoked access token JTIs — allows early revocation before natural expiry (60 min TTL)
CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti         TEXT PRIMARY KEY,            -- JWT jti claim
    user_id     TEXT NOT NULL,
    revoked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL                -- auto-cleaned when past expiry
);
CREATE INDEX IF NOT EXISTS idx_rat_expires ON revoked_access_tokens(expires_at);

-- One-time, campaign-bound WebSocket handshake tickets.
CREATE TABLE IF NOT EXISTS websocket_tickets (
    ticket_hash       TEXT NOT NULL PRIMARY KEY
                      CONSTRAINT ck_ws_ticket_hash CHECK (
                          length(ticket_hash)=64
                          AND ticket_hash NOT GLOB '*[^0-9a-f]*'
                      ),
    campaign_id       TEXT NOT NULL
                      CONSTRAINT fk_ws_ticket_campaign
                      REFERENCES campaigns(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL
                      CONSTRAINT fk_ws_ticket_user
                      REFERENCES users(id) ON DELETE CASCADE,
    credential_kind   TEXT NOT NULL
                      CONSTRAINT ck_ws_ticket_kind CHECK (
                          credential_kind IN ('bearer', 'api_key')
                      ),
    bearer_subject    TEXT,
    bearer_jti        TEXT,
    bearer_expires_at TEXT,
    api_key_id        TEXT
                      CONSTRAINT fk_ws_ticket_api_key
                      REFERENCES api_keys(id) ON DELETE CASCADE,
    required_scope    TEXT,
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    consumed_at       TEXT,
    CONSTRAINT ck_ws_ticket_created_at CHECK (
        strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at)=created_at
    ),
    CONSTRAINT ck_ws_ticket_expires_at CHECK (
        strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at)=expires_at
    ),
    CONSTRAINT ck_ws_ticket_consumed_at CHECK (
        consumed_at IS NULL OR (
            strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) IS NOT NULL
            AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at)=consumed_at
        )
    ),
    CONSTRAINT ck_ws_ticket_time_order CHECK (
        julianday(expires_at) > julianday(created_at)
        AND (
            consumed_at IS NULL
            OR julianday(consumed_at) < julianday(expires_at)
        )
    ),
    CONSTRAINT ck_ws_ticket_source_shape CHECK (
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length(trim(bearer_subject)) > 0
            AND bearer_subject=trim(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length(trim(bearer_jti)) > 0
            AND bearer_jti=trim(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            ) IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            )=bearer_expires_at
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND api_key_id IS NOT NULL
            AND length(trim(api_key_id)) > 0
            AND api_key_id=trim(api_key_id)
            AND required_scope='read'
        )
    )
);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_expires
    ON websocket_tickets(expires_at);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_user
    ON websocket_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_campaign
    ON websocket_tickets(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ws_tickets_api_key
    ON websocket_tickets(api_key_id);
"""

# ── Migration: v4 → v5 ────────────────────────────────────────────────────────
# Applied automatically by AresDatabase.connect() when SCHEMA_VERSION mismatch.

# V5 → V6: adds revoked_access_tokens table for JWT JTI blacklist (logout revocation).
# Databases upgraded from v5 will not have this table — this migration adds it safely
# via CREATE TABLE IF NOT EXISTS so running it on a fresh v6 DB is also a no-op.
MIGRATION_V5_TO_V6 = """
CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rat_expires ON revoked_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_rat_user    ON revoked_access_tokens(user_id);
"""

MIGRATION_V4_TO_V5 = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'reporter',
    is_active INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (datetime('now')), last_login TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role     ON users(role);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, key_hash TEXT NOT NULL, key_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'read', is_active INTEGER NOT NULL DEFAULT 1,
    last_used TEXT, expires_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_apikeys_user   ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_apikeys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')), used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_exp  ON refresh_tokens(expires_at);
"""
