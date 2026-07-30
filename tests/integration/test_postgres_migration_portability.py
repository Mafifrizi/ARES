"""Real PostgreSQL execution tests for the historical Alembic chain."""
from __future__ import annotations

import asyncio
import builtins
import importlib
import importlib.machinery
import multiprocessing
import os
import re
import sys
import threading
import time
import types
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POSTGRES_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_SAFE_DATABASE_NAME = re.compile(r"^ares_migration_[0-9a-f]{32}$")
_SAFE_EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_WORKER_TIMEOUT_SECONDS = 45.0
_WORKER_SETTLE_SECONDS = 5.0
_POSTGRES_OPERATION_TIMEOUT_SECONDS = 15.0
_WORKER_POLL_SECONDS = 0.01
_OWNED_WORKERS: set[_OwnedWorker] = set()
_EXPECTED_TABLES = {
    "campaigns",
    "module_runs",
    "findings",
    "hosts",
    "credentials",
    "loot",
    "audit_log",
    "users",
    "api_keys",
    "refresh_tokens",
    "revoked_access_tokens",
    "rate_limit_events",
}
_EXPECTED_FOREIGN_KEYS = {
    ("module_runs", "campaign_id", "campaigns", "CASCADE"),
    ("findings", "campaign_id", "campaigns", "CASCADE"),
    ("hosts", "campaign_id", "campaigns", "CASCADE"),
    ("credentials", "campaign_id", "campaigns", "CASCADE"),
    ("credentials", "host_id", "hosts", "SET NULL"),
    ("loot", "campaign_id", "campaigns", "CASCADE"),
    ("loot", "host_id", "hosts", "SET NULL"),
    ("audit_log", "campaign_id", "campaigns", "SET NULL"),
    ("api_keys", "user_id", "users", "CASCADE"),
    ("refresh_tokens", "user_id", "users", "CASCADE"),
}
_EXPECTED_INDEXES = {
    "idx_module_runs_campaign": ("campaign_id",),
    "idx_module_runs_completed": ("completed_at",),
    "idx_findings_campaign": ("campaign_id",),
    "idx_findings_severity": ("severity",),
    "idx_findings_fp": ("false_positive",),
    "idx_findings_mitre": ("mitre_technique",),
    "idx_findings_cvss": ("cvss_score",),
    "idx_hosts_campaign": ("campaign_id",),
    "idx_hosts_ip": ("ip_address",),
    "idx_hosts_domain": ("domain",),
    "idx_creds_campaign": ("campaign_id",),
    "idx_creds_username": ("username",),
    "idx_creds_type": ("cred_type",),
    "idx_loot_campaign": ("campaign_id",),
    "idx_loot_type": ("loot_type",),
    "idx_audit_campaign": ("campaign_id",),
    "idx_audit_actor": ("actor",),
    "idx_audit_action": ("action",),
    "idx_users_username": ("username",),
    "idx_users_role": ("role",),
    "idx_apikeys_user": ("user_id",),
    "idx_apikeys_prefix": ("key_prefix",),
    "idx_refresh_user": ("user_id",),
    "idx_refresh_exp": ("expires_at",),
    "idx_rat_expires": ("expires_at",),
    "idx_rle_ip": ("ip_address",),
    "idx_rle_timestamp": ("timestamp",),
    "idx_rle_blocked": ("blocked",),
}
_POSTGRES_INDEX_TABLES = {
    "idx_module_runs_campaign": "module_runs",
    "idx_module_runs_completed": "module_runs",
    "idx_findings_campaign": "findings",
    "idx_findings_severity": "findings",
    "idx_findings_fp": "findings",
    "idx_findings_mitre": "findings",
    "idx_findings_cvss": "findings",
    "idx_hosts_campaign": "hosts",
    "idx_hosts_ip": "hosts",
    "idx_hosts_domain": "hosts",
    "idx_creds_campaign": "credentials",
    "idx_creds_username": "credentials",
    "idx_creds_type": "credentials",
    "idx_loot_campaign": "loot",
    "idx_loot_type": "loot",
    "idx_audit_campaign": "audit_log",
    "idx_audit_actor": "audit_log",
    "idx_audit_action": "audit_log",
    "idx_users_username": "users",
    "idx_users_role": "users",
    "idx_apikeys_user": "api_keys",
    "idx_apikeys_prefix": "api_keys",
    "idx_refresh_user": "refresh_tokens",
    "idx_refresh_exp": "refresh_tokens",
    "idx_rat_expires": "revoked_access_tokens",
    "idx_rle_ip": "rate_limit_events",
    "idx_rle_timestamp": "rate_limit_events",
    "idx_rle_blocked": "rate_limit_events",
}
_EXPECTED_COLUMN_ORDER = {
    "campaigns": (
        "id", "name", "client", "operator", "noise_profile", "status",
        "scope_json", "targets_json", "notes", "created_at", "updated_at",
    ),
    "module_runs": (
        "id", "campaign_id", "module_id", "outcome", "success",
        "duration_ms", "completed_at",
    ),
    "findings": (
        "id", "campaign_id", "module_id", "title", "description",
        "severity", "confidence", "mitre_technique", "mitre_tactic",
        "cvss_score", "cvss_vector", "evidence_json", "remediation",
        "host", "validated", "false_positive", "discovered_at", "trace_id",
    ),
    "hosts": (
        "id", "campaign_id", "ip_address", "hostname", "fqdn", "os",
        "os_version", "domain", "is_dc", "open_ports_json", "tags_json",
        "first_seen", "last_seen",
    ),
    "credentials": (
        "id", "campaign_id", "host_id", "username", "secret_enc",
        "cred_type", "domain", "source_module", "notes", "cracked",
        "cracked_value_enc", "captured_at",
    ),
    "loot": (
        "id", "campaign_id", "host_id", "loot_type", "name",
        "description", "content_enc", "size_bytes", "path_on_target",
        "source_module", "tags_json", "captured_at",
    ),
    "audit_log": (
        "id", "campaign_id", "actor", "action", "detail", "module_id",
        "timestamp",
    ),
    "users": (
        "id", "username", "hashed_password", "role", "is_active",
        "created_by", "created_at", "last_login",
    ),
    "api_keys": (
        "id", "user_id", "name", "key_hash", "key_prefix", "scopes",
        "is_active", "last_used", "expires_at", "created_at",
    ),
    "refresh_tokens": (
        "id", "user_id", "is_revoked", "expires_at", "created_at",
        "used_at",
    ),
    "revoked_access_tokens": (
        "jti", "user_id", "revoked_at", "expires_at",
    ),
    "rate_limit_events": (
        "id", "ip_address", "bucket", "username", "blocked", "timestamp",
    ),
}
_POSTGRES_INTEGER_COLUMNS = {
    ("module_runs", "success"),
    ("hosts", "is_dc"),
    ("credentials", "cracked"),
    ("loot", "size_bytes"),
    ("audit_log", "id"),
    ("users", "is_active"),
    ("api_keys", "is_active"),
    ("refresh_tokens", "is_revoked"),
    ("rate_limit_events", "id"),
    ("rate_limit_events", "blocked"),
    ("findings", "validated"),
    ("findings", "false_positive"),
}
_POSTGRES_FLOAT_COLUMNS = {
    ("module_runs", "duration_ms"),
    ("findings", "confidence"),
    ("findings", "cvss_score"),
}
_POSTGRES_TIMESTAMP_COLUMNS = {
    ("campaigns", "created_at"),
    ("campaigns", "updated_at"),
    ("module_runs", "completed_at"),
    ("findings", "discovered_at"),
    ("hosts", "first_seen"),
    ("hosts", "last_seen"),
    ("credentials", "captured_at"),
    ("loot", "captured_at"),
    ("audit_log", "timestamp"),
    ("users", "created_at"),
    ("users", "last_login"),
    ("api_keys", "last_used"),
    ("api_keys", "expires_at"),
    ("api_keys", "created_at"),
    ("refresh_tokens", "expires_at"),
    ("refresh_tokens", "created_at"),
    ("refresh_tokens", "used_at"),
    ("revoked_access_tokens", "revoked_at"),
    ("revoked_access_tokens", "expires_at"),
    ("rate_limit_events", "timestamp"),
}
_POSTGRES_FINITE_TIMESTAMP_CONSTRAINTS = {
    ("campaigns", "created_at"): (
        "ck_campaigns_created_at_finite",
        False,
    ),
    ("campaigns", "updated_at"): (
        "ck_campaigns_updated_at_finite",
        False,
    ),
    ("module_runs", "completed_at"): (
        "ck_module_runs_completed_at_finite",
        False,
    ),
    ("findings", "discovered_at"): (
        "ck_findings_discovered_at_finite",
        False,
    ),
    ("hosts", "first_seen"): ("ck_hosts_first_seen_finite", False),
    ("hosts", "last_seen"): ("ck_hosts_last_seen_finite", False),
    ("credentials", "captured_at"): (
        "ck_credentials_captured_at_finite",
        False,
    ),
    ("loot", "captured_at"): ("ck_loot_captured_at_finite", False),
    ("audit_log", "timestamp"): ("ck_audit_log_timestamp_finite", False),
    ("users", "created_at"): ("ck_users_created_at_finite", False),
    ("users", "last_login"): ("ck_users_last_login_finite", True),
    ("api_keys", "last_used"): ("ck_api_keys_last_used_finite", True),
    ("api_keys", "expires_at"): ("ck_api_keys_expires_at_finite", True),
    ("api_keys", "created_at"): ("ck_api_keys_created_at_finite", False),
    ("refresh_tokens", "expires_at"): (
        "ck_refresh_tokens_expires_at_finite",
        False,
    ),
    ("refresh_tokens", "created_at"): (
        "ck_refresh_tokens_created_at_finite",
        False,
    ),
    ("refresh_tokens", "used_at"): (
        "ck_refresh_tokens_used_at_finite",
        True,
    ),
    ("revoked_access_tokens", "revoked_at"): (
        "ck_revoked_access_tokens_revoked_at_finite",
        False,
    ),
    ("revoked_access_tokens", "expires_at"): (
        "ck_revoked_access_tokens_expires_at_finite",
        False,
    ),
    ("rate_limit_events", "timestamp"): (
        "ck_rate_limit_events_timestamp_finite",
        False,
    ),
}
_POSTGRES_NULLABLE_COLUMNS = {
    ("campaigns", "notes"),
    ("findings", "mitre_technique"),
    ("findings", "mitre_tactic"),
    ("findings", "remediation"),
    ("findings", "host"),
    ("hosts", "hostname"),
    ("hosts", "fqdn"),
    ("hosts", "os"),
    ("hosts", "os_version"),
    ("hosts", "domain"),
    ("credentials", "host_id"),
    ("credentials", "secret_enc"),
    ("credentials", "domain"),
    ("credentials", "source_module"),
    ("credentials", "notes"),
    ("credentials", "cracked_value_enc"),
    ("loot", "host_id"),
    ("loot", "description"),
    ("loot", "content_enc"),
    ("loot", "size_bytes"),
    ("loot", "path_on_target"),
    ("loot", "source_module"),
    ("audit_log", "campaign_id"),
    ("audit_log", "detail"),
    ("audit_log", "module_id"),
    ("users", "last_login"),
    ("api_keys", "last_used"),
    ("api_keys", "expires_at"),
    ("refresh_tokens", "used_at"),
    ("rate_limit_events", "username"),
}
_POSTGRES_DEFAULTS = {
    ("campaigns", "client"): "literal:Internal",
    ("campaigns", "operator"): "literal:unknown",
    ("campaigns", "noise_profile"): "literal:stealth",
    ("campaigns", "status"): "literal:created",
    ("campaigns", "scope_json"): "literal:[]",
    ("campaigns", "targets_json"): "literal:[]",
    ("campaigns", "notes"): "literal:",
    ("campaigns", "created_at"): "now",
    ("campaigns", "updated_at"): "now",
    ("module_runs", "success"): "literal:0",
    ("module_runs", "duration_ms"): "literal:0.0",
    ("module_runs", "completed_at"): "now",
    ("findings", "confidence"): "literal:1.0",
    ("findings", "cvss_score"): "literal:0.0",
    ("findings", "cvss_vector"): "literal:",
    ("findings", "evidence_json"): "literal:{}",
    ("findings", "remediation"): "literal:",
    ("findings", "validated"): "literal:0",
    ("findings", "false_positive"): "literal:0",
    ("findings", "discovered_at"): "now",
    ("findings", "trace_id"): "literal:",
    ("hosts", "is_dc"): "literal:0",
    ("hosts", "open_ports_json"): "literal:[]",
    ("hosts", "tags_json"): "literal:[]",
    ("hosts", "first_seen"): "now",
    ("hosts", "last_seen"): "now",
    ("credentials", "notes"): "literal:",
    ("credentials", "cracked"): "literal:0",
    ("credentials", "captured_at"): "now",
    ("loot", "description"): "literal:",
    ("loot", "size_bytes"): "literal:0",
    ("loot", "tags_json"): "literal:[]",
    ("loot", "captured_at"): "now",
    ("audit_log", "id"): "sequence",
    ("audit_log", "actor"): "literal:system",
    ("audit_log", "detail"): "literal:",
    ("audit_log", "timestamp"): "now",
    ("users", "role"): "literal:reporter",
    ("users", "is_active"): "literal:1",
    ("users", "created_by"): "literal:system",
    ("users", "created_at"): "now",
    ("api_keys", "scopes"): "literal:read",
    ("api_keys", "is_active"): "literal:1",
    ("api_keys", "created_at"): "now",
    ("refresh_tokens", "is_revoked"): "literal:0",
    ("refresh_tokens", "created_at"): "now",
    ("revoked_access_tokens", "revoked_at"): "now",
    ("rate_limit_events", "id"): "sequence",
    ("rate_limit_events", "blocked"): "literal:0",
    ("rate_limit_events", "timestamp"): "now",
}


@dataclass(frozen=True, eq=False)
class _PostgresConfig:
    host: str = field(repr=False)
    port: int = field(repr=False)
    user: str = field(repr=False)
    maintenance_database: str = field(repr=False)


@dataclass(frozen=True, eq=False)
class _MigrationHarness:
    config: _PostgresConfig = field(repr=False)
    database_name: str = field(repr=False)


@dataclass(eq=False)
class _OwnedWorker:
    process: Any = field(repr=False)
    channel: Any = field(repr=False)
    child_channel: Any = field(default=None, repr=False)
    start_attempted: bool = False
    may_have_started: bool = False
    death_proven: bool = False
    settled_exit_code: int | None = None
    eof: bool = False
    parent_closed: bool = False
    child_closed: bool = False
    process_closed: bool = False
    closed: bool = False


@dataclass(frozen=True)
class _PostgresCatalogContract:
    tables: tuple[str, ...]
    columns: tuple[
        tuple[str, str, str, bool, str | None], ...
    ]
    primary_keys: tuple[tuple[str, tuple[str, ...]], ...]
    unique_constraints: tuple[
        tuple[str, str, tuple[str, ...]], ...
    ]
    checks: tuple[tuple[str, str, str], ...]
    foreign_keys: tuple[
        tuple[
            str,
            str,
            tuple[str, ...],
            str,
            tuple[str, ...],
            str,
            str,
        ],
        ...,
    ]
    indexes: tuple[
        tuple[str, str, tuple[str, ...], bool, str | None], ...
    ]
    sequences: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class _PostgresIsolationFingerprint:
    schemas: tuple[str, ...] = field(repr=False)
    relations: tuple[tuple[object, ...], ...] = field(repr=False)
    columns: tuple[tuple[object, ...], ...] = field(repr=False)
    constraints: tuple[tuple[object, ...], ...] = field(repr=False)
    indexes: tuple[tuple[object, ...], ...] = field(repr=False)
    sequences: tuple[tuple[object, ...], ...] = field(repr=False)
    versions: tuple[tuple[str, str], ...] = field(repr=False)


@dataclass(frozen=True)
class _PostgresLegacyRecipe:
    constraints_to_drop: tuple[tuple[str, str], ...]
    tables_to_drop: tuple[str, ...]
    nullable_columns: tuple[tuple[str, str], ...]
    indexes_to_create: tuple[tuple[str, str, tuple[str, ...]], ...]


class _BoundedTransaction:
    def __init__(self, transaction: Any) -> None:
        self._transaction = transaction

    async def start(self) -> object:
        return await asyncio.wait_for(
            self._transaction.start(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def commit(self) -> object:
        return await asyncio.wait_for(
            self._transaction.commit(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def rollback(self) -> object:
        return await asyncio.wait_for(
            self._transaction.rollback(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )


class _BoundedConnection:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def execute(self, *args: object) -> object:
        return await asyncio.wait_for(
            self._connection.execute(*args),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def fetch(self, *args: object) -> object:
        return await asyncio.wait_for(
            self._connection.fetch(*args),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def fetchrow(self, *args: object) -> object:
        return await asyncio.wait_for(
            self._connection.fetchrow(*args),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def fetchval(self, *args: object) -> object:
        return await asyncio.wait_for(
            self._connection.fetchval(*args),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    async def close(self) -> None:
        await asyncio.wait_for(
            self._connection.close(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )

    def transaction(self) -> _BoundedTransaction:
        return _BoundedTransaction(self._connection.transaction())


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _requires_candidate_origin(name: str) -> bool:
    return (
        name in {"ares", "migrations", "tests.unit", "tests.integration"}
        or name.startswith(("ares.", "migrations."))
        or name.startswith(("tests.unit.", "tests.integration."))
    )


def _path_is_within_candidate(path: object, candidate_root: Path) -> bool:
    try:
        resolved_path = os.path.normcase(
            str(Path(path).resolve(strict=False))
        )
        resolved_root = os.path.normcase(
            str(candidate_root.resolve(strict=True))
        )
        return os.path.commonpath((resolved_path, resolved_root)) == (
            resolved_root
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _module_origin_is_candidate_local(
    module: object,
    candidate_root: Path,
) -> bool:
    spec = getattr(module, "__spec__", None)
    concrete_origins: list[object] = []
    module_file = getattr(module, "__file__", None)
    if module_file is not None:
        concrete_origins.append(module_file)
    spec_origin = getattr(spec, "origin", None)
    if spec_origin not in {None, "built-in", "frozen"}:
        concrete_origins.append(spec_origin)
    concrete_is_local = not concrete_origins or all(
        _path_is_within_candidate(origin, candidate_root)
        for origin in concrete_origins
    )
    search_locations = getattr(spec, "submodule_search_locations", None)
    if search_locations is None:
        search_locations = getattr(module, "__path__", None)
    if search_locations is None:
        locations_are_local = True
        has_locations = False
    else:
        locations = tuple(search_locations)
        has_locations = bool(locations)
        locations_are_local = has_locations and all(
            _path_is_within_candidate(location, candidate_root)
            for location in locations
        )
    return (
        concrete_is_local
        and locations_are_local
        and (bool(concrete_origins) or has_locations)
    )


def _spec_origin_is_candidate_local(
    spec: object,
    candidate_root: Path,
) -> bool:
    concrete_origins: list[object] = []
    spec_origin = getattr(spec, "origin", None)
    if spec_origin not in {None, "built-in", "frozen"}:
        concrete_origins.append(spec_origin)
    concrete_is_local = not concrete_origins or all(
        _path_is_within_candidate(origin, candidate_root)
        for origin in concrete_origins
    )
    search_locations = getattr(spec, "submodule_search_locations", None)
    if search_locations is None:
        locations_are_local = True
        has_locations = False
    else:
        locations = tuple(search_locations)
        has_locations = bool(locations)
        locations_are_local = has_locations and all(
            _path_is_within_candidate(location, candidate_root)
            for location in locations
        )
    return (
        concrete_is_local
        and locations_are_local
        and (bool(concrete_origins) or has_locations)
    )


def _relative_path_is_first_party(relative_path: Path) -> bool:
    folded_parts = tuple(part.casefold() for part in relative_path.parts)
    if not folded_parts:
        return False
    if folded_parts[0] in {"ares", "migrations"}:
        return True
    return (
        len(folded_parts) >= 2
        and folded_parts[:2] in {("tests", "unit"), ("tests", "integration")}
    )


def _frame_file_is_first_party(
    module_file: object,
    candidate_root: Path,
) -> bool:
    if not isinstance(module_file, (str, os.PathLike)):
        return False
    try:
        resolved_file = Path(module_file).resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    for root in (candidate_root, _REPO_ROOT):
        try:
            relative_path = resolved_file.relative_to(root.resolve())
        except ValueError:
            continue
        if _relative_path_is_first_party(relative_path):
            return True
    folded_parts = tuple(part.casefold() for part in resolved_file.parts)
    if len(folded_parts) >= 2 and folded_parts[-2:] == (
        "migrations",
        "env.py",
    ):
        return True
    return (
        len(folded_parts) >= 3
        and folded_parts[-3:-1] == ("migrations", "versions")
        and re.fullmatch(r"[0-9]{4}_[a-z0-9_]+\.py", folded_parts[-1])
        is not None
    )


def _frame_is_first_party(
    frame: types.FrameType,
    candidate_root: Path,
) -> bool:
    globals_map = frame.f_globals
    name = globals_map.get("__name__")
    package = globals_map.get("__package__")
    if isinstance(name, str) and _requires_candidate_origin(name):
        return True
    if isinstance(package, str) and _requires_candidate_origin(package):
        return True
    return _frame_file_is_first_party(
        globals_map.get("__file__"),
        candidate_root,
    )


class _CandidateOriginFinder:
    def __init__(
        self,
        ledger: _CandidateOriginLedger,
        delegates: tuple[object, ...],
    ) -> None:
        self._ledger = ledger
        self._delegates = delegates

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> object:
        for finder in self._delegates:
            find_spec = getattr(finder, "find_spec", None)
            if find_spec is None:
                continue
            spec = find_spec(fullname, path, target)
            if spec is not None:
                self._ledger.observe_spec(fullname, spec)
                return spec
        return None


@dataclass(slots=True, repr=False)
class _CandidateOriginLedger:
    candidate_root: Path
    isolated: bool = False
    violated: bool = False
    _finder: _CandidateOriginFinder | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _previous_profile: object = field(default=None, init=False, repr=False)
    _profile_callback: object = field(default=None, init=False, repr=False)
    _previous_meta_path: tuple[object, ...] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _observed_frame_origins: set[
        tuple[
            types.CodeType,
            int,
            str | None,
            str | None,
            str | None,
        ]
    ] = field(
        default_factory=set,
        init=False,
        repr=False,
    )

    def observe_spec(self, name: str, spec: object) -> None:
        if _requires_candidate_origin(name) and not (
            _spec_origin_is_candidate_local(spec, self.candidate_root)
        ):
            self.violated = True

    def observe_modules(self, modules: object) -> None:
        if not _loaded_first_party_origins_are_candidate_local(
            modules,
            self.candidate_root,
        ):
            self.violated = True

    def _profile(
        self,
        frame: types.FrameType,
        event: str,
        arg: object,
    ) -> None:
        if event == "call":
            globals_map = frame.f_globals
            raw_file = globals_map.get("__file__")
            try:
                normalized_file = (
                    os.fspath(raw_file)
                    if isinstance(raw_file, (str, os.PathLike))
                    else None
                )
            except TypeError:
                normalized_file = None
            raw_name = globals_map.get("__name__")
            raw_package = globals_map.get("__package__")
            observation = (
                frame.f_code,
                id(globals_map),
                raw_name if isinstance(raw_name, str) else None,
                raw_package if isinstance(raw_package, str) else None,
                normalized_file,
            )
            if observation not in self._observed_frame_origins:
                self._observed_frame_origins.add(observation)
                if _frame_is_first_party(frame, self.candidate_root):
                    module_file = frame.f_globals.get("__file__")
                    if module_file is None or not _path_is_within_candidate(
                        module_file,
                        self.candidate_root,
                    ):
                        self.violated = True
        previous = self._previous_profile
        if not self.isolated and callable(previous):
            previous(frame, event, arg)

    def install(self) -> None:
        self._previous_meta_path = tuple(sys.meta_path)
        delegates = tuple(
            finder
            for finder in self._previous_meta_path
            if not isinstance(finder, _CandidateOriginFinder)
        )
        self._finder = _CandidateOriginFinder(self, delegates)
        sys.meta_path.insert(0, self._finder)
        self._previous_profile = sys.getprofile()
        self._profile_callback = self._profile
        sys.setprofile(self._profile_callback)

    def installed_exactly(self) -> bool:
        return (
            self._finder is not None
            and bool(sys.meta_path)
            and sys.meta_path[0] is self._finder
            and sys.getprofile() is self._profile_callback
        )

    def close(self) -> None:
        previous_meta_path = self._previous_meta_path
        if previous_meta_path is not None:
            sys.meta_path[:] = previous_meta_path
        sys.setprofile(self._previous_profile)
        self._finder = None
        self._profile_callback = None
        self._previous_profile = None
        self._previous_meta_path = None
        self._observed_frame_origins.clear()


_ACTIVE_ORIGIN_LEDGERS: list[_CandidateOriginLedger] = []


def _loaded_first_party_origins_are_candidate_local(
    modules: object,
    candidate_root: Path,
) -> bool:
    try:
        loaded = tuple(modules.items())
    except AttributeError:
        return False
    for name, module in loaded:
        if not isinstance(name, str) or not _requires_candidate_origin(name):
            continue
        if module is None or not _module_origin_is_candidate_local(
            module,
            candidate_root,
        ):
            return False
    return True


def _assert_candidate_origin_boundary(
    ledger: _CandidateOriginLedger | None = None,
) -> None:
    ledgers = (
        (ledger,)
        if ledger is not None
        else tuple(_ACTIVE_ORIGIN_LEDGERS)
    )
    for active_ledger in ledgers:
        active_ledger.observe_modules(sys.modules)
    if not (
        _path_is_within_candidate(__file__, _REPO_ROOT)
        and all(
            not active_ledger.violated
            and active_ledger.installed_exactly()
            for active_ledger in ledgers
        )
        and _loaded_first_party_origins_are_candidate_local(
            sys.modules,
            _REPO_ROOT,
        )
    ):
        raise RuntimeError(
            "first-party migration import escaped the source candidate"
        )


@contextmanager
def _candidate_origin_boundary(
    *,
    isolated: bool = False,
) -> Iterator[_CandidateOriginLedger]:
    ledger = _CandidateOriginLedger(_REPO_ROOT, isolated=isolated)
    ledger.install()
    _ACTIVE_ORIGIN_LEDGERS.append(ledger)
    try:
        _assert_candidate_origin_boundary(ledger)
        yield ledger
    finally:
        try:
            _assert_candidate_origin_boundary(ledger)
        finally:
            for index in range(len(_ACTIVE_ORIGIN_LEDGERS) - 1, -1, -1):
                if _ACTIVE_ORIGIN_LEDGERS[index] is ledger:
                    del _ACTIVE_ORIGIN_LEDGERS[index]
                    break
            ledger.close()


@pytest.fixture(scope="module", autouse=True)
def _final_candidate_origin_boundary() -> Iterator[None]:
    with _candidate_origin_boundary():
        yield


def _postgres_config() -> _PostgresConfig:
    present = [name for name in _POSTGRES_ENV if name in os.environ]
    if not present:
        pytest.skip("real PostgreSQL test environment is not configured")
    if len(present) != len(_POSTGRES_ENV):
        pytest.fail("Incomplete PostgreSQL test environment", pytrace=False)
    values = {name: os.environ[name] for name in _POSTGRES_ENV}
    if any(not value or value != value.strip() for value in values.values()):
        pytest.fail("Invalid PostgreSQL test environment", pytrace=False)
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if not raw_port.isascii() or not raw_port.isdecimal():
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    try:
        port = int(raw_port)
    except ValueError:
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    if str(port) != raw_port or not 1 <= port <= 65535:
        pytest.fail(
            "PostgreSQL test port is outside its valid range",
            pytrace=False,
        )
    return _PostgresConfig(
        host=values["ARES_TEST_POSTGRES_HOST"],
        port=port,
        user=values["ARES_TEST_POSTGRES_USER"],
        maintenance_database=values["ARES_TEST_POSTGRES_DB"],
    )


def _child_postgres_config() -> _PostgresConfig:
    present = [name for name in _POSTGRES_ENV if name in os.environ]
    if len(present) != len(_POSTGRES_ENV):
        raise RuntimeError("worker-postgres-config-error")
    values = {name: os.environ[name] for name in _POSTGRES_ENV}
    if any(not value or value != value.strip() for value in values.values()):
        raise RuntimeError("worker-postgres-config-error")
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise RuntimeError("worker-postgres-config-error")
    try:
        port = int(raw_port)
    except ValueError:
        raise RuntimeError("worker-postgres-config-error") from None
    if str(port) != raw_port or not 1 <= port <= 65535:
        raise RuntimeError("worker-postgres-config-error")
    return _PostgresConfig(
        host=values["ARES_TEST_POSTGRES_HOST"],
        port=port,
        user=values["ARES_TEST_POSTGRES_USER"],
        maintenance_database=values["ARES_TEST_POSTGRES_DB"],
    )


def _migration_url(
    config: _PostgresConfig,
    database_name: str,
    *,
    ordinary_driver: bool = False,
) -> str:
    from sqlalchemy.engine import URL

    driver = "postgresql" if ordinary_driver else "postgresql+asyncpg"
    return URL.create(
        driver,
        username=config.user,
        host=config.host,
        port=config.port,
        database=database_name,
    ).render_as_string(hide_password=False)


def _alembic_config(url: str) -> Any:
    import argparse

    from alembic.config import Config

    config = Config(str(_REPO_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(_REPO_ROOT / "migrations"),
    )
    config.set_main_option(
        "sqlalchemy.url",
        os.environ.get("ARES_DATABASE_URL", "sqlite:///unused.db"),
    )
    config.cmd_opts = argparse.Namespace(x=[f"db_url={url}"])
    return config


def _redirect_child_output() -> None:
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(sink, 1)
        os.dup2(sink, 2)
    finally:
        os.close(sink)


def _safe_exception_type(exc: Exception) -> str:
    exception_type = type(exc).__name__
    if _SAFE_EXCEPTION_TYPE.fullmatch(exception_type) is None:
        return "Exception"
    return exception_type


def _worker_send(channel: Any, frame: tuple[str, ...]) -> None:
    channel.send(frame)


def _prepare_child_migration(
    payload: dict[object, object],
    command: Any,
) -> tuple[Any, Any, str, str | None]:
    allowed_keys = {
        "mode",
        "operation",
        "revision",
        "database_name",
        "fault",
    }
    if set(payload) - allowed_keys:
        raise RuntimeError("worker-payload-error")
    postgres_config = _child_postgres_config()
    database_name = payload.get("database_name")
    if (
        not isinstance(database_name, str)
        or _SAFE_DATABASE_NAME.fullmatch(database_name) is None
    ):
        raise RuntimeError("worker-payload-error")
    if database_name == postgres_config.maintenance_database:
        raise RuntimeError("worker-payload-error")
    migration_url = _migration_url(
        postgres_config,
        database_name,
        ordinary_driver=True,
    )
    config = _alembic_config(migration_url)
    operation = payload.get("operation")
    revision = payload.get("revision")
    fault = payload.get("fault")
    if (
        operation not in {"upgrade", "downgrade"}
        or not isinstance(revision, str)
        or not revision
        or fault
        not in {
            None,
            "0005-before-alter",
            "0005-after-alter",
            "0006-after-rename",
        }
    ):
        raise RuntimeError("worker-payload-error")
    action = (
        command.upgrade if operation == "upgrade" else command.downgrade
    )
    return config, action, revision, fault


def _prepared_child_target_is_authoritative(
    config: object,
    database_name: str,
) -> bool:
    from sqlalchemy.engine import make_url

    command_options = getattr(config, "cmd_opts", None)
    arguments = getattr(command_options, "x", None)
    if not isinstance(arguments, list) or len(arguments) != 1:
        return False
    key, separator, raw_url = arguments[0].partition("=")
    if key != "db_url" or separator != "=" or not raw_url:
        return False
    try:
        parsed = make_url(raw_url)
    except Exception:
        return False
    expected = _child_postgres_config()
    return (
        parsed.drivername == "postgresql"
        and parsed.host == expected.host
        and parsed.port == expected.port
        and parsed.username == expected.user
        and parsed.password is None
        and parsed.database == database_name
        and not parsed.query
    )


def _worker_import_then_remove_external_probe() -> None:
    from tempfile import TemporaryDirectory

    parent = importlib.import_module("ares")
    package_path = getattr(parent, "__path__", None)
    if package_path is None:
        raise RuntimeError("worker-origin-probe-error")
    original_locations = tuple(package_path)
    name = "ares.worker_removed_origin_probe"
    child_name = "worker_removed_origin_probe"
    with TemporaryDirectory(prefix="ares-worker-origin-") as directory:
        external_package = Path(directory) / "ares"
        external_package.mkdir()
        (external_package / f"{child_name}.py").write_text(
            "def marker():\n    return True\n",
            encoding="utf-8",
        )
        package_path.append(str(external_package))
        importlib.invalidate_caches()
        try:
            imported = importlib.import_module(name)
            marker = getattr(imported, "marker", None)
            if not callable(marker) or marker() is not True:
                raise RuntimeError("worker-origin-probe-error")
        finally:
            sys.modules.pop(name, None)
            if hasattr(parent, child_name):
                delattr(parent, child_name)
            package_path[:] = original_locations
            importlib.invalidate_caches()


def _alembic_worker_entry(channel: Any) -> None:
    """Execute one operation after establishing a secret-free IPC boundary."""
    _redirect_child_output()
    exit_code = 0
    try:
        emit_success = False
        with _candidate_origin_boundary():
            forbidden_preloads = (
                "alembic",
                "sqlalchemy",
                "asyncpg",
            )
            if any(
                name == prefix or name.startswith(f"{prefix}.")
                for name in sys.modules
                for prefix in forbidden_preloads
            ):
                raise RuntimeError("worker-import-boundary-error")
            from alembic import command

            initial = channel.recv()
            if (
                not isinstance(initial, tuple)
                or len(initial) != 2
                or initial[0] != "PAYLOAD"
                or not isinstance(initial[1], dict)
            ):
                raise RuntimeError("worker-payload-error")
            payload = initial[1]
            mode = payload.get("mode")

            if mode == "protocol-ok-before-ready":
                _worker_send(channel, ("OK",))
                return
            if mode == "setup-error":
                raise RuntimeError("worker-setup-error")

            if mode in {
                "migrate",
                "ipc-prepare-success",
                "ipc-prepare-error",
            }:
                config, action, revision, fault = _prepare_child_migration(
                    payload,
                    command,
                )
                database_name = payload.get("database_name")
                if not isinstance(database_name, str) or not (
                    _prepared_child_target_is_authoritative(
                        config,
                        database_name,
                    )
                ):
                    raise RuntimeError("worker-target-error")
                if mode == "migrate" and fault is not None:
                    from alembic.operations import Operations

                    original_alter = Operations.alter_column

                    def _failing_alter(
                        operations: Operations,
                        table_name: str,
                        column_name: str,
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        is_trace = (
                            table_name == "findings"
                            and column_name == "trace_id"
                        )
                        is_credential = (
                            table_name == "credentials"
                            and column_name
                            in {"cracked_value", "cracked_value_enc"}
                        )
                        if fault == "0005-before-alter" and is_trace:
                            raise RuntimeError("worker-test-error")
                        result = original_alter(
                            operations,
                            table_name,
                            column_name,
                            *args,
                            **kwargs,
                        )
                        if (
                            fault == "0005-after-alter"
                            and is_trace
                        ) or (
                            fault == "0006-after-rename"
                            and is_credential
                        ):
                            raise RuntimeError("worker-test-error")
                        return result

                    Operations.alter_column = _failing_alter
            elif mode in {
                "success",
                "success-dirty-origin",
                "success-dirty-origin-removed",
                "migration-error",
                "block",
                "protocol-duplicate-ready",
                "protocol-duplicate-ok",
                "protocol-malformed",
                "protocol-eof-before-terminal",
                "protocol-success-crash",
                "protocol-zero-without-success",
            }:
                revision = ""
                config = None
                action = None
            else:
                raise RuntimeError("worker-mode-error")

            _worker_send(channel, ("READY",))
            if mode == "protocol-duplicate-ready":
                _worker_send(channel, ("READY",))
            go = channel.recv()
            if go != ("GO",):
                raise RuntimeError("worker-go-error")

            if mode == "block":
                threading.Event().wait()
            if mode in {"migration-error", "ipc-prepare-error"}:
                raise RuntimeError("worker-test-error")
            if mode == "protocol-malformed":
                _worker_send(channel, ("UNKNOWN",))
                return
            if mode in {
                "protocol-eof-before-terminal",
                "protocol-zero-without-success",
            }:
                return
            if mode == "protocol-duplicate-ok":
                _worker_send(channel, ("OK",))
                _worker_send(channel, ("OK",))
                return
            if mode == "protocol-success-crash":
                _worker_send(channel, ("OK",))
                raise SystemExit(71)
            if mode == "success-dirty-origin":
                dirty_module = types.ModuleType("ares.worker_dirty_probe")
                dirty_origin = _REPO_ROOT.parent / "worker_dirty_probe.py"
                dirty_module.__file__ = str(dirty_origin)
                dirty_module.__spec__ = importlib.machinery.ModuleSpec(
                    "ares.worker_dirty_probe",
                    loader=None,
                    origin=str(dirty_origin),
                )
                sys.modules["ares.worker_dirty_probe"] = dirty_module
            if mode == "success-dirty-origin-removed":
                _worker_import_then_remove_external_probe()
            if mode == "migrate":
                action(config, revision)
            emit_success = True
        if emit_success:
            _worker_send(channel, ("OK",))
    except Exception as exc:
        exit_code = 70
        try:
            _worker_send(channel, ("ERROR", _safe_exception_type(exc)))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        channel.close()
    if exit_code:
        raise SystemExit(exit_code)


async def _wait_for_process_exit(process: Any, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while process.is_alive() and time.monotonic() < deadline:
        process.join(timeout=0)
        await asyncio.sleep(_WORKER_POLL_SECONDS)
    process.join(timeout=0)
    return not process.is_alive() and process.exitcode is not None


def _add_fixed_cleanup_note(
    primary: Exception,
    action: str,
    cleanup_error: Exception,
) -> None:
    primary.add_note(
        f"Alembic worker cleanup failed [{action}: "
        f"{type(cleanup_error).__name__}]"
    )


def _close_unowned_endpoint(
    endpoint: Any,
    action: str,
    primary: Exception,
) -> None:
    if endpoint is None:
        return
    try:
        endpoint.close()
    except Exception as cleanup_error:
        _add_fixed_cleanup_note(primary, action, cleanup_error)


def _process_may_have_started(process: Any) -> bool:
    try:
        if process.pid is not None:
            return True
    except Exception:
        return True
    try:
        return bool(process.is_alive())
    except Exception:
        return True


def _close_settled_worker_resources(worker: _OwnedWorker) -> None:
    failures: list[tuple[str, Exception]] = []
    if not worker.parent_closed:
        try:
            worker.channel.close()
            worker.parent_closed = True
        except Exception as exc:
            failures.append(("close-parent-endpoint", exc))
    if worker.child_channel is not None and not worker.child_closed:
        try:
            worker.child_channel.close()
            worker.child_closed = True
        except Exception as exc:
            failures.append(("close-child-endpoint", exc))
    if not worker.process_closed:
        try:
            worker.process.close()
            worker.process_closed = True
        except Exception as exc:
            failures.append(("close-process", exc))
    if failures:
        error = RuntimeError("Alembic worker resource closure failed")
        for action, failure in failures:
            _add_fixed_cleanup_note(error, action, failure)
        raise error from None
    worker.closed = True
    _OWNED_WORKERS.discard(worker)


async def _settle_worker(
    worker: _OwnedWorker,
    *,
    terminate: bool,
) -> int:
    if worker.closed:
        raise RuntimeError("Alembic worker ownership was already closed")
    if worker.death_proven:
        exit_code = (
            -1
            if worker.settled_exit_code is None
            else worker.settled_exit_code
        )
        _close_settled_worker_resources(worker)
        return exit_code
    process = worker.process
    try:
        process_id = process.pid
    except Exception:
        process_id = None
        worker.may_have_started = True
    if process_id is None:
        if worker.may_have_started:
            raise RuntimeError("Alembic worker death was not proven")
        worker.death_proven = True
        worker.settled_exit_code = -1
        _close_settled_worker_resources(worker)
        return -1

    if terminate and process.is_alive():
        process.terminate()
    settled = await _wait_for_process_exit(
        process,
        _WORKER_SETTLE_SECONDS,
    )
    if not settled and terminate:
        process.kill()
        settled = await _wait_for_process_exit(
            process,
            _WORKER_SETTLE_SECONDS,
        )
    if not settled:
        raise RuntimeError("Alembic worker death was not proven")

    exit_code = int(process.exitcode)
    worker.death_proven = True
    worker.settled_exit_code = exit_code
    process.join(timeout=0)
    _close_settled_worker_resources(worker)
    return exit_code


async def _receive_worker_frame(
    worker: _OwnedWorker,
    *,
    deadline: float,
) -> tuple[str, ...] | None:
    while time.monotonic() < deadline:
        try:
            has_frame = worker.channel.poll()
        except (BrokenPipeError, EOFError, OSError):
            worker.eof = True
            return None
        if has_frame:
            try:
                frame = worker.channel.recv()
            except (BrokenPipeError, EOFError, OSError):
                worker.eof = True
                return None
            if not isinstance(frame, tuple) or not all(
                isinstance(item, str) for item in frame
            ):
                raise RuntimeError("Alembic worker failed [ProtocolError]")
            return frame
        if not worker.process.is_alive():
            await asyncio.sleep(0)
            try:
                has_frame = worker.channel.poll()
            except (BrokenPipeError, EOFError, OSError):
                worker.eof = True
                return None
            if has_frame:
                continue
            try:
                worker.channel.recv()
            except (BrokenPipeError, EOFError, OSError):
                worker.eof = True
                return None
            raise RuntimeError("Alembic worker failed [ProtocolError]")
        await asyncio.sleep(_WORKER_POLL_SECONDS)
    raise TimeoutError


async def _run_worker(
    payload: dict[str, str],
    *,
    timeout: float,
    started: asyncio.Event | None = None,
) -> None:
    parent_channel = None
    child_channel = None
    process = None
    pipe_resources: tuple[Any, ...] = ()
    try:
        context = multiprocessing.get_context("spawn")
        pipe_result = context.Pipe(duplex=True)
        if isinstance(pipe_result, (tuple, list)):
            pipe_resources = tuple(pipe_result)
        if len(pipe_resources) != 2:
            raise RuntimeError("worker-pipe-construction-error")
        parent_channel, child_channel = pipe_resources
    except Exception as exc:
        primary = RuntimeError(
            f"Alembic worker startup failed [{type(exc).__name__}]"
        )
        for index, endpoint in enumerate(pipe_resources):
            _close_unowned_endpoint(
                endpoint,
                f"close-pipe-endpoint-{index}",
                primary,
            )
        raise primary from None
    try:
        process = context.Process(
            target=_alembic_worker_entry,
            args=(child_channel,),
            name="ares-alembic-worker",
        )
    except Exception as exc:
        primary = RuntimeError(
            f"Alembic worker startup failed [{type(exc).__name__}]"
        )
        _close_unowned_endpoint(
            parent_channel,
            "close-parent-endpoint",
            primary,
        )
        _close_unowned_endpoint(
            child_channel,
            "close-child-endpoint",
            primary,
        )
        raise primary from None

    worker = _OwnedWorker(
        process=process,
        channel=parent_channel,
        child_channel=child_channel,
    )
    _OWNED_WORKERS.add(worker)
    try:
        worker.start_attempted = True
        process.start()
        worker.may_have_started = True
        child_channel.close()
        worker.child_closed = True
        parent_channel.send(("PAYLOAD", payload))
    except Exception as exc:
        worker.may_have_started = (
            worker.may_have_started or _process_may_have_started(process)
        )
        primary = RuntimeError(
            f"Alembic worker startup failed [{type(exc).__name__}]"
        )
        try:
            await asyncio.shield(
                _settle_worker(worker, terminate=True)
            )
        except Exception as cleanup_error:
            _add_fixed_cleanup_note(
                primary,
                "settle-startup-worker",
                cleanup_error,
            )
        raise primary from None

    protocol_failure = False
    terminal: tuple[str, ...] | None = None
    try:
        ready_deadline = time.monotonic() + _WORKER_SETTLE_SECONDS
        ready = await _receive_worker_frame(
            worker,
            deadline=ready_deadline,
        )
        if ready != ("READY",):
            setup_error = (
                ready is not None
                and len(ready) == 2
                and ready[0] == "ERROR"
                and _SAFE_EXCEPTION_TYPE.fullmatch(ready[1]) is not None
            )
            if setup_error:
                after_setup_error = await _receive_worker_frame(
                    worker,
                    deadline=time.monotonic() + _WORKER_SETTLE_SECONDS,
                )
                exit_code = await _settle_worker(
                    worker,
                    terminate=False,
                )
                if after_setup_error is None and exit_code == 70:
                    raise RuntimeError(
                        f"Alembic worker failed [{ready[1]}]"
                    ) from None
            raise RuntimeError("Alembic worker failed [ProtocolError]")
        if started is not None:
            started.set()
        parent_channel.send(("GO",))

        terminal_deadline = time.monotonic() + timeout
        terminal = await _receive_worker_frame(
            worker,
            deadline=terminal_deadline,
        )
        if terminal is None or (
            terminal != ("OK",)
            and not (
                len(terminal) == 2
                and terminal[0] == "ERROR"
                and _SAFE_EXCEPTION_TYPE.fullmatch(terminal[1]) is not None
            )
        ):
            raise RuntimeError("Alembic worker failed [ProtocolError]")

        after_terminal = await _receive_worker_frame(
            worker,
            deadline=time.monotonic() + _WORKER_SETTLE_SECONDS,
        )
        if after_terminal is not None:
            raise RuntimeError("Alembic worker failed [ProtocolError]")
        exit_code = await _settle_worker(worker, terminate=False)
        if terminal == ("OK",) and exit_code == 0:
            return
        if terminal[0] == "ERROR" and exit_code == 70:
            raise RuntimeError(
                f"Alembic worker failed [{terminal[1]}]"
            ) from None
        raise RuntimeError("Alembic worker failed [ProtocolError]")
    except TimeoutError:
        protocol_failure = True
        raise RuntimeError("Alembic worker timed out") from None
    except asyncio.CancelledError:
        protocol_failure = True
        raise
    except RuntimeError:
        protocol_failure = True
        raise
    finally:
        if worker in _OWNED_WORKERS:
            try:
                await asyncio.shield(
                    _settle_worker(worker, terminate=protocol_failure)
                )
            except RuntimeError:
                raise RuntimeError(
                    "Alembic worker settlement failed"
                ) from None


async def _alembic(
    harness: _MigrationHarness,
    operation: str,
    revision: str,
    *,
    fault: str | None = None,
) -> None:
    if operation not in {"upgrade", "downgrade"}:
        raise AssertionError("unknown migration operation")
    payload = {
        "mode": "migrate",
        "database_name": harness.database_name,
        "operation": operation,
        "revision": revision,
    }
    if fault is not None:
        payload["fault"] = fault
    await _run_worker(
        payload,
        timeout=_WORKER_TIMEOUT_SECONDS,
    )


def _sanitized_setup_failure(action: str, exc: Exception) -> RuntimeError:
    return RuntimeError(
        f"PostgreSQL migration setup failed [{action}: {type(exc).__name__}]"
    )


async def _attempt_cleanup(
    action: str,
    cleanup: Callable[[], Awaitable[object]],
    failures: list[str],
) -> None:
    try:
        await asyncio.wait_for(
            cleanup(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        failures.append(f"{action}: {type(exc).__name__}")


async def _settle_owned_workers_for_cleanup(
    failures: list[str],
) -> bool:
    for worker in tuple(_OWNED_WORKERS):
        try:
            await _settle_worker(worker, terminate=True)
        except Exception as exc:
            failures.append(
                f"settle-alembic-worker: {type(exc).__name__}"
            )
    return not _OWNED_WORKERS


@asynccontextmanager
async def _postgres_harness(
) -> AsyncIterator[_MigrationHarness]:
    config = _postgres_config()
    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg is required for configured PostgreSQL tests",
            pytrace=False,
        )

    database_name = f"ares_migration_{uuid4().hex}"
    _require_fixed(
        _SAFE_DATABASE_NAME.fullmatch(database_name) is not None,
        "generated PostgreSQL database identifier was unsafe",
    )
    _require_fixed(
        database_name != config.maintenance_database,
        "generated PostgreSQL database identifier collided",
    )

    admin = None
    creation_attempted = False
    cleanup_failures: list[str] = []
    try:
        try:
            admin = await asyncio.wait_for(
                asyncpg.connect(
                    host=config.host,
                    port=config.port,
                    user=config.user,
                    database=config.maintenance_database,
                ),
                timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise _sanitized_setup_failure("admin-connect", exc) from None

        creation_attempted = True
        try:
            await asyncio.wait_for(
                admin.execute(f'CREATE DATABASE "{database_name}"'),
                timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            raise _sanitized_setup_failure("database-create", exc) from None

        yield _MigrationHarness(
            config=config,
            database_name=database_name,
        )
    finally:
        primary_failure = sys.exception()
        workers_settled = await _settle_owned_workers_for_cleanup(
            cleanup_failures
        )
        if creation_attempted and admin is not None and workers_settled:

            async def _drop_database() -> None:
                await asyncio.wait_for(
                    admin.execute(
                        """
                        SELECT pg_terminate_backend(pid)
                        FROM pg_stat_activity
                        WHERE datname=$1 AND pid <> pg_backend_pid()
                        """,
                        database_name,
                    ),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                await asyncio.wait_for(
                    admin.execute(
                        f'DROP DATABASE IF EXISTS "{database_name}" '
                        "WITH (FORCE)"
                    ),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )

            await _attempt_cleanup(
                "drop-test-database",
                _drop_database,
                cleanup_failures,
            )
        elif creation_attempted and not workers_settled:
            cleanup_failures.append("drop-test-database: WorkerOwnershipError")
        if admin is not None:
            await _attempt_cleanup(
                "close-admin-connection",
                admin.close,
                cleanup_failures,
            )
        if cleanup_failures:
            if primary_failure is not None:
                for failure in cleanup_failures:
                    primary_failure.add_note(
                        f"PostgreSQL migration cleanup failure [{failure}]"
                    )
            else:
                raise RuntimeError(
                    "PostgreSQL migration cleanup failed: "
                    + "; ".join(cleanup_failures)
                ) from None


async def _connect(harness: _MigrationHarness) -> Any:
    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg is required for configured PostgreSQL tests",
            pytrace=False,
        )
    try:
        connection = await asyncio.wait_for(
            asyncpg.connect(
                host=harness.config.host,
                port=harness.config.port,
                user=harness.config.user,
                database=harness.database_name,
            ),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )
        return _BoundedConnection(connection)
    except Exception as exc:
        raise _sanitized_setup_failure("catalog-connect", exc) from None


async def _postgres_integrity_failure(
    connection: Any,
    statement: str,
    *parameters: object,
    expected_type: str,
) -> bool:
    rejected = False
    try:
        await connection.execute(statement, *parameters)
    except Exception as exc:
        rejected = type(exc).__name__ == expected_type
    reusable = await connection.fetchval("SELECT 1") == 1
    return rejected and reusable


async def _seed_postgres_contract(connection: Any) -> None:
    await connection.execute(
        "INSERT INTO campaigns(id, name) VALUES($1, $2)",
        "campaign-contract",
        "Synthetic campaign",
    )
    await connection.execute(
        """
        INSERT INTO module_runs(id, campaign_id, module_id, outcome)
        VALUES($1, $2, $3, $4)
        """,
        "run-contract",
        "campaign-contract",
        "module",
        "complete",
    )
    await connection.execute(
        """
        INSERT INTO findings(
            id, campaign_id, module_id, title, description, severity
        ) VALUES($1, $2, $3, $4, $5, $6)
        """,
        "finding-contract",
        "campaign-contract",
        "module",
        "Synthetic finding",
        "Synthetic description",
        "low",
    )
    await connection.execute(
        """
        INSERT INTO hosts(id, campaign_id, ip_address)
        VALUES($1, $2, $3)
        """,
        "host-contract",
        "campaign-contract",
        "192.0.2.10",
    )
    await connection.execute(
        """
        INSERT INTO credentials(
            id, campaign_id, host_id, username, cred_type
        ) VALUES($1, $2, $3, $4, $5)
        """,
        "credential-contract",
        "campaign-contract",
        "host-contract",
        "synthetic-user",
        "password",
    )
    await connection.execute(
        """
        INSERT INTO loot(id, campaign_id, host_id, loot_type, name)
        VALUES($1, $2, $3, $4, $5)
        """,
        "loot-contract",
        "campaign-contract",
        "host-contract",
        "metadata",
        "Synthetic loot",
    )
    await connection.execute(
        "INSERT INTO audit_log(campaign_id, action) VALUES($1, $2)",
        "campaign-contract",
        "synthetic-action",
    )
    await connection.execute(
        """
        INSERT INTO users(id, username, hashed_password)
        VALUES($1, $2, $3)
        """,
        "user-contract",
        "synthetic-account",
        "synthetic-hash",
    )
    await connection.execute(
        """
        INSERT INTO api_keys(id, user_id, name, key_hash, key_prefix)
        VALUES($1, $2, $3, $4, $5)
        """,
        "api-key-contract",
        "user-contract",
        "Synthetic key",
        "synthetic-hash",
        "synthetic",
    )
    await connection.execute(
        """
        INSERT INTO refresh_tokens(id, user_id, expires_at)
        VALUES($1, $2, $3)
        """,
        "refresh-contract",
        "user-contract",
        datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    await connection.execute(
        """
        INSERT INTO revoked_access_tokens(jti, user_id, expires_at)
        VALUES($1, $2, $3)
        """,
        "revoked-contract",
        "user-contract",
        datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    await connection.execute(
        """
        INSERT INTO rate_limit_events(ip_address, bucket)
        VALUES($1, $2)
        """,
        "192.0.2.20",
        "synthetic-bucket",
    )


async def _postgres_isolation_fingerprint(
    connection: Any,
) -> _PostgresIsolationFingerprint:
    try:
        schemas = tuple(
            str(row["schema_name"])
            for row in await connection.fetch(
                """
                SELECT nspname AS schema_name
                FROM pg_namespace
                WHERE nspname !~ '^pg_'
                  AND nspname <> 'information_schema'
                ORDER BY nspname
                """
            )
        )
        relations = tuple(
            tuple(row.values())
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    relation.relname AS relation_name,
                    relation.relkind AS relation_kind,
                    relation.relpersistence AS persistence
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                ORDER BY
                    namespace.nspname,
                    relation.relname,
                    relation.relkind
                """
            )
        )
        columns = tuple(
            tuple(row.values())
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    relation.relname AS relation_name,
                    attribute.attnum AS ordinal_position,
                    attribute.attname AS column_name,
                    format_type(
                        attribute.atttypid,
                        attribute.atttypmod
                    ) AS formatted_type,
                    attribute.attnotnull AS not_null,
                    pg_get_expr(
                        default_value.adbin,
                        default_value.adrelid
                    ) AS default_expression,
                    attribute.attidentity AS identity_kind,
                    attribute.attgenerated AS generated_kind
                FROM pg_attribute AS attribute
                JOIN pg_class AS relation
                  ON relation.oid=attribute.attrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                LEFT JOIN pg_attrdef AS default_value
                  ON default_value.adrelid=attribute.attrelid
                 AND default_value.adnum=attribute.attnum
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
                ORDER BY
                    namespace.nspname,
                    relation.relname,
                    attribute.attnum
                """
            )
        )
        constraints = tuple(
            tuple(row.values())
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    relation.relname AS relation_name,
                    constraint_value.conname AS constraint_name,
                    constraint_value.contype AS constraint_type,
                    pg_get_constraintdef(
                        constraint_value.oid,
                        true
                    ) AS definition
                FROM pg_constraint AS constraint_value
                JOIN pg_class AS relation
                  ON relation.oid=constraint_value.conrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                ORDER BY
                    namespace.nspname,
                    relation.relname,
                    constraint_value.conname
                """
            )
        )
        indexes = tuple(
            tuple(row.values())
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    table_relation.relname AS relation_name,
                    index_relation.relname AS index_name,
                    index_value.indisunique AS is_unique,
                    index_value.indisprimary AS is_primary,
                    pg_get_indexdef(index_relation.oid) AS definition
                FROM pg_index AS index_value
                JOIN pg_class AS table_relation
                  ON table_relation.oid=index_value.indrelid
                JOIN pg_class AS index_relation
                  ON index_relation.oid=index_value.indexrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=table_relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                ORDER BY
                    namespace.nspname,
                    table_relation.relname,
                    index_relation.relname
                """
            )
        )
        sequences = tuple(
            tuple(row.values())
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    relation.relname AS sequence_name,
                    format_type(
                        sequence_value.seqtypid,
                        NULL
                    ) AS data_type,
                    sequence_value.seqstart AS start_value,
                    sequence_value.seqmin AS minimum_value,
                    sequence_value.seqmax AS maximum_value,
                    sequence_value.seqincrement AS increment_value,
                    sequence_value.seqcycle AS cycles,
                    sequence_value.seqcache AS cache_size
                FROM pg_sequence AS sequence_value
                JOIN pg_class AS relation
                  ON relation.oid=sequence_value.seqrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                ORDER BY namespace.nspname, relation.relname
                """
            )
        )
        version_rows = tuple(
            (
                str(row["schema_name"]),
                str(row["version_state"]),
            )
            for row in await connection.fetch(
                """
                SELECT
                    namespace.nspname AS schema_name,
                    table_to_xml(
                        relation.oid::regclass,
                        true,
                        false,
                        ''
                    )::text AS version_state
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname !~ '^pg_'
                  AND namespace.nspname <> 'information_schema'
                  AND relation.relkind IN ('r', 'p')
                  AND relation.relname='alembic_version'
                ORDER BY namespace.nspname
                """
            )
        )
        return _PostgresIsolationFingerprint(
            schemas=schemas,
            relations=relations,
            columns=columns,
            constraints=constraints,
            indexes=indexes,
            sequences=sequences,
            versions=version_rows,
        )
    except Exception as exc:
        raise _sanitized_setup_failure(
            "isolation-fingerprint",
            exc,
        ) from None


def _isolation_fingerprint_has_no_ares_state(
    fingerprint: _PostgresIsolationFingerprint,
) -> bool:
    forbidden_relations = _EXPECTED_TABLES | {"alembic_version"}
    return (
        not fingerprint.versions
        and all(
            str(relation[1]) not in forbidden_relations
            for relation in fingerprint.relations
        )
    )


async def _database_fingerprint(
    config: _PostgresConfig,
    database_name: str,
) -> _PostgresIsolationFingerprint:
    harness = _MigrationHarness(
        config=config,
        database_name=database_name,
    )
    connection = await _connect(harness)
    try:
        return await _postgres_isolation_fingerprint(connection)
    finally:
        primary = sys.exception()
        try:
            await connection.close()
        except Exception as cleanup_error:
            if primary is not None:
                primary.add_note(
                    "PostgreSQL migration fingerprint cleanup failed "
                    f"[{type(cleanup_error).__name__}]"
                )
            else:
                raise _sanitized_setup_failure(
                    "fingerprint-close",
                    cleanup_error,
                ) from None


async def _database_revision(
    config: _PostgresConfig,
    database_name: str,
) -> str | None:
    harness = _MigrationHarness(
        config=config,
        database_name=database_name,
    )
    connection = await _connect(harness)
    try:
        return await _version(connection)
    finally:
        primary = sys.exception()
        try:
            await connection.close()
        except Exception as cleanup_error:
            if primary is not None:
                primary.add_note(
                    "PostgreSQL migration revision cleanup failed "
                    f"[{type(cleanup_error).__name__}]"
                )
            else:
                raise _sanitized_setup_failure(
                    "revision-close",
                    cleanup_error,
                ) from None


async def _version(connection: Any) -> str | None:
    exists = await connection.fetchval(
        "SELECT to_regclass('alembic_version') IS NOT NULL"
    )
    if not exists:
        return None
    value = await connection.fetchval(
        "SELECT version_num FROM alembic_version"
    )
    return None if value is None else str(value)


def _normalize_postgres_expression(value: str) -> str:
    normalized = value.lower().replace('"', "")
    normalized = re.sub(r"\s+", "", normalized)
    while normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1]
    if normalized.startswith("check(") and normalized.endswith(")"):
        normalized = normalized[6:-1]
    return normalized.replace("(", "").replace(")", "")


def _postgres_default_kind(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    lowered = normalized.lower()
    if lowered.startswith("nextval("):
        return "sequence"
    if "now()" in lowered:
        return "now"
    while normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()
    cast_position = normalized.rfind("::")
    if cast_position >= 0:
        normalized = normalized[:cast_position]
    normalized = normalized.strip()
    if len(normalized) >= 2 and normalized[0] == normalized[-1] == "'":
        normalized = normalized[1:-1].replace("''", "'")
    return f"literal:{normalized}"


async def _postgres_catalog_contract(
    connection: Any,
) -> _PostgresCatalogContract:
    tables = tuple(
        str(row["table_name"])
        for row in await connection.fetch(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema=current_schema()
              AND table_type='BASE TABLE'
              AND table_name <> 'alembic_version'
            ORDER BY table_name
            """
        )
    )
    columns = tuple(
        (
            str(row["table_name"]),
            str(row["column_name"]),
            str(row["data_type"]),
            str(row["is_nullable"]) == "YES",
            _postgres_default_kind(row["column_default"]),
        )
        for row in await connection.fetch(
            """
            SELECT
                table_name,
                ordinal_position,
                column_name,
                data_type,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND table_name <> 'alembic_version'
            ORDER BY table_name, ordinal_position
            """
        )
    )
    primary_keys = tuple(
        (
            str(row["table_name"]),
            tuple(str(value) for value in row["columns"]),
        )
        for row in await connection.fetch(
            """
            SELECT
                relation.relname AS table_name,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(constraint.conkey)
                        WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=constraint.conrelid
                     AND attribute.attnum=key.attnum
                    ORDER BY key.position
                ) AS columns
            FROM pg_constraint AS constraint
            JOIN pg_class AS relation
              ON relation.oid=constraint.conrelid
            WHERE relation.relnamespace=current_schema()::regnamespace
              AND constraint.contype='p'
              AND relation.relname <> 'alembic_version'
            ORDER BY relation.relname
            """
        )
    )
    unique_constraints = tuple(
        (
            str(row["table_name"]),
            str(row["constraint_name"]),
            tuple(str(value) for value in row["columns"]),
        )
        for row in await connection.fetch(
            """
            SELECT
                relation.relname AS table_name,
                constraint.conname AS constraint_name,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(constraint.conkey)
                        WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=constraint.conrelid
                     AND attribute.attnum=key.attnum
                    ORDER BY key.position
                ) AS columns
            FROM pg_constraint AS constraint
            JOIN pg_class AS relation
              ON relation.oid=constraint.conrelid
            WHERE relation.relnamespace=current_schema()::regnamespace
              AND constraint.contype='u'
            ORDER BY relation.relname, constraint.conname
            """
        )
    )
    checks = tuple(
        (
            str(row["table_name"]),
            str(row["constraint_name"]),
            _normalize_postgres_expression(str(row["definition"])),
        )
        for row in await connection.fetch(
            """
            SELECT
                relation.relname AS table_name,
                constraint.conname AS constraint_name,
                pg_get_constraintdef(constraint.oid) AS definition
            FROM pg_constraint AS constraint
            JOIN pg_class AS relation
              ON relation.oid=constraint.conrelid
            WHERE relation.relnamespace=current_schema()::regnamespace
              AND constraint.contype='c'
            ORDER BY relation.relname, constraint.conname
            """
        )
    )
    foreign_keys = tuple(
        (
            str(row["table_name"]),
            str(row["constraint_name"]),
            tuple(str(value) for value in row["local_columns"]),
            str(row["remote_table"]),
            tuple(str(value) for value in row["remote_columns"]),
            str(row["update_action"]),
            str(row["delete_action"]),
        )
        for row in await connection.fetch(
            """
            SELECT
                source.relname AS table_name,
                constraint.conname AS constraint_name,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(constraint.conkey)
                        WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=constraint.conrelid
                     AND attribute.attnum=key.attnum
                    ORDER BY key.position
                ) AS local_columns,
                target.relname AS remote_table,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(constraint.confkey)
                        WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=constraint.confrelid
                     AND attribute.attnum=key.attnum
                    ORDER BY key.position
                ) AS remote_columns,
                CASE constraint.confupdtype
                    WHEN 'a' THEN 'NO ACTION'
                    WHEN 'r' THEN 'RESTRICT'
                    WHEN 'c' THEN 'CASCADE'
                    WHEN 'n' THEN 'SET NULL'
                    WHEN 'd' THEN 'SET DEFAULT'
                END AS update_action,
                CASE constraint.confdeltype
                    WHEN 'a' THEN 'NO ACTION'
                    WHEN 'r' THEN 'RESTRICT'
                    WHEN 'c' THEN 'CASCADE'
                    WHEN 'n' THEN 'SET NULL'
                    WHEN 'd' THEN 'SET DEFAULT'
                END AS delete_action
            FROM pg_constraint AS constraint
            JOIN pg_class AS source
              ON source.oid=constraint.conrelid
            JOIN pg_class AS target
              ON target.oid=constraint.confrelid
            WHERE source.relnamespace=current_schema()::regnamespace
              AND constraint.contype='f'
            ORDER BY source.relname, constraint.conname
            """
        )
    )
    indexes = tuple(
        (
            str(row["table_name"]),
            str(row["index_name"]),
            tuple(str(value) for value in row["columns"]),
            bool(row["is_unique"]),
            (
                None
                if row["predicate"] is None
                else _normalize_postgres_expression(str(row["predicate"]))
            ),
        )
        for row in await connection.fetch(
            """
            SELECT
                table_relation.relname AS table_name,
                index_relation.relname AS index_name,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(index_catalog.indkey)
                        WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=table_relation.oid
                     AND attribute.attnum=key.attnum
                    WHERE key.position <= index_catalog.indnkeyatts
                    ORDER BY key.position
                ) AS columns,
                index_catalog.indisunique AS is_unique,
                pg_get_expr(
                    index_catalog.indpred,
                    index_catalog.indrelid
                ) AS predicate
            FROM pg_index AS index_catalog
            JOIN pg_class AS table_relation
              ON table_relation.oid=index_catalog.indrelid
            JOIN pg_class AS index_relation
              ON index_relation.oid=index_catalog.indexrelid
            WHERE table_relation.relnamespace=current_schema()::regnamespace
              AND NOT EXISTS (
                  SELECT 1 FROM pg_constraint AS constraint
                  WHERE constraint.conindid=index_catalog.indexrelid
              )
            ORDER BY table_relation.relname, index_relation.relname
            """
        )
    )
    sequences = tuple(
        str(row["sequence_name"])
        for row in await connection.fetch(
            """
            SELECT sequence_name
            FROM information_schema.sequences
            WHERE sequence_schema=current_schema()
            ORDER BY sequence_name
            """
        )
    )
    return _PostgresCatalogContract(
        tables=tables,
        columns=columns,
        primary_keys=primary_keys,
        unique_constraints=unique_constraints,
        checks=checks,
        foreign_keys=foreign_keys,
        indexes=indexes,
        sequences=sequences,
    )


def _fixed_postgres_contract(revision: str) -> _PostgresCatalogContract:
    if revision == "base":
        return _PostgresCatalogContract((), (), (), (), (), (), (), ())
    tables = {
        "campaigns",
        "module_runs",
        "findings",
        "hosts",
        "credentials",
        "loot",
        "audit_log",
        "users",
        "api_keys",
        "refresh_tokens",
    }
    if revision >= "0003":
        tables.add("rate_limit_events")
    if revision >= "0004":
        tables.add("revoked_access_tokens")
    ordered_tables = tuple(sorted(tables))
    order = {
        table: tuple(columns)
        for table, columns in _EXPECTED_COLUMN_ORDER.items()
        if table in tables
    }
    if revision == "0001":
        order["findings"] = tuple(
            column for column in order["findings"] if column != "trace_id"
        )
    if revision < "0006":
        order["credentials"] = tuple(
            "cracked_value" if column == "cracked_value_enc" else column
            for column in order["credentials"]
        )
    columns: list[tuple[str, str, str, bool, str | None]] = []
    for table in ordered_tables:
        for column in order[table]:
            canonical_column = (
                "cracked_value_enc"
                if column == "cracked_value"
                else column
            )
            key = (table, canonical_column)
            if key in _POSTGRES_INTEGER_COLUMNS:
                data_type = "integer"
            elif key in _POSTGRES_FLOAT_COLUMNS:
                data_type = "double precision"
            elif key in _POSTGRES_TIMESTAMP_COLUMNS:
                data_type = "timestamp with time zone"
            else:
                data_type = "text"
            nullable = key in _POSTGRES_NULLABLE_COLUMNS
            if table == "findings" and column == "trace_id":
                nullable = revision < "0005"
            columns.append(
                (
                    table,
                    column,
                    data_type,
                    nullable,
                    _POSTGRES_DEFAULTS.get(key),
                )
            )
    primary_keys = tuple(
        (
            table,
            (
                "jti"
                if table == "revoked_access_tokens"
                else "id",
            ),
        )
        for table in ordered_tables
    )
    unique_constraints = tuple(
        sorted(
            (
                ("hosts", "uq_hosts_campaign_ip", ("campaign_id", "ip_address")),
                ("users", "uq_users_username", ("username",)),
            )
        )
    )
    foreign_key_names = {
        ("module_runs", "campaign_id"): "fk_module_runs_campaign",
        ("findings", "campaign_id"): "fk_findings_campaign",
        ("hosts", "campaign_id"): "fk_hosts_campaign",
        ("credentials", "campaign_id"): "fk_credentials_campaign",
        ("credentials", "host_id"): "fk_credentials_host",
        ("loot", "campaign_id"): "fk_loot_campaign",
        ("loot", "host_id"): "fk_loot_host",
        ("audit_log", "campaign_id"): "fk_audit_campaign",
        ("api_keys", "user_id"): "fk_api_keys_user",
        ("refresh_tokens", "user_id"): "fk_refresh_tokens_user",
    }
    foreign_keys = tuple(
        sorted(
            (
                table,
                foreign_key_names[(table, local)],
                (local,),
                remote,
                ("id",),
                "NO ACTION",
                action,
            )
            for table, local, remote, action in _EXPECTED_FOREIGN_KEYS
            if table in tables
        )
    )
    index_names = set(_EXPECTED_INDEXES)
    if revision == "0001":
        index_names.discard("idx_findings_cvss")
    if revision < "0003":
        index_names.difference_update(
            {"idx_rle_ip", "idx_rle_timestamp", "idx_rle_blocked"}
        )
    if revision < "0004":
        index_names.discard("idx_rat_expires")
    indexes = tuple(
        sorted(
            (
                _POSTGRES_INDEX_TABLES[name],
                name,
                columns,
                False,
                None,
            )
            for name, columns in _EXPECTED_INDEXES.items()
            if name in index_names
        )
    )
    checks = [
        (
            table,
            name,
            (
                f"{column}isnullorisfinite{column}"
                if nullable
                else f"isfinite{column}"
            ),
        )
        for (table, column), (name, nullable) in (
            _POSTGRES_FINITE_TIMESTAMP_CONSTRAINTS.items()
        )
        if table in tables
    ]
    if revision >= "0003":
        checks.append(
            (
                "rate_limit_events",
                "ck_rate_limit_events_blocked_bool",
                "blocked=anyarray[0,1]",
            )
        )
    sequences = ["audit_log_id_seq"]
    if revision >= "0003":
        sequences.append("rate_limit_events_id_seq")
    return _PostgresCatalogContract(
        tables=ordered_tables,
        columns=tuple(columns),
        primary_keys=primary_keys,
        unique_constraints=unique_constraints,
        checks=tuple(sorted(checks)),
        foreign_keys=foreign_keys,
        indexes=indexes,
        sequences=tuple(sorted(sequences)),
    )


def _fixed_legacy_postgres_contract(
    revision: str,
) -> _PostgresCatalogContract:
    repaired = _fixed_postgres_contract(revision)
    tables = tuple(
        table for table in repaired.tables if table != "module_runs"
    )
    columns = tuple(
        (
            table,
            column,
            data_type,
            (
                True
                if table == "findings"
                and column in {"cvss_score", "cvss_vector", "trace_id"}
                else nullable
            ),
            default,
        )
        for table, column, data_type, nullable, default in repaired.columns
        if table != "module_runs"
    )
    indexes = tuple(
        index for index in repaired.indexes if index[0] != "module_runs"
    ) + (
        (
            "findings",
            "idx_findings_validated",
            ("validated",),
            False,
            None,
        ),
    )
    return replace(
        repaired,
        tables=tables,
        columns=columns,
        primary_keys=tuple(
            item for item in repaired.primary_keys if item[0] != "module_runs"
        ),
        checks=(),
        foreign_keys=(),
        indexes=tuple(sorted(indexes)),
    )


_POSTGRES_RUNTIME_LEGACY_CONSTRAINT_RECIPE = (
    ("0001", "module_runs", "fk_module_runs_campaign"),
    ("0001", "findings", "fk_findings_campaign"),
    ("0001", "hosts", "fk_hosts_campaign"),
    ("0001", "credentials", "fk_credentials_campaign"),
    ("0001", "credentials", "fk_credentials_host"),
    ("0001", "loot", "fk_loot_campaign"),
    ("0001", "loot", "fk_loot_host"),
    ("0001", "audit_log", "fk_audit_campaign"),
    ("0001", "api_keys", "fk_api_keys_user"),
    ("0001", "refresh_tokens", "fk_refresh_tokens_user"),
    ("0001", "campaigns", "ck_campaigns_created_at_finite"),
    ("0001", "campaigns", "ck_campaigns_updated_at_finite"),
    ("0001", "module_runs", "ck_module_runs_completed_at_finite"),
    ("0001", "findings", "ck_findings_discovered_at_finite"),
    ("0001", "hosts", "ck_hosts_first_seen_finite"),
    ("0001", "hosts", "ck_hosts_last_seen_finite"),
    ("0001", "credentials", "ck_credentials_captured_at_finite"),
    ("0001", "loot", "ck_loot_captured_at_finite"),
    ("0001", "audit_log", "ck_audit_log_timestamp_finite"),
    ("0001", "users", "ck_users_created_at_finite"),
    ("0001", "users", "ck_users_last_login_finite"),
    ("0001", "api_keys", "ck_api_keys_last_used_finite"),
    ("0001", "api_keys", "ck_api_keys_expires_at_finite"),
    ("0001", "api_keys", "ck_api_keys_created_at_finite"),
    ("0001", "refresh_tokens", "ck_refresh_tokens_expires_at_finite"),
    ("0001", "refresh_tokens", "ck_refresh_tokens_created_at_finite"),
    ("0001", "refresh_tokens", "ck_refresh_tokens_used_at_finite"),
    (
        "0003",
        "rate_limit_events",
        "ck_rate_limit_events_blocked_bool",
    ),
    (
        "0003",
        "rate_limit_events",
        "ck_rate_limit_events_timestamp_finite",
    ),
    (
        "0004",
        "revoked_access_tokens",
        "ck_revoked_access_tokens_revoked_at_finite",
    ),
    (
        "0004",
        "revoked_access_tokens",
        "ck_revoked_access_tokens_expires_at_finite",
    ),
)


def _postgres_runtime_legacy_recipe(
    revision: str,
) -> _PostgresLegacyRecipe:
    if revision not in {"0001", "0002", "0003", "0004", "0005"}:
        raise AssertionError("unsupported PostgreSQL legacy recipe revision")
    nullable_columns = [
        ("findings", "cvss_score"),
        ("findings", "cvss_vector"),
    ]
    if revision >= "0002":
        nullable_columns.append(("findings", "trace_id"))
    return _PostgresLegacyRecipe(
        constraints_to_drop=tuple(
            (table, constraint)
            for introduced, table, constraint in (
                _POSTGRES_RUNTIME_LEGACY_CONSTRAINT_RECIPE
            )
            if introduced <= revision
        ),
        tables_to_drop=("module_runs",),
        nullable_columns=tuple(nullable_columns),
        indexes_to_create=(
            (
                "idx_findings_validated",
                "findings",
                ("validated",),
            ),
        ),
    )


@pytest.fixture(autouse=True)
def _forbid_runtime_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    from ares.db.postgres import PostgresDatabase

    async def _prohibited_connect(*_args: object, **_kwargs: object) -> None:
        pytest.fail(
            "runtime PostgreSQL bootstrap was invoked",
            pytrace=False,
        )

    monkeypatch.setattr(PostgresDatabase, "connect", _prohibited_connect)


def _clear_postgres_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _POSTGRES_ENV:
        monkeypatch.delenv(name, raising=False)


def test_postgres_legacy_recipe_does_not_call_expected_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_recipe = _postgres_runtime_legacy_recipe("0005")

    def _poisoned_oracle(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("expected oracle was traversed by fixture recipe")

    module = sys.modules[__name__]
    monkeypatch.setattr(
        module,
        "_fixed_postgres_contract",
        _poisoned_oracle,
    )
    monkeypatch.setattr(
        module,
        "_fixed_legacy_postgres_contract",
        _poisoned_oracle,
    )
    constructed = _postgres_runtime_legacy_recipe("0005")
    _require_fixed(
        constructed == expected_recipe,
        "PostgreSQL legacy recipe depended on an expected oracle",
    )


def test_postgres_legacy_recipe_and_oracle_have_no_mutable_alias() -> None:
    def _deeply_immutable(value: object) -> bool:
        if isinstance(value, tuple):
            return all(_deeply_immutable(item) for item in value)
        return isinstance(value, (str, int, bool, type(None)))

    recipe = _postgres_runtime_legacy_recipe("0005")
    oracle = _fixed_legacy_postgres_contract("0005")
    recipe_constraints = list(recipe.constraints_to_drop)
    oracle_tables = list(oracle.tables)
    recipe_constraints.append(
        ("synthetic_table", "synthetic_constraint")
    )
    oracle_tables.append("synthetic_table")
    independent = (
        tuple(recipe_constraints) != recipe.constraints_to_drop
        and tuple(oracle_tables) != oracle.tables
        and _postgres_runtime_legacy_recipe("0005") == recipe
        and _fixed_legacy_postgres_contract("0005") == oracle
        and all(
            _deeply_immutable(value)
            for value in (
                recipe.constraints_to_drop,
                recipe.tables_to_drop,
                recipe.nullable_columns,
                recipe.indexes_to_create,
                oracle.tables,
                oracle.columns,
                oracle.checks,
                oracle.foreign_keys,
            )
        )
    )
    _require_fixed(
        independent,
        "PostgreSQL legacy recipe and oracle share mutable state",
    )


def test_postgres_configuration_all_absent_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_postgres_environment(monkeypatch)
    skipped = False
    try:
        _postgres_config()
    except pytest.skip.Exception:
        skipped = True
    _require_fixed(
        skipped,
        "absent PostgreSQL configuration did not intentionally skip",
    )


def test_noncanonical_database_names_do_not_configure_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_postgres_environment(monkeypatch)
    monkeypatch.setenv("ARES_TEST_POSTGRES_DATABASE", "ignored")
    monkeypatch.setenv("ARES_DATABASE_URL", "ignored")
    skipped = False
    try:
        _postgres_config()
    except pytest.skip.Exception:
        skipped = True
    _require_fixed(
        skipped,
        "noncanonical database configuration activated the harness",
    )


@pytest.mark.parametrize(
    "values",
    [
        {"ARES_TEST_POSTGRES_HOST": "configured"},
        {
            "ARES_TEST_POSTGRES_HOST": "",
            "ARES_TEST_POSTGRES_PORT": "5432",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": " ",
            "ARES_TEST_POSTGRES_PORT": "5432",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "05432",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "+5432",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "65536",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "",
            "ARES_TEST_POSTGRES_PORT": "",
            "ARES_TEST_POSTGRES_USER": "",
            "ARES_TEST_POSTGRES_DB": "",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "not-a-port",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
        {
            "ARES_TEST_POSTGRES_HOST": "configured",
            "ARES_TEST_POSTGRES_PORT": "\u0665\u0664\u0663\u0662",
            "ARES_TEST_POSTGRES_USER": "configured",
            "ARES_TEST_POSTGRES_DB": "configured",
        },
    ],
    ids=(
        "partial",
        "empty",
        "whitespace",
        "empty-port",
        "noncanonical-port",
        "signed-port",
        "out-of-range-port",
        "all-empty",
        "malformed-port",
        "non-ascii-port",
    ),
)
def test_postgres_configuration_invalid_states_fail(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[str, str],
) -> None:
    _clear_postgres_environment(monkeypatch)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    failed = False
    try:
        _postgres_config()
    except pytest.fail.Exception:
        failed = True
    _require_fixed(
        failed,
        "invalid PostgreSQL configuration did not fail",
    )


def test_postgres_configuration_complete_shape_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_postgres_environment(monkeypatch)
    values = {
        "ARES_TEST_POSTGRES_HOST": "configured",
        "ARES_TEST_POSTGRES_PORT": "5432",
        "ARES_TEST_POSTGRES_USER": "configured",
        "ARES_TEST_POSTGRES_DB": "configured",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    config = _postgres_config()
    accepted = (
        config.port == 5432
        and bool(config.host)
        and bool(config.user)
        and bool(config.maintenance_database)
    )
    _require_fixed(
        accepted,
        "complete PostgreSQL configuration was rejected",
    )


@pytest.mark.asyncio
async def test_complete_configuration_without_driver_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_postgres_environment(monkeypatch)
    values = {
        "ARES_TEST_POSTGRES_HOST": "configured",
        "ARES_TEST_POSTGRES_PORT": "5432",
        "ARES_TEST_POSTGRES_USER": "configured",
        "ARES_TEST_POSTGRES_DB": "configured",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    real_import = builtins.__import__

    def _without_asyncpg(
        name: str,
        *args: object,
        **kwargs: object,
    ) -> object:
        if name == "asyncpg":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _without_asyncpg)
    failed = False
    try:
        async with _postgres_harness():
            pytest.fail(
                "driver gate unexpectedly entered database setup",
                pytrace=False,
            )
    except pytest.fail.Exception:
        failed = True
    _require_fixed(
        failed,
        "configured PostgreSQL harness accepted a missing driver",
    )


@pytest.mark.asyncio
async def test_owned_worker_completion_and_error_are_settled() -> None:
    await _run_worker({"mode": "success"}, timeout=2.0)
    failed = False
    try:
        await _run_worker({"mode": "migration-error"}, timeout=2.0)
    except RuntimeError:
        failed = True
    _require_fixed(failed, "worker exception did not propagate")
    _require_fixed(
        len(_OWNED_WORKERS) == 0,
        "completed worker remained owned",
    )


@pytest.mark.asyncio
async def test_owned_worker_timeout_is_terminated() -> None:
    started = asyncio.Event()
    failed = False
    try:
        await _run_worker(
            {"mode": "block"},
            timeout=0.1,
            started=started,
        )
    except RuntimeError:
        failed = True
    _require_fixed(started.is_set(), "blocking worker never became ready")
    _require_fixed(failed, "blocking worker did not time out")
    _require_fixed(
        len(_OWNED_WORKERS) == 0,
        "timed-out worker remained owned",
    )


@pytest.mark.asyncio
async def test_owned_worker_parent_cancellation_is_settled() -> None:
    started = asyncio.Event()
    task = asyncio.create_task(
        _run_worker(
            {"mode": "block"},
            timeout=30.0,
            started=started,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    cancelled = False
    try:
        await task
    except asyncio.CancelledError:
        cancelled = True
    _require_fixed(cancelled, "worker parent cancellation was suppressed")
    _require_fixed(
        len(_OWNED_WORKERS) == 0,
        "cancelled worker remained owned",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "protocol-ok-before-ready",
        "protocol-duplicate-ready",
        "protocol-duplicate-ok",
        "protocol-malformed",
        "protocol-eof-before-terminal",
        "protocol-success-crash",
        "protocol-zero-without-success",
    ],
)
async def test_worker_protocol_rejects_invalid_sequences(mode: str) -> None:
    failed = False
    try:
        await _run_worker({"mode": mode}, timeout=2.0)
    except RuntimeError:
        failed = True
    _require_fixed(failed, "invalid worker protocol sequence was accepted")
    _require_fixed(
        len(_OWNED_WORKERS) == 0,
        "invalid worker protocol retained a settled worker",
    )


@pytest.mark.asyncio
async def test_worker_setup_failure_occurs_before_ready() -> None:
    started = asyncio.Event()
    caught: Exception | None = None
    try:
        await _run_worker(
            {"mode": "setup-error"},
            timeout=2.0,
            started=started,
        )
    except RuntimeError as error:
        caught = error
    fixed_failure = (
        type(caught) is RuntimeError
        and str(caught) == "Alembic worker failed [RuntimeError]"
        and bool(getattr(caught, "__suppress_context__", False))
    )
    _require_fixed(
        fixed_failure,
        "worker setup failure was not sanitized",
    )
    _require_fixed(
        not started.is_set(),
        "worker setup failure was incorrectly reported as ready",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    ["success-dirty-origin", "success-dirty-origin-removed"],
    ids=("present-at-final-guard", "removed-before-final-guard"),
)
async def test_worker_final_origin_guard_rejects_late_dirty_import(
    mode: str,
) -> None:
    failed = False
    try:
        await _run_worker(
            {"mode": mode},
            timeout=2.0,
        )
    except RuntimeError:
        failed = True
    _require_fixed(
        failed and not _OWNED_WORKERS,
        "worker final origin guard accepted a late dirty import",
    )


class _IntegrationOriginProbeLoader:
    def create_module(self, _spec: object) -> None:
        return None

    def exec_module(self, _module: object) -> None:
        return None


class _IntegrationOriginProbeFinder:
    def __init__(self, name: str, spec: object) -> None:
        self._name = name
        self._spec = spec

    def find_spec(
        self,
        fullname: str,
        _path: object = None,
        _target: object = None,
    ) -> object:
        return self._spec if fullname == self._name else None


@contextmanager
def _integration_origin_probe(
    name: str,
    spec: object,
) -> Iterator[Callable[[], None]]:
    finder = _IntegrationOriginProbeFinder(name, spec)
    parent_name, _, child_name = name.rpartition(".")
    parent = (
        importlib.import_module(parent_name)
        if parent_name
        else None
    )
    missing = object()
    previous_module = sys.modules.pop(name, missing)
    previous_attribute = (
        parent.__dict__.get(child_name, missing)
        if parent is not None
        else missing
    )
    sys.meta_path.insert(0, finder)

    def _import_then_remove() -> None:
        importlib.import_module(name)
        sys.modules.pop(name, None)
        if parent is not None and child_name in parent.__dict__:
            delattr(parent, child_name)

    try:
        yield _import_then_remove
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        sys.modules.pop(name, None)
        if previous_module is not missing:
            sys.modules[name] = previous_module
        if parent is not None:
            if previous_attribute is missing:
                if child_name in parent.__dict__:
                    delattr(parent, child_name)
            else:
                setattr(parent, child_name, previous_attribute)


@pytest.mark.parametrize(
    ("name", "mixed"),
    [
        ("ares.integration_removed_probe", False),
        ("migrations.versions.0007_add_websocket_tickets", False),
        ("migrations.versions.integration_mixed_probe", True),
    ],
    ids=("dirty-ares", "dirty-0007", "mixed-namespace"),
)
def test_integration_origin_ledger_retains_removed_import(
    tmp_path: Path,
    name: str,
    mixed: bool,
) -> None:
    if mixed:
        spec = importlib.machinery.ModuleSpec(
            name,
            loader=None,
            is_package=True,
        )
        spec.submodule_search_locations = [
            str(_REPO_ROOT / "migrations" / "versions"),
            str(tmp_path),
        ]
    else:
        spec = importlib.machinery.ModuleSpec(
            name,
            _IntegrationOriginProbeLoader(),
            origin=str(tmp_path / "probe.py"),
        )
    rejected = False
    try:
        with _integration_origin_probe(name, spec) as import_then_remove:
            with _candidate_origin_boundary(isolated=True):
                import_then_remove()
    except RuntimeError:
        rejected = True
    _require_fixed(
        rejected,
        "integration origin ledger forgot a removed import",
    )


def test_integration_final_origin_guard_rejects_late_dirty_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dirty_module = types.ModuleType("migrations.versions.late_dirty_probe")
    dirty_origin = tmp_path / "late_dirty_probe.py"
    dirty_module.__file__ = str(dirty_origin)
    dirty_module.__spec__ = importlib.machinery.ModuleSpec(
        "migrations.versions.late_dirty_probe",
        loader=None,
        origin=str(dirty_origin),
    )
    monkeypatch.setitem(
        sys.modules,
        "migrations.versions.late_dirty_probe",
        dirty_module,
    )
    rejected = not _loaded_first_party_origins_are_candidate_local(
        sys.modules,
        _REPO_ROOT,
    )
    _require_fixed(
        rejected,
        "integration final origin guard accepted a late dirty import",
    )


def _integration_reused_origin_probe_body() -> None:
    return None


def test_integration_origin_ledger_rechecks_reused_code(
    tmp_path: Path,
) -> None:
    probe_code = _integration_reused_origin_probe_body.__code__
    local_probe = types.FunctionType(
        probe_code,
        {
            "__name__": "migrations.versions.integration_reused_probe",
            "__package__": "migrations.versions",
            "__file__": str(
                _REPO_ROOT
                / "migrations"
                / "versions"
                / "0006_integration_reused_probe.py"
            ),
        },
    )
    dirty_probe = types.FunctionType(
        probe_code,
        {
            "__name__": "migrations.versions.integration_reused_probe",
            "__package__": "migrations.versions",
            "__file__": str(
                tmp_path
                / "migrations"
                / "versions"
                / "0007_integration_reused_probe.py"
            ),
        },
    )
    rejected = False
    try:
        with _candidate_origin_boundary(isolated=True):
            local_probe()
            dirty_probe()
    except RuntimeError:
        rejected = True
    _require_fixed(
        rejected,
        "integration origin ledger cached a stale frame origin",
    )


def test_integration_origin_ledger_ignores_unrelated_migrations_directory(
    tmp_path: Path,
) -> None:
    third_party_probe = types.FunctionType(
        _integration_reused_origin_probe_body.__code__,
        {
            "__name__": "third_party.integration_origin_probe",
            "__package__": "third_party",
            "__file__": str(
                tmp_path / "migrations" / "integration_origin_probe.py"
            ),
        },
    )
    with _candidate_origin_boundary(isolated=True):
        third_party_probe()


@dataclass(slots=True, repr=False)
class _IpcConfidentialityAudit:
    forbidden_values: tuple[str, ...] = field(repr=False)
    process_args_safe: bool = False
    process_closed: bool = False
    parent_endpoint_closed: bool = False
    sensitive_seen: bool = False
    unsafe_object_seen: bool = False
    sent_signatures: list[tuple[str, int]] = field(
        default_factory=list,
        repr=False,
    )
    received_signatures: list[tuple[str, int]] = field(
        default_factory=list,
        repr=False,
    )

    def _observe_value(self, value: object) -> None:
        if isinstance(value, str):
            if any(marker in value for marker in self.forbidden_values):
                self.sensitive_seen = True
            folded = value.casefold()
            if folded in {
                "postgresql",
                "postgresql+asyncpg",
                "asyncpg",
            } or any(
                marker in folded
                for marker in (
                    "postgresql://",
                    "postgresql+asyncpg://",
                    "ares_test_postgres_",
                )
            ):
                self.sensitive_seen = True
            return
        if isinstance(value, bytes):
            lowered = value.lower()
            if any(
                marker.encode("utf-8") in value
                for marker in self.forbidden_values
            ) or b"postgresql" in lowered:
                self.sensitive_seen = True
            return
        if isinstance(value, int) and any(
            marker.isdecimal() and int(marker) == value
            for marker in self.forbidden_values
        ):
            self.sensitive_seen = True
            return
        if isinstance(value, dict):
            for key, item in value.items():
                self._observe_value(key)
                self._observe_value(item)
            return
        if isinstance(value, (tuple, list)):
            for item in value:
                self._observe_value(item)
            return
        module_name = type(value).__module__
        if module_name.startswith(("alembic", "sqlalchemy")):
            self.unsafe_object_seen = True

    def observe_process(self, kwargs: dict[str, object]) -> None:
        arguments = kwargs.get("args")
        safe_shape = (
            kwargs.get("target") is _alembic_worker_entry
            and isinstance(arguments, tuple)
            and len(arguments) == 1
        )
        if isinstance(arguments, tuple):
            for argument in arguments:
                self._observe_value(argument)
        self.process_args_safe = safe_shape

    def observe_frame(self, direction: str, frame: object) -> None:
        self._observe_value(frame)
        if not isinstance(frame, tuple) or not frame:
            self.unsafe_object_seen = True
            return
        kind = frame[0] if isinstance(frame[0], str) else "INVALID"
        signature = (kind, len(frame))
        if direction == "sent":
            self.sent_signatures.append(signature)
        else:
            self.received_signatures.append(signature)


@dataclass(slots=True, repr=False)
class _AuditedParentChannel:
    raw: object = field(repr=False)
    audit: _IpcConfidentialityAudit = field(repr=False)

    def send(self, frame: object) -> None:
        self.audit.observe_frame("sent", frame)
        self.raw.send(frame)

    def recv(self) -> object:
        frame = self.raw.recv()
        self.audit.observe_frame("received", frame)
        return frame

    def poll(self) -> bool:
        return bool(self.raw.poll())

    def close(self) -> None:
        self.raw.close()
        self.audit.parent_endpoint_closed = True


@dataclass(slots=True, repr=False)
class _AuditedProcess:
    raw: object = field(repr=False)
    audit: _IpcConfidentialityAudit = field(repr=False)

    def __getattr__(self, name: str) -> object:
        return getattr(self.raw, name)

    def close(self) -> None:
        self.raw.close()
        self.audit.process_closed = True


@dataclass(slots=True, repr=False)
class _AuditedSpawnContext:
    raw: object = field(repr=False)
    audit: _IpcConfidentialityAudit = field(repr=False)
    child_endpoint: object = field(default=None, init=False, repr=False)

    def Pipe(self, *, duplex: bool) -> tuple[object, object]:  # noqa: N802
        parent, child = self.raw.Pipe(duplex=duplex)
        self.child_endpoint = child
        return _AuditedParentChannel(parent, self.audit), child

    def Process(self, **kwargs: object) -> _AuditedProcess:  # noqa: N802
        self.audit.observe_process(kwargs)
        return _AuditedProcess(self.raw.Process(**kwargs), self.audit)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "should_succeed"),
    [
        ("ipc-prepare-success", True),
        ("ipc-prepare-error", False),
    ],
    ids=("prepared-success", "prepared-sanitized-failure"),
)
async def test_migration_ipc_uses_only_fixed_control_data(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    should_succeed: bool,
) -> None:
    canonical_values = {
        "ARES_TEST_POSTGRES_HOST": "ipc-host-canary",
        "ARES_TEST_POSTGRES_PORT": "5432",
        "ARES_TEST_POSTGRES_USER": "ipc-user-canary",
        "ARES_TEST_POSTGRES_DB": "ipc-maintenance-canary",
    }
    for name, value in canonical_values.items():
        monkeypatch.setenv(name, value)
    real_context = multiprocessing.get_context("spawn")
    audit = _IpcConfidentialityAudit(
        tuple(canonical_values.values())
    )
    audited_context = _AuditedSpawnContext(real_context, audit)
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: audited_context,
    )
    caught: Exception | None = None
    try:
        await _run_worker(
            {
                "mode": mode,
                "database_name": f"ares_migration_{'a' * 32}",
                "operation": "upgrade",
                "revision": "0001",
            },
            timeout=5.0,
        )
    except RuntimeError as error:
        caught = error

    child_endpoint_closed = bool(
        audited_context.child_endpoint is not None
        and getattr(audited_context.child_endpoint, "closed", False)
    )
    expected_received = (
        [("READY", 1), ("OK", 1)]
        if should_succeed
        else [("READY", 1), ("ERROR", 2)]
    )
    result_safe = (
        (caught is None if should_succeed else type(caught) is RuntimeError)
        and (
            should_succeed
            or str(caught) == "Alembic worker failed [RuntimeError]"
        )
        and audit.process_args_safe
        and audit.sent_signatures
        == [("PAYLOAD", 2), ("GO", 1)]
        and audit.received_signatures == expected_received
        and not audit.sensitive_seen
        and not audit.unsafe_object_seen
        and audit.parent_endpoint_closed
        and child_endpoint_closed
        and audit.process_closed
        and not _OWNED_WORKERS
    )
    _require_fixed(
        result_safe,
        "migration IPC confidentiality protocol diverged",
    )


def test_child_constructs_explicit_target_from_inherited_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_environment = {
        "ARES_TEST_POSTGRES_HOST": "child-host-canary",
        "ARES_TEST_POSTGRES_PORT": "5432",
        "ARES_TEST_POSTGRES_USER": "child-user-canary",
        "ARES_TEST_POSTGRES_DB": "child-maintenance-canary",
    }
    for name, value in child_environment.items():
        monkeypatch.setenv(name, value)
    target = f"ares_migration_{'b' * 32}"
    target_url_was_child_local = False
    config_sentinel = object()
    upgrade_sentinel = object()

    def _capture_config(url: str) -> object:
        nonlocal target_url_was_child_local
        target_url_was_child_local = (
            target in url
            and child_environment["ARES_TEST_POSTGRES_HOST"] in url
            and child_environment["ARES_TEST_POSTGRES_USER"] in url
        )
        return config_sentinel

    monkeypatch.setattr(
        sys.modules[__name__],
        "_alembic_config",
        _capture_config,
    )
    config, action, revision, fault = _prepare_child_migration(
        {
            "mode": "migrate",
            "database_name": target,
            "operation": "upgrade",
            "revision": "0001",
        },
        types.SimpleNamespace(
            upgrade=upgrade_sentinel,
            downgrade=object(),
        ),
    )
    prepared = (
        target_url_was_child_local
        and config is config_sentinel
        and action is upgrade_sentinel
        and revision == "0001"
        and fault is None
    )
    _require_fixed(
        prepared,
        "child-side explicit migration target construction failed",
    )


def test_malformed_child_target_is_rejected_before_url_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_environment = {
        "ARES_TEST_POSTGRES_HOST": "configured",
        "ARES_TEST_POSTGRES_PORT": "5432",
        "ARES_TEST_POSTGRES_USER": "configured",
        "ARES_TEST_POSTGRES_DB": "configured",
    }
    for name, value in child_environment.items():
        monkeypatch.setenv(name, value)
    url_constructed = False

    def _record_url(*_args: object, **_kwargs: object) -> str:
        nonlocal url_constructed
        url_constructed = True
        return "unexpected"

    monkeypatch.setattr(
        sys.modules[__name__],
        "_migration_url",
        _record_url,
    )
    failed = False
    try:
        _prepare_child_migration(
            {
                "mode": "migrate",
                "database_name": "invalid",
                "operation": "upgrade",
                "revision": "0001",
            },
            types.SimpleNamespace(
                upgrade=object(),
                downgrade=object(),
            ),
        )
    except RuntimeError:
        failed = True
    _require_fixed(
        failed and not url_constructed,
        "malformed child target reached URL construction",
    )


@pytest.mark.asyncio
async def test_child_configuration_failure_returns_fixed_protocol_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_postgres_environment(monkeypatch)
    caught: Exception | None = None
    try:
        await _run_worker(
            {
                "mode": "migrate",
                "database_name": f"ares_migration_{'c' * 32}",
                "operation": "upgrade",
                "revision": "0001",
            },
            timeout=2.0,
        )
    except RuntimeError as error:
        caught = error
    fixed_result = (
        type(caught) is RuntimeError
        and str(caught) == "Alembic worker failed [RuntimeError]"
        and bool(getattr(caught, "__suppress_context__", False))
        and not _OWNED_WORKERS
    )
    _require_fixed(
        fixed_result,
        "child configuration failure exposed non-protocol data",
    )


class _WorkerConstructionError(RuntimeError):
    pass


class _WorkerStartError(RuntimeError):
    pass


class _WorkerEndpointCloseError(RuntimeError):
    pass


class _ConstructionEndpoint:
    def __init__(self, *, fail_close_once: bool = False) -> None:
        self.closed = False
        self.close_attempts = 0
        self.fail_close_once = fail_close_once

    def close(self) -> None:
        self.close_attempts += 1
        if self.fail_close_once and self.close_attempts == 1:
            raise _WorkerEndpointCloseError
        self.closed = True


class _NeverStartedProcess:
    def __init__(self) -> None:
        self.pid = None
        self.exitcode = None
        self.closed = False
        self.start_called = False

    def start(self) -> None:
        self.start_called = True
        raise _WorkerStartError

    def is_alive(self) -> bool:
        return False

    def close(self) -> None:
        self.closed = True


class _PipeFailureContext:
    def Pipe(self, *, duplex: bool) -> object:  # noqa: N802
        del duplex
        raise _WorkerConstructionError


class _PartialPipeFailureContext:
    def __init__(self) -> None:
        self.endpoint = _ConstructionEndpoint()

    def Pipe(self, *, duplex: bool) -> tuple[object]:  # noqa: N802
        del duplex
        return (self.endpoint,)


class _ProcessFailureContext:
    def __init__(self) -> None:
        self.parent = _ConstructionEndpoint()
        self.child = _ConstructionEndpoint()
        self.process_kwargs: dict[str, object] | None = None

    def Pipe(  # noqa: N802
        self,
        *,
        duplex: bool,
    ) -> tuple[object, object]:
        del duplex
        return self.parent, self.child

    def Process(self, **kwargs: object) -> object:  # noqa: N802
        self.process_kwargs = dict(kwargs)
        raise _WorkerConstructionError


class _StartFailureContext:
    def __init__(self, *, fail_parent_close_once: bool = False) -> None:
        self.parent = _ConstructionEndpoint(
            fail_close_once=fail_parent_close_once
        )
        self.child = _ConstructionEndpoint()
        self.process = _NeverStartedProcess()

    def Pipe(  # noqa: N802
        self,
        *,
        duplex: bool,
    ) -> tuple[object, object]:
        del duplex
        return self.parent, self.child

    def Process(  # noqa: N802
        self,
        **_kwargs: object,
    ) -> _NeverStartedProcess:
        return self.process


@pytest.mark.asyncio
async def test_worker_pipe_construction_failure_leaves_no_owned_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: _PipeFailureContext(),
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    failed_closed = (
        type(caught) is RuntimeError
        and str(caught)
        == "Alembic worker startup failed [_WorkerConstructionError]"
        and bool(getattr(caught, "__suppress_context__", False))
        and not _OWNED_WORKERS
    )
    _require_fixed(
        failed_closed,
        "Pipe construction failure leaked worker ownership",
    )


@pytest.mark.asyncio
async def test_worker_partial_pipe_result_closes_obtained_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _PartialPipeFailureContext()
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: context,
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    failed_closed = (
        type(caught) is RuntimeError
        and context.endpoint.closed
        and not _OWNED_WORKERS
    )
    _require_fixed(
        failed_closed,
        "partial Pipe construction leaked its obtained endpoint",
    )


@pytest.mark.asyncio
async def test_worker_process_construction_failure_closes_both_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ProcessFailureContext()
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: context,
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    process_arguments_are_control_only = (
        context.process_kwargs is not None
        and context.process_kwargs.get("target") is _alembic_worker_entry
        and context.process_kwargs.get("args") == (context.child,)
        and context.process_kwargs.get("name") == "ares-alembic-worker"
        and set(context.process_kwargs) == {"target", "args", "name"}
    )
    failed_closed = (
        type(caught) is RuntimeError
        and context.parent.closed
        and context.child.closed
        and process_arguments_are_control_only
        and not _OWNED_WORKERS
    )
    _require_fixed(
        failed_closed,
        "Process construction failure did not close Pipe endpoints",
    )


@pytest.mark.asyncio
async def test_worker_start_failure_before_child_creation_is_settled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _StartFailureContext()
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: context,
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    settled = (
        type(caught) is RuntimeError
        and context.process.start_called
        and context.process.closed
        and context.parent.closed
        and context.child.closed
        and not _OWNED_WORKERS
    )
    _require_fixed(
        settled,
        "pre-child start failure did not settle all owned resources",
    )


@pytest.mark.asyncio
async def test_worker_start_failure_preserves_fixed_primary_when_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _StartFailureContext(fail_parent_close_once=True)
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: context,
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    retained = tuple(_OWNED_WORKERS)
    primary_preserved = (
        type(caught) is RuntimeError
        and str(caught)
        == "Alembic worker startup failed [_WorkerStartError]"
        and tuple(getattr(caught, "__notes__", ()))
        == (
            "Alembic worker cleanup failed "
            "[settle-startup-worker: RuntimeError]",
        )
        and len(retained) == 1
    )
    if retained:
        await _settle_worker(retained[0], terminate=True)
    _require_fixed(
        primary_preserved and not _OWNED_WORKERS,
        "startup cleanup failure replaced its fixed primary failure",
    )


class _AmbiguousStartProcess:
    def __init__(self, process: Any) -> None:
        self._process = process
        self._closed = False
        self._final_exitcode: int | None = None

    def start(self) -> None:
        self._process.start()
        raise _WorkerStartError

    @property
    def exitcode(self) -> int | None:
        if self._closed:
            return self._final_exitcode
        return self._process.exitcode

    def is_alive(self) -> bool:
        return False if self._closed else bool(self._process.is_alive())

    def close(self) -> None:
        self._final_exitcode = self._process.exitcode
        self._process.close()
        self._closed = True

    def __getattr__(self, name: str) -> object:
        return getattr(self._process, name)


class _AmbiguousStartContext:
    def __init__(self, context: Any) -> None:
        self._context = context
        self.endpoints: tuple[Any, Any] | None = None
        self.process: _AmbiguousStartProcess | None = None

    def Pipe(self, *, duplex: bool) -> tuple[Any, Any]:  # noqa: N802
        self.endpoints = self._context.Pipe(duplex=duplex)
        return self.endpoints

    def Process(  # noqa: N802
        self,
        **kwargs: object,
    ) -> _AmbiguousStartProcess:
        self.process = _AmbiguousStartProcess(
            self._context.Process(**kwargs)
        )
        return self.process


@pytest.mark.asyncio
async def test_worker_ambiguous_start_failure_settles_real_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_context = multiprocessing.get_context("spawn")
    context = _AmbiguousStartContext(real_context)
    monkeypatch.setattr(
        multiprocessing,
        "get_context",
        lambda _method: context,
    )
    caught: Exception | None = None
    try:
        await _run_worker({"mode": "success"}, timeout=1.0)
    except RuntimeError as error:
        caught = error
    endpoints_closed = (
        context.endpoints is not None
        and all(endpoint.closed for endpoint in context.endpoints)
    )
    child_settled = (
        context.process is not None
        and context.process.exitcode is not None
        and not context.process.is_alive()
    )
    _require_fixed(
        type(caught) is RuntimeError
        and endpoints_closed
        and child_settled
        and not _OWNED_WORKERS,
        "ambiguous Process.start failure left a live child or endpoint",
    )


class _FakeWorkerChannel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeWorkerProcess:
    def __init__(self, *, kill_succeeds: bool) -> None:
        self.pid = 1
        self.exitcode: int | None = None
        self._alive = True
        self._kill_succeeds = kill_succeeds
        self.terminate_called = False
        self.kill_called = False
        self.closed = False

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout: float = 0) -> None:
        del timeout

    def terminate(self) -> None:
        self.terminate_called = True

    def kill(self) -> None:
        self.kill_called = True
        if self._kill_succeeds:
            self._alive = False
            self.exitcode = -9

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_worker_settlement_escalates_from_terminate_to_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys.modules[__name__],
        "_WORKER_SETTLE_SECONDS",
        0.02,
    )
    process = _FakeWorkerProcess(kill_succeeds=True)
    worker = _OwnedWorker(process=process, channel=_FakeWorkerChannel())
    _OWNED_WORKERS.add(worker)
    exit_code = await _settle_worker(worker, terminate=True)
    _require_fixed(
        process.terminate_called
        and process.kill_called
        and process.closed
        and exit_code == -9
        and worker not in _OWNED_WORKERS,
        "worker settlement did not escalate and release ownership",
    )


@pytest.mark.asyncio
async def test_unproven_worker_death_retains_ownership_and_blocks_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys.modules[__name__],
        "_WORKER_SETTLE_SECONDS",
        0.02,
    )
    process = _FakeWorkerProcess(kill_succeeds=False)
    worker = _OwnedWorker(process=process, channel=_FakeWorkerChannel())
    _OWNED_WORKERS.add(worker)
    failed = False
    try:
        await _settle_worker(worker, terminate=True)
    except RuntimeError:
        failed = True
    cleanup_failures: list[str] = []
    cleanup_allowed = await _settle_owned_workers_for_cleanup(
        cleanup_failures
    )
    retained = worker in _OWNED_WORKERS
    process._alive = False
    process.exitcode = -9
    await _settle_worker(worker, terminate=True)
    _require_fixed(
        failed
        and not cleanup_allowed
        and retained
        and bool(cleanup_failures)
        and worker not in _OWNED_WORKERS,
        "unproven worker death did not retain ownership and block cleanup",
    )


@pytest.mark.asyncio
async def test_empty_postgres_base_to_0006_uses_only_alembic() -> None:
    async with _postgres_harness() as harness:
        connection = await _connect(harness)
        try:
            initial_tables = await connection.fetchval(
                """
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema=current_schema()
                  AND table_type='BASE TABLE'
                """
            )
            no_alembic_version = (
                await connection.fetchval(
                    "SELECT to_regclass('alembic_version') IS NULL"
                )
                is True
            )
        finally:
            await connection.close()

        _require_fixed(
            initial_tables == 0 and no_alembic_version,
            "disposable PostgreSQL database was not genuinely empty",
        )
        await _alembic(harness, "upgrade", "0006")

        connection = await _connect(harness)
        try:
            tables = {
                str(row["table_name"])
                for row in await connection.fetch(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema=current_schema()
                      AND table_type='BASE TABLE'
                    """
                )
            }
            reached_revision = await _version(connection) == "0006"
            migration_only_tables = (
                tables == _EXPECTED_TABLES | {"alembic_version"}
            )
        finally:
            await connection.close()

        _require_fixed(
            reached_revision,
            "PostgreSQL did not reach revision 0006",
        )
        _require_fixed(
            migration_only_tables,
            "PostgreSQL migration-created table contract diverged",
        )


@pytest.mark.asyncio
async def test_explicit_postgres_target_excludes_environment_decoy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as selected:
        async with _postgres_harness() as decoy:
            distinct_safe_targets = (
                selected.database_name != decoy.database_name
                and selected.database_name
                != selected.config.maintenance_database
                and decoy.database_name != decoy.config.maintenance_database
                and _SAFE_DATABASE_NAME.fullmatch(selected.database_name)
                is not None
                and _SAFE_DATABASE_NAME.fullmatch(decoy.database_name)
                is not None
            )
            _require_fixed(
                distinct_safe_targets,
                "PostgreSQL target isolation identifiers were unsafe",
            )
            maintenance_before = await _database_fingerprint(
                selected.config,
                selected.config.maintenance_database,
            )
            selected_before = await _database_fingerprint(
                selected.config,
                selected.database_name,
            )
            decoy_before = await _database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            empty_baselines = (
                _isolation_fingerprint_has_no_ares_state(selected_before)
                and _isolation_fingerprint_has_no_ares_state(decoy_before)
            )
            _require_fixed(
                empty_baselines,
                "PostgreSQL isolation baselines were not empty",
            )
            decoy_url = _migration_url(
                decoy.config,
                decoy.database_name,
                ordinary_driver=True,
            )
            monkeypatch.setenv("ARES_DATABASE_URL", decoy_url)

            await _alembic(selected, "upgrade", "0004")
            selected_after_upgrade = await _database_fingerprint(
                selected.config,
                selected.database_name,
            )
            revision_after_upgrade = await _database_revision(
                selected.config,
                selected.database_name,
            )
            decoy_after_upgrade = await _database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            maintenance_after_upgrade = await _database_fingerprint(
                selected.config,
                selected.config.maintenance_database,
            )

            await _alembic(selected, "upgrade", "0004")
            selected_after_repeat = await _database_fingerprint(
                selected.config,
                selected.database_name,
            )
            revision_after_repeat = await _database_revision(
                selected.config,
                selected.database_name,
            )
            decoy_after_repeat = await _database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            maintenance_after_repeat = await _database_fingerprint(
                selected.config,
                selected.config.maintenance_database,
            )

            await _alembic(selected, "downgrade", "0003")
            selected_after_downgrade = await _database_fingerprint(
                selected.config,
                selected.database_name,
            )
            revision_after_downgrade = await _database_revision(
                selected.config,
                selected.database_name,
            )
            decoy_after_downgrade = await _database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            maintenance_after_downgrade = await _database_fingerprint(
                selected.config,
                selected.config.maintenance_database,
            )

            await _alembic(selected, "upgrade", "0004")
            selected_after_reupgrade = await _database_fingerprint(
                selected.config,
                selected.database_name,
            )
            revision_after_reupgrade = await _database_revision(
                selected.config,
                selected.database_name,
            )
            decoy_after_reupgrade = await _database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            maintenance_after_reupgrade = await _database_fingerprint(
                selected.config,
                selected.config.maintenance_database,
            )

            target_transitions_are_exact = (
                selected_after_upgrade != selected_before
                and revision_after_upgrade == "0004"
                and selected_after_repeat == selected_after_upgrade
                and revision_after_repeat == "0004"
                and selected_after_downgrade != selected_after_upgrade
                and revision_after_downgrade == "0003"
                and selected_after_reupgrade == selected_after_upgrade
                and revision_after_reupgrade == "0004"
            )
            decoy_remained_exact = all(
                fingerprint == decoy_before
                and _isolation_fingerprint_has_no_ares_state(fingerprint)
                for fingerprint in (
                    decoy_after_upgrade,
                    decoy_after_repeat,
                    decoy_after_downgrade,
                    decoy_after_reupgrade,
                )
            )
            maintenance_remained_exact = all(
                fingerprint == maintenance_before
                for fingerprint in (
                    maintenance_after_upgrade,
                    maintenance_after_repeat,
                    maintenance_after_downgrade,
                    maintenance_after_reupgrade,
                )
            )
            _require_fixed(
                target_transitions_are_exact
                and decoy_remained_exact
                and maintenance_remained_exact,
                "explicit PostgreSQL migration target isolation failed",
            )


@pytest.mark.asyncio
async def test_postgres_revision_round_trip_preserves_rows() -> None:
    async with _postgres_harness() as harness:
        for revision in ("0001", "0002", "0003", "0004", "0005"):
            await _alembic(harness, "upgrade", revision)
            connection = await _connect(harness)
            try:
                reached_revision = await _version(connection) == revision
                if revision == "0001":
                    await connection.execute(
                        "INSERT INTO campaigns(id, name) VALUES($1, $2)",
                        "campaign-a",
                        "Migration campaign",
                    )
                    await connection.execute(
                        """
                        INSERT INTO credentials(
                            id, campaign_id, username, cred_type, cracked_value
                        ) VALUES($1, $2, $3, $4, $5)
                        """,
                        "credential-a",
                        "campaign-a",
                        "synthetic-user",
                        "password",
                        "synthetic-encrypted-marker",
                    )
            finally:
                await connection.close()
            _require_fixed(
                reached_revision,
                "PostgreSQL revision sequence stopped unexpectedly",
            )

        await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            upgrade_preserved = (
                await connection.fetchval(
                    """
                    SELECT cracked_value_enc IS NOT NULL
                    FROM credentials WHERE id=$1
                    """,
                    "credential-a",
                )
                is True
            )
        finally:
            await connection.close()
        _require_fixed(
            upgrade_preserved,
            "PostgreSQL revision 0006 did not preserve the credential value",
        )

        await _alembic(harness, "downgrade", "0005")
        connection = await _connect(harness)
        try:
            downgrade_preserved = (
                await connection.fetchval(
                    """
                    SELECT cracked_value IS NOT NULL
                    FROM credentials WHERE id=$1
                    """,
                    "credential-a",
                )
                is True
            )
        finally:
            await connection.close()
        _require_fixed(
            downgrade_preserved,
            "PostgreSQL revision 0006 downgrade lost a credential value",
        )

        for revision in ("0004", "0003", "0002", "0001"):
            await _alembic(harness, "downgrade", revision)
            connection = await _connect(harness)
            try:
                reached_revision = await _version(connection) == revision
            finally:
                await connection.close()
            _require_fixed(
                reached_revision,
                "PostgreSQL downgrade sequence stopped unexpectedly",
            )

        connection = await _connect(harness)
        try:
            parent_columns = {
                str(row["column_name"])
                for row in await connection.fetch(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema=current_schema()
                      AND table_name='findings'
                    """
                )
            }
        finally:
            await connection.close()
        parent_is_repaired = (
            {"cvss_score", "cvss_vector"}.issubset(parent_columns)
            and "trace_id" not in parent_columns
        )
        _require_fixed(
            parent_is_repaired,
            "PostgreSQL revision 0002 downgrade contradicted its parent",
        )

        await _alembic(harness, "downgrade", "base")
        connection = await _connect(harness)
        try:
            remaining_application_tables = await connection.fetchval(
                """
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema=current_schema()
                  AND table_name = ANY($1::text[])
                """,
                list(_EXPECTED_TABLES),
            )
        finally:
            await connection.close()
        _require_fixed(
            remaining_application_tables == 0,
            "PostgreSQL downgrade to base retained an application table",
        )

        await _alembic(harness, "upgrade", "0006")


@pytest.mark.asyncio
async def test_postgres_downgrades_restore_exact_repaired_parents() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0006")

        parent_by_revision = {
            "0006": "0005",
            "0005": "0004",
            "0004": "0003",
            "0003": "0002",
            "0002": "0001",
            "0001": "base",
        }
        for _revision, parent in parent_by_revision.items():
            await _alembic(harness, "downgrade", parent)
            connection = await _connect(harness)
            try:
                actual = await _postgres_catalog_contract(connection)
            finally:
                await connection.close()
            expected = _fixed_postgres_contract(parent)
            _require_fixed(
                actual == expected,
                "PostgreSQL downgrade did not restore its repaired parent",
            )


@pytest.mark.asyncio
async def test_postgres_0006_catalog_types_defaults_fks_and_indexes() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            all_column_rows = await connection.fetch(
                """
                SELECT
                    table_name,
                    ordinal_position,
                    column_name,
                    data_type,
                    is_nullable
                FROM information_schema.columns
                WHERE table_schema=current_schema()
                  AND table_name = ANY($1::text[])
                ORDER BY table_name, ordinal_position
                """,
                list(_EXPECTED_COLUMN_ORDER),
            )
            actual_columns: dict[str, list[tuple[str, str, str]]] = {}
            for row in all_column_rows:
                actual_columns.setdefault(
                    str(row["table_name"]),
                    [],
                ).append(
                    (
                        str(row["column_name"]),
                        str(row["data_type"]),
                        str(row["is_nullable"]),
                    )
                )
            columns_are_exact = True
            for table, expected_order in _EXPECTED_COLUMN_ORDER.items():
                rows = actual_columns.get(table, [])
                if tuple(row[0] for row in rows) != expected_order:
                    columns_are_exact = False
                    break
                for name, data_type, nullable in rows:
                    key = (table, name)
                    if key in _POSTGRES_INTEGER_COLUMNS:
                        expected_type = "integer"
                    elif key in _POSTGRES_FLOAT_COLUMNS:
                        expected_type = "double precision"
                    elif key in _POSTGRES_TIMESTAMP_COLUMNS:
                        expected_type = "timestamp with time zone"
                    else:
                        expected_type = "text"
                    expected_nullable = (
                        "YES"
                        if key in _POSTGRES_NULLABLE_COLUMNS
                        else "NO"
                    )
                    if (
                        data_type != expected_type
                        or nullable != expected_nullable
                    ):
                        columns_are_exact = False
                        break
                if not columns_are_exact:
                    break

            sequence_defaults = {
                (str(row["table_name"]), str(row["column_name"]))
                for row in await connection.fetch(
                    """
                    SELECT table_name, column_name
                    FROM information_schema.columns
                    WHERE table_schema=current_schema()
                      AND column_default LIKE 'nextval(%'
                    """
                )
            }
            sequence_contract_matches = sequence_defaults == {
                ("audit_log", "id"),
                ("rate_limit_events", "id"),
            }
            timestamp_rows = await connection.fetch(
                """
                SELECT table_name, column_name, data_type, column_default
                FROM information_schema.columns
                WHERE table_schema=current_schema()
                  AND (
                    (table_name='campaigns' AND column_name='created_at')
                    OR
                    (table_name='module_runs' AND column_name='completed_at')
                    OR
                    (table_name='findings' AND column_name='discovered_at')
                    OR
                    (table_name='rate_limit_events' AND column_name='timestamp')
                    OR
                    (
                        table_name='revoked_access_tokens'
                        AND column_name='revoked_at'
                    )
                  )
                """
            )
            timestamps_are_aware = len(timestamp_rows) == 5 and all(
                row["data_type"] == "timestamp with time zone"
                and "now()" in str(row["column_default"]).lower()
                for row in timestamp_rows
            )
            hardened_columns = await connection.fetchval(
                """
                SELECT count(*)
                FROM information_schema.columns
                WHERE table_schema=current_schema()
                  AND table_name='findings'
                  AND column_name = ANY(
                      ARRAY['cvss_score', 'cvss_vector', 'trace_id']
                  )
                  AND is_nullable='NO'
                """
            )
            nullability_matches = hardened_columns == 3

            foreign_key_rows = await connection.fetch(
                """
                SELECT
                    source.relname AS source_table,
                    source_column.attname AS source_column,
                    target.relname AS target_table,
                    CASE constraint.confdeltype
                        WHEN 'c' THEN 'CASCADE'
                        WHEN 'n' THEN 'SET NULL'
                        ELSE 'OTHER'
                    END AS delete_action
                FROM pg_constraint AS constraint
                JOIN pg_class AS source
                  ON source.oid=constraint.conrelid
                JOIN pg_class AS target
                  ON target.oid=constraint.confrelid
                JOIN pg_attribute AS source_column
                  ON source_column.attrelid=source.oid
                 AND source_column.attnum=constraint.conkey[1]
                WHERE constraint.contype='f'
                  AND source.relnamespace=current_schema()::regnamespace
                """
            )
            foreign_keys = {
                (
                    str(row["source_table"]),
                    str(row["source_column"]),
                    str(row["target_table"]),
                    str(row["delete_action"]),
                )
                for row in foreign_key_rows
            }

            index_rows = await connection.fetch(
                """
                SELECT
                    index_class.relname AS index_name,
                    array_agg(attribute.attname ORDER BY key.ordinality) AS columns
                FROM pg_index AS index_catalog
                JOIN pg_class AS table_class
                  ON table_class.oid=index_catalog.indrelid
                JOIN pg_class AS index_class
                  ON index_class.oid=index_catalog.indexrelid
                JOIN unnest(index_catalog.indkey)
                    WITH ORDINALITY AS key(attnum, ordinality)
                  ON key.attnum > 0
                JOIN pg_attribute AS attribute
                  ON attribute.attrelid=table_class.oid
                 AND attribute.attnum=key.attnum
                WHERE table_class.relnamespace=current_schema()::regnamespace
                  AND NOT index_catalog.indisprimary
                  AND NOT index_catalog.indisunique
                GROUP BY index_class.relname
                """,
            )
            indexes = {
                str(row["index_name"]): tuple(row["columns"])
                for row in index_rows
            }
            primary_key_tables = {
                str(row["table_name"])
                for row in await connection.fetch(
                    """
                    SELECT table_class.relname AS table_name
                    FROM pg_constraint AS constraint
                    JOIN pg_class AS table_class
                      ON table_class.oid=constraint.conrelid
                    WHERE constraint.contype='p'
                      AND table_class.relnamespace=
                          current_schema()::regnamespace
                    """
                )
            }
            primary_keys_match = primary_key_tables == _EXPECTED_TABLES
            unique_contracts = {
                str(row["constraint_name"])
                for row in await connection.fetch(
                    """
                    SELECT constraint_name
                    FROM information_schema.table_constraints
                    WHERE table_schema=current_schema()
                      AND constraint_type='UNIQUE'
                    """
                )
            }
            uniqueness_matches = unique_contracts == {
                "uq_hosts_campaign_ip",
                "uq_users_username",
            }

            fk_rejected = False
            try:
                await connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title, description, severity
                    ) VALUES($1, $2, $3, $4, $5, $6)
                    """,
                    "finding-a",
                    "missing-campaign",
                    "module-a",
                    "title",
                    "description",
                    "high",
                )
            except Exception as exc:
                fk_rejected = type(exc).__name__ == "ForeignKeyViolationError"
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()

        _require_fixed(
            columns_are_exact,
            "PostgreSQL ordered column/type/nullability contract diverged",
        )
        _require_fixed(
            sequence_contract_matches,
            "PostgreSQL sequence-backed identity contract diverged",
        )
        _require_fixed(
            timestamps_are_aware,
            "PostgreSQL timestamp/default contract diverged",
        )
        _require_fixed(
            nullability_matches,
            "PostgreSQL finding nullability contract diverged",
        )
        _require_fixed(
            primary_keys_match,
            "PostgreSQL primary-key contract diverged",
        )
        _require_fixed(
            uniqueness_matches,
            "PostgreSQL uniqueness contract diverged",
        )
        _require_fixed(
            foreign_keys == _EXPECTED_FOREIGN_KEYS,
            "PostgreSQL foreign-key contract diverged",
        )
        _require_fixed(
            indexes == _EXPECTED_INDEXES,
            "PostgreSQL logical index contract diverged",
        )
        _require_fixed(
            fk_rejected,
            "PostgreSQL did not enforce a required foreign key",
        )
        _require_fixed(
            reusable,
            "PostgreSQL connection was not reusable after a constraint error",
        )


@pytest.mark.asyncio
async def test_postgres_all_timestamp_columns_reject_infinity() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            await _seed_postgres_contract(connection)
            constraint_rows = await connection.fetch(
                """
                SELECT
                    relation.relname AS table_name,
                    constraint.conname AS constraint_name,
                    pg_get_constraintdef(constraint.oid) AS definition
                FROM pg_constraint AS constraint
                JOIN pg_class AS relation
                  ON relation.oid=constraint.conrelid
                WHERE relation.relnamespace=current_schema()::regnamespace
                  AND constraint.contype='c'
                """
            )
            observed_constraints = {
                (
                    str(row["table_name"]),
                    str(row["constraint_name"]),
                ): " ".join(
                    str(row["definition"]).lower().replace('"', "").split()
                )
                for row in constraint_rows
            }
            semantic_constraints_match = True
            for (
                table,
                column,
            ), (name, nullable) in (
                _POSTGRES_FINITE_TIMESTAMP_CONSTRAINTS.items()
            ):
                definition = observed_constraints.get((table, name), "")
                compact = definition.replace(" ", "").replace("(", "").replace(
                    ")", ""
                )
                has_finite = f"isfinite{column}" in compact
                has_nullable = f"{column}isnullor" in compact
                if not has_finite or has_nullable != nullable:
                    semantic_constraints_match = False
                    break

            key_by_table = {
                "campaigns": ("id", "campaign-contract"),
                "module_runs": ("id", "run-contract"),
                "findings": ("id", "finding-contract"),
                "hosts": ("id", "host-contract"),
                "credentials": ("id", "credential-contract"),
                "loot": ("id", "loot-contract"),
                "audit_log": ("id", 1),
                "users": ("id", "user-contract"),
                "api_keys": ("id", "api-key-contract"),
                "refresh_tokens": ("id", "refresh-contract"),
                "revoked_access_tokens": ("jti", "revoked-contract"),
                "rate_limit_events": ("id", 1),
            }
            finite_value = datetime(2030, 1, 1, tzinfo=timezone.utc)
            enforced_for_every_column = True
            for (table, column), (_name, nullable) in sorted(
                _POSTGRES_FINITE_TIMESTAMP_CONSTRAINTS.items()
            ):
                key_name, key_value = key_by_table[table]
                update_finite = (
                    f'UPDATE "{table}" SET "{column}"=$1 '  # noqa: S608
                    f'WHERE "{key_name}"=$2'
                )
                await connection.execute(
                    update_finite,
                    finite_value,
                    key_value,
                )
                finite_applied = await connection.fetchval(
                    (
                        f'SELECT isfinite("{column}") FROM "{table}" '  # noqa: S608
                        f'WHERE "{key_name}"=$1'
                    ),
                    key_value,
                )
                positive_rejected = await _postgres_integrity_failure(
                    connection,
                    (
                        f'UPDATE "{table}" '  # noqa: S608
                        f'SET "{column}"=\'infinity\'::timestamptz '
                        f'WHERE "{key_name}"=$1'
                    ),
                    key_value,
                    expected_type="CheckViolationError",
                )
                positive_unchanged = await connection.fetchval(
                    (
                        f'SELECT isfinite("{column}") FROM "{table}" '  # noqa: S608
                        f'WHERE "{key_name}"=$1'
                    ),
                    key_value,
                )
                negative_rejected = await _postgres_integrity_failure(
                    connection,
                    (
                        f'UPDATE "{table}" '  # noqa: S608
                        f'SET "{column}"=\'-infinity\'::timestamptz '
                        f'WHERE "{key_name}"=$1'
                    ),
                    key_value,
                    expected_type="CheckViolationError",
                )
                negative_unchanged = await connection.fetchval(
                    (
                        f'SELECT isfinite("{column}") FROM "{table}" '  # noqa: S608
                        f'WHERE "{key_name}"=$1'
                    ),
                    key_value,
                )
                if nullable:
                    await connection.execute(
                        (
                            f'UPDATE "{table}" SET "{column}"=NULL '  # noqa: S608
                            f'WHERE "{key_name}"=$1'
                        ),
                        key_value,
                    )
                    null_contract = await connection.fetchval(
                        (
                            f'SELECT "{column}" IS NULL FROM "{table}" '  # noqa: S608
                            f'WHERE "{key_name}"=$1'
                        ),
                        key_value,
                    )
                    await connection.execute(
                        update_finite,
                        finite_value,
                        key_value,
                    )
                else:
                    null_contract = await _postgres_integrity_failure(
                        connection,
                        (
                            f'UPDATE "{table}" SET "{column}"=NULL '  # noqa: S608
                            f'WHERE "{key_name}"=$1'
                        ),
                        key_value,
                        expected_type="NotNullViolationError",
                    )
                if not all(
                    (
                        finite_applied is True,
                        positive_rejected,
                        positive_unchanged is True,
                        negative_rejected,
                        negative_unchanged is True,
                        null_contract is True,
                    )
                ):
                    enforced_for_every_column = False
                    break
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()

        _require_fixed(
            semantic_constraints_match,
            "PostgreSQL finite timestamp catalog contract diverged",
        )
        _require_fixed(
            enforced_for_every_column and reusable,
            "PostgreSQL finite timestamp enforcement diverged",
        )


@pytest.mark.asyncio
async def test_postgres_0006_enforces_complete_relational_contract() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            await _seed_postgres_contract(connection)
            key_by_table = {
                "campaigns": ("id", "campaign-contract"),
                "module_runs": ("id", "run-contract"),
                "findings": ("id", "finding-contract"),
                "hosts": ("id", "host-contract"),
                "credentials": ("id", "credential-contract"),
                "loot": ("id", "loot-contract"),
                "audit_log": ("id", 1),
                "users": ("id", "user-contract"),
                "api_keys": ("id", "api-key-contract"),
                "refresh_tokens": ("id", "refresh-contract"),
                "revoked_access_tokens": ("jti", "revoked-contract"),
                "rate_limit_events": ("id", 1),
            }

            required_columns_rejected = True
            for table, order in _EXPECTED_COLUMN_ORDER.items():
                key_name, key_value = key_by_table[table]
                for name in order:
                    if (table, name) in _POSTGRES_NULLABLE_COLUMNS:
                        continue
                    statement = (
                        f'UPDATE "{table}" SET "{name}"=NULL '  # noqa: S608
                        f'WHERE "{key_name}"=$1'
                    )
                    if not await _postgres_integrity_failure(
                        connection,
                        statement,
                        key_value,
                        expected_type="NotNullViolationError",
                    ):
                        required_columns_rejected = False
                        break

            foreign_keys_rejected = True
            for table, local, _remote, _action in sorted(
                _EXPECTED_FOREIGN_KEYS
            ):
                key_name, key_value = key_by_table[table]
                statement = (
                    f'UPDATE "{table}" SET "{local}"=$1 '  # noqa: S608
                    f'WHERE "{key_name}"=$2'
                )
                if not await _postgres_integrity_failure(
                    connection,
                    statement,
                    "missing-parent",
                    key_value,
                    expected_type="ForeignKeyViolationError",
                ):
                    foreign_keys_rejected = False
                    break

            duplicate_host_rejected = await _postgres_integrity_failure(
                connection,
                """
                INSERT INTO hosts(id, campaign_id, ip_address)
                VALUES($1, $2, $3)
                """,
                "host-duplicate",
                "campaign-contract",
                "192.0.2.10",
                expected_type="UniqueViolationError",
            )
            duplicate_user_rejected = await _postgres_integrity_failure(
                connection,
                """
                INSERT INTO users(id, username, hashed_password)
                VALUES($1, $2, $3)
                """,
                "user-duplicate",
                "synthetic-account",
                "synthetic-hash",
                expected_type="UniqueViolationError",
            )

            transaction = connection.transaction()
            await transaction.start()
            try:
                await connection.execute(
                    "DELETE FROM hosts WHERE id=$1",
                    "host-contract",
                )
                set_null_rows = await connection.fetchrow(
                    """
                    SELECT
                        (SELECT host_id IS NULL FROM credentials WHERE id=$1)
                            AS credential_cleared,
                        (SELECT host_id IS NULL FROM loot WHERE id=$2)
                            AS loot_cleared
                    """,
                    "credential-contract",
                    "loot-contract",
                )
                set_null_enforced = (
                    set_null_rows is not None
                    and set_null_rows["credential_cleared"] is True
                    and set_null_rows["loot_cleared"] is True
                )
            finally:
                await transaction.rollback()

            transaction = connection.transaction()
            await transaction.start()
            try:
                await connection.execute(
                    "DELETE FROM campaigns WHERE id=$1",
                    "campaign-contract",
                )
                campaign_actions = await connection.fetchrow(
                    """
                    SELECT
                        (SELECT count(*) FROM module_runs) AS runs,
                        (SELECT count(*) FROM findings) AS findings,
                        (SELECT count(*) FROM hosts) AS hosts,
                        (SELECT count(*) FROM credentials) AS credentials,
                        (SELECT count(*) FROM loot) AS loot,
                        (
                            SELECT campaign_id IS NULL
                            FROM audit_log
                            WHERE id=1
                        ) AS audit_cleared
                    """
                )
                campaign_actions_enforced = (
                    campaign_actions is not None
                    and tuple(campaign_actions.values())
                    == (0, 0, 0, 0, 0, True)
                )
            finally:
                await transaction.rollback()

            transaction = connection.transaction()
            await transaction.start()
            try:
                await connection.execute(
                    "DELETE FROM users WHERE id=$1",
                    "user-contract",
                )
                user_actions = await connection.fetchrow(
                    """
                    SELECT
                        (SELECT count(*) FROM api_keys) AS api_keys,
                        (SELECT count(*) FROM refresh_tokens)
                            AS refresh_tokens
                    """
                )
                user_cascade_enforced = (
                    user_actions is not None
                    and tuple(user_actions.values()) == (0, 0)
                )
            finally:
                await transaction.rollback()

            timestamp_values = await connection.fetchrow(
                """
                SELECT
                    (SELECT created_at FROM campaigns LIMIT 1) AS campaign,
                    (SELECT completed_at FROM module_runs LIMIT 1) AS run,
                    (SELECT discovered_at FROM findings LIMIT 1) AS finding,
                    (SELECT first_seen FROM hosts LIMIT 1) AS host,
                    (SELECT captured_at FROM credentials LIMIT 1)
                        AS credential,
                    (SELECT captured_at FROM loot LIMIT 1) AS loot,
                    (SELECT timestamp FROM audit_log LIMIT 1) AS audit,
                    (SELECT created_at FROM users LIMIT 1) AS account,
                    (SELECT created_at FROM api_keys LIMIT 1) AS api_key,
                    (SELECT created_at FROM refresh_tokens LIMIT 1)
                        AS refresh,
                    (SELECT revoked_at FROM revoked_access_tokens LIMIT 1)
                        AS revoked,
                    (SELECT timestamp FROM rate_limit_events LIMIT 1)
                        AS rate_limit
                """
            )
            timestamp_defaults_execute = (
                timestamp_values is not None
                and all(
                    isinstance(value, datetime)
                    and value.utcoffset() is not None
                    for value in timestamp_values.values()
                )
            )
            integer_defaults_execute = (
                await connection.fetchrow(
                    """
                    SELECT
                        (SELECT success=0 FROM module_runs LIMIT 1) AS run,
                        (
                            SELECT validated=0 AND false_positive=0
                            FROM findings LIMIT 1
                        ) AS finding,
                        (SELECT is_dc=0 FROM hosts LIMIT 1) AS host,
                        (SELECT cracked=0 FROM credentials LIMIT 1)
                            AS credential,
                        (SELECT is_active=1 FROM users LIMIT 1) AS account,
                        (SELECT is_active=1 FROM api_keys LIMIT 1) AS api_key,
                        (SELECT is_revoked=0 FROM refresh_tokens LIMIT 1)
                            AS refresh,
                        (SELECT blocked=0 FROM rate_limit_events LIMIT 1)
                            AS rate_limit
                    """
                )
            )
            integer_defaults_match = (
                integer_defaults_execute is not None
                and all(integer_defaults_execute.values())
            )

            audit_second = await connection.fetchval(
                """
                INSERT INTO audit_log(action) VALUES($1)
                RETURNING id
                """,
                "second-action",
            )
            await connection.execute(
                "DELETE FROM audit_log WHERE id=$1",
                audit_second,
            )
            audit_third = await connection.fetchval(
                """
                INSERT INTO audit_log(action) VALUES($1)
                RETURNING id
                """,
                "third-action",
            )
            rate_second = await connection.fetchval(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES($1, $2)
                RETURNING id
                """,
                "192.0.2.21",
                "synthetic-bucket",
            )
            await connection.execute(
                "DELETE FROM rate_limit_events WHERE id=$1",
                rate_second,
            )
            rate_third = await connection.fetchval(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES($1, $2)
                RETURNING id
                """,
                "192.0.2.22",
                "synthetic-bucket",
            )
            monotonic_sequences = (
                int(audit_third) > int(audit_second)
                and int(rate_third) > int(rate_second)
            )
        finally:
            await connection.close()

        _require_fixed(
            required_columns_rejected,
            "PostgreSQL accepted NULL in a required column",
        )
        _require_fixed(
            foreign_keys_rejected,
            "PostgreSQL accepted an invalid foreign-key parent",
        )
        _require_fixed(
            duplicate_host_rejected and duplicate_user_rejected,
            "PostgreSQL uniqueness enforcement diverged",
        )
        _require_fixed(
            set_null_enforced,
            "PostgreSQL SET NULL behavior diverged",
        )
        _require_fixed(
            campaign_actions_enforced and user_cascade_enforced,
            "PostgreSQL cascade behavior diverged",
        )
        _require_fixed(
            timestamp_defaults_execute,
            "PostgreSQL aware timestamp defaults diverged",
        )
        _require_fixed(
            integer_defaults_match,
            "PostgreSQL integer defaults diverged",
        )
        _require_fixed(
            monotonic_sequences,
            "PostgreSQL sequence behavior diverged",
        )


@pytest.mark.asyncio
async def test_postgres_0003_blocked_integer_contract_is_enforced() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0003")
        connection = await _connect(harness)
        try:
            await connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES($1, $2)
                """,
                "synthetic-a",
                "bucket",
            )
            await connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket, blocked)
                VALUES($1, $2, $3)
                """,
                "synthetic-b",
                "bucket",
                0,
            )
            await connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket, blocked)
                VALUES($1, $2, $3)
                """,
                "synthetic-c",
                "bucket",
                1,
            )
            valid_contract = await connection.fetchrow(
                """
                SELECT count(*) AS row_count,
                       min(blocked) AS minimum,
                       max(blocked) AS maximum,
                       bool_and(timestamp IS NOT NULL) AS timestamps_present
                FROM rate_limit_events
                """
            )
            rejected = 0
            for index, value in enumerate((None, -1, 2, 17)):
                try:
                    await connection.execute(
                        """
                        INSERT INTO rate_limit_events(
                            ip_address, bucket, blocked
                        ) VALUES($1, $2, $3)
                        """,
                        f"synthetic-invalid-{index}",
                        "bucket",
                        value,
                    )
                except Exception as exc:
                    if type(exc).__name__ in {
                        "CheckViolationError",
                        "NotNullViolationError",
                    }:
                        rejected += 1
            invalid_rows = await connection.fetchval(
                """
                SELECT count(*) FROM rate_limit_events
                WHERE ip_address LIKE 'synthetic-invalid-%'
                """
            )
            check_definition = await connection.fetchval(
                """
                SELECT pg_get_constraintdef(constraint.oid)
                FROM pg_constraint AS constraint
                JOIN pg_class AS relation
                  ON relation.oid=constraint.conrelid
                WHERE relation.relname='rate_limit_events'
                  AND constraint.conname='ck_rate_limit_events_blocked_bool'
                """
            )
            check_is_semantic = (
                isinstance(check_definition, str)
                and "blocked" in check_definition
                and "= ANY" in check_definition
                and "0" in check_definition
                and "1" in check_definition
            )
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()

        valid_values = (
            valid_contract is not None
            and valid_contract["row_count"] == 3
            and valid_contract["minimum"] == 0
            and valid_contract["maximum"] == 1
            and valid_contract["timestamps_present"] is True
        )
        _require_fixed(
            valid_values
            and rejected == 4
            and invalid_rows == 0
            and check_is_semantic
            and reusable,
            "PostgreSQL blocked integer contract was not enforced",
        )

        await _alembic(harness, "downgrade", "0002")
        connection = await _connect(harness)
        try:
            removed = (
                await connection.fetchval(
                    "SELECT to_regclass('rate_limit_events') IS NULL"
                )
                is True
            )
        finally:
            await connection.close()
        await _alembic(harness, "upgrade", "0003")
        connection = await _connect(harness)
        try:
            reupgrade_rejected = False
            try:
                await connection.execute(
                    """
                    INSERT INTO rate_limit_events(
                        ip_address, bucket, blocked
                    ) VALUES($1, $2, $3)
                    """,
                    "synthetic-reupgrade",
                    "bucket",
                    2,
                )
            except Exception as exc:
                reupgrade_rejected = (
                    type(exc).__name__ == "CheckViolationError"
                )
        finally:
            await connection.close()
        _require_fixed(
            removed and reupgrade_rejected,
            "PostgreSQL 0003 downgrade/re-upgrade lost enforcement",
        )


@pytest.mark.asyncio
async def test_postgres_0005_trace_normalization_round_trip() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0004")
        connection = await _connect(harness)
        try:
            await connection.execute(
                "INSERT INTO campaigns(id, name) VALUES($1, $2)",
                "campaign-trace",
                "Migration campaign",
            )
            for index, trace_value in enumerate((None, "", "trace-marker")):
                await connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title,
                        description, severity, trace_id
                    ) VALUES($1, $2, $3, $4, $5, $6, $7)
                    """,
                    f"finding-{index}",
                    "campaign-trace",
                    "module",
                    f"title-{index}",
                    "description",
                    "low",
                    trace_value,
                )
        finally:
            await connection.close()

        await _alembic(harness, "upgrade", "0005")
        connection = await _connect(harness)
        try:
            upgraded = await connection.fetchrow(
                """
                SELECT count(*) AS row_count,
                       count(*) FILTER (WHERE trace_id IS NULL) AS null_count,
                       count(*) FILTER (WHERE trace_id='') AS empty_count,
                       count(*) FILTER (
                           WHERE trace_id='trace-marker'
                       ) AS marker_count,
                       count(DISTINCT title) AS title_count
                FROM findings
                """
            )
        finally:
            await connection.close()
        upgraded_correctly = (
            upgraded is not None
            and tuple(upgraded.values()) == (3, 0, 2, 1, 3)
        )
        _require_fixed(
            upgraded_correctly,
            "PostgreSQL trace normalization changed protected state",
        )

        await _alembic(harness, "downgrade", "0004")
        connection = await _connect(harness)
        try:
            await connection.execute(
                """
                INSERT INTO findings(
                    id, campaign_id, module_id, title,
                    description, severity, trace_id
                ) VALUES($1, $2, $3, $4, $5, $6, NULL)
                """,
                "finding-after-downgrade",
                "campaign-trace",
                "module",
                "title-after-downgrade",
                "description",
                "low",
            )
        finally:
            await connection.close()
        await _alembic(harness, "upgrade", "0005")
        connection = await _connect(harness)
        try:
            reupgraded = await connection.fetchrow(
                """
                SELECT count(*) AS row_count,
                       count(*) FILTER (WHERE trace_id IS NULL) AS null_count,
                       count(*) FILTER (WHERE trace_id='') AS empty_count,
                       count(*) FILTER (
                           WHERE trace_id='trace-marker'
                       ) AS marker_count
                FROM findings
                """
            )
        finally:
            await connection.close()
        reupgraded_correctly = (
            reupgraded is not None
            and tuple(reupgraded.values()) == (4, 0, 3, 1)
        )
        _require_fixed(
            reupgraded_correctly,
            "PostgreSQL trace re-upgrade diverged",
        )


async def _install_postgres_version_failure(connection: Any) -> None:
    await connection.execute(
        """
        CREATE OR REPLACE FUNCTION migration_version_failure()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $body$
        BEGIN
            RAISE EXCEPTION 'migration version update denied';
        END;
        $body$
        """
    )
    await connection.execute(
        """
        CREATE TRIGGER migration_version_failure
        BEFORE UPDATE ON alembic_version
        FOR EACH ROW EXECUTE FUNCTION migration_version_failure()
        """
    )


async def _remove_postgres_version_failure(connection: Any) -> None:
    await connection.execute(
        "DROP TRIGGER IF EXISTS migration_version_failure "
        "ON alembic_version"
    )
    await connection.execute(
        "DROP FUNCTION IF EXISTS migration_version_failure()"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize(
    "boundary",
    ["before-hardening", "after-hardening", "version-update"],
)
async def test_postgres_0005_failure_boundaries_roll_back_atomically(
    direction: str,
    boundary: str,
) -> None:
    async with _postgres_harness() as harness:
        starting_revision = "0004" if direction == "upgrade" else "0005"
        result_revision = "0005" if direction == "upgrade" else "0004"
        await _alembic(harness, "upgrade", starting_revision)
        connection = await _connect(harness)
        try:
            await connection.execute(
                "INSERT INTO campaigns(id, name) VALUES($1, $2)",
                "campaign-failure",
                "Synthetic campaign",
            )
            await connection.execute(
                """
                INSERT INTO findings(
                    id, campaign_id, module_id, title,
                    description, severity, trace_id
                ) VALUES($1, $2, $3, $4, $5, $6, $7)
                """,
                "finding-failure",
                "campaign-failure",
                "module",
                "Synthetic title",
                "Synthetic description",
                "low",
                None if direction == "upgrade" else "",
            )
            before_contract = await _postgres_catalog_contract(connection)
            before_rows = await connection.fetchrow(
                """
                SELECT
                    count(*) AS rows,
                    count(*) FILTER (WHERE trace_id IS NULL) AS nulls,
                    count(*) FILTER (WHERE trace_id='') AS empty_values
                FROM findings
                """
            )
            if boundary == "version-update":
                await _install_postgres_version_failure(connection)
        finally:
            await connection.close()

        fault = {
            "before-hardening": "0005-before-alter",
            "after-hardening": "0005-after-alter",
            "version-update": None,
        }[boundary]
        failed = False
        try:
            if direction == "upgrade":
                await _alembic(
                    harness,
                    "upgrade",
                    "0005",
                    fault=fault,
                )
            else:
                await _alembic(
                    harness,
                    "downgrade",
                    "0004",
                    fault=fault,
                )
        except RuntimeError:
            failed = True

        connection = await _connect(harness)
        try:
            if boundary == "version-update":
                await _remove_postgres_version_failure(connection)
            after_contract = await _postgres_catalog_contract(connection)
            after_rows = await connection.fetchrow(
                """
                SELECT
                    count(*) AS rows,
                    count(*) FILTER (WHERE trace_id IS NULL) AS nulls,
                    count(*) FILTER (WHERE trace_id='') AS empty_values
                FROM findings
                """
            )
            current_revision = await _version(connection)
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()
        rolled_back = (
            failed
            and before_contract == after_contract
            and before_rows is not None
            and after_rows is not None
            and tuple(before_rows.values()) == tuple(after_rows.values())
            and current_revision == starting_revision
            and reusable
        )
        _require_fixed(
            rolled_back,
            "PostgreSQL revision 0005 failure was not atomic",
        )

        if direction == "upgrade":
            await _alembic(harness, "upgrade", "0005")
        else:
            await _alembic(harness, "downgrade", "0004")
        connection = await _connect(harness)
        try:
            recovered = (
                await _version(connection) == result_revision
                and await _postgres_catalog_contract(connection)
                == _fixed_postgres_contract(result_revision)
            )
        finally:
            await connection.close()
        _require_fixed(
            recovered,
            "PostgreSQL revision 0005 did not recover after rollback",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize("boundary", ["rename", "version-update"])
async def test_postgres_0006_failure_after_rename_rolls_back_atomically(
    direction: str,
    boundary: str,
) -> None:
    async with _postgres_harness() as harness:
        starting_revision = "0005" if direction == "upgrade" else "0006"
        result_revision = "0006" if direction == "upgrade" else "0005"
        source_column = (
            "cracked_value"
            if direction == "upgrade"
            else "cracked_value_enc"
        )
        result_column = (
            "cracked_value_enc"
            if direction == "upgrade"
            else "cracked_value"
        )
        await _alembic(harness, "upgrade", starting_revision)
        connection = await _connect(harness)
        try:
            await connection.execute(
                "INSERT INTO campaigns(id, name) VALUES($1, $2)",
                "campaign-rename",
                "Synthetic campaign",
            )
            await connection.execute(
                f"""
                INSERT INTO credentials(
                    id, campaign_id, username, cred_type, "{source_column}"
                ) VALUES($1, $2, $3, $4, $5)
                """,
                "credential-rename",
                "campaign-rename",
                "synthetic-user",
                "password",
                "synthetic-marker",
            )
            before_contract = await _postgres_catalog_contract(connection)
            if boundary == "version-update":
                await _install_postgres_version_failure(connection)
        finally:
            await connection.close()

        failed = False
        try:
            if direction == "upgrade":
                await _alembic(
                    harness,
                    "upgrade",
                    "0006",
                    fault=(
                        "0006-after-rename"
                        if boundary == "rename"
                        else None
                    ),
                )
            else:
                await _alembic(
                    harness,
                    "downgrade",
                    "0005",
                    fault=(
                        "0006-after-rename"
                        if boundary == "rename"
                        else None
                    ),
                )
        except RuntimeError:
            failed = True

        connection = await _connect(harness)
        try:
            if boundary == "version-update":
                await _remove_postgres_version_failure(connection)
            after_contract = await _postgres_catalog_contract(connection)
            source_value_query = (
                "SELECT count(*) FROM credentials "
                "WHERE cracked_value IS NOT NULL"
                if source_column == "cracked_value"
                else "SELECT count(*) FROM credentials "
                "WHERE cracked_value_enc IS NOT NULL"
            )
            unchanged_value = await connection.fetchval(
                source_value_query
            )
            current_revision = await _version(connection)
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()
        _require_fixed(
            failed
            and before_contract == after_contract
            and unchanged_value == 1
            and current_revision == starting_revision
            and reusable,
            "PostgreSQL revision 0006 failure was not atomic",
        )

        if direction == "upgrade":
            await _alembic(harness, "upgrade", "0006")
        else:
            await _alembic(harness, "downgrade", "0005")
        connection = await _connect(harness)
        try:
            result_value_query = (
                "SELECT count(*) FROM credentials "
                "WHERE cracked_value IS NOT NULL"
                if result_column == "cracked_value"
                else "SELECT count(*) FROM credentials "
                "WHERE cracked_value_enc IS NOT NULL"
            )
            recovered_value = await connection.fetchval(
                result_value_query
            )
            recovered = (
                await _version(connection) == result_revision
                and await _postgres_catalog_contract(connection)
                == _fixed_postgres_contract(result_revision)
                and recovered_value == 1
            )
        finally:
            await connection.close()
        _require_fixed(
            recovered,
            "PostgreSQL revision 0006 did not recover after rollback",
        )


async def _transform_postgres_runtime_legacy_catalog(
    connection: Any,
    revision: str,
) -> None:
    recipe = _postgres_runtime_legacy_recipe(revision)
    for table, name in recipe.constraints_to_drop:
        await connection.execute(
            f'ALTER TABLE "{table}" DROP CONSTRAINT "{name}"'
        )
    for table in recipe.tables_to_drop:
        await connection.execute(f'DROP TABLE "{table}"')
    for table, column in recipe.nullable_columns:
        await connection.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" DROP NOT NULL'
        )
    for name, table, columns in recipe.indexes_to_create:
        rendered_columns = ", ".join(
            f'"{column}"' for column in columns
        )
        await connection.execute(
            f'CREATE INDEX "{name}" ON "{table}" ({rendered_columns})'
        )


async def _seed_postgres_legacy_catalog(
    connection: Any,
    revision: str,
) -> None:
    await connection.execute(
        "INSERT INTO campaigns(id, name) VALUES($1, $2)",
        "legacy-campaign",
        "Synthetic legacy campaign",
    )
    if revision >= "0002":
        await connection.execute(
            """
            INSERT INTO findings(
                id, campaign_id, module_id, title,
                description, severity, cvss_score, cvss_vector, trace_id
            ) VALUES($1, $2, $3, $4, $5, $6, NULL, NULL, NULL)
            """,
            "legacy-finding",
            "legacy-campaign",
            "module",
            "Synthetic finding",
            "Synthetic description",
            "low",
        )
    else:
        await connection.execute(
            """
            INSERT INTO findings(
                id, campaign_id, module_id, title,
                description, severity, cvss_score, cvss_vector
            ) VALUES($1, $2, $3, $4, $5, $6, NULL, NULL)
            """,
            "legacy-finding",
            "legacy-campaign",
            "module",
            "Synthetic finding",
            "Synthetic description",
            "low",
        )
    await connection.execute(
        """
        INSERT INTO hosts(id, campaign_id, ip_address)
        VALUES($1, $2, $3)
        """,
        "legacy-host",
        "legacy-campaign",
        "192.0.2.70",
    )
    await connection.execute(
        """
        INSERT INTO credentials(
            id, campaign_id, host_id, username, cred_type, cracked_value
        ) VALUES($1, $2, $3, $4, $5, $6)
        """,
        "legacy-credential",
        "legacy-campaign",
        "legacy-host",
        "synthetic-user",
        "password",
        "synthetic-marker",
    )
    await connection.execute(
        """
        INSERT INTO loot(id, campaign_id, host_id, loot_type, name)
        VALUES($1, $2, $3, $4, $5)
        """,
        "legacy-loot",
        "legacy-campaign",
        "legacy-host",
        "metadata",
        "Synthetic loot",
    )
    await connection.execute(
        "INSERT INTO audit_log(campaign_id, action) VALUES($1, $2)",
        "legacy-campaign",
        "synthetic-action",
    )
    await connection.execute(
        """
        INSERT INTO users(id, username, hashed_password)
        VALUES($1, $2, $3)
        """,
        "legacy-user",
        "synthetic-account",
        "synthetic-hash",
    )
    await connection.execute(
        """
        INSERT INTO api_keys(id, user_id, name, key_hash, key_prefix)
        VALUES($1, $2, $3, $4, $5)
        """,
        "legacy-api-key",
        "legacy-user",
        "Synthetic key",
        "synthetic-hash",
        "synthetic",
    )
    await connection.execute(
        """
        INSERT INTO refresh_tokens(id, user_id, expires_at)
        VALUES($1, $2, $3)
        """,
        "legacy-refresh",
        "legacy-user",
        datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    if revision >= "0003":
        await connection.execute(
            """
            INSERT INTO rate_limit_events(ip_address, bucket)
            VALUES($1, $2)
            """,
            "192.0.2.71",
            "synthetic-bucket",
        )
    if revision >= "0004":
        await connection.execute(
            """
            INSERT INTO revoked_access_tokens(jti, user_id, expires_at)
            VALUES($1, $2, $3)
            """,
            "legacy-revoked",
            "legacy-user",
            datetime(2099, 1, 1, tzinfo=timezone.utc),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "legacy_revision",
    ["0001", "0002", "0003", "0004", "0005"],
)
async def test_complete_postgres_runtime_legacy_catalogs_are_preserved(
    legacy_revision: str,
) -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", legacy_revision)
        connection = await _connect(harness)
        try:
            await _transform_postgres_runtime_legacy_catalog(
                connection,
                legacy_revision,
            )
            await _seed_postgres_legacy_catalog(
                connection,
                legacy_revision,
            )
            initial_contract = await _postgres_catalog_contract(connection)
        finally:
            await connection.close()
        _require_fixed(
            initial_contract
            == _fixed_legacy_postgres_contract(legacy_revision),
            "constructed PostgreSQL legacy catalog diverged",
        )

        await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            row_counts = await connection.fetchrow(
                """
                SELECT
                    (SELECT count(*) FROM campaigns) AS campaigns,
                    (SELECT count(*) FROM findings) AS findings,
                    (SELECT count(*) FROM hosts) AS hosts,
                    (SELECT count(*) FROM credentials) AS credentials,
                    (SELECT count(*) FROM loot) AS loot,
                    (SELECT count(*) FROM audit_log) AS audit,
                    (SELECT count(*) FROM users) AS users,
                    (SELECT count(*) FROM api_keys) AS api_keys,
                    (SELECT count(*) FROM refresh_tokens) AS refresh_tokens
                """
            )
            protected_value_present = await connection.fetchval(
                """
                SELECT count(*) FROM credentials
                WHERE cracked_value_enc IS NOT NULL
                """
            )
            structural_drift_deferred = (
                await connection.fetchval(
                    "SELECT to_regclass('module_runs') IS NULL"
                )
                is True
                and not (
                    await _postgres_catalog_contract(connection)
                ).foreign_keys
            )
            current_revision = await _version(connection)
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()
        preserved = (
            row_counts is not None
            and tuple(row_counts.values())
            == (1, 1, 1, 1, 1, 1, 1, 1, 1)
            and protected_value_present == 1
            and structural_drift_deferred
            and current_revision == "0006"
            and reusable
        )
        _require_fixed(
            preserved,
            "PostgreSQL legacy catalog upgrade lost protected state",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("revision", "column"),
    [("0002", "cvss_score"), ("0005", "trace_id")],
)
async def test_postgres_legacy_missing_column_variants(
    revision: str,
    column: str,
) -> None:
    async with _postgres_harness() as harness:
        parent = "0001" if revision == "0002" else "0004"
        await _alembic(harness, "upgrade", parent)
        connection = await _connect(harness)
        try:
            if revision == "0002":
                await connection.execute(
                    "ALTER TABLE findings DROP COLUMN cvss_score"
                )
                await connection.execute(
                    "ALTER TABLE findings DROP COLUMN cvss_vector"
                )
            else:
                await connection.execute(
                    "ALTER TABLE findings DROP COLUMN trace_id"
                )
        finally:
            await connection.close()

        await _alembic(harness, "upgrade", revision)
        connection = await _connect(harness)
        try:
            repaired = (
                await connection.fetchval(
                    """
                    SELECT count(*)
                    FROM information_schema.columns
                    WHERE table_schema=current_schema()
                      AND table_name='findings'
                      AND column_name=$1
                      AND is_nullable='NO'
                    """,
                    column,
                )
                == 1
            )
        finally:
            await connection.close()
        _require_fixed(
            repaired,
            "PostgreSQL legacy finding catalog was not reconciled",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    ["target-only", "both", "neither"],
)
async def test_postgres_0006_catalog_variants(variant: str) -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0005")
        connection = await _connect(harness)
        try:
            if variant == "target-only":
                await connection.execute(
                    "ALTER TABLE credentials "
                    "RENAME COLUMN cracked_value TO cracked_value_enc"
                )
            elif variant == "both":
                await connection.execute(
                    "ALTER TABLE credentials ADD COLUMN cracked_value_enc TEXT"
                )
            else:
                await connection.execute(
                    "ALTER TABLE credentials DROP COLUMN cracked_value"
                )
        finally:
            await connection.close()

        if variant == "target-only":
            await _alembic(harness, "upgrade", "0006")
            connection = await _connect(harness)
            try:
                accepted = await _version(connection) == "0006"
            finally:
                await connection.close()
            _require_fixed(
                accepted,
                "PostgreSQL target-only catalog was not accepted",
            )
            return

        with pytest.raises(
            RuntimeError,
            match="^Alembic worker failed \\[RuntimeError\\]$",
        ):
            await _alembic(harness, "upgrade", "0006")
        connection = await _connect(harness)
        try:
            remained_at_parent = await _version(connection) == "0005"
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()
        _require_fixed(
            remained_at_parent,
            "failed PostgreSQL revision advanced the Alembic version",
        )
        _require_fixed(
            reusable,
            "PostgreSQL connection was not reusable after migration failure",
        )


async def _postgres_credential_catalog_fingerprint(
    connection: Any,
) -> tuple[object, ...]:
    columns = tuple(
        tuple(row.values())
        for row in await connection.fetch(
            """
            SELECT
                column_name,
                ordinal_position,
                data_type,
                udt_name,
                is_nullable,
                column_default,
                is_identity
            FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND table_name='credentials'
            ORDER BY ordinal_position
            """
        )
    )
    constraints = tuple(
        tuple(row.values())
        for row in await connection.fetch(
            """
            SELECT
                constraint.conname,
                constraint.contype,
                pg_get_constraintdef(constraint.oid)
            FROM pg_constraint AS constraint
            JOIN pg_class AS relation
              ON relation.oid=constraint.conrelid
            WHERE relation.relnamespace=current_schema()::regnamespace
              AND relation.relname='credentials'
            ORDER BY constraint.conname
            """
        )
    )
    indexes = tuple(
        tuple(row.values())
        for row in await connection.fetch(
            """
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname=current_schema()
              AND tablename='credentials'
            ORDER BY indexname
            """
        )
    )
    return columns, constraints, indexes


async def _prepare_postgres_0006_variant(
    connection: Any,
    *,
    source: str,
    target: str,
    variant: str,
) -> None:
    if variant == "source-only":
        return
    if variant == "target-only":
        await connection.execute(
            f'ALTER TABLE credentials RENAME COLUMN "{source}" TO "{target}"'
        )
        return
    if variant == "both":
        await connection.execute(
            f'ALTER TABLE credentials ADD COLUMN "{target}" TEXT'
        )
        return
    if variant == "neither":
        await connection.execute(
            f'ALTER TABLE credentials DROP COLUMN "{source}"'
        )
        return
    if variant.startswith("wrong-target-"):
        await connection.execute(
            f'ALTER TABLE credentials DROP COLUMN "{source}"'
        )
        inspected = target
        if variant.endswith("-type"):
            definition = "VARCHAR(64)"
        elif variant.endswith("-nullability"):
            definition = "TEXT NOT NULL"
        elif variant.endswith("-default-null"):
            definition = "TEXT DEFAULT NULL"
        elif variant.endswith("-default"):
            definition = "TEXT DEFAULT ''::text"
        else:
            raise AssertionError("unknown PostgreSQL target variant")
        await connection.execute(
            f'ALTER TABLE credentials ADD COLUMN "{inspected}" {definition}'
        )
        return
    if variant.startswith("wrong-source-"):
        if variant.endswith("-type"):
            await connection.execute(
                f'ALTER TABLE credentials ALTER COLUMN "{source}" '
                "TYPE VARCHAR(64)"
            )
        elif variant.endswith("-nullability"):
            await connection.execute(
                f'ALTER TABLE credentials ALTER COLUMN "{source}" SET NOT NULL'
            )
        elif variant.endswith("-default-null"):
            await connection.execute(
                f'ALTER TABLE credentials ALTER COLUMN "{source}" '
                "SET DEFAULT NULL"
            )
        elif variant.endswith("-default"):
            await connection.execute(
                f'ALTER TABLE credentials ALTER COLUMN "{source}" '
                "SET DEFAULT ''::text"
            )
        else:
            raise AssertionError("unknown PostgreSQL source variant")
        return
    raise AssertionError("unknown PostgreSQL revision 0006 variant")


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize(
    "variant",
    [
        "source-only",
        "target-only",
        "both",
        "neither",
        "wrong-source-type",
        "wrong-source-nullability",
        "wrong-source-default",
        "wrong-source-default-null",
        "wrong-target-type",
        "wrong-target-nullability",
        "wrong-target-default",
        "wrong-target-default-null",
    ],
)
async def test_postgres_0006_exact_column_state_machine(
    direction: str,
    variant: str,
) -> None:
    async with _postgres_harness() as harness:
        if direction == "upgrade":
            await _alembic(harness, "upgrade", "0005")
            source = "cracked_value"
            target = "cracked_value_enc"
            parent_revision = "0005"
            result_revision = "0006"
        else:
            await _alembic(harness, "upgrade", "0006")
            source = "cracked_value_enc"
            target = "cracked_value"
            parent_revision = "0006"
            result_revision = "0005"

        connection = await _connect(harness)
        try:
            await _prepare_postgres_0006_variant(
                connection,
                source=source,
                target=target,
                variant=variant,
            )
            present_columns = {
                str(row["column_name"])
                for row in await connection.fetch(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema=current_schema()
                      AND table_name='credentials'
                    """
                )
            }
            value_column = (
                source
                if source in present_columns
                else target if target in present_columns else None
            )
            await connection.execute(
                "INSERT INTO campaigns(id, name) VALUES($1, $2)",
                "campaign-0006",
                "Migration campaign",
            )
            if value_column == "cracked_value":
                await connection.execute(
                    """
                    INSERT INTO credentials(
                        id, campaign_id, username, cred_type, cracked_value
                    ) VALUES($1, $2, $3, $4, $5)
                    """,
                    "credential-0006",
                    "campaign-0006",
                    "synthetic-user",
                    "password",
                    "synthetic-marker",
                )
            elif value_column == "cracked_value_enc":
                await connection.execute(
                    """
                    INSERT INTO credentials(
                        id, campaign_id, username, cred_type, cracked_value_enc
                    ) VALUES($1, $2, $3, $4, $5)
                    """,
                    "credential-0006",
                    "campaign-0006",
                    "synthetic-user",
                    "password",
                    "synthetic-marker",
                )
            before_catalog = await _postgres_credential_catalog_fingerprint(
                connection
            )
            before_rows = await connection.fetchval(
                "SELECT count(*) FROM credentials"
            )
        finally:
            await connection.close()

        failed = False
        try:
            if direction == "upgrade":
                await _alembic(harness, "upgrade", "0006")
            else:
                await _alembic(harness, "downgrade", "0005")
        except RuntimeError:
            failed = True

        connection = await _connect(harness)
        try:
            after_catalog = await _postgres_credential_catalog_fingerprint(
                connection
            )
            after_rows = await connection.fetchval(
                "SELECT count(*) FROM credentials"
            )
            target_definition = await connection.fetchrow(
                """
                SELECT data_type, udt_name, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema=current_schema()
                  AND table_name='credentials'
                  AND column_name=$1
                """,
                target,
            )
            target_is_exact = (
                target_definition is not None
                and target_definition["data_type"] == "text"
                and target_definition["udt_name"] == "text"
                and target_definition["is_nullable"] == "YES"
                and target_definition["column_default"] is None
            )
            if target == "cracked_value_enc":
                preserved = (
                    await connection.fetchval(
                        """
                        SELECT count(*) FROM credentials
                        WHERE cracked_value_enc IS NOT NULL
                        """
                    )
                    == 1
                )
            else:
                preserved = (
                    await connection.fetchval(
                        """
                        SELECT count(*) FROM credentials
                        WHERE cracked_value IS NOT NULL
                        """
                    )
                    == 1
                )
            current_revision = await _version(connection)
            reusable = await connection.fetchval("SELECT 1") == 1
        finally:
            await connection.close()

        allowed = variant in {"source-only", "target-only"}
        if allowed:
            _require_fixed(
                not failed
                and current_revision == result_revision
                and target_is_exact
                and preserved
                and reusable,
                "PostgreSQL revision 0006 rejected an exact catalog",
            )
        else:
            _require_fixed(
                failed
                and current_revision == parent_revision
                and before_catalog == after_catalog
                and before_rows == after_rows
                and reusable,
                "PostgreSQL revision 0006 changed an incompatible catalog",
            )
