"""SQLite execution tests for the portable historical Alembic chain."""
from __future__ import annotations

import argparse
import importlib
import importlib.machinery
import os
import re
import sqlite3
import sys
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import URL

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_APP_TABLES = {
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
_EXPECTED_COLUMNS = {
    "campaigns": {
        "id",
        "name",
        "client",
        "operator",
        "noise_profile",
        "status",
        "scope_json",
        "targets_json",
        "notes",
        "created_at",
        "updated_at",
    },
    "module_runs": {
        "id",
        "campaign_id",
        "module_id",
        "outcome",
        "success",
        "duration_ms",
        "completed_at",
    },
    "findings": {
        "id",
        "campaign_id",
        "module_id",
        "title",
        "description",
        "severity",
        "confidence",
        "mitre_technique",
        "mitre_tactic",
        "cvss_score",
        "cvss_vector",
        "trace_id",
        "evidence_json",
        "remediation",
        "host",
        "validated",
        "false_positive",
        "discovered_at",
    },
    "hosts": {
        "id",
        "campaign_id",
        "ip_address",
        "hostname",
        "fqdn",
        "os",
        "os_version",
        "domain",
        "is_dc",
        "open_ports_json",
        "tags_json",
        "first_seen",
        "last_seen",
    },
    "credentials": {
        "id",
        "campaign_id",
        "host_id",
        "username",
        "secret_enc",
        "cred_type",
        "domain",
        "source_module",
        "notes",
        "cracked",
        "cracked_value_enc",
        "captured_at",
    },
    "loot": {
        "id",
        "campaign_id",
        "host_id",
        "loot_type",
        "name",
        "description",
        "content_enc",
        "size_bytes",
        "path_on_target",
        "source_module",
        "tags_json",
        "captured_at",
    },
    "audit_log": {
        "id",
        "campaign_id",
        "actor",
        "action",
        "detail",
        "module_id",
        "timestamp",
    },
    "users": {
        "id",
        "username",
        "hashed_password",
        "role",
        "is_active",
        "created_by",
        "created_at",
        "last_login",
    },
    "api_keys": {
        "id",
        "user_id",
        "name",
        "key_hash",
        "key_prefix",
        "scopes",
        "is_active",
        "last_used",
        "expires_at",
        "created_at",
    },
    "refresh_tokens": {
        "id",
        "user_id",
        "is_revoked",
        "expires_at",
        "created_at",
        "used_at",
    },
    "revoked_access_tokens": {
        "jti",
        "user_id",
        "revoked_at",
        "expires_at",
    },
    "rate_limit_events": {
        "id",
        "ip_address",
        "bucket",
        "username",
        "blocked",
        "timestamp",
    },
}
_EXPECTED_COLUMN_ORDER = {
    "campaigns": (
        "id",
        "name",
        "client",
        "operator",
        "noise_profile",
        "status",
        "scope_json",
        "targets_json",
        "notes",
        "created_at",
        "updated_at",
    ),
    "module_runs": (
        "id",
        "campaign_id",
        "module_id",
        "outcome",
        "success",
        "duration_ms",
        "completed_at",
    ),
    "findings": (
        "id",
        "campaign_id",
        "module_id",
        "title",
        "description",
        "severity",
        "confidence",
        "mitre_technique",
        "mitre_tactic",
        "cvss_score",
        "cvss_vector",
        "evidence_json",
        "remediation",
        "host",
        "validated",
        "false_positive",
        "discovered_at",
        "trace_id",
    ),
    "hosts": (
        "id",
        "campaign_id",
        "ip_address",
        "hostname",
        "fqdn",
        "os",
        "os_version",
        "domain",
        "is_dc",
        "open_ports_json",
        "tags_json",
        "first_seen",
        "last_seen",
    ),
    "credentials": (
        "id",
        "campaign_id",
        "host_id",
        "username",
        "secret_enc",
        "cred_type",
        "domain",
        "source_module",
        "notes",
        "cracked",
        "cracked_value_enc",
        "captured_at",
    ),
    "loot": (
        "id",
        "campaign_id",
        "host_id",
        "loot_type",
        "name",
        "description",
        "content_enc",
        "size_bytes",
        "path_on_target",
        "source_module",
        "tags_json",
        "captured_at",
    ),
    "audit_log": (
        "id",
        "campaign_id",
        "actor",
        "action",
        "detail",
        "module_id",
        "timestamp",
    ),
    "users": (
        "id",
        "username",
        "hashed_password",
        "role",
        "is_active",
        "created_by",
        "created_at",
        "last_login",
    ),
    "api_keys": (
        "id",
        "user_id",
        "name",
        "key_hash",
        "key_prefix",
        "scopes",
        "is_active",
        "last_used",
        "expires_at",
        "created_at",
    ),
    "refresh_tokens": (
        "id",
        "user_id",
        "is_revoked",
        "expires_at",
        "created_at",
        "used_at",
    ),
    "revoked_access_tokens": (
        "jti",
        "user_id",
        "revoked_at",
        "expires_at",
    ),
    "rate_limit_events": (
        "id",
        "ip_address",
        "bucket",
        "username",
        "blocked",
        "timestamp",
    ),
}
_EXPECTED_SQLITE_COLUMN_FINGERPRINTS = {
    "campaigns": (
        ("id", "TEXT", 1, None, 1),
        ("name", "TEXT", 1, None, 0),
        ("client", "TEXT", 1, "'Internal'", 0),
        ("operator", "TEXT", 1, "'unknown'", 0),
        ("noise_profile", "TEXT", 1, "'stealth'", 0),
        ("status", "TEXT", 1, "'created'", 0),
        ("scope_json", "TEXT", 1, "'[]'", 0),
        ("targets_json", "TEXT", 1, "'[]'", 0),
        ("notes", "TEXT", 0, "''", 0),
        ("created_at", "TEXT", 1, "datetime('now')", 0),
        ("updated_at", "TEXT", 1, "datetime('now')", 0),
    ),
    "module_runs": (
        ("id", "TEXT", 1, None, 1),
        ("campaign_id", "TEXT", 1, None, 0),
        ("module_id", "TEXT", 1, None, 0),
        ("outcome", "TEXT", 1, None, 0),
        ("success", "INTEGER", 1, "'0'", 0),
        ("duration_ms", "FLOAT", 1, "'0.0'", 0),
        ("completed_at", "TEXT", 1, "datetime('now')", 0),
    ),
    "findings": (
        ("id", "TEXT", 1, None, 1),
        ("campaign_id", "TEXT", 1, None, 0),
        ("module_id", "TEXT", 1, None, 0),
        ("title", "TEXT", 1, None, 0),
        ("description", "TEXT", 1, None, 0),
        ("severity", "TEXT", 1, None, 0),
        ("confidence", "FLOAT", 1, "'1.0'", 0),
        ("mitre_technique", "TEXT", 0, None, 0),
        ("mitre_tactic", "TEXT", 0, None, 0),
        ("cvss_score", "FLOAT", 1, "'0.0'", 0),
        ("cvss_vector", "TEXT", 1, "''", 0),
        ("evidence_json", "TEXT", 1, "'{}'", 0),
        ("remediation", "TEXT", 0, "''", 0),
        ("host", "TEXT", 0, None, 0),
        ("validated", "INTEGER", 1, "'0'", 0),
        ("false_positive", "INTEGER", 1, "'0'", 0),
        ("discovered_at", "TEXT", 1, "datetime('now')", 0),
        ("trace_id", "TEXT", 1, "''", 0),
    ),
    "hosts": (
        ("id", "TEXT", 1, None, 1),
        ("campaign_id", "TEXT", 1, None, 0),
        ("ip_address", "TEXT", 1, None, 0),
        ("hostname", "TEXT", 0, None, 0),
        ("fqdn", "TEXT", 0, None, 0),
        ("os", "TEXT", 0, None, 0),
        ("os_version", "TEXT", 0, None, 0),
        ("domain", "TEXT", 0, None, 0),
        ("is_dc", "INTEGER", 1, "'0'", 0),
        ("open_ports_json", "TEXT", 1, "'[]'", 0),
        ("tags_json", "TEXT", 1, "'[]'", 0),
        ("first_seen", "TEXT", 1, "datetime('now')", 0),
        ("last_seen", "TEXT", 1, "datetime('now')", 0),
    ),
    "credentials": (
        ("id", "TEXT", 1, None, 1),
        ("campaign_id", "TEXT", 1, None, 0),
        ("host_id", "TEXT", 0, None, 0),
        ("username", "TEXT", 1, None, 0),
        ("secret_enc", "TEXT", 0, None, 0),
        ("cred_type", "TEXT", 1, None, 0),
        ("domain", "TEXT", 0, None, 0),
        ("source_module", "TEXT", 0, None, 0),
        ("notes", "TEXT", 0, "''", 0),
        ("cracked", "INTEGER", 1, "'0'", 0),
        ("cracked_value_enc", "TEXT", 0, None, 0),
        ("captured_at", "TEXT", 1, "datetime('now')", 0),
    ),
    "loot": (
        ("id", "TEXT", 1, None, 1),
        ("campaign_id", "TEXT", 1, None, 0),
        ("host_id", "TEXT", 0, None, 0),
        ("loot_type", "TEXT", 1, None, 0),
        ("name", "TEXT", 1, None, 0),
        ("description", "TEXT", 0, "''", 0),
        ("content_enc", "TEXT", 0, None, 0),
        ("size_bytes", "INTEGER", 0, "'0'", 0),
        ("path_on_target", "TEXT", 0, None, 0),
        ("source_module", "TEXT", 0, None, 0),
        ("tags_json", "TEXT", 1, "'[]'", 0),
        ("captured_at", "TEXT", 1, "datetime('now')", 0),
    ),
    "audit_log": (
        ("id", "INTEGER", 1, None, 1),
        ("campaign_id", "TEXT", 0, None, 0),
        ("actor", "TEXT", 1, "'system'", 0),
        ("action", "TEXT", 1, None, 0),
        ("detail", "TEXT", 0, "''", 0),
        ("module_id", "TEXT", 0, None, 0),
        ("timestamp", "TEXT", 1, "datetime('now')", 0),
    ),
    "users": (
        ("id", "TEXT", 1, None, 1),
        ("username", "TEXT", 1, None, 0),
        ("hashed_password", "TEXT", 1, None, 0),
        ("role", "TEXT", 1, "'reporter'", 0),
        ("is_active", "INTEGER", 1, "'1'", 0),
        ("created_by", "TEXT", 1, "'system'", 0),
        ("created_at", "TEXT", 1, "datetime('now')", 0),
        ("last_login", "TEXT", 0, None, 0),
    ),
    "api_keys": (
        ("id", "TEXT", 1, None, 1),
        ("user_id", "TEXT", 1, None, 0),
        ("name", "TEXT", 1, None, 0),
        ("key_hash", "TEXT", 1, None, 0),
        ("key_prefix", "TEXT", 1, None, 0),
        ("scopes", "TEXT", 1, "'read'", 0),
        ("is_active", "INTEGER", 1, "'1'", 0),
        ("last_used", "TEXT", 0, None, 0),
        ("expires_at", "TEXT", 0, None, 0),
        ("created_at", "TEXT", 1, "datetime('now')", 0),
    ),
    "refresh_tokens": (
        ("id", "TEXT", 1, None, 1),
        ("user_id", "TEXT", 1, None, 0),
        ("is_revoked", "INTEGER", 1, "'0'", 0),
        ("expires_at", "TEXT", 1, None, 0),
        ("created_at", "TEXT", 1, "datetime('now')", 0),
        ("used_at", "TEXT", 0, None, 0),
    ),
    "revoked_access_tokens": (
        ("jti", "TEXT", 1, None, 1),
        ("user_id", "TEXT", 1, None, 0),
        ("revoked_at", "TEXT", 1, "datetime('now')", 0),
        ("expires_at", "TEXT", 1, None, 0),
    ),
    "rate_limit_events": (
        ("id", "INTEGER", 1, None, 1),
        ("ip_address", "TEXT", 1, None, 0),
        ("bucket", "TEXT", 1, None, 0),
        ("username", "TEXT", 0, None, 0),
        ("blocked", "INTEGER", 1, "'0'", 0),
        ("timestamp", "TEXT", 1, "datetime('now')", 0),
    ),
}
_EXPECTED_UNIQUE_CONSTRAINTS = {
    ("hosts", ("campaign_id", "ip_address")),
    ("users", ("username",)),
}
_EXPECTED_INDEXES = {
    "idx_module_runs_campaign": ("module_runs", ("campaign_id",)),
    "idx_module_runs_completed": ("module_runs", ("completed_at",)),
    "idx_findings_campaign": ("findings", ("campaign_id",)),
    "idx_findings_severity": ("findings", ("severity",)),
    "idx_findings_fp": ("findings", ("false_positive",)),
    "idx_findings_mitre": ("findings", ("mitre_technique",)),
    "idx_findings_cvss": ("findings", ("cvss_score",)),
    "idx_hosts_campaign": ("hosts", ("campaign_id",)),
    "idx_hosts_ip": ("hosts", ("ip_address",)),
    "idx_hosts_domain": ("hosts", ("domain",)),
    "idx_creds_campaign": ("credentials", ("campaign_id",)),
    "idx_creds_username": ("credentials", ("username",)),
    "idx_creds_type": ("credentials", ("cred_type",)),
    "idx_loot_campaign": ("loot", ("campaign_id",)),
    "idx_loot_type": ("loot", ("loot_type",)),
    "idx_audit_campaign": ("audit_log", ("campaign_id",)),
    "idx_audit_actor": ("audit_log", ("actor",)),
    "idx_audit_action": ("audit_log", ("action",)),
    "idx_users_username": ("users", ("username",)),
    "idx_users_role": ("users", ("role",)),
    "idx_apikeys_user": ("api_keys", ("user_id",)),
    "idx_apikeys_prefix": ("api_keys", ("key_prefix",)),
    "idx_refresh_user": ("refresh_tokens", ("user_id",)),
    "idx_refresh_exp": ("refresh_tokens", ("expires_at",)),
    "idx_rat_expires": ("revoked_access_tokens", ("expires_at",)),
    "idx_rle_ip": ("rate_limit_events", ("ip_address",)),
    "idx_rle_timestamp": ("rate_limit_events", ("timestamp",)),
    "idx_rle_blocked": ("rate_limit_events", ("blocked",)),
}
_EXPECTED_FOREIGN_KEYS = {
    ("module_runs", "campaign_id", "campaigns", "id", "CASCADE"),
    ("findings", "campaign_id", "campaigns", "id", "CASCADE"),
    ("hosts", "campaign_id", "campaigns", "id", "CASCADE"),
    ("credentials", "campaign_id", "campaigns", "id", "CASCADE"),
    ("credentials", "host_id", "hosts", "id", "SET NULL"),
    ("loot", "campaign_id", "campaigns", "id", "CASCADE"),
    ("loot", "host_id", "hosts", "id", "SET NULL"),
    ("audit_log", "campaign_id", "campaigns", "id", "SET NULL"),
    ("api_keys", "user_id", "users", "id", "CASCADE"),
    ("refresh_tokens", "user_id", "users", "id", "CASCADE"),
}


@dataclass(frozen=True)
class _CatalogContract:
    tables: tuple[str, ...]
    columns: tuple[
        tuple[str, tuple[tuple[str, str, int, object, int], ...]], ...
    ]
    primary_keys: tuple[tuple[str, tuple[str, ...]], ...]
    unique_constraints: tuple[tuple[str, tuple[str, ...]], ...]
    checks: tuple[tuple[str, str, str], ...]
    foreign_keys: tuple[
        tuple[str, str, str, str, str, str], ...
    ]
    indexes: tuple[
        tuple[str, str, tuple[str, ...], bool, str | None], ...
    ]
    autoincrement_tables: tuple[str, ...]


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
    resolved_locally = (
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
    )
    _require_fixed(
        resolved_locally,
        "first-party migration test import escaped the source candidate",
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


def test_migration_test_process_resolves_first_party_code_locally() -> None:
    _assert_candidate_origin_boundary()


def _synthetic_module(
    name: str,
    *,
    origin: Path | None = None,
    search_locations: tuple[Path, ...] | None = None,
) -> types.ModuleType:
    module = types.ModuleType(name)
    if search_locations is None:
        spec = importlib.machinery.ModuleSpec(
            name,
            loader=None,
            origin=None if origin is None else str(origin),
        )
        if origin is not None:
            module.__file__ = str(origin)
    else:
        spec = importlib.machinery.ModuleSpec(
            name,
            loader=None,
            is_package=True,
        )
        spec.submodule_search_locations = [
            str(location) for location in search_locations
        ]
        module.__path__ = list(spec.submodule_search_locations)
    module.__spec__ = spec
    return module


def test_candidate_origin_guard_rejects_dirty_only_first_party_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TemporaryDirectory(prefix="ares-origin-tripwire-") as directory:
        dirty_root = Path(directory)
        dirty_ares_file = dirty_root / "ares" / "dirty_only_probe.py"
        dirty_ares_file.parent.mkdir(parents=True)
        dirty_ares_file.write_text("", encoding="utf-8")
        dirty_migration_root = (
            dirty_root / "migrations" / "versions" / "dirty_only_probe"
        )
        dirty_migration_root.mkdir(parents=True)
        dirty_modules = {
            "ares.dirty_only_probe": _synthetic_module(
                "ares.dirty_only_probe",
                origin=dirty_ares_file,
            ),
            "migrations.versions.dirty_only_probe": _synthetic_module(
                "migrations.versions.dirty_only_probe",
                search_locations=(dirty_migration_root,),
            ),
        }
        for name, module in dirty_modules.items():
            monkeypatch.setitem(sys.modules, name, module)
        dirty_counterparts_absent = all(
            not _REPO_ROOT.joinpath(*name.split(".")).with_suffix(
                ".py"
            ).exists()
            and not _REPO_ROOT.joinpath(
                *name.split("."),
                "__init__.py",
            ).exists()
            for name in dirty_modules
        )
        guard_rejected = not (
            _loaded_first_party_origins_are_candidate_local(
                sys.modules,
                _REPO_ROOT,
            )
        )
    _require_fixed(
        dirty_counterparts_absent and guard_rejected,
        "candidate origin guard accepted a dirty-only first-party module",
    )


def test_candidate_origin_guard_handles_namespace_policy_without_false_positives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TemporaryDirectory(prefix="ares-origin-third-party-") as directory:
        external_root = Path(directory)
        local_namespace = _synthetic_module(
            "tests.unit.candidate_namespace_probe",
            search_locations=(_REPO_ROOT / "tests" / "unit",),
        )
        third_party_namespace = _synthetic_module(
            "third_party_namespace.probe",
            search_locations=(external_root,),
        )
        monkeypatch.setitem(
            sys.modules,
            "tests.unit.candidate_namespace_probe",
            local_namespace,
        )
        monkeypatch.setitem(
            sys.modules,
            "third_party_namespace.probe",
            third_party_namespace,
        )
        accepted = _loaded_first_party_origins_are_candidate_local(
            sys.modules,
            _REPO_ROOT,
        )
    _require_fixed(
        accepted,
        "candidate origin guard rejected an allowed namespace module",
    )


@pytest.mark.parametrize(
    ("name", "namespace"),
    [
        ("ares.late_dirty_probe", False),
        ("migrations.versions.late_dirty_probe", True),
        ("ares.db.websocket_tickets", False),
        ("migrations.versions.0007_add_websocket_tickets", False),
    ],
    ids=(
        "late-ares-module",
        "late-migration-namespace",
        "late-ticket-module",
        "late-0007-module",
    ),
)
def test_final_candidate_origin_boundary_rejects_late_dirty_imports(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    namespace: bool,
) -> None:
    _assert_candidate_origin_boundary()
    with TemporaryDirectory(prefix="ares-final-origin-") as directory:
        external_root = Path(directory)
        if namespace:
            module = _synthetic_module(
                name,
                search_locations=(external_root,),
            )
        else:
            module_path = external_root / "late_dirty_probe.py"
            module_path.write_text("", encoding="utf-8")
            module = _synthetic_module(name, origin=module_path)
        monkeypatch.setitem(sys.modules, name, module)
        rejected = not _loaded_first_party_origins_are_candidate_local(
            sys.modules,
            _REPO_ROOT,
        )
    _require_fixed(
        rejected,
        "final candidate origin boundary accepted a late dirty import",
    )


def test_final_candidate_origin_boundary_accepts_late_local_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "ares.late_candidate_probe",
        _synthetic_module(
            "ares.late_candidate_probe",
            origin=_REPO_ROOT / "ares" / "late_candidate_probe.py",
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "migrations.versions.late_candidate_probe",
        _synthetic_module(
            "migrations.versions.late_candidate_probe",
            search_locations=(_REPO_ROOT / "migrations" / "versions",),
        ),
    )
    _assert_candidate_origin_boundary()


def test_final_candidate_origin_boundary_rejects_mixed_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TemporaryDirectory(prefix="ares-mixed-origin-") as directory:
        monkeypatch.setitem(
            sys.modules,
            "tests.integration.mixed_candidate_probe",
            _synthetic_module(
                "tests.integration.mixed_candidate_probe",
                search_locations=(
                    _REPO_ROOT / "tests" / "integration",
                    Path(directory),
                ),
            ),
        )
        rejected = not _loaded_first_party_origins_are_candidate_local(
            sys.modules,
            _REPO_ROOT,
        )
    _require_fixed(
        rejected,
        "final candidate origin boundary accepted a mixed namespace",
    )


def test_final_candidate_origin_boundary_runs_after_ordinary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _record_boundary(
        _ledger: _CandidateOriginLedger | None = None,
    ) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(
        sys.modules[__name__],
        "_assert_candidate_origin_boundary",
        _record_boundary,
    )
    ordinary_failure_survived = False
    try:
        with _candidate_origin_boundary():
            raise RuntimeError
    except RuntimeError:
        ordinary_failure_survived = True
    _require_fixed(
        ordinary_failure_survived and calls == 2,
        "candidate origin finalizer did not run after an ordinary failure",
    )


class _OriginProbeLoader:
    def create_module(self, _spec: object) -> None:
        return None

    def exec_module(self, _module: object) -> None:
        return None


class _OriginProbeFinder:
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
def _origin_probe(
    name: str,
    spec: object,
) -> Iterator[Callable[[], None]]:
    finder = _OriginProbeFinder(name, spec)
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


def _concrete_probe_spec(name: str, origin: Path) -> object:
    return importlib.machinery.ModuleSpec(
        name,
        _OriginProbeLoader(),
        origin=str(origin),
    )


def _namespace_probe_spec(
    name: str,
    locations: tuple[Path, ...],
) -> object:
    spec = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)
    spec.submodule_search_locations = [
        str(location)
        for location in locations
    ]
    return spec


@pytest.mark.parametrize(
    ("name", "probe_kind"),
    [
        ("ares.ledger_dirty_probe", "concrete"),
        ("migrations.versions.ledger_dirty_probe", "concrete"),
        ("migrations.versions.0007_add_websocket_tickets", "concrete"),
        ("ares.db.websocket_tickets", "concrete"),
        ("migrations.versions.ledger_mixed_probe", "mixed"),
    ],
    ids=(
        "dirty-ares-removed",
        "dirty-migration-removed",
        "dirty-0007-removed",
        "dirty-ticket-removed",
        "mixed-namespace-removed",
    ),
)
def test_origin_ledger_retains_removed_first_party_violation(
    name: str,
    probe_kind: str,
) -> None:
    rejected = False
    with TemporaryDirectory(prefix="ares-origin-ledger-") as directory:
        external_root = Path(directory)
        if probe_kind == "mixed":
            spec = _namespace_probe_spec(
                name,
                (
                    _REPO_ROOT / "migrations" / "versions",
                    external_root,
                ),
            )
        else:
            spec = _concrete_probe_spec(
                name,
                external_root / "probe.py",
            )
        try:
            with _origin_probe(name, spec) as import_then_remove:
                with _candidate_origin_boundary(isolated=True):
                    import_then_remove()
        except pytest.fail.Exception:
            rejected = True
    _require_fixed(
        rejected,
        "candidate origin ledger forgot a removed first-party import",
    )


@pytest.mark.parametrize(
    ("name", "spec_kind"),
    [
        ("migrations.versions.ledger_local_probe", "local"),
        ("third_party_ledger_probe", "third-party"),
    ],
    ids=("candidate-local-removed", "unrelated-namespace-removed"),
)
def test_origin_ledger_accepts_removed_safe_import(
    name: str,
    spec_kind: str,
) -> None:
    if spec_kind == "local":
        spec = _concrete_probe_spec(
            name,
            _REPO_ROOT / "migrations" / "versions" / "probe.py",
        )
    else:
        with TemporaryDirectory(
            prefix="ares-origin-third-party-"
        ) as directory:
            spec = _namespace_probe_spec(name, (Path(directory),))
            with _origin_probe(name, spec) as import_then_remove:
                with _candidate_origin_boundary(isolated=True):
                    import_then_remove()
            return
    with _origin_probe(name, spec) as import_then_remove:
        with _candidate_origin_boundary(isolated=True):
            import_then_remove()


def test_origin_ledger_final_guard_runs_after_ordinary_failure() -> None:
    rejected_by_final_guard = False
    with TemporaryDirectory(prefix="ares-origin-finally-") as directory:
        name = "ares.removed_before_final_guard"
        spec = _concrete_probe_spec(name, Path(directory) / "probe.py")
        try:
            with _origin_probe(name, spec) as import_then_remove:
                with _candidate_origin_boundary(isolated=True):
                    import_then_remove()
                    raise RuntimeError
        except pytest.fail.Exception:
            rejected_by_final_guard = True
    _require_fixed(
        rejected_by_final_guard,
        "candidate origin ledger final guard was skipped after failure",
    )


def _reused_origin_probe_body() -> None:
    return None


def test_origin_ledger_rechecks_reused_code_with_changed_origin() -> None:
    rejected = False
    with TemporaryDirectory(prefix="ares-origin-reused-code-") as directory:
        external_file = Path(directory) / "migrations" / "versions" / (
            "0007_external_probe.py"
        )
        probe_code = _reused_origin_probe_body.__code__
        local_probe = types.FunctionType(
            probe_code,
            {
                "__name__": "migrations.versions.reused_code_probe",
                "__package__": "migrations.versions",
                "__file__": str(
                    _REPO_ROOT
                    / "migrations"
                    / "versions"
                    / "0006_reused_code_probe.py"
                ),
            },
        )
        dirty_probe = types.FunctionType(
            probe_code,
            {
                "__name__": "migrations.versions.reused_code_probe",
                "__package__": "migrations.versions",
                "__file__": str(external_file),
            },
        )
        try:
            with _candidate_origin_boundary(isolated=True):
                local_probe()
                dirty_probe()
        except pytest.fail.Exception:
            rejected = True
    _require_fixed(
        rejected,
        "candidate origin ledger cached a stale frame origin",
    )


def test_origin_ledger_ignores_unrelated_migrations_directory() -> None:
    with TemporaryDirectory(prefix="ares-origin-unrelated-") as directory:
        third_party_probe = types.FunctionType(
            _reused_origin_probe_body.__code__,
            {
                "__name__": "third_party.origin_probe",
                "__package__": "third_party",
                "__file__": str(
                    Path(directory) / "migrations" / "origin_probe.py"
                ),
            },
        )
        with _candidate_origin_boundary(isolated=True):
            third_party_probe()


def test_origin_ledger_requires_first_meta_path_position() -> None:
    displaced_was_rejected = False
    finder = _OriginProbeFinder("unrelated_displacement_probe", object())
    with _candidate_origin_boundary(isolated=True) as ledger:
        sys.meta_path.insert(0, finder)
        try:
            try:
                _assert_candidate_origin_boundary(ledger)
            except pytest.fail.Exception:
                displaced_was_rejected = True
        finally:
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)
    _require_fixed(
        displaced_was_rejected,
        "candidate origin finder accepted displaced ownership",
    )


def test_origin_ledger_restores_exact_observer_state() -> None:
    previous_meta_path = tuple(sys.meta_path)
    previous_profile = sys.getprofile()
    ledger = _CandidateOriginLedger(_REPO_ROOT, isolated=True)

    def _replacement_profile(
        _frame: types.FrameType,
        _event: str,
        _arg: object,
    ) -> None:
        return None

    ledger.install()
    sys.meta_path.insert(0, _OriginProbeFinder("observer_tamper", object()))
    sys.setprofile(_replacement_profile)
    ledger.close()
    restored = (
        tuple(sys.meta_path) == previous_meta_path
        and sys.getprofile() is previous_profile
        and not ledger._observed_frame_origins
    )
    _require_fixed(
        restored,
        "candidate origin ledger did not restore observer state",
    )


@contextmanager
def _temporary_database(label: str) -> Iterator[Path]:
    with TemporaryDirectory(prefix=f"ares-migration-{label}-") as directory:
        path = Path(directory) / "catalog.db"
        outside_repository = _REPO_ROOT not in path.resolve().parents
        _require_fixed(
            outside_repository,
            "migration database was created inside the repository",
        )
        yield path


def _sqlite_url(path: Path, *, async_driver: bool = False) -> str:
    driver = "sqlite+aiosqlite" if async_driver else "sqlite"
    return f"{driver}:///{path.resolve().as_posix()}"


def _config(
    *,
    configured_url: str,
    x_url: str | None = None,
    x_arguments: list[str] | None = None,
) -> Config:
    if x_url is not None and x_arguments is not None:
        raise AssertionError("conflicting test configuration")
    config = Config(str(_REPO_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(_REPO_ROOT / "migrations"),
    )
    config.set_main_option("sqlalchemy.url", configured_url)
    config.cmd_opts = argparse.Namespace(
        x=(
            x_arguments
            if x_arguments is not None
            else ([] if x_url is None else [f"db_url={x_url}"])
        )
    )
    return config


def _upgrade(path: Path, revision: str, *, async_driver: bool = False) -> None:
    url = _sqlite_url(path, async_driver=async_driver)
    command.upgrade(_config(configured_url=url, x_url=url), revision)


def _downgrade(path: Path, revision: str) -> None:
    url = _sqlite_url(path)
    command.downgrade(_config(configured_url=url, x_url=url), revision)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _version(path: Path) -> str | None:
    connection = _connect(path)
    try:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='alembic_version'"
        ).fetchone()
        if exists is None:
            return None
        row = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        return None if row is None else str(row[0])
    finally:
        connection.close()


def _database_is_empty_and_unstamped(path: Path) -> bool:
    if not path.exists():
        return True
    connection = sqlite3.connect(path)
    try:
        application_objects = connection.execute(
            """
            SELECT count(*) FROM sqlite_master
            WHERE type IN ('table', 'index')
              AND name NOT LIKE 'sqlite_%'
            """
        ).fetchone()
        return application_objects == (0,)
    finally:
        connection.close()


def _statement_class(statement: object) -> str:
    normalized = " ".join(str(statement).strip().upper().split())
    if normalized == "PRAGMA JOURNAL_MODE = WAL":
        return "sqlite-journal-policy"
    if normalized == "PRAGMA FOREIGN_KEYS = ON":
        return "sqlite-foreign-key-policy"
    if normalized.startswith(("CREATE ", "ALTER ", "DROP ")):
        return "migration-ddl"
    return "other"


class _RecordingCursor:
    def __init__(self, cursor: object, statements: list[str]) -> None:
        self._cursor = cursor
        self._statements = statements

    def execute(self, statement: object, *args: object, **kwargs: object) -> object:
        self._statements.append(_statement_class(statement))
        return self._cursor.execute(statement, *args, **kwargs)

    def __getattr__(self, name: str) -> object:
        return getattr(self._cursor, name)


class _RecordingConnection:
    def __init__(self, connection: object, statements: list[str]) -> None:
        self._connection = connection
        self._statements = statements

    def cursor(self, *args: object, **kwargs: object) -> _RecordingCursor:
        cursor = self._connection.cursor(*args, **kwargs)
        return _RecordingCursor(cursor, self._statements)

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)


def _column_map(
    connection: sqlite3.Connection,
    table: str,
) -> dict[str, tuple[str, int, object, int]]:
    return {
        str(row[1]): (str(row[2]), int(row[3]), row[4], int(row[5]))
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    }


def _index_map(
    connection: sqlite3.Connection,
) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    tables = tuple(_EXPECTED_APP_TABLES)
    for table in tables:
        for row in connection.execute(f'PRAGMA index_list("{table}")'):
            name = str(row[1])
            if name.startswith("sqlite_autoindex_"):
                continue
            columns = tuple(
                str(item[2])
                for item in connection.execute(f'PRAGMA index_info("{name}")')
            )
            result[name] = (table, columns)
    return result


def _foreign_keys(
    connection: sqlite3.Connection,
) -> set[tuple[str, str, str, str, str]]:
    result: set[tuple[str, str, str, str, str]] = set()
    for table in _EXPECTED_APP_TABLES:
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")'):
            result.add(
                (
                    table,
                    str(row[3]),
                    str(row[2]),
                    str(row[4]),
                    str(row[6]).upper(),
                )
            )
    return result


def _ordered_column_fingerprint(
    connection: sqlite3.Connection,
    table: str,
) -> tuple[tuple[str, str, int, object, int], ...]:
    return tuple(
        (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    )


def _unique_constraints(
    connection: sqlite3.Connection,
) -> set[tuple[str, tuple[str, ...]]]:
    result: set[tuple[str, tuple[str, ...]]] = set()
    for table in _EXPECTED_APP_TABLES:
        for row in connection.execute(f'PRAGMA index_list("{table}")'):
            if str(row[3]) != "u":
                continue
            name = str(row[1])
            columns = tuple(
                str(item[2])
                for item in connection.execute(f'PRAGMA index_info("{name}")')
            )
            result.add((table, columns))
    return result


def _normalize_sql_expression(value: str) -> str:
    normalized = value.lower().replace('"', "").replace("`", "")
    return re.sub(r"[\s()]+", "", normalized)


def _named_checks(create_sql: str) -> tuple[tuple[str, str], ...]:
    checks: list[tuple[str, str]] = []
    pattern = re.compile(
        r"\bCONSTRAINT\s+[\"`]?([A-Za-z_][A-Za-z0-9_]*)[\"`]?"
        r"\s+CHECK\s*\(",
        re.IGNORECASE,
    )
    for match in pattern.finditer(create_sql):
        start = match.end()
        depth = 1
        position = start
        quote: str | None = None
        while position < len(create_sql) and depth:
            character = create_sql[position]
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            position += 1
        if depth:
            raise AssertionError("unterminated SQLite CHECK expression")
        checks.append(
            (
                match.group(1),
                _normalize_sql_expression(
                    create_sql[start : position - 1]
                ),
            )
        )
    return tuple(sorted(checks))


def _sqlite_catalog_contract(
    connection: sqlite3.Connection,
) -> _CatalogContract:
    tables = tuple(
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table'
              AND name NOT LIKE 'sqlite_%'
              AND name != 'alembic_version'
            ORDER BY name
            """
        )
    )
    columns = tuple(
        (table, _ordered_column_fingerprint(connection, table))
        for table in tables
    )
    primary_keys = tuple(
        (
            table,
            tuple(
                name
                for _position, name in sorted(
                    (
                        int(row[5]),
                        str(row[1]),
                    )
                    for row in connection.execute(
                        f'PRAGMA table_info("{table}")'
                    )
                    if int(row[5]) > 0
                )
            ),
        )
        for table in tables
    )
    unique_constraints: list[tuple[str, tuple[str, ...]]] = []
    indexes: list[
        tuple[str, str, tuple[str, ...], bool, str | None]
    ] = []
    foreign_keys: list[
        tuple[str, str, str, str, str, str]
    ] = []
    checks: list[tuple[str, str, str]] = []
    autoincrement_tables: list[str] = []
    for table in tables:
        table_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        table_sql = "" if table_sql_row is None else str(table_sql_row[0])
        if "AUTOINCREMENT" in table_sql.upper():
            autoincrement_tables.append(table)
        checks.extend(
            (table, name, expression)
            for name, expression in _named_checks(table_sql)
        )
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")'):
            foreign_keys.append(
                (
                    table,
                    str(row[3]),
                    str(row[2]),
                    str(row[4]),
                    str(row[5]).upper(),
                    str(row[6]).upper(),
                )
            )
        for row in connection.execute(f'PRAGMA index_list("{table}")'):
            name = str(row[1])
            index_columns = tuple(
                str(item[2])
                for item in connection.execute(
                    f'PRAGMA index_info("{name}")'
                )
            )
            origin = str(row[3])
            if origin == "u":
                unique_constraints.append((table, index_columns))
                continue
            if origin != "c":
                continue
            index_sql_row = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type='index' AND name=?",
                (name,),
            ).fetchone()
            index_sql = (
                ""
                if index_sql_row is None or index_sql_row[0] is None
                else str(index_sql_row[0])
            )
            predicate_match = re.search(
                r"\bWHERE\b(.+)$",
                index_sql,
                flags=re.IGNORECASE,
            )
            predicate = (
                None
                if predicate_match is None
                else _normalize_sql_expression(predicate_match.group(1))
            )
            indexes.append(
                (
                    table,
                    name,
                    index_columns,
                    bool(row[2]),
                    predicate,
                )
            )
    return _CatalogContract(
        tables=tables,
        columns=columns,
        primary_keys=tuple(primary_keys),
        unique_constraints=tuple(sorted(unique_constraints)),
        checks=tuple(sorted(checks)),
        foreign_keys=tuple(sorted(foreign_keys)),
        indexes=tuple(sorted(indexes)),
        autoincrement_tables=tuple(sorted(autoincrement_tables)),
    )


def _fixed_sqlite_contract(revision: str) -> _CatalogContract:
    if revision == "base":
        return _CatalogContract((), (), (), (), (), (), (), ())
    tables = {
        "schema_version",
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

    expected_columns = {
        table: tuple(columns)
        for table, columns in _EXPECTED_SQLITE_COLUMN_FINGERPRINTS.items()
        if table in tables
    }
    expected_columns["schema_version"] = (
        ("version", "INTEGER", 1, None, 1),
        ("applied_at", "TEXT", 1, "datetime('now')", 0),
    )
    findings = list(expected_columns["findings"])
    if revision == "0001":
        findings = [column for column in findings if column[0] != "trace_id"]
    elif revision < "0005":
        findings = [
            (
                column[0],
                column[1],
                0 if column[0] == "trace_id" else column[2],
                column[3],
                column[4],
            )
            for column in findings
        ]
    expected_columns["findings"] = tuple(findings)
    if revision < "0006":
        expected_columns["credentials"] = tuple(
            (
                "cracked_value" if column[0] == "cracked_value_enc" else column[0],
                column[1],
                column[2],
                column[3],
                column[4],
            )
            for column in expected_columns["credentials"]
        )

    primary_keys = tuple(
        (
            table,
            tuple(
                column[0]
                for column in expected_columns[table]
                if column[4] > 0
            ),
        )
        for table in ordered_tables
    )
    unique_constraints = tuple(
        sorted(
            constraint
            for constraint in _EXPECTED_UNIQUE_CONSTRAINTS
            if constraint[0] in tables
        )
    )
    foreign_keys = tuple(
        sorted(
            (
                table,
                local,
                remote,
                remote_column,
                "NO ACTION",
                on_delete,
            )
            for (
                table,
                local,
                remote,
                remote_column,
                on_delete,
            ) in _EXPECTED_FOREIGN_KEYS
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
                table,
                name,
                columns,
                False,
                None,
            )
            for name, (table, columns) in _EXPECTED_INDEXES.items()
            if name in index_names
        )
    )
    checks = (
        (
            "rate_limit_events",
            "ck_rate_limit_events_blocked_bool",
            "blockedin0,1",
        ),
    ) if revision >= "0003" else ()
    autoincrement_tables = (
        ("audit_log", "rate_limit_events")
        if revision >= "0003"
        else ("audit_log",)
    )
    return _CatalogContract(
        tables=ordered_tables,
        columns=tuple(
            (table, expected_columns[table]) for table in ordered_tables
        ),
        primary_keys=primary_keys,
        unique_constraints=unique_constraints,
        checks=checks,
        foreign_keys=foreign_keys,
        indexes=indexes,
        autoincrement_tables=autoincrement_tables,
    )


def _seed_campaign_and_credential(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute(
            "INSERT INTO campaigns(id, name) VALUES(?, ?)",
            ("campaign-a", "Migration campaign"),
        )
        connection.execute(
            """
            INSERT INTO credentials(
                id, campaign_id, username, cred_type, cracked_value
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (
                "credential-a",
                "campaign-a",
                "synthetic-user",
                "password",
                "synthetic-encrypted-marker",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _credential_marker_survived(path: Path, column: str) -> bool:
    connection = _connect(path)
    try:
        if column == "cracked_value_enc":
            row = connection.execute(
                "SELECT cracked_value_enc IS NOT NULL FROM credentials "
                "WHERE id='credential-a'"
            ).fetchone()
        elif column == "cracked_value":
            row = connection.execute(
                "SELECT cracked_value IS NOT NULL FROM credentials "
                "WHERE id='credential-a'"
            ).fetchone()
        else:
            raise AssertionError("unknown credential column")
        return row == (1,)
    finally:
        connection.close()


def _expected_integrity_failure(
    connection: sqlite3.Connection,
    statement: str,
    parameters: tuple[object, ...],
) -> bool:
    rejected = False
    try:
        connection.execute(statement, parameters)
        connection.commit()
    except sqlite3.IntegrityError:
        rejected = True
        connection.rollback()
    reusable = connection.execute("SELECT 1").fetchone() == (1,)
    return rejected and reusable


def _seed_complete_contract(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO campaigns(id, name) VALUES(?, ?)",
        ("campaign-contract", "Synthetic campaign"),
    )
    connection.execute(
        """
        INSERT INTO module_runs(
            id, campaign_id, module_id, outcome
        ) VALUES(?, ?, ?, ?)
        """,
        ("run-contract", "campaign-contract", "module", "complete"),
    )
    connection.execute(
        """
        INSERT INTO findings(
            id, campaign_id, module_id, title, description, severity
        ) VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            "finding-contract",
            "campaign-contract",
            "module",
            "Synthetic finding",
            "Synthetic description",
            "low",
        ),
    )
    connection.execute(
        """
        INSERT INTO hosts(id, campaign_id, ip_address)
        VALUES(?, ?, ?)
        """,
        ("host-contract", "campaign-contract", "192.0.2.10"),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            id, campaign_id, host_id, username, cred_type
        ) VALUES(?, ?, ?, ?, ?)
        """,
        (
            "credential-contract",
            "campaign-contract",
            "host-contract",
            "synthetic-user",
            "password",
        ),
    )
    connection.execute(
        """
        INSERT INTO loot(
            id, campaign_id, host_id, loot_type, name
        ) VALUES(?, ?, ?, ?, ?)
        """,
        (
            "loot-contract",
            "campaign-contract",
            "host-contract",
            "metadata",
            "Synthetic loot",
        ),
    )
    connection.execute(
        """
        INSERT INTO audit_log(campaign_id, action)
        VALUES(?, ?)
        """,
        ("campaign-contract", "synthetic-action"),
    )
    connection.execute(
        """
        INSERT INTO users(id, username, hashed_password)
        VALUES(?, ?, ?)
        """,
        ("user-contract", "synthetic-account", "synthetic-hash"),
    )
    connection.execute(
        """
        INSERT INTO api_keys(
            id, user_id, name, key_hash, key_prefix
        ) VALUES(?, ?, ?, ?, ?)
        """,
        (
            "api-key-contract",
            "user-contract",
            "Synthetic key",
            "synthetic-hash",
            "synthetic",
        ),
    )
    connection.execute(
        """
        INSERT INTO refresh_tokens(id, user_id, expires_at)
        VALUES(?, ?, ?)
        """,
        ("refresh-contract", "user-contract", "2099-01-01 00:00:00"),
    )
    connection.execute(
        """
        INSERT INTO revoked_access_tokens(jti, user_id, expires_at)
        VALUES(?, ?, ?)
        """,
        ("revoked-contract", "user-contract", "2099-01-01 00:00:00"),
    )
    connection.execute(
        """
        INSERT INTO rate_limit_events(ip_address, bucket)
        VALUES(?, ?)
        """,
        ("192.0.2.20", "synthetic-bucket"),
    )
    connection.commit()


def _split_sqlite_table_clauses(create_sql: str) -> list[str]:
    start = create_sql.find("(")
    end = create_sql.rfind(")")
    if start < 0 or end <= start:
        raise AssertionError("invalid SQLite table definition")
    body = create_sql[start + 1 : end]
    clauses: list[str] = []
    depth = 0
    quote: str | None = None
    clause_start = 0
    for position, character in enumerate(body):
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            clauses.append(body[clause_start:position].strip())
            clause_start = position + 1
    clauses.append(body[clause_start:].strip())
    return clauses


def _sqlite_clause_column(clause: str) -> str | None:
    stripped = clause.lstrip()
    if re.match(
        r"^(CONSTRAINT|PRIMARY|UNIQUE|CHECK|FOREIGN)\b",
        stripped,
        flags=re.IGNORECASE,
    ):
        return None
    match = re.match(
        r'^(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([^\s]+))',
        stripped,
    )
    if match is None:
        raise AssertionError("invalid SQLite column clause")
    return next(value for value in match.groups() if value is not None)


def _rebuild_legacy_table(
    connection: sqlite3.Connection,
    table: str,
    revision: str,
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    if row is None:
        raise AssertionError("missing source table for legacy transformation")
    index_sql = tuple(
        str(index[0])
        for index in connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='index' AND tbl_name=? AND sql IS NOT NULL "
            "ORDER BY name",
            (table,),
        )
    )
    clauses = _split_sqlite_table_clauses(str(row[0]))
    clauses = [
        clause
        for clause in clauses
        if "FOREIGN KEY" not in clause.upper()
    ]
    if table == "rate_limit_events":
        clauses = [
            clause
            for clause in clauses
            if "CHECK" not in clause.upper()
        ]
    if table == "findings":
        rewritten: list[str] = []
        deferred: list[str] = []
        for clause in clauses:
            column = _sqlite_clause_column(clause)
            if column in {"cvss_score", "cvss_vector", "trace_id"}:
                clause = re.sub(
                    r"\s+NOT\s+NULL\b",
                    "",
                    clause,
                    flags=re.IGNORECASE,
                )
            if column in {"cvss_score", "cvss_vector"}:
                deferred.append(clause)
            else:
                rewritten.append(clause)
        confidence_position = next(
            index
            for index, clause in enumerate(rewritten)
            if _sqlite_clause_column(clause) == "confidence"
        )
        clauses = (
            rewritten[:confidence_position]
            + deferred
            + rewritten[confidence_position:]
        )
    temporary = f"migration_legacy_{table}"
    create_sql = (
        f'CREATE TABLE "{temporary}" (\n'
        + ",\n".join(clauses)
        + "\n)"
    )
    if table in {"audit_log", "rate_limit_events"}:
        create_sql = re.sub(
            r"\s+AUTOINCREMENT\b",
            "",
            create_sql,
            flags=re.IGNORECASE,
        )
    columns = tuple(
        str(column[1])
        for column in connection.execute(f'PRAGMA table_info("{table}")')
    )
    quoted_columns = ", ".join(f'"{name}"' for name in columns)
    connection.execute(create_sql)
    connection.execute(
        f'INSERT INTO "{temporary}" ({quoted_columns}) '  # noqa: S608
        f'SELECT {quoted_columns} FROM "{table}"'
    )
    connection.execute(f'DROP TABLE "{table}"')
    connection.execute(
        f'ALTER TABLE "{temporary}" RENAME TO "{table}"'
    )
    for statement in index_sql:
        connection.execute(statement)


def _fixed_legacy_sqlite_contract(revision: str) -> _CatalogContract:
    repaired = _fixed_sqlite_contract(revision)
    tables = tuple(
        table
        for table in repaired.tables
        if table not in {"module_runs", "schema_version"}
    )
    columns = dict(repaired.columns)
    findings_by_name = {
        column[0]: column for column in columns["findings"]
    }
    historical_finding_order = (
        "id",
        "campaign_id",
        "module_id",
        "title",
        "description",
        "severity",
        "cvss_score",
        "cvss_vector",
        "confidence",
        "mitre_technique",
        "mitre_tactic",
        "evidence_json",
        "remediation",
        "host",
        "validated",
        "false_positive",
        "discovered_at",
    ) + (("trace_id",) if revision >= "0002" else ())
    columns["findings"] = tuple(
        (
            name,
            findings_by_name[name][1],
            (
                0
                if name in {"cvss_score", "cvss_vector", "trace_id"}
                else findings_by_name[name][2]
            ),
            findings_by_name[name][3],
            findings_by_name[name][4],
        )
        for name in historical_finding_order
    )
    indexes = [
        index
        for index in repaired.indexes
        if index[0] != "module_runs"
    ]
    indexes.append(
        (
            "findings",
            "idx_findings_validated",
            ("validated",),
            False,
            None,
        )
    )
    return replace(
        repaired,
        tables=tables,
        columns=tuple((table, columns[table]) for table in tables),
        primary_keys=tuple(
            item for item in repaired.primary_keys if item[0] in tables
        ),
        foreign_keys=(),
        indexes=tuple(sorted(indexes)),
        checks=(),
        autoincrement_tables=(),
    )


def _create_transformed_legacy_catalog(path: Path, revision: str) -> None:
    _upgrade(path, revision)
    connection = _connect(path)
    foreign_keys_enabled = True
    try:
        connection.commit()
        connection.execute("PRAGMA foreign_keys=OFF")
        foreign_keys_enabled = False
        connection.execute("DROP TABLE module_runs")
        connection.execute("DROP TABLE schema_version")
        for table in (
            "findings",
            "hosts",
            "credentials",
            "loot",
            "audit_log",
            "api_keys",
            "refresh_tokens",
        ):
            _rebuild_legacy_table(connection, table, revision)
        if revision >= "0003":
            _rebuild_legacy_table(
                connection,
                "rate_limit_events",
                revision,
            )
        connection.execute(
            "CREATE INDEX idx_findings_validated "
            "ON findings(validated)"
        )
        connection.execute(
            "INSERT INTO campaigns(id, name) VALUES(?, ?)",
            ("legacy-campaign", "Synthetic legacy campaign"),
        )
        trace_column_exists = revision >= "0002"
        finding_count = 3 if trace_column_exists else 1
        for index in range(finding_count):
            base_values = (
                f"legacy-finding-{index}",
                "legacy-campaign",
                "module",
                f"Synthetic finding {index}",
                "Synthetic legacy description",
                "low",
                None if index == 0 else float(index),
                None if index == 0 else f"VECTOR-{index}",
            )
            if trace_column_exists:
                trace_value = (None, "", "synthetic-trace")[index]
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title, description,
                        severity, cvss_score, cvss_vector, trace_id
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*base_values, trace_value),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title, description,
                        severity, cvss_score, cvss_vector
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    base_values,
                )
        connection.execute(
            """
            INSERT INTO hosts(id, campaign_id, ip_address, hostname)
            VALUES(?, ?, ?, ?)
            """,
            (
                "legacy-host",
                "legacy-campaign",
                "192.0.2.40",
                "synthetic-host",
            ),
        )
        connection.execute(
            """
            INSERT INTO credentials(
                id, campaign_id, host_id, username, cred_type, cracked_value
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-credential",
                "legacy-campaign",
                "legacy-host",
                "synthetic-user",
                "password",
                "synthetic-encrypted-marker",
            ),
        )
        connection.execute(
            """
            INSERT INTO loot(id, campaign_id, host_id, loot_type, name)
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                "legacy-loot",
                "legacy-campaign",
                "legacy-host",
                "metadata",
                "Synthetic loot",
            ),
        )
        connection.execute(
            "INSERT INTO audit_log(campaign_id, action) VALUES(?, ?)",
            ("legacy-campaign", "synthetic-action"),
        )
        connection.execute(
            """
            INSERT INTO users(id, username, hashed_password)
            VALUES(?, ?, ?)
            """,
            ("legacy-user", "synthetic-account", "synthetic-hash"),
        )
        connection.execute(
            """
            INSERT INTO api_keys(id, user_id, name, key_hash, key_prefix)
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                "legacy-api-key",
                "legacy-user",
                "Synthetic key",
                "synthetic-hash",
                "synthetic",
            ),
        )
        connection.execute(
            """
            INSERT INTO refresh_tokens(id, user_id, expires_at)
            VALUES(?, ?, ?)
            """,
            ("legacy-refresh", "legacy-user", "2099-01-01 00:00:00"),
        )
        if revision >= "0003":
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.41", "synthetic-bucket"),
            )
        if revision >= "0004":
            connection.execute(
                """
                INSERT INTO revoked_access_tokens(jti, user_id, expires_at)
                VALUES(?, ?, ?)
                """,
                ("legacy-revoked", "legacy-user", "2099-01-01 00:00:00"),
            )
        connection.commit()
    finally:
        if not foreign_keys_enabled:
            connection.execute("PRAGMA foreign_keys=ON")
        connection.close()
    current = _connect(path)
    try:
        complete_contract = (
            _sqlite_catalog_contract(current)
            == _fixed_legacy_sqlite_contract(revision)
        )
    finally:
        current.close()
    _require_fixed(
        complete_contract,
        "constructed legacy SQLite catalog diverged",
    )


@pytest.mark.parametrize(
    "async_driver",
    [False, True],
    ids=("ordinary-sqlite-url", "aiosqlite-factory-url"),
)
def test_sqlite_url_driver_forms_execute_real_migrations(
    monkeypatch: pytest.MonkeyPatch,
    async_driver: bool,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("driver") as path:
        _upgrade(path, "0001", async_driver=async_driver)
        reached_revision = _version(path) == "0001"
        _require_fixed(
            reached_revision,
            "SQLite URL form did not execute revision 0001",
        )


def test_x_url_precedes_configured_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("x-priority") as selected:
        other = selected.parent / "configured.db"
        selected_url = _sqlite_url(selected)
        command.upgrade(
            _config(
                configured_url=_sqlite_url(other),
                x_url=selected_url,
            ),
            "0001",
        )
        selected_exists = selected.exists()
        other_absent = not other.exists()
        _require_fixed(
            selected_exists and other_absent,
            "the documented x-argument did not select the migration target",
        )


def test_explicit_target_excludes_environment_and_ini_decoys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _temporary_database("target-precedence") as selected:
        environment_decoy = selected.parent / "environment.db"
        configured_decoy = selected.parent / "configured.db"
        monkeypatch.setenv(
            "ARES_DATABASE_URL",
            _sqlite_url(environment_decoy),
        )
        command.upgrade(
            _config(
                configured_url=_sqlite_url(configured_decoy),
                x_url=_sqlite_url(selected),
            ),
            "0001",
        )
        selected_reached_revision = _version(selected) == "0001"
        decoys_untouched = all(
            _database_is_empty_and_unstamped(path)
            for path in (environment_decoy, configured_decoy)
        )
        _require_fixed(
            selected_reached_revision and decoys_untouched,
            "explicit migration target isolation failed",
        )


@pytest.mark.parametrize(
    "x_arguments",
    [
        ["db_url"],
        ["db_url="],
        ["db_url= "],
        ["db_url= sqlite:///invalid"],
        ["db_url=sqlite:///invalid "],
    ],
    ids=(
        "bare",
        "empty",
        "whitespace",
        "leading-whitespace",
        "trailing-whitespace",
    ),
)
def test_invalid_explicit_target_cannot_fall_through(
    monkeypatch: pytest.MonkeyPatch,
    x_arguments: list[str],
) -> None:
    with _temporary_database("invalid-explicit") as root:
        environment_decoy = root.parent / "environment.db"
        configured_decoy = root.parent / "configured.db"
        monkeypatch.setenv(
            "ARES_DATABASE_URL",
            _sqlite_url(environment_decoy),
        )
        failed = False
        try:
            command.upgrade(
                _config(
                    configured_url=_sqlite_url(configured_decoy),
                    x_arguments=x_arguments,
                ),
                "0001",
            )
        except RuntimeError:
            failed = True
        decoys_untouched = all(
            _database_is_empty_and_unstamped(path)
            for path in (environment_decoy, configured_decoy)
        )
        _require_fixed(
            failed and decoys_untouched,
            "invalid explicit target reached a fallback database",
        )


@pytest.mark.parametrize("identical", [False, True], ids=("conflicting", "identical"))
def test_duplicate_explicit_targets_fail_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    identical: bool,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("duplicate-target") as first:
        second = first if identical else first.parent / "second.db"
        configured_decoy = first.parent / "configured.db"
        failed = False
        try:
            command.upgrade(
                _config(
                    configured_url=_sqlite_url(configured_decoy),
                    x_arguments=[
                        f"db_url={_sqlite_url(first)}",
                        f"db_url={_sqlite_url(second)}",
                    ],
                ),
                "0001",
            )
        except RuntimeError:
            failed = True
        candidates_untouched = all(
            _database_is_empty_and_unstamped(path)
            for path in {first, second, configured_decoy}
        )
        _require_fixed(
            failed and candidates_untouched,
            "duplicate explicit targets were not rejected atomically",
        )


@pytest.mark.parametrize("environment_value", ["", " ", " value", "value "])
def test_present_invalid_environment_target_cannot_use_ini(
    monkeypatch: pytest.MonkeyPatch,
    environment_value: str,
) -> None:
    with _temporary_database("invalid-environment") as configured_decoy:
        monkeypatch.setenv("ARES_DATABASE_URL", environment_value)
        failed = False
        try:
            command.upgrade(
                _config(configured_url=_sqlite_url(configured_decoy)),
                "0001",
            )
        except RuntimeError:
            failed = True
        decoy_untouched = _database_is_empty_and_unstamped(configured_decoy)
        _require_fixed(
            failed and decoy_untouched,
            "invalid environment target fell through to ini",
        )


def test_empty_configured_target_fails_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    failed = False
    try:
        command.upgrade(
            _config(configured_url=""),
            "0001",
        )
    except RuntimeError:
        failed = True
    _require_fixed(failed, "empty configured migration target was accepted")


def test_unicode_percent_and_query_sqlite_target_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with TemporaryDirectory(prefix="ares-migration-url-") as directory:
        path = Path(directory) / "catalog-%-unicode-\u03bb.db"
        outside_repository = _REPO_ROOT not in path.resolve().parents
        url = URL.create(
            "sqlite",
            database=path.resolve().as_posix(),
            query={"timeout": "5"},
        ).render_as_string(hide_password=False)
        command.upgrade(
            _config(configured_url="sqlite:///unused.db", x_url=url),
            "0001",
        )
        reached_revision = _version(path) == "0001"
        _require_fixed(
            outside_repository and reached_revision,
            "structured SQLite URL components were not preserved",
        )


@pytest.mark.parametrize(
    "driver",
    ["postgresql", "postgresql+asyncpg"],
    ids=("ordinary-postgresql", "asyncpg-postgresql"),
)
def test_postgresql_url_components_and_repeated_query_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
    driver: str,
) -> None:
    import sqlalchemy.ext.asyncio as sqlalchemy_asyncio
    from sqlalchemy.engine import make_url

    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    captured: dict[str, str] = {}

    class _CaptureConnection:
        async def __aenter__(self) -> _CaptureConnection:
            return self

        async def __aexit__(
            self,
            _exc_type: object,
            _exc: object,
            _traceback: object,
        ) -> None:
            return None

        async def run_sync(self, _callable: object) -> None:
            raise RuntimeError("capture-complete")

    class _CaptureEngine:
        def connect(self) -> _CaptureConnection:
            return _CaptureConnection()

        async def dispose(self) -> None:
            return None

    def _capture_engine(
        section: dict[str, str],
        **_kwargs: object,
    ) -> _CaptureEngine:
        captured["url"] = section["sqlalchemy.url"]
        return _CaptureEngine()

    monkeypatch.setattr(
        sqlalchemy_asyncio,
        "async_engine_from_config",
        _capture_engine,
    )
    authority_component = "synthetic%component/\u03bb"
    original = URL.create(
        driver,
        username="synthetic:user",
        password=authority_component,
        host="db.example.invalid",
        port=5432,
        database="synthetic%database-\u03bb",
        query={
            "application_name": ("first", "second"),
            "sslmode": "require",
        },
    )
    failed_safely = False
    try:
        command.upgrade(
            _config(
                configured_url="sqlite:///unused.db",
                x_url=original.render_as_string(hide_password=False),
            ),
            "0001",
        )
    except RuntimeError:
        failed_safely = True

    captured_url = make_url(captured.get("url", "invalid://"))
    components_preserved = (
        captured_url.drivername == "postgresql+asyncpg"
        and captured_url.username == original.username
        and captured_url.password == original.password
        and captured_url.host == original.host
        and captured_url.port == original.port
        and captured_url.database == original.database
        and captured_url.query == original.query
    )
    _require_fixed(
        failed_safely and components_preserved,
        "structured PostgreSQL URL normalization diverged",
    )


def test_sqlite_connection_policy_precedes_migration_ddl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    real_connect = sqlite3.connect
    statement_classes: list[str] = []

    def _recording_connect(*args: object, **kwargs: object) -> object:
        connection = real_connect(*args, **kwargs)
        return _RecordingConnection(connection, statement_classes)

    monkeypatch.setattr(sqlite3, "connect", _recording_connect)
    with _temporary_database("pragma-order") as path:
        _upgrade(path, "0001")

    journal_positions = [
        index
        for index, value in enumerate(statement_classes)
        if value == "sqlite-journal-policy"
    ]
    foreign_positions = [
        index
        for index, value in enumerate(statement_classes)
        if value == "sqlite-foreign-key-policy"
    ]
    ddl_positions = [
        index
        for index, value in enumerate(statement_classes)
        if value == "migration-ddl"
    ]
    ordered = (
        len(journal_positions) == 1
        and len(foreign_positions) == 1
        and bool(ddl_positions)
        and journal_positions[0] < ddl_positions[0]
        and foreign_positions[0] < ddl_positions[0]
    )
    _require_fixed(
        ordered,
        "SQLite connection policy did not precede migration DDL",
    )


def test_configured_url_is_the_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("fallback") as path:
        command.upgrade(
            _config(configured_url=_sqlite_url(path)),
            "0001",
        )
        reached_revision = _version(path) == "0001"
        _require_fixed(
            reached_revision,
            "configured Alembic URL fallback did not run",
        )


def test_environment_url_is_a_sanitized_legacy_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _temporary_database("environment-fallback") as selected:
        other = selected.parent / "configured.db"
        monkeypatch.setenv("ARES_DATABASE_URL", _sqlite_url(selected))
        command.upgrade(
            _config(configured_url=_sqlite_url(other)),
            "0001",
        )
        selected_exists = selected.exists()
        other_absent = not other.exists()
        _require_fixed(
            selected_exists and other_absent,
            "environment URL fallback did not select the migration target",
        )


@pytest.mark.parametrize(
    ("failure_type", "expected_message"),
    [
        (
            ImportError,
            "Alembic logging configuration failed [ImportError]",
        ),
        (
            RuntimeError,
            "Alembic logging configuration failed [RuntimeError]",
        ),
    ],
    ids=("logging-import", "logging-runtime"),
)
def test_logging_configuration_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_type: type[Exception],
    expected_message: str,
) -> None:
    import logging.config
    import traceback

    marker = "synthetic-logging-detail"

    def _fail_logging_configuration(*_args: object, **_kwargs: object) -> None:
        raise failure_type(marker)

    caught: Exception | None = None
    with _temporary_database("logging-sanitization") as path:
        with monkeypatch.context() as context:
            context.delenv("ARES_DATABASE_URL", raising=False)
            context.setattr(
                logging.config,
                "fileConfig",
                _fail_logging_configuration,
            )
            try:
                _upgrade(path, "0001")
            except Exception as error:
                caught = error

    captured = capsys.readouterr()
    rendered = (
        ""
        if caught is None
        else "".join(
            traceback.format_exception(
                type(caught),
                caught,
                caught.__traceback__,
            )
        )
    )
    sanitized = (
        caught is not None
        and type(caught).__name__ == "_AlembicSanitizedError"
        and str(caught) == expected_message
        and bool(getattr(caught, "__suppress_context__", False))
        and marker not in captured.out
        and marker not in captured.err
        and marker not in rendered
    )
    _require_fixed(
        sanitized,
        "Alembic logging failure diagnostics were not sanitized",
    )


def test_offline_and_unsupported_execution_fail_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("failure-contract") as path:
        url = _sqlite_url(path)
        with pytest.raises(
            RuntimeError,
            match=(
                "^Offline migration is not supported for the "
                "ARES historical chain$"
            ),
        ):
            command.upgrade(
                _config(configured_url=url, x_url=url),
                "0001",
                sql=True,
            )
        with pytest.raises(
            RuntimeError,
            match="^Unsupported Alembic database dialect$",
        ):
            command.upgrade(
                _config(
                    configured_url="mysql+asyncmy://invalid",
                    x_url="mysql+asyncmy://invalid",
                ),
                "0001",
            )
        with pytest.raises(
            RuntimeError,
            match="^Invalid Alembic database URL$",
        ):
            command.upgrade(
                _config(configured_url="://", x_url="://"),
                "0001",
            )


def test_revision_by_revision_round_trip_preserves_owned_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("round-trip") as path:
        for revision in ("0001", "0002", "0003", "0004", "0005"):
            _upgrade(path, revision)
            reached_revision = _version(path) == revision
            _require_fixed(
                reached_revision,
                "revision-by-revision upgrade stopped at the wrong revision",
            )
            if revision == "0001":
                _seed_campaign_and_credential(path)

        _upgrade(path, "0006")
        renamed_value_survived = _credential_marker_survived(
            path, "cracked_value_enc"
        )
        _require_fixed(
            renamed_value_survived,
            "revision 0006 did not preserve the credential value",
        )

        _downgrade(path, "0005")
        restored_value_survived = _credential_marker_survived(
            path, "cracked_value"
        )
        _require_fixed(
            restored_value_survived,
            "revision 0006 downgrade did not preserve the credential value",
        )

        _downgrade(path, "0004")
        connection = _connect(path)
        try:
            trace_after_0005 = _column_map(connection, "findings").get(
                "trace_id"
            )
        finally:
            connection.close()
        trace_retained = (
            trace_after_0005 is not None and trace_after_0005[1] == 0
        )
        _require_fixed(
            trace_retained,
            "revision 0005 downgrade removed earlier trace metadata",
        )

        _downgrade(path, "0003")
        _downgrade(path, "0002")
        _downgrade(path, "0001")
        connection = _connect(path)
        try:
            parent_columns = _column_map(connection, "findings")
        finally:
            connection.close()
        parent_is_repaired = (
            {"cvss_score", "cvss_vector"}.issubset(parent_columns)
            and "trace_id" not in parent_columns
        )
        _require_fixed(
            parent_is_repaired,
            "revision 0002 downgrade contradicted the repaired parent",
        )

        _downgrade(path, "base")
        connection = _connect(path)
        try:
            remaining_tables = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                    """
                )
            }
        finally:
            connection.close()
        base_is_empty = not remaining_tables.intersection(
            _EXPECTED_APP_TABLES
        )
        _require_fixed(
            base_is_empty,
            "downgrade to base retained an application table",
        )

        _upgrade(path, "0006")
        _upgrade(path, "0006")
        final_revision = _version(path) == "0006"
        _require_fixed(
            final_revision,
            "re-upgrade did not return to revision 0006",
        )


def test_every_downgrade_restores_exact_repaired_parent_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("exact-parent-fingerprints") as path:
        _upgrade(path, "0006")

        parent_by_revision = {
            "0006": "0005",
            "0005": "0004",
            "0004": "0003",
            "0003": "0002",
            "0002": "0001",
            "0001": "base",
        }
        for _revision, parent in parent_by_revision.items():
            _downgrade(path, parent)
            connection = _connect(path)
            try:
                actual = _sqlite_catalog_contract(connection)
            finally:
                connection.close()
            expected = _fixed_sqlite_contract(parent)
            exact_parent_restored = actual == expected
            _require_fixed(
                exact_parent_restored,
                "downgrade did not restore the exact repaired parent catalog",
            )


def _replace_contract_table_columns(
    contract: _CatalogContract,
    table: str,
    columns: tuple[tuple[str, str, int, object, int], ...],
) -> _CatalogContract:
    return replace(
        contract,
        columns=tuple(
            (name, columns if name == table else current)
            for name, current in contract.columns
        ),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-table",
        "extra-table",
        "missing-column",
        "extra-column",
        "column-order",
        "column-type",
        "column-nullability",
        "column-default",
        "primary-key-order",
        "foreign-key-target",
        "foreign-key-delete",
        "foreign-key-update",
        "check-always-true",
        "check-expanded-values",
        "index-columns",
        "index-order",
        "index-uniqueness",
        "duplicate-equivalent-index",
        "autoincrement",
    ],
)
def test_fixed_catalog_oracle_rejects_semantic_mutations(
    mutation: str,
) -> None:
    expected = _fixed_sqlite_contract("0006")
    mutated = expected
    campaign_columns = dict(expected.columns)["campaigns"]
    if mutation == "missing-table":
        mutated = replace(expected, tables=expected.tables[1:])
    elif mutation == "extra-table":
        mutated = replace(expected, tables=(*expected.tables, "unexpected"))
    elif mutation == "missing-column":
        mutated = _replace_contract_table_columns(
            expected,
            "campaigns",
            campaign_columns[:-1],
        )
    elif mutation == "extra-column":
        mutated = _replace_contract_table_columns(
            expected,
            "campaigns",
            (*campaign_columns, ("unexpected", "TEXT", 0, None, 0)),
        )
    elif mutation == "column-order":
        reordered = list(campaign_columns)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        mutated = _replace_contract_table_columns(
            expected,
            "campaigns",
            tuple(reordered),
        )
    elif mutation in {
        "column-type",
        "column-nullability",
        "column-default",
    }:
        changed = list(campaign_columns)
        name, data_type, required, default, primary = changed[1]
        if mutation == "column-type":
            data_type = "INTEGER"
        elif mutation == "column-nullability":
            required = 0
        else:
            default = "'unexpected'"
        changed[1] = (name, data_type, required, default, primary)
        mutated = _replace_contract_table_columns(
            expected,
            "campaigns",
            tuple(changed),
        )
    elif mutation == "primary-key-order":
        mutated = replace(
            expected,
            primary_keys=(
                ("campaigns", ("name", "id")),
                *expected.primary_keys[1:],
            ),
        )
    elif mutation.startswith("foreign-key-"):
        changed_foreign_keys = list(expected.foreign_keys)
        table, local, remote, remote_column, update, delete = (
            changed_foreign_keys[0]
        )
        if mutation == "foreign-key-target":
            remote = "unexpected_parent"
        elif mutation == "foreign-key-delete":
            delete = "RESTRICT"
        else:
            update = "CASCADE"
        changed_foreign_keys[0] = (
            table,
            local,
            remote,
            remote_column,
            update,
            delete,
        )
        mutated = replace(
            expected,
            foreign_keys=tuple(changed_foreign_keys),
        )
    elif mutation == "check-always-true":
        mutated = replace(
            expected,
            checks=(
                (
                    "rate_limit_events",
                    "ck_rate_limit_events_blocked_bool",
                    "1",
                ),
            ),
        )
    elif mutation == "check-expanded-values":
        mutated = replace(
            expected,
            checks=(
                (
                    "rate_limit_events",
                    "ck_rate_limit_events_blocked_bool",
                    "blockedin0,1,2",
                ),
            ),
        )
    elif mutation.startswith("index-"):
        changed_indexes = list(expected.indexes)
        table, name, columns, unique, predicate = changed_indexes[0]
        if mutation == "index-columns":
            columns = ("name",)
        elif mutation == "index-order":
            columns = tuple(reversed((*columns, "name")))
        else:
            unique = True
        changed_indexes[0] = (
            table,
            name,
            columns,
            unique,
            predicate,
        )
        mutated = replace(expected, indexes=tuple(changed_indexes))
    elif mutation == "duplicate-equivalent-index":
        table, _name, columns, unique, predicate = expected.indexes[0]
        mutated = replace(
            expected,
            indexes=(
                *expected.indexes,
                (
                    table,
                    "idx_unexpected_duplicate",
                    columns,
                    unique,
                    predicate,
                ),
            ),
        )
    elif mutation == "autoincrement":
        mutated = replace(
            expected,
            autoincrement_tables=("rate_limit_events",),
        )
    else:
        raise AssertionError("unknown catalog mutation")
    _require_fixed(
        mutated != expected,
        "fixed catalog oracle accepted a semantic mutation",
    )


def _sqlite_table_clauses(
    connection: sqlite3.Connection,
    table: str,
) -> list[str]:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    if row is None or row[0] is None:
        raise AssertionError("missing SQLite mutation source table")
    return _split_sqlite_table_clauses(str(row[0]))


def _rebuild_sqlite_mutation_table(
    connection: sqlite3.Connection,
    table: str,
    clauses: list[str],
) -> None:
    index_statements = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='index' AND tbl_name=? AND sql IS NOT NULL "
            "ORDER BY name",
            (table,),
        )
    )
    source_columns = tuple(
        str(row[1])
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    )
    target_columns = tuple(
        column
        for clause in clauses
        for column in [_sqlite_clause_column(clause)]
        if column is not None
    )
    copied_columns = tuple(
        column for column in source_columns if column in target_columns
    )
    temporary = "migration_oracle_mutation"
    connection.commit()
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.execute(
            f'CREATE TABLE "{temporary}" (\n'
            + ",\n".join(clauses)
            + "\n)"
        )
        if copied_columns:
            quoted = ", ".join(f'"{column}"' for column in copied_columns)
            connection.execute(
                f'INSERT INTO "{temporary}" ({quoted}) '  # noqa: S608
                f'SELECT {quoted} FROM "{table}"'
            )
        connection.execute(f'DROP TABLE "{table}"')
        connection.execute(
            f'ALTER TABLE "{temporary}" RENAME TO "{table}"'
        )
        for statement in index_statements:
            connection.execute(statement)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def _replace_sqlite_column_clause(
    clauses: list[str],
    column: str,
    replacement: str,
) -> list[str]:
    replaced = False
    result: list[str] = []
    for clause in clauses:
        if _sqlite_clause_column(clause) == column:
            if replaced:
                raise AssertionError("duplicate SQLite mutation column")
            result.append(replacement)
            replaced = True
        else:
            result.append(clause)
    if not replaced:
        raise AssertionError("missing SQLite mutation column")
    return result


def _replace_sqlite_constraint_clause(
    clauses: list[str],
    marker: str,
    transform: Callable[[str], str],
) -> list[str]:
    replaced = False
    result: list[str] = []
    for clause in clauses:
        if marker.lower() in clause.lower():
            if replaced:
                raise AssertionError("ambiguous SQLite mutation constraint")
            result.append(transform(clause))
            replaced = True
        else:
            result.append(clause)
    if not replaced:
        raise AssertionError("missing SQLite mutation constraint")
    return result


def _apply_real_sqlite_catalog_mutation(
    connection: sqlite3.Connection,
    mutation: str,
) -> None:
    if mutation == "missing-table":
        connection.execute("DROP TABLE schema_version")
        connection.commit()
        return
    if mutation == "extra-table":
        connection.execute(
            "CREATE TABLE unexpected_catalog_probe(marker TEXT)"
        )
        connection.commit()
        return
    if mutation in {
        "missing-column",
        "extra-column",
        "column-order",
        "column-type",
        "column-nullability",
        "column-default",
        "primary-key-order",
    }:
        clauses = _sqlite_table_clauses(connection, "schema_version")
        if mutation == "missing-column":
            clauses = [
                clause
                for clause in clauses
                if _sqlite_clause_column(clause) != "applied_at"
            ]
        elif mutation == "extra-column":
            constraint_position = next(
                (
                    index
                    for index, clause in enumerate(clauses)
                    if _sqlite_clause_column(clause) is None
                ),
                len(clauses),
            )
            clauses.insert(constraint_position, '"unexpected" TEXT')
        elif mutation == "column-order":
            column_positions = [
                index
                for index, clause in enumerate(clauses)
                if _sqlite_clause_column(clause) is not None
            ]
            first, second = column_positions[:2]
            clauses[first], clauses[second] = clauses[second], clauses[first]
        elif mutation == "column-type":
            clauses = _replace_sqlite_column_clause(
                clauses,
                "applied_at",
                '"applied_at" INTEGER NOT NULL '
                "DEFAULT (datetime('now'))",
            )
        elif mutation == "column-nullability":
            clauses = _replace_sqlite_column_clause(
                clauses,
                "applied_at",
                '"applied_at" TEXT DEFAULT (datetime(\'now\'))',
            )
        elif mutation == "column-default":
            clauses = _replace_sqlite_column_clause(
                clauses,
                "applied_at",
                '"applied_at" TEXT NOT NULL DEFAULT \'unexpected\'',
            )
        else:
            clauses = _replace_sqlite_constraint_clause(
                clauses,
                "primary key",
                lambda clause: re.sub(
                    r"PRIMARY\s+KEY\s*\([^)]*\)",
                    "PRIMARY KEY (version, applied_at)",
                    clause,
                    count=1,
                    flags=re.IGNORECASE,
                ),
            )
        _rebuild_sqlite_mutation_table(
            connection,
            "schema_version",
            clauses,
        )
        return
    if mutation in {
        "foreign-key-target",
        "foreign-key-delete",
        "foreign-key-update",
    }:
        clauses = _sqlite_table_clauses(connection, "module_runs")

        def _mutate_foreign_key(clause: str) -> str:
            if mutation == "foreign-key-target":
                return re.sub(
                    r'REFERENCES\s+["`]?campaigns["`]?\s*'
                    r'\(\s*["`]?id["`]?\s*\)',
                    "REFERENCES users (id)",
                    clause,
                    count=1,
                    flags=re.IGNORECASE,
                )
            if mutation == "foreign-key-delete":
                return re.sub(
                    r"ON\s+DELETE\s+CASCADE",
                    "ON DELETE RESTRICT",
                    clause,
                    count=1,
                    flags=re.IGNORECASE,
                )
            return f"{clause} ON UPDATE CASCADE"

        clauses = _replace_sqlite_constraint_clause(
            clauses,
            "foreign key",
            _mutate_foreign_key,
        )
        _rebuild_sqlite_mutation_table(
            connection,
            "module_runs",
            clauses,
        )
        return
    if mutation in {"check-always-true", "check-expanded-values"}:
        clauses = _sqlite_table_clauses(connection, "rate_limit_events")
        expression = (
            "1"
            if mutation == "check-always-true"
            else "blocked IN (0, 1, 2)"
        )
        clauses = _replace_sqlite_constraint_clause(
            clauses,
            "ck_rate_limit_events_blocked_bool",
            lambda _clause: (
                "CONSTRAINT ck_rate_limit_events_blocked_bool "
                f"CHECK ({expression})"
            ),
        )
        _rebuild_sqlite_mutation_table(
            connection,
            "rate_limit_events",
            clauses,
        )
        return
    if mutation == "index-columns":
        connection.execute("DROP INDEX idx_findings_campaign")
        connection.execute(
            "CREATE INDEX idx_findings_campaign ON findings(severity)"
        )
        connection.commit()
        return
    if mutation == "index-order":
        clauses = _sqlite_table_clauses(connection, "hosts")
        clauses = _replace_sqlite_constraint_clause(
            clauses,
            "uq_hosts_campaign_ip",
            lambda clause: re.sub(
                r"UNIQUE\s*\(\s*[\"`]?campaign_id[\"`]?\s*,\s*"
                r"[\"`]?ip_address[\"`]?\s*\)",
                "UNIQUE (ip_address, campaign_id)",
                clause,
                count=1,
                flags=re.IGNORECASE,
            ),
        )
        _rebuild_sqlite_mutation_table(connection, "hosts", clauses)
        return
    if mutation == "index-uniqueness":
        connection.execute("DROP INDEX idx_findings_campaign")
        connection.execute(
            "CREATE UNIQUE INDEX idx_findings_campaign "
            "ON findings(campaign_id)"
        )
        connection.commit()
        return
    if mutation == "duplicate-equivalent-index":
        connection.execute(
            "CREATE INDEX idx_unexpected_duplicate "
            "ON findings(campaign_id)"
        )
        connection.commit()
        return
    if mutation == "autoincrement":
        clauses = _sqlite_table_clauses(connection, "audit_log")
        clauses = [
            re.sub(
                r"\s+AUTOINCREMENT\b",
                "",
                clause,
                count=1,
                flags=re.IGNORECASE,
            )
            for clause in clauses
        ]
        _rebuild_sqlite_mutation_table(connection, "audit_log", clauses)
        return
    raise AssertionError("unknown real SQLite catalog mutation")


def _catalog_contract_changed_fields(
    actual: _CatalogContract,
    expected: _CatalogContract,
) -> set[str]:
    return {
        name
        for name in (
            "tables",
            "columns",
            "primary_keys",
            "unique_constraints",
            "checks",
            "foreign_keys",
            "indexes",
            "autoincrement_tables",
        )
        if getattr(actual, name) != getattr(expected, name)
    }


@pytest.mark.parametrize(
    ("mutation", "intended_fields"),
    [
        ("missing-table", {"tables", "columns", "primary_keys"}),
        ("extra-table", {"tables", "columns", "primary_keys"}),
        ("missing-column", {"columns"}),
        ("extra-column", {"columns"}),
        ("column-order", {"columns"}),
        ("column-type", {"columns"}),
        ("column-nullability", {"columns"}),
        ("column-default", {"columns"}),
        ("primary-key-order", {"columns", "primary_keys"}),
        ("foreign-key-target", {"foreign_keys"}),
        ("foreign-key-delete", {"foreign_keys"}),
        ("foreign-key-update", {"foreign_keys"}),
        ("check-always-true", {"checks"}),
        ("check-expanded-values", {"checks"}),
        ("index-columns", {"indexes"}),
        ("index-order", {"unique_constraints"}),
        ("index-uniqueness", {"indexes"}),
        ("duplicate-equivalent-index", {"indexes"}),
        ("autoincrement", {"autoincrement_tables"}),
    ],
)
def test_real_sqlite_catalog_mutations_are_rejected_by_fixed_oracle(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    intended_fields: set[str],
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"real-oracle-{mutation}") as path:
        _upgrade(path, "0006")
        connection = _connect(path)
        try:
            expected = _fixed_sqlite_contract("0006")
            pristine = _sqlite_catalog_contract(connection)
            _apply_real_sqlite_catalog_mutation(connection, mutation)
            actual = _sqlite_catalog_contract(connection)
            changed_fields = _catalog_contract_changed_fields(
                actual,
                expected,
            )
            integrity_ok = (
                connection.execute("PRAGMA integrity_check").fetchone()
                == ("ok",)
            )
        finally:
            connection.close()
        rejected_for_intended_property = (
            pristine == expected
            and actual != expected
            and changed_fields == intended_fields
            and integrity_ok
            and _version(path) == "0006"
        )
        _require_fixed(
            rejected_for_intended_property,
            "real SQLite mutation did not isolate the intended contract",
        )


def test_fresh_revision_0006_catalog_and_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("catalog") as path:
        _upgrade(path, "0006")
        connection = _connect(path)
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                    """
                )
            }
            application_tables_match = (
                tables
                == _EXPECTED_APP_TABLES
                | {"alembic_version", "schema_version"}
                and {"alembic_version", "schema_version"}.issubset(tables)
                and "websocket_tickets" not in tables
            )
            columns_match = all(
                _ordered_column_fingerprint(connection, table)
                == _EXPECTED_SQLITE_COLUMN_FINGERPRINTS[table]
                and tuple(_column_map(connection, table)) == expected
                for table, expected in _EXPECTED_COLUMN_ORDER.items()
            )
            primary_keys_match = all(
                sum(item[3] for item in _column_map(connection, table).values())
                == 1
                for table in _EXPECTED_APP_TABLES
            )
            indexes_match = _index_map(connection) == _EXPECTED_INDEXES
            foreign_keys_match = (
                _foreign_keys(connection) == _EXPECTED_FOREIGN_KEYS
            )
            unique_constraints_match = (
                _unique_constraints(connection)
                == _EXPECTED_UNIQUE_CONSTRAINTS
            )
            autoincrement_tables = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND upper(sql) LIKE '%AUTOINCREMENT%'
                    """
                )
            }
            autoincrement_match = autoincrement_tables == {
                "audit_log",
                "rate_limit_events",
            }
            blocked_table_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type='table' AND name='rate_limit_events'
                """
            ).fetchone()
            blocked_check_match = (
                blocked_table_sql is not None
                and "blocked in (0, 1)"
                in " ".join(str(blocked_table_sql[0]).lower().split())
            )

            finding_columns = _column_map(connection, "findings")
            critical_nullability = (
                finding_columns["cvss_score"][1] == 1
                and finding_columns["cvss_vector"][1] == 1
                and finding_columns["trace_id"][1] == 1
            )
            timestamp_defaults = all(
                "datetime" in str(default).lower()
                for table, column in (
                    ("campaigns", "created_at"),
                    ("module_runs", "completed_at"),
                    ("findings", "discovered_at"),
                    ("rate_limit_events", "timestamp"),
                    ("revoked_access_tokens", "revoked_at"),
                )
                for default in [_column_map(connection, table)[column][2]]
            )

            bad_fk_rejected = False
            try:
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title, description, severity
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "finding-a",
                        "missing-campaign",
                        "module-a",
                        "title",
                        "description",
                        "high",
                    ),
                )
            except sqlite3.IntegrityError:
                bad_fk_rejected = True
            finally:
                connection.rollback()
        finally:
            connection.close()

        _require_fixed(
            application_tables_match,
            "revision 0006 table contract is incomplete",
        )
        _require_fixed(
            columns_match,
            "revision 0006 column contract is incomplete",
        )
        _require_fixed(
            primary_keys_match,
            "revision 0006 primary-key contract is incomplete",
        )
        _require_fixed(
            indexes_match,
            "revision 0006 logical index contract diverged",
        )
        _require_fixed(
            foreign_keys_match,
            "revision 0006 foreign-key contract diverged",
        )
        _require_fixed(
            unique_constraints_match,
            "revision 0006 uniqueness contract diverged",
        )
        _require_fixed(
            autoincrement_match,
            "revision 0006 SQLite autoincrement contract diverged",
        )
        _require_fixed(
            blocked_check_match,
            "revision 0006 blocked check contract diverged",
        )
        _require_fixed(
            critical_nullability,
            "finding hardening contract diverged",
        )
        _require_fixed(
            timestamp_defaults,
            "SQLite database-time defaults diverged",
        )
        _require_fixed(
            bad_fk_rejected,
            "SQLite did not enforce a required foreign key",
        )


def test_sqlite_revision_0006_enforces_relational_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("enforcement") as path:
        _upgrade(path, "0006")
        connection = _connect(path)
        try:
            _seed_complete_contract(connection)
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
            for table, columns in _EXPECTED_SQLITE_COLUMN_FINGERPRINTS.items():
                key_name, key_value = key_by_table[table]
                for name, _kind, required, _default, primary in columns:
                    if not required or primary:
                        continue
                    statement = (
                        f'UPDATE "{table}" SET "{name}"=NULL '  # noqa: S608
                        f'WHERE "{key_name}"=?'
                    )
                    if not _expected_integrity_failure(
                        connection,
                        statement,
                        (key_value,),
                    ):
                        required_columns_rejected = False
                        break

            foreign_keys_rejected = True
            for table, local, _remote, _remote_column, _action in sorted(
                _EXPECTED_FOREIGN_KEYS
            ):
                key_name, key_value = key_by_table[table]
                statement = (
                    f'UPDATE "{table}" SET "{local}"=? '  # noqa: S608
                    f'WHERE "{key_name}"=?'
                )
                if not _expected_integrity_failure(
                    connection,
                    statement,
                    ("missing-parent", key_value),
                ):
                    foreign_keys_rejected = False
                    break

            duplicate_host_rejected = _expected_integrity_failure(
                connection,
                """
                INSERT INTO hosts(id, campaign_id, ip_address)
                VALUES(?, ?, ?)
                """,
                ("host-duplicate", "campaign-contract", "192.0.2.10"),
            )
            duplicate_username_rejected = _expected_integrity_failure(
                connection,
                """
                INSERT INTO users(id, username, hashed_password)
                VALUES(?, ?, ?)
                """,
                ("user-duplicate", "synthetic-account", "synthetic-hash"),
            )

            connection.execute("SAVEPOINT set_null_probe")
            connection.execute(
                "DELETE FROM hosts WHERE id=?",
                ("host-contract",),
            )
            host_dependents = connection.execute(
                """
                SELECT
                    (SELECT host_id IS NULL FROM credentials WHERE id=?),
                    (SELECT host_id IS NULL FROM loot WHERE id=?)
                """,
                ("credential-contract", "loot-contract"),
            ).fetchone()
            set_null_enforced = host_dependents == (1, 1)
            connection.execute("ROLLBACK TO set_null_probe")
            connection.execute("RELEASE set_null_probe")

            connection.execute("SAVEPOINT campaign_cascade_probe")
            connection.execute(
                "DELETE FROM campaigns WHERE id=?",
                ("campaign-contract",),
            )
            campaign_dependents = connection.execute(
                """
                SELECT
                    (SELECT count(*) FROM module_runs),
                    (SELECT count(*) FROM findings),
                    (SELECT count(*) FROM hosts),
                    (SELECT count(*) FROM credentials),
                    (SELECT count(*) FROM loot),
                    (SELECT campaign_id IS NULL FROM audit_log WHERE id=1)
                """
            ).fetchone()
            campaign_actions_enforced = campaign_dependents == (
                0,
                0,
                0,
                0,
                0,
                1,
            )
            connection.execute("ROLLBACK TO campaign_cascade_probe")
            connection.execute("RELEASE campaign_cascade_probe")

            connection.execute("SAVEPOINT user_cascade_probe")
            connection.execute(
                "DELETE FROM users WHERE id=?",
                ("user-contract",),
            )
            user_dependents = connection.execute(
                """
                SELECT
                    (SELECT count(*) FROM api_keys),
                    (SELECT count(*) FROM refresh_tokens)
                """
            ).fetchone()
            user_cascade_enforced = user_dependents == (0, 0)
            connection.execute("ROLLBACK TO user_cascade_probe")
            connection.execute("RELEASE user_cascade_probe")

            timestamp_defaults_execute = all(
                connection.execute(
                    f'SELECT "{column}" IS NOT NULL '  # noqa: S608
                    f'AND typeof("{column}")="text" FROM "{table}" LIMIT 1'
                ).fetchone()
                == (1,)
                for table, column in (
                    ("campaigns", "created_at"),
                    ("module_runs", "completed_at"),
                    ("findings", "discovered_at"),
                    ("hosts", "first_seen"),
                    ("credentials", "captured_at"),
                    ("loot", "captured_at"),
                    ("audit_log", "timestamp"),
                    ("users", "created_at"),
                    ("api_keys", "created_at"),
                    ("refresh_tokens", "created_at"),
                    ("revoked_access_tokens", "revoked_at"),
                    ("rate_limit_events", "timestamp"),
                )
            )
            integer_defaults_execute = (
                connection.execute(
                    """
                    SELECT
                        (SELECT success=0 FROM module_runs LIMIT 1),
                        (SELECT validated=0 AND false_positive=0
                         FROM findings LIMIT 1),
                        (SELECT is_dc=0 FROM hosts LIMIT 1),
                        (SELECT cracked=0 FROM credentials LIMIT 1),
                        (SELECT is_active=1 FROM users LIMIT 1),
                        (SELECT is_active=1 FROM api_keys LIMIT 1),
                        (SELECT is_revoked=0 FROM refresh_tokens LIMIT 1),
                        (SELECT blocked=0 FROM rate_limit_events LIMIT 1)
                    """
                ).fetchone()
                == (1, 1, 1, 1, 1, 1, 1, 1)
            )

            connection.execute(
                "INSERT INTO audit_log(action) VALUES(?)",
                ("second-action",),
            )
            audit_second = int(connection.execute(
                "SELECT max(id) FROM audit_log"
            ).fetchone()[0])
            connection.execute(
                "DELETE FROM audit_log WHERE id=?",
                (audit_second,),
            )
            connection.execute(
                "INSERT INTO audit_log(action) VALUES(?)",
                ("third-action",),
            )
            audit_third = int(connection.execute(
                "SELECT max(id) FROM audit_log"
            ).fetchone()[0])
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.21", "synthetic-bucket"),
            )
            rate_second = int(connection.execute(
                "SELECT max(id) FROM rate_limit_events"
            ).fetchone()[0])
            connection.execute(
                "DELETE FROM rate_limit_events WHERE id=?",
                (rate_second,),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.22", "synthetic-bucket"),
            )
            rate_third = int(connection.execute(
                "SELECT max(id) FROM rate_limit_events"
            ).fetchone()[0])
            connection.commit()
            monotonic_ids = (
                audit_third > audit_second and rate_third > rate_second
            )
        finally:
            connection.close()

        _require_fixed(
            required_columns_rejected,
            "SQLite accepted NULL in a required non-primary column",
        )
        _require_fixed(
            foreign_keys_rejected,
            "SQLite accepted an invalid foreign-key parent",
        )
        _require_fixed(
            duplicate_host_rejected and duplicate_username_rejected,
            "SQLite uniqueness enforcement diverged",
        )
        _require_fixed(
            set_null_enforced,
            "SQLite SET NULL behavior diverged",
        )
        _require_fixed(
            campaign_actions_enforced and user_cascade_enforced,
            "SQLite cascade behavior diverged",
        )
        _require_fixed(
            timestamp_defaults_execute,
            "SQLite timestamp default behavior diverged",
        )
        _require_fixed(
            integer_defaults_execute,
            "SQLite integer default behavior diverged",
        )
        _require_fixed(
            monotonic_ids,
            "SQLite autoincrement behavior diverged",
        )


def test_revision_0003_blocked_integer_contract_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("blocked-contract") as path:
        _upgrade(path, "0003")
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO rate_limit_events(ip_address, bucket) VALUES(?, ?)",
                ("synthetic-a", "bucket"),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket, blocked)
                VALUES(?, ?, ?)
                """,
                ("synthetic-b", "bucket", 0),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket, blocked)
                VALUES(?, ?, ?)
                """,
                ("synthetic-c", "bucket", 1),
            )
            connection.commit()
            valid_rows = connection.execute(
                """
                SELECT count(*), min(blocked), max(blocked)
                FROM rate_limit_events
                """
            ).fetchone()

            rejected = 0
            for index, value in enumerate((None, -1, 2, 17)):
                try:
                    connection.execute(
                        """
                        INSERT INTO rate_limit_events(
                            ip_address, bucket, blocked
                        ) VALUES(?, ?, ?)
                        """,
                        (f"synthetic-invalid-{index}", "bucket", value),
                    )
                    connection.commit()
                except sqlite3.IntegrityError:
                    rejected += 1
                    connection.rollback()
            invalid_rows = connection.execute(
                """
                SELECT count(*) FROM rate_limit_events
                WHERE ip_address LIKE 'synthetic-invalid-%'
                """
            ).fetchone()
            reusable = connection.execute("SELECT 1").fetchone() == (1,)
            table_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type='table' AND name='rate_limit_events'
                """
            ).fetchone()
            normalized_check = (
                table_sql is not None
                and "blocked IN (0, 1)"
                in " ".join(str(table_sql[0]).split())
            )
        finally:
            connection.close()

        contract_enforced = (
            valid_rows == (3, 0, 1)
            and rejected == 4
            and invalid_rows == (0,)
            and reusable
            and normalized_check
        )
        _require_fixed(
            contract_enforced,
            "revision 0003 blocked contract was not enforced",
        )

        _downgrade(path, "0002")
        connection = _connect(path)
        try:
            removed = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='rate_limit_events'
                """
            ).fetchone() is None
        finally:
            connection.close()
        _upgrade(path, "0003")
        connection = _connect(path)
        try:
            reupgrade_rejected = False
            try:
                connection.execute(
                    """
                    INSERT INTO rate_limit_events(
                        ip_address, bucket, blocked
                    ) VALUES(?, ?, ?)
                    """,
                    ("synthetic-reupgrade", "bucket", 2),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                reupgrade_rejected = True
                connection.rollback()
        finally:
            connection.close()
        _require_fixed(
            removed and reupgrade_rejected,
            "revision 0003 downgrade/re-upgrade lost enforcement",
        )


def test_sqlite_autoincrement_sequence_lifecycle_is_monotonic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("autoincrement-sequence") as path:
        _upgrade(path, "0003")
        connection = _connect(path)
        try:
            connection.execute(
                """
                CREATE TABLE unrelated_sequence_probe(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    marker TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO unrelated_sequence_probe(marker) VALUES(?)",
                ("synthetic",),
            )
            for action in ("first", "second"):
                connection.execute(
                    "INSERT INTO audit_log(action) VALUES(?)",
                    (action,),
                )
            for address in ("192.0.2.50", "192.0.2.51"):
                connection.execute(
                    """
                    INSERT INTO rate_limit_events(ip_address, bucket)
                    VALUES(?, ?)
                    """,
                    (address, "bucket"),
                )
            connection.execute("DELETE FROM audit_log WHERE id=2")
            connection.execute(
                "INSERT INTO audit_log(action) VALUES(?)",
                ("third",),
            )
            connection.execute(
                "INSERT INTO audit_log(id, action) VALUES(?, ?)",
                (100, "explicit-high"),
            )
            connection.execute(
                "INSERT INTO audit_log(action) VALUES(?)",
                ("after-high",),
            )
            connection.execute(
                "DELETE FROM rate_limit_events WHERE id=2"
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.52", "bucket"),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(id, ip_address, bucket)
                VALUES(?, ?, ?)
                """,
                (200, "192.0.2.53", "bucket"),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.54", "bucket"),
            )
            connection.commit()
            allocated = (
                connection.execute(
                    "SELECT max(id) FROM audit_log"
                ).fetchone()
                == (101,)
                and connection.execute(
                    "SELECT max(id) FROM rate_limit_events"
                ).fetchone()
                == (201,)
            )
            sequence_rows = dict(
                connection.execute(
                    """
                    SELECT name, seq FROM sqlite_sequence
                    WHERE name IN (
                        'audit_log',
                        'rate_limit_events',
                        'unrelated_sequence_probe'
                    )
                    """
                )
            )
            sequence_state_matches = sequence_rows == {
                "audit_log": 101,
                "rate_limit_events": 201,
                "unrelated_sequence_probe": 1,
            }
        finally:
            connection.close()

        _downgrade(path, "0002")
        connection = _connect(path)
        try:
            after_rate_drop = dict(
                connection.execute(
                    "SELECT name, seq FROM sqlite_sequence"
                )
            )
        finally:
            connection.close()
        rate_sequence_removed = (
            "rate_limit_events" not in after_rate_drop
            and after_rate_drop.get("audit_log") == 101
            and after_rate_drop.get("unrelated_sequence_probe") == 1
        )

        _downgrade(path, "base")
        connection = _connect(path)
        try:
            after_base = dict(
                connection.execute(
                    "SELECT name, seq FROM sqlite_sequence"
                )
            )
        finally:
            connection.close()
        audit_sequence_removed = (
            "audit_log" not in after_base
            and after_base.get("unrelated_sequence_probe") == 1
        )

        _upgrade(path, "0003")
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO audit_log(action) VALUES(?)",
                ("fresh",),
            )
            connection.execute(
                """
                INSERT INTO rate_limit_events(ip_address, bucket)
                VALUES(?, ?)
                """,
                ("192.0.2.55", "bucket"),
            )
            connection.commit()
            clean_reinitialization = (
                connection.execute(
                    "SELECT max(id) FROM audit_log"
                ).fetchone()
                == (1,)
                and connection.execute(
                    "SELECT max(id) FROM rate_limit_events"
                ).fetchone()
                == (1,)
                and connection.execute(
                    """
                    SELECT seq FROM sqlite_sequence
                    WHERE name='unrelated_sequence_probe'
                    """
                ).fetchone()
                == (1,)
            )
        finally:
            connection.close()

        _require_fixed(
            allocated
            and sequence_state_matches
            and rate_sequence_removed
            and audit_sequence_removed
            and clean_reinitialization,
            "SQLite AUTOINCREMENT sequence lifecycle diverged",
        )


@pytest.mark.parametrize(
    "legacy_revision",
    ["0001", "0002", "0003", "0004", "0005"],
)
def test_complete_head_era_catalogs_preserve_data_and_defer_known_drift(
    monkeypatch: pytest.MonkeyPatch,
    legacy_revision: str,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"complete-legacy-{legacy_revision}") as path:
        _create_transformed_legacy_catalog(path, legacy_revision)
        connection = _connect(path)
        try:
            initial_fingerprint_matches = (
                _sqlite_catalog_contract(connection)
                == _fixed_legacy_sqlite_contract(legacy_revision)
                and _version(path) == legacy_revision
            )
        finally:
            connection.close()
        _require_fixed(
            initial_fingerprint_matches,
            "frozen HEAD-era catalog fingerprint diverged",
        )

        _upgrade(path, "0006")
        connection = _connect(path)
        try:
            row_counts = connection.execute(
                """
                SELECT
                    (SELECT count(*) FROM campaigns),
                    (SELECT count(*) FROM findings),
                    (SELECT count(*) FROM hosts),
                    (SELECT count(*) FROM credentials),
                    (SELECT count(*) FROM loot),
                    (SELECT count(*) FROM audit_log),
                    (SELECT count(*) FROM users),
                    (SELECT count(*) FROM api_keys),
                    (SELECT count(*) FROM refresh_tokens)
                """
            ).fetchone()
            expected_finding_count = 3 if legacy_revision >= "0002" else 1
            unrelated_rows_survived = row_counts == (
                1,
                expected_finding_count,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
            )
            credential_value_survived = (
                connection.execute(
                    """
                    SELECT count(*) FROM credentials
                    WHERE cracked_value_enc IS NOT NULL
                    """
                ).fetchone()
                == (1,)
            )
            final_finding_columns = _column_map(connection, "findings")
            cvss_drift_deferred = (
                final_finding_columns["cvss_score"][1]
                == (1 if legacy_revision == "0001" else 0)
                and final_finding_columns["cvss_vector"][1]
                == (1 if legacy_revision == "0001" else 0)
            )
            trace_drift_deferred = (
                final_finding_columns["trace_id"][1]
                == (0 if legacy_revision == "0005" else 1)
            )
            table_names = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name NOT LIKE 'sqlite_%'
                    """
                )
            }
            structural_drift_remains = (
                "module_runs" not in table_names
                and "schema_version" not in table_names
                and not _foreign_keys(connection)
                and "idx_findings_validated"
                in {
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type='index' AND sql IS NOT NULL
                        """
                    )
                }
            )
            rate_check_state_is_historical = True
            if legacy_revision >= "0003":
                rate_sql = connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type='table' AND name='rate_limit_events'
                    """
                ).fetchone()
                rate_check_state_is_historical = (
                    rate_sql is not None
                    and "blocked in (0,1)"
                    not in str(rate_sql[0]).lower().replace(" ", "")
                )
            final_revision = _version(path) == "0006"
        finally:
            connection.close()

        _require_fixed(
            unrelated_rows_survived and credential_value_survived,
            "legacy upgrade lost protected or unrelated rows",
        )
        _require_fixed(
            cvss_drift_deferred
            and trace_drift_deferred
            and structural_drift_remains
            and rate_check_state_is_historical,
            "legacy drift was silently misclassified as repaired",
        )
        _require_fixed(
            final_revision,
            "legacy catalog did not advance to revision 0006",
        )


def test_revision_0002_reconciles_legacy_missing_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("legacy-0002") as path:
        _upgrade(path, "0001")
        connection = _connect(path)
        try:
            connection.execute("ALTER TABLE findings DROP COLUMN cvss_score")
            connection.execute("ALTER TABLE findings DROP COLUMN cvss_vector")
            connection.commit()
        finally:
            connection.close()
        _upgrade(path, "0002")
        connection = _connect(path)
        try:
            columns = _column_map(connection, "findings")
        finally:
            connection.close()
        repaired = (
            {"cvss_score", "cvss_vector", "trace_id"}.issubset(columns)
            and columns["cvss_score"][1] == 1
            and columns["cvss_vector"][1] == 1
        )
        _require_fixed(
            repaired,
            "revision 0002 did not reconcile the legacy catalog",
        )


def test_revision_0005_reconciles_missing_trace_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("legacy-0005") as path:
        _upgrade(path, "0004")
        connection = _connect(path)
        try:
            connection.execute("ALTER TABLE findings DROP COLUMN trace_id")
            connection.commit()
        finally:
            connection.close()
        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            trace = _column_map(connection, "findings").get("trace_id")
        finally:
            connection.close()
        hardened = trace is not None and trace[1] == 1
        _require_fixed(
            hardened,
            "revision 0005 did not reconcile missing trace metadata",
        )


def test_revision_0005_normalizes_only_null_trace_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("trace-normalization") as path:
        _upgrade(path, "0004")
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES(?, ?)",
                ("campaign-trace", "Migration campaign"),
            )
            for index, trace_value in enumerate((None, "", "trace-marker")):
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, campaign_id, module_id, title,
                        description, severity, trace_id
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"finding-{index}",
                        "campaign-trace",
                        "module",
                        f"title-{index}",
                        "description",
                        "low",
                        trace_value,
                    ),
                )
            connection.commit()
        finally:
            connection.close()

        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            upgraded = connection.execute(
                """
                SELECT
                    count(*),
                    sum(trace_id IS NULL),
                    sum(trace_id=''),
                    sum(trace_id='trace-marker'),
                    count(DISTINCT title)
                FROM findings
                """
            ).fetchone()
        finally:
            connection.close()
        _require_fixed(
            upgraded == (3, 0, 2, 1, 3),
            "revision 0005 trace normalization changed protected state",
        )

        _downgrade(path, "0004")
        connection = _connect(path)
        try:
            downgraded = connection.execute(
                """
                SELECT count(*), sum(trace_id=''), sum(trace_id='trace-marker')
                FROM findings
                """
            ).fetchone()
            connection.execute(
                """
                INSERT INTO findings(
                    id, campaign_id, module_id, title,
                    description, severity, trace_id
                ) VALUES(?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    "finding-after-downgrade",
                    "campaign-trace",
                    "module",
                    "title-after-downgrade",
                    "description",
                    "low",
                ),
            )
            connection.commit()
        finally:
            connection.close()
        _require_fixed(
            downgraded == (3, 2, 1),
            "revision 0005 downgrade reconstructed legacy NULL state",
        )

        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            reupgraded = connection.execute(
                """
                SELECT
                    count(*),
                    sum(trace_id IS NULL),
                    sum(trace_id=''),
                    sum(trace_id='trace-marker')
                FROM findings
                """
            ).fetchone()
        finally:
            connection.close()
        _require_fixed(
            reupgraded == (4, 0, 3, 1),
            "revision 0005 re-upgrade normalization diverged",
        )


def _install_sqlite_version_failure(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER migration_version_failure
            BEFORE UPDATE ON alembic_version
            BEGIN
                SELECT RAISE(ABORT, 'migration version update denied');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()


def _remove_sqlite_version_failure(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute(
            "DROP TRIGGER IF EXISTS migration_version_failure"
        )
        connection.commit()
    finally:
        connection.close()


class _PrimaryTraceMigrationError(RuntimeError):
    pass


class _RollbackSavepointError(RuntimeError):
    pass


class _ReleaseSavepointError(RuntimeError):
    pass


class _SavepointCreationError(RuntimeError):
    pass


class _ConnectionInvalidationError(RuntimeError):
    pass


class _TraceSavepointBind:
    def __init__(
        self,
        *,
        fail_savepoint: bool = False,
        fail_rollback: bool = False,
        fail_release: bool = False,
        fail_invalidate: bool = False,
    ) -> None:
        self.fail_savepoint = fail_savepoint
        self.fail_rollback = fail_rollback
        self.fail_release = fail_release
        self.fail_invalidate = fail_invalidate
        self.actions: list[str] = []
        self.invalidation_attempted = False
        self.commit_called = False

    def exec_driver_sql(self, statement: str) -> None:
        normalized = " ".join(statement.upper().split())
        if normalized.startswith("SAVEPOINT "):
            action = "savepoint"
        elif normalized.startswith("ROLLBACK TO SAVEPOINT "):
            action = "rollback"
        elif normalized.startswith("RELEASE SAVEPOINT "):
            action = "release"
        else:
            action = "unexpected"
        self.actions.append(action)
        if action == "savepoint" and self.fail_savepoint:
            raise _SavepointCreationError
        if action == "rollback" and self.fail_rollback:
            raise _RollbackSavepointError
        if action == "release" and self.fail_release:
            raise _ReleaseSavepointError

    def invalidate(self) -> None:
        self.invalidation_attempted = True
        if self.fail_invalidate:
            raise _ConnectionInvalidationError

    def commit(self) -> None:
        self.commit_called = True


def _traceback_retains(
    traceback: object,
    expected: object,
) -> bool:
    current = traceback
    while current is not None:
        if current is expected:
            return True
        current = current.tb_next
    return False


@pytest.mark.parametrize(
    (
        "fail_rollback",
        "fail_release",
        "fail_invalidate",
        "expected_actions",
        "expected_invalidation",
        "expected_notes",
    ),
    [
        (
            False,
            False,
            False,
            ("savepoint", "rollback", "release"),
            False,
            (),
        ),
        (
            True,
            False,
            False,
            ("savepoint", "rollback"),
            True,
            (
                "Migration 0005 savepoint cleanup failed "
                "[rollback-savepoint: _RollbackSavepointError]",
            ),
        ),
        (
            False,
            True,
            False,
            ("savepoint", "rollback", "release"),
            True,
            (
                "Migration 0005 savepoint cleanup failed "
                "[release-savepoint: _ReleaseSavepointError]",
            ),
        ),
        (
            True,
            False,
            True,
            ("savepoint", "rollback"),
            True,
            (
                "Migration 0005 savepoint cleanup failed "
                "[rollback-savepoint: _RollbackSavepointError]",
                "Migration 0005 savepoint cleanup failed "
                "[invalidate-connection: _ConnectionInvalidationError]",
            ),
        ),
    ],
    ids=(
        "cleanup-succeeds",
        "rollback-fails",
        "release-fails",
        "rollback-and-invalidation-fail",
    ),
)
def test_revision_0005_savepoint_cleanup_preserves_primary_exception(
    monkeypatch: pytest.MonkeyPatch,
    fail_rollback: bool,
    fail_release: bool,
    fail_invalidate: bool,
    expected_actions: tuple[str, ...],
    expected_invalidation: bool,
    expected_notes: tuple[str, ...],
) -> None:
    revision = importlib.import_module(
        "migrations.versions.0005_add_trace_id_to_findings"
    )
    bind = _TraceSavepointBind(
        fail_rollback=fail_rollback,
        fail_release=fail_release,
        fail_invalidate=fail_invalidate,
    )
    primary = _PrimaryTraceMigrationError()
    original_traceback: list[object] = []

    @contextmanager
    def _failing_batch(*_args: object, **_kwargs: object) -> Iterator[object]:
        try:
            raise primary
        except _PrimaryTraceMigrationError as error:
            original_traceback.append(error.__traceback__)
            raise
        yield object()

    monkeypatch.setattr(
        revision,
        "op",
        types.SimpleNamespace(
            get_bind=lambda: bind,
            batch_alter_table=_failing_batch,
        ),
    )
    caught: Exception | None = None
    try:
        revision._alter_trace("sqlite", nullable=False)
    except _PrimaryTraceMigrationError as error:
        caught = error
    notes = tuple(getattr(caught, "__notes__", ()))
    preserved = (
        caught is primary
        and len(original_traceback) == 1
        and _traceback_retains(
            getattr(caught, "__traceback__", None),
            original_traceback[0],
        )
        and tuple(bind.actions) == expected_actions
        and bind.invalidation_attempted is expected_invalidation
        and notes == expected_notes
        and not bind.commit_called
    )
    _require_fixed(
        preserved,
        "revision 0005 cleanup replaced or exposed the primary failure",
    )


def test_revision_0005_savepoint_creation_failure_does_not_run_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = importlib.import_module(
        "migrations.versions.0005_add_trace_id_to_findings"
    )
    bind = _TraceSavepointBind(fail_savepoint=True)
    batch_entered = False

    @contextmanager
    def _unexpected_batch(
        *_args: object,
        **_kwargs: object,
    ) -> Iterator[object]:
        nonlocal batch_entered
        batch_entered = True
        yield object()

    monkeypatch.setattr(
        revision,
        "op",
        types.SimpleNamespace(
            get_bind=lambda: bind,
            batch_alter_table=_unexpected_batch,
        ),
    )
    caught: Exception | None = None
    try:
        revision._alter_trace("sqlite", nullable=False)
    except _SavepointCreationError as error:
        caught = error
    failed_closed = (
        isinstance(caught, _SavepointCreationError)
        and bind.actions == ["savepoint"]
        and not batch_entered
        and not bind.commit_called
        and not getattr(caught, "__notes__", ())
    )
    _require_fixed(
        failed_closed,
        "revision 0005 savepoint creation failure ran unsafe cleanup",
    )


class _MigrationCleanupProbeError(RuntimeError):
    pass


def test_alembic_command_preserves_revision_primary_and_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from alembic.operations import Operations
    from sqlalchemy.ext.asyncio import AsyncEngine

    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("0005-command-primary") as path:
        _upgrade(path, "0004")
        primary = _PrimaryTraceMigrationError()
        original_traceback: list[object] = []
        original_dispose = AsyncEngine.dispose

        @contextmanager
        def _raise_primary(
            *_args: object,
            **_kwargs: object,
        ) -> Iterator[object]:
            try:
                raise primary
            except _PrimaryTraceMigrationError as error:
                original_traceback.append(error.__traceback__)
                raise
            yield object()

        async def _dispose_then_fail(
            engine: AsyncEngine,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            await original_dispose(engine)
            raise _MigrationCleanupProbeError

        caught: Exception | None = None
        with monkeypatch.context() as context:
            context.setattr(
                Operations,
                "batch_alter_table",
                _raise_primary,
            )
            context.setattr(
                AsyncEngine,
                "dispose",
                _dispose_then_fail,
            )
            try:
                _upgrade(path, "0005")
            except Exception as error:
                caught = error

        notes = tuple(getattr(caught, "__notes__", ()))
        preserved = (
            caught is primary
            and len(original_traceback) == 1
            and _traceback_retains(
                getattr(caught, "__traceback__", None),
                original_traceback[0],
            )
            and notes
            == (
                "Alembic engine cleanup failed "
                "[_MigrationCleanupProbeError]",
            )
            and _version(path) == "0004"
        )
        _require_fixed(
            preserved,
            "Alembic command replaced a revision-owned primary failure",
        )


def test_alembic_operational_failure_remains_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import traceback

    from alembic.operations import Operations
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.ext.asyncio import AsyncEngine

    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("0005-command-operational") as path:
        _upgrade(path, "0004")
        sensitive_marker = "operational-detail-canary"
        cleanup_marker = "cleanup-detail-canary"
        operational = OperationalError(
            sensitive_marker,
            {},
            RuntimeError(sensitive_marker),
        )
        original_dispose = AsyncEngine.dispose

        @contextmanager
        def _raise_operational(
            *_args: object,
            **_kwargs: object,
        ) -> Iterator[object]:
            raise operational
            yield object()

        async def _dispose_then_fail(
            engine: AsyncEngine,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            await original_dispose(engine)
            raise _MigrationCleanupProbeError(cleanup_marker)

        caught: Exception | None = None
        with monkeypatch.context() as context:
            context.setattr(
                Operations,
                "batch_alter_table",
                _raise_operational,
            )
            context.setattr(
                AsyncEngine,
                "dispose",
                _dispose_then_fail,
            )
            try:
                _upgrade(path, "0005")
            except Exception as error:
                caught = error

        captured = capsys.readouterr()
        rendered = (
            ""
            if caught is None
            else "".join(
                traceback.format_exception(
                    type(caught),
                    caught,
                    caught.__traceback__,
                )
            )
        )
        confidential = (
            sensitive_marker
            not in captured.out
            and sensitive_marker not in captured.err
            and sensitive_marker not in rendered
            and cleanup_marker not in captured.out
            and cleanup_marker not in captured.err
            and cleanup_marker not in rendered
        )
        sanitized = (
            type(caught) is RuntimeError
            and str(caught)
            == "Alembic online migration failed [OperationalError]"
            and bool(getattr(caught, "__suppress_context__", False))
            and _version(path) == "0004"
        )
        _require_fixed(
            sanitized and confidential,
            "Alembic operational failure diagnostics were not sanitized",
        )


def test_revision_0005_rollback_failure_invalidates_real_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from alembic.operations import Operations
    from sqlalchemy.engine import Connection

    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("0005-rollback-invalidation") as path:
        _upgrade(path, "0004")
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES(?, ?)",
                ("campaign-invalidation", "Synthetic campaign"),
            )
            connection.execute(
                """
                INSERT INTO findings(
                    id, campaign_id, module_id, title,
                    description, severity, trace_id
                ) VALUES(?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    "finding-invalidation",
                    "campaign-invalidation",
                    "module",
                    "Synthetic title",
                    "Synthetic description",
                    "low",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        original_batch = Operations.batch_alter_table
        original_execute = Connection.execute
        original_exec_driver_sql = Connection.exec_driver_sql
        original_invalidate = Connection.invalidate
        normalization_seen = False
        rollback_failed = False
        invalidation_seen = False
        savepoint_actions: list[str] = []

        @contextmanager
        def _fail_after_normalization(
            operations: Operations,
            table_name: str,
            *args: object,
            **kwargs: object,
        ) -> Iterator[object]:
            if table_name == "findings":
                raise _PrimaryTraceMigrationError
            with original_batch(
                operations,
                table_name,
                *args,
                **kwargs,
            ) as batch:
                yield batch

        def _record_normalization(
            connection: Connection,
            statement: object,
            *args: object,
            **kwargs: object,
        ) -> object:
            nonlocal normalization_seen
            normalized = " ".join(str(statement).upper().split())
            if normalized.startswith("UPDATE FINDINGS SET TRACE_ID="):
                normalization_seen = True
            return original_execute(connection, statement, *args, **kwargs)

        def _fail_rollback_to_savepoint(
            connection: Connection,
            statement: str,
            *args: object,
            **kwargs: object,
        ) -> object:
            nonlocal rollback_failed
            normalized = " ".join(statement.upper().split())
            if normalized.startswith("SAVEPOINT "):
                savepoint_actions.append("savepoint")
            if normalized.startswith("ROLLBACK TO SAVEPOINT "):
                savepoint_actions.append("rollback")
                rollback_failed = True
                raise _RollbackSavepointError
            if normalized.startswith("RELEASE SAVEPOINT "):
                savepoint_actions.append("release")
            return original_exec_driver_sql(
                connection,
                statement,
                *args,
                **kwargs,
            )

        def _record_invalidation(
            connection: Connection,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal invalidation_seen
            invalidation_seen = True
            original_invalidate(connection, *args, **kwargs)

        caught_failure = False
        with monkeypatch.context() as context:
            context.setattr(
                Operations,
                "batch_alter_table",
                _fail_after_normalization,
            )
            context.setattr(Connection, "execute", _record_normalization)
            context.setattr(
                Connection,
                "exec_driver_sql",
                _fail_rollback_to_savepoint,
            )
            context.setattr(Connection, "invalidate", _record_invalidation)
            try:
                _upgrade(path, "0005")
            except _PrimaryTraceMigrationError:
                caught_failure = True

        connection = _connect(path)
        try:
            remained_exact_parent = (
                _sqlite_catalog_contract(connection)
                == _fixed_sqlite_contract("0004")
            )
            row_unchanged = (
                connection.execute(
                    """
                    SELECT count(*), count(*) FILTER (WHERE trace_id IS NULL)
                    FROM findings
                    """
                ).fetchone()
                == (1, 1)
            )
            no_temporary_table = (
                connection.execute(
                    """
                    SELECT count(*) FROM sqlite_master
                    WHERE type='table' AND name LIKE '_alembic_tmp_%'
                    """
                ).fetchone()
                == (0,)
            )
            foreign_keys_enabled = (
                connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
            )
        finally:
            connection.close()
        remained_at_parent = _version(path) == "0004"

        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            retry_converged = (
                _sqlite_catalog_contract(connection)
                == _fixed_sqlite_contract("0005")
                and connection.execute(
                    """
                    SELECT count(*), count(*) FILTER (WHERE trace_id='')
                    FROM findings
                    """
                ).fetchone()
                == (1, 1)
            )
        finally:
            connection.close()
        _require_fixed(
            caught_failure
            and normalization_seen
            and rollback_failed
            and invalidation_seen
            and savepoint_actions == ["savepoint", "rollback"]
            and remained_exact_parent
            and row_unchanged
            and remained_at_parent
            and no_temporary_table
            and foreign_keys_enabled
            and _version(path) == "0005"
            and retry_converged,
            "revision 0005 rollback failure was not safely recoverable",
        )


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize(
    "boundary",
    ["before-hardening", "after-hardening", "version-update"],
)
def test_revision_0005_failure_boundaries_are_recoverable(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
    boundary: str,
) -> None:
    from alembic.operations import Operations

    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"0005-failure-{direction}-{boundary}") as path:
        starting_revision = "0004" if direction == "upgrade" else "0005"
        result_revision = "0005" if direction == "upgrade" else "0004"
        _upgrade(path, starting_revision)
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES(?, ?)",
                ("campaign-failure", "Synthetic campaign"),
            )
            trace_value = None if direction == "upgrade" else ""
            connection.execute(
                """
                INSERT INTO findings(
                    id, campaign_id, module_id, title,
                    description, severity, trace_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "finding-failure",
                    "campaign-failure",
                    "module",
                    "Synthetic title",
                    "Synthetic description",
                    "low",
                    trace_value,
                ),
            )
            connection.commit()
            before_rows = connection.execute(
                "SELECT count(*), count(DISTINCT title) FROM findings"
            ).fetchone()
        finally:
            connection.close()

        original_batch = Operations.batch_alter_table
        if boundary != "version-update":

            @contextmanager
            def _failing_batch(
                operations: Operations,
                table_name: str,
                *args: object,
                **kwargs: object,
            ) -> Iterator[object]:
                if (
                    table_name == "findings"
                    and boundary == "before-hardening"
                ):
                    raise RuntimeError("migration fault injection")
                with original_batch(
                    operations,
                    table_name,
                    *args,
                    **kwargs,
                ) as batch:
                    yield batch
                if (
                    table_name == "findings"
                    and boundary == "after-hardening"
                ):
                    raise RuntimeError("migration fault injection")

            monkeypatch.setattr(
                Operations,
                "batch_alter_table",
                _failing_batch,
            )
        else:
            _install_sqlite_version_failure(path)

        failed = False
        try:
            if direction == "upgrade":
                _upgrade(path, "0005")
            else:
                _downgrade(path, "0004")
        except RuntimeError:
            failed = True

        monkeypatch.setattr(
            Operations,
            "batch_alter_table",
            original_batch,
        )
        _remove_sqlite_version_failure(path)
        connection = _connect(path)
        try:
            after_failure_rows = connection.execute(
                """
                SELECT
                    count(*),
                    count(DISTINCT title),
                    count(*) FILTER (WHERE trace_id IS NULL),
                    count(*) FILTER (WHERE trace_id='')
                FROM findings
                """
            ).fetchone()
            temporary_tables = connection.execute(
                """
                SELECT count(*) FROM sqlite_master
                WHERE type='table' AND name LIKE '_alembic_tmp_%'
                """
            ).fetchone()
            foreign_keys_enabled = (
                connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
            )
        finally:
            connection.close()
        remained_at_start = _version(path) == starting_revision
        no_data_loss = (
            before_rows is not None
            and after_failure_rows is not None
            and after_failure_rows[:2] == before_rows
            and sum(after_failure_rows[2:]) == before_rows[0]
        )

        if direction == "upgrade":
            _upgrade(path, "0005")
        else:
            _downgrade(path, "0004")
        connection = _connect(path)
        try:
            recovered_contract = (
                _sqlite_catalog_contract(connection)
                == _fixed_sqlite_contract(result_revision)
            )
            sentinel_preserved = (
                connection.execute(
                    """
                    SELECT count(*), count(*) FILTER (WHERE trace_id='')
                    FROM findings
                    """
                ).fetchone()
                == (1, 1)
            )
        finally:
            connection.close()
        _require_fixed(
            failed
            and remained_at_start
            and no_data_loss
            and temporary_tables == (0,)
            and foreign_keys_enabled
            and _version(path) == result_revision
            and recovered_contract
            and sentinel_preserved,
            "revision 0005 failure boundary was not safely recoverable",
        )


@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_revision_0006_failure_after_rename_is_recoverable(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"0006-version-failure-{direction}") as path:
        starting_revision = "0005" if direction == "upgrade" else "0006"
        result_revision = "0006" if direction == "upgrade" else "0005"
        expected_column = (
            "cracked_value_enc" if direction == "upgrade" else "cracked_value"
        )
        _upgrade(path, starting_revision)
        connection = _connect(path)
        try:
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES(?, ?)",
                ("campaign-rename", "Synthetic campaign"),
            )
            source_column = (
                "cracked_value"
                if direction == "upgrade"
                else "cracked_value_enc"
            )
            connection.execute(
                f"""
                INSERT INTO credentials(
                    id, campaign_id, username, cred_type, "{source_column}"
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (
                    "credential-rename",
                    "campaign-rename",
                    "synthetic-user",
                    "password",
                    "synthetic-marker",
                ),
            )
            connection.commit()
            before_rows = connection.execute(
                "SELECT count(*) FROM credentials"
            ).fetchone()
        finally:
            connection.close()

        _install_sqlite_version_failure(path)
        failed = False
        try:
            if direction == "upgrade":
                _upgrade(path, "0006")
            else:
                _downgrade(path, "0005")
        except RuntimeError:
            failed = True
        _remove_sqlite_version_failure(path)

        connection = _connect(path)
        try:
            intermediate_columns = _column_map(
                connection,
                "credentials",
            )
            exactly_one_name = (
                ("cracked_value" in intermediate_columns)
                != ("cracked_value_enc" in intermediate_columns)
            )
            intermediate_rows = connection.execute(
                "SELECT count(*) FROM credentials"
            ).fetchone()
            temporary_tables = connection.execute(
                """
                SELECT count(*) FROM sqlite_master
                WHERE type='table' AND name LIKE '_alembic_tmp_%'
                """
            ).fetchone()
            foreign_keys_enabled = (
                connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
            )
        finally:
            connection.close()

        if direction == "upgrade":
            _upgrade(path, "0006")
        else:
            _downgrade(path, "0005")
        connection = _connect(path)
        try:
            final_contract = (
                _sqlite_catalog_contract(connection)
                == _fixed_sqlite_contract(result_revision)
            )
            value_query = (
                "SELECT count(*) FROM credentials "
                "WHERE cracked_value IS NOT NULL"
                if expected_column == "cracked_value"
                else "SELECT count(*) FROM credentials "
                "WHERE cracked_value_enc IS NOT NULL"
            )
            value_preserved = (
                connection.execute(value_query).fetchone()
                == (1,)
            )
            reusable = connection.execute("SELECT 1").fetchone() == (1,)
        finally:
            connection.close()
        _require_fixed(
            failed
            and _version(path) == result_revision
            and exactly_one_name
            and before_rows == intermediate_rows
            and temporary_tables == (0,)
            and foreign_keys_enabled
            and final_contract
            and value_preserved
            and reusable,
            "revision 0006 rename failure was not safely recoverable",
        )


def test_revision_0006_accepts_already_renamed_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database("renamed-0006") as path:
        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            connection.execute(
                "ALTER TABLE credentials "
                "RENAME COLUMN cracked_value TO cracked_value_enc"
            )
            connection.commit()
        finally:
            connection.close()
        _upgrade(path, "0006")
        reached_revision = _version(path) == "0006"
        _require_fixed(
            reached_revision,
            "revision 0006 rejected the verified target-only catalog",
        )


@pytest.mark.parametrize(
    "variant",
    ["both", "neither"],
)
def test_revision_0006_rejects_ambiguous_or_missing_catalog(
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"invalid-0006-{variant}") as path:
        _upgrade(path, "0005")
        connection = _connect(path)
        try:
            if variant == "both":
                connection.execute(
                    "ALTER TABLE credentials "
                    "ADD COLUMN cracked_value_enc TEXT"
                )
            else:
                connection.execute(
                    "ALTER TABLE credentials DROP COLUMN cracked_value"
                )
            connection.commit()
        finally:
            connection.close()
        caught: Exception | None = None
        try:
            _upgrade(path, "0006")
        except RuntimeError as error:
            caught = error
        remained_at_parent = _version(path) == "0005"
        expected_message = (
            "Ambiguous credentials catalog for migration 0006"
            if variant == "both"
            else "Incompatible credentials catalog for migration 0006"
        )
        rejected_with_fixed_revision_error = (
            type(caught) is RuntimeError
            and str(caught) == expected_message
        )
        _require_fixed(
            remained_at_parent and rejected_with_fixed_revision_error,
            "failed revision 0006 advanced the Alembic version",
        )


def _credential_catalog_fingerprint(
    connection: sqlite3.Connection,
) -> tuple[object, ...]:
    table_sql = connection.execute(
        """
        SELECT sql FROM sqlite_master
        WHERE type='table' AND name='credentials'
        """
    ).fetchone()
    columns = tuple(
        (row[1], row[2], row[3], row[4], row[5])
        for row in connection.execute('PRAGMA table_info("credentials")')
    )
    foreign_keys = tuple(
        tuple(row[2:8])
        for row in connection.execute(
            'PRAGMA foreign_key_list("credentials")'
        )
    )
    indexes = tuple(
        sorted(
            (
                row[1],
                row[2],
                row[3],
                row[4],
                tuple(
                    item[2]
                    for item in connection.execute(
                        f'PRAGMA index_info("{row[1]}")'
                    )
                ),
            )
            for row in connection.execute(
                'PRAGMA index_list("credentials")'
            )
        )
    )
    return table_sql is not None, columns, foreign_keys, indexes


def _prepare_0006_variant(
    connection: sqlite3.Connection,
    *,
    source: str,
    target: str,
    variant: str,
) -> None:
    if variant == "source-only":
        return
    if variant == "target-only":
        connection.execute(
            f'ALTER TABLE credentials RENAME COLUMN "{source}" TO "{target}"'
        )
        return
    if variant == "both":
        connection.execute(
            f'ALTER TABLE credentials ADD COLUMN "{target}" TEXT'
        )
        return
    if variant == "neither":
        connection.execute(
            f'ALTER TABLE credentials DROP COLUMN "{source}"'
        )
        return

    if variant.startswith("wrong-source-"):
        inspected = source
        scratch = "migration_0006_scratch"
        connection.execute(
            f'ALTER TABLE credentials RENAME COLUMN "{source}" TO "{scratch}"'
        )
    elif variant.startswith("wrong-target-"):
        inspected = target
        connection.execute(
            f'ALTER TABLE credentials DROP COLUMN "{source}"'
        )
    else:
        raise AssertionError("unknown revision 0006 test variant")

    if variant.endswith("-type"):
        definition = "VARCHAR(64)"
    elif variant.endswith("-nullability"):
        definition = "TEXT NOT NULL"
    elif variant.endswith("-default-empty"):
        definition = "TEXT DEFAULT ''"
    elif variant.endswith("-default"):
        definition = "TEXT DEFAULT NULL"
    else:
        raise AssertionError("unknown revision 0006 definition variant")
    connection.execute(
        f'ALTER TABLE credentials ADD COLUMN "{inspected}" {definition}'
    )
    if variant.startswith("wrong-source-"):
        connection.execute(
            'ALTER TABLE credentials DROP COLUMN "migration_0006_scratch"'
        )


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
        "wrong-source-default-empty",
        "wrong-target-type",
        "wrong-target-nullability",
        "wrong-target-default",
        "wrong-target-default-empty",
    ],
)
def test_revision_0006_exact_column_state_machine(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
    variant: str,
) -> None:
    monkeypatch.delenv("ARES_DATABASE_URL", raising=False)
    with _temporary_database(f"0006-{direction}-{variant}") as path:
        if direction == "upgrade":
            _upgrade(path, "0005")
            source = "cracked_value"
            target = "cracked_value_enc"
            parent_revision = "0005"
            result_revision = "0006"
        else:
            _upgrade(path, "0006")
            source = "cracked_value_enc"
            target = "cracked_value"
            parent_revision = "0006"
            result_revision = "0005"

        connection = _connect(path)
        try:
            _prepare_0006_variant(
                connection,
                source=source,
                target=target,
                variant=variant,
            )
            present_columns = set(_column_map(connection, "credentials"))
            value_column = (
                source
                if source in present_columns
                else target if target in present_columns else None
            )
            connection.execute(
                "INSERT INTO campaigns(id, name) VALUES(?, ?)",
                ("campaign-0006", "Migration campaign"),
            )
            if value_column is not None:
                connection.execute(
                    f"""
                    INSERT INTO credentials(
                        id, campaign_id, username, cred_type, "{value_column}"
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        "credential-0006",
                        "campaign-0006",
                        "synthetic-user",
                        "password",
                        "synthetic-marker",
                    ),
                )
            connection.commit()
            before_catalog = _credential_catalog_fingerprint(connection)
            before_rows = connection.execute(
                "SELECT count(*) FROM credentials"
            ).fetchone()
        finally:
            connection.close()

        allowed = variant in {"source-only", "target-only"}
        failed = False
        try:
            if direction == "upgrade":
                _upgrade(path, "0006")
            else:
                _downgrade(path, "0005")
        except RuntimeError:
            failed = True

        connection = _connect(path)
        try:
            after_catalog = _credential_catalog_fingerprint(connection)
            after_rows = connection.execute(
                "SELECT count(*) FROM credentials"
            ).fetchone()
            columns = _column_map(connection, "credentials")
            target_definition = columns.get(target)
            target_is_exact = (
                target_definition is not None
                and target_definition[0].upper() == "TEXT"
                and target_definition[1] == 0
                and target_definition[2] is None
            )
            if target not in columns:
                preserved = False
            elif target == "cracked_value_enc":
                preserved = (
                    connection.execute(
                        """
                        SELECT count(*) FROM credentials
                        WHERE cracked_value_enc IS NOT NULL
                        """
                    ).fetchone()
                    == (1,)
                )
            else:
                preserved = (
                    connection.execute(
                        """
                        SELECT count(*) FROM credentials
                        WHERE cracked_value IS NOT NULL
                        """
                    ).fetchone()
                    == (1,)
                )
            reusable = connection.execute("SELECT 1").fetchone() == (1,)
        finally:
            connection.close()

        if allowed:
            accepted = (
                not failed
                and _version(path) == result_revision
                and source not in columns
                and target_is_exact
                and preserved
                and reusable
            )
            _require_fixed(
                accepted,
                "revision 0006 rejected a valid exact catalog",
            )
        else:
            rejected_atomically = (
                failed
                and _version(path) == parent_revision
                and before_catalog == after_catalog
                and before_rows == after_rows
                and reusable
            )
            _require_fixed(
                rejected_atomically,
                "revision 0006 changed an incompatible catalog",
            )
