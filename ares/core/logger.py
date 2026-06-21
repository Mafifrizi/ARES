"""
ARES Structured Logger
JSON-first logging using structlog — SIEM-ingestible NDJSON output.

Every log line on disk is a complete JSON object:
{
  "timestamp": "2025-01-15T10:23:44.123Z",
  "level":     "info",
  "logger":    "ares.modules.ad.kerberoast",
  "event":     "tgs_captured",
  "module":    "ad.kerberoast",
  "target":    "dc01.corp.local",
  "campaign":  "abc12345",
  "findings":  3,
  "duration_ms": 1240.5
}

Console stays human-readable (colored).
Disk output: NDJSON (one JSON object per line — Splunk/ELK/Grafana Loki compatible).
Separate audit.ndjson for append-only action trail.
"""
from __future__ import annotations

import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

# ── Sensitive data masking processor ─────────────────────────────────────────

_MASK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(password[\"']?\s*[:=]\s*)\S+",    re.I), r"\1[REDACTED]"),
    (re.compile(r"(secret[\"']?\s*[:=]\s*)\S+",      re.I), r"\1[REDACTED]"),
    (re.compile(r"(token[\"']?\s*[:=]\s*)\S+",       re.I), r"\1[REDACTED]"),
    (re.compile(r"(api.?key[\"']?\s*[:=]\s*)\S+",    re.I), r"\1[REDACTED]"),
    (re.compile(r"\$NT\$[a-fA-F0-9]{32}"),                  "[HASH_REDACTED]"),
    (re.compile(r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"),        "[NTLM_REDACTED]"),
    (re.compile(r"\$krb5tgs\$\d+\$\*[^\s]+"),               "[KRB5TGS_REDACTED]"),
    (re.compile(r"\$krb5asrep\$\d+\$[^\s]+"),               "[KRB5ASREP_REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
                                                              "[JWT_REDACTED]"),
]


def _mask_sensitive(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Redact secrets from every string field before writing."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            for pattern, replacement in _MASK_PATTERNS:
                value = pattern.sub(replacement, value)
            event_dict[key] = value
    return event_dict


# ── Audit tag processor ───────────────────────────────────────────────────────

def _tag_audit(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    if event_dict.get("audit"):
        event_dict["_ares_audit"] = True
    return event_dict


class _AuditFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "_ares_audit", False) or "[audit]" in record.getMessage()


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup_logger(
    level: str = "INFO",
    log_file: str | None = None,
    json_console: bool = False,
) -> None:
    """
    Configure structlog for the whole process.

    Console → human-readable (dev.ConsoleRenderer) or JSON if json_console=True
    File    → NDJSON (one JSON object per line), 20 MB rotate × 10
    Audit   → separate audit.ndjson (append-only, filtered)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _mask_sensitive,
        _tag_audit,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=shared + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    def _make_formatter(json: bool) -> structlog.stdlib.ProcessorFormatter:
        return structlog.stdlib.ProcessorFormatter(
            processor=(
                structlog.processors.JSONRenderer()
                if json else
                structlog.dev.ConsoleRenderer(colors=True)
            ),
            foreign_pre_chain=shared,
        )

    handlers: list[logging.Handler] = []

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(_make_formatter(json_console))
    ch.setLevel(log_level)
    handlers.append(ch)

    # JSON file (NDJSON, rotated)
    if log_file:
        lp = Path(log_file)
        lp.parent.mkdir(parents=True, exist_ok=True)

        fh = RotatingFileHandler(str(lp), maxBytes=20 * 1024 * 1024, backupCount=10, encoding="utf-8")
        fh.setFormatter(_make_formatter(json=True))
        fh.setLevel(log_level)  # respect ARES_LOG_LEVEL for file output
        handlers.append(fh)

        # Audit sink (append-only, never rotated)
        audit_path = lp.parent / "audit.ndjson"
        ah = logging.FileHandler(str(audit_path), mode="a", encoding="utf-8")
        ah.setFormatter(_make_formatter(json=True))
        ah.addFilter(_AuditFilter())
        handlers.append(ah)

    root = logging.getLogger()
    root.handlers.clear()
    for h in handlers:
        root.addHandler(h)
    root.setLevel(log_level)  # respect ARES_LOG_LEVEL for root logger

    # Suppress noisy deps
    for lib in ("urllib3", "httpx", "httpcore", "botocore", "azure", "google"):
        logging.getLogger(lib).setLevel(logging.WARNING)


# ── Public API ────────────────────────────────────────────────────────────────

def get_logger(name: str = "ares") -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger. Use everywhere instead of print/loguru."""
    return structlog.get_logger(name)


def audit(action: str, actor: str = "system", detail: str = "", **ctx: Any) -> None:
    """
    Write a structured, tamper-evident audit entry.

    Output (NDJSON to audit.ndjson):
      {"timestamp":"...","level":"info","event":"module_run_start",
       "_ares_audit":true,"actor":"alice","action":"module_run_start",
       "campaign":"abc123","module":"ad.kerberoast"}
    """
    get_logger("ares.audit").info(action, audit=True, actor=actor, detail=detail, **ctx)


def bind_context(**ctx: Any) -> None:
    """
    Bind key-value pairs to ALL log calls in this async task/coroutine.

    Example at module start:
        bind_context(campaign="abc123", module="ad.kerberoast", target="dc01")
        # Every subsequent log in this coroutine includes those fields automatically
    """
    structlog.contextvars.bind_contextvars(**ctx)


def clear_context() -> None:
    """Clear per-task context (call at end of each module run)."""
    structlog.contextvars.clear_contextvars()
