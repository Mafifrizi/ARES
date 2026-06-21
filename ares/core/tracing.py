"""
ARES OpenTelemetry Distributed Tracing — v3.1.0 (canonical)

Single source of truth for all tracing in ARES.
Replaces ares/telemetry/tracing.py (deleted — this file is the merge target).

Provides trace ID correlation from:
    HTTP request → engine → module execution → outgoing HTTP

Features:
    - OTLP gRPC exporter (Jaeger / Grafana Tempo / OTLP-compatible)
    - Console exporter for local dev (ARES_OTEL_CONSOLE=true)
    - FastAPI auto-instrumentation (per-request spans with route + status)
    - @trace_module() decorator — wraps module run() in a child span
    - span() / async_span() context managers for inline spans
    - inject_trace_context() — W3C traceparent header for outgoing calls
    - TraceIDLogFilter — injects trace_id + span_id into every loguru record
    - X-Trace-Id response header set by server middleware
    - Full NoOp fallback — zero overhead when opentelemetry not installed

Environment variables:
    ARES_OTEL_ENDPOINT    — OTLP gRPC endpoint (e.g. http://jaeger:4317)
    ARES_OTEL_SERVICE     — Service name shown in trace UI (default: ares-api)
    ARES_OTEL_SAMPLE_RATE — 0.0–1.0 sampling rate (default: 1.0 = 100%)
    ARES_OTEL_CONSOLE     — also print spans to stdout (dev mode, default: false)

Usage:

    # Decorator (preferred for module run() methods):
    @trace_module("ad.kerberoast")
    async def run(self, dc, domain, ...):
        ...

    # Inline span:
    async with async_span("ad.kerberoast.tgs_request", {"dc": dc}):
        tickets = await request_tgs(...)

    # Inject into outgoing request headers:
    headers = inject_trace_context({})
    await httpx.get(url, headers=headers)
"""
from __future__ import annotations

import functools
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Callable, Generator

from ares.core.logger import get_logger

logger = get_logger("ares.core.tracing")


# ── Optional dependency guard ─────────────────────────────────────────────────

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.trace import StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


# ── NoOp implementations (used when OTel not installed or not configured) ─────

class _NoOpSpan:
    """
    Context-manager no-op span — identical public API to real OTel span.
    Used when opentelemetry-sdk is not installed. All methods are intentional
    no-ops (pass) that satisfy the interface contract without side effects.
    """
    def set_attribute(self, key: str, value: Any) -> None:    pass  # no-op by design
    def set_status(self, *a: Any, **kw: Any) -> None:         pass  # no-op by design
    def record_exception(self, exc: Exception, **kw: Any) -> None: pass  # no-op by design
    def add_event(self, name: str, attributes: dict | None = None) -> None: pass  # no-op by design
    def get_span_context(self) -> None:                       return None
    def __enter__(self) -> "_NoOpSpan":                       return self
    def __exit__(self, *a: Any) -> None:                      pass  # no-op by design


class _NoOpTracer:
    def start_as_current_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()
    def start_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()


_NOOP_TRACER = _NoOpTracer()
_provider: Any = None
_tracer:   Any = None


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup_tracing(
    service_name:  str   = "ares-api",
    otel_endpoint: str   = "",
    sample_rate:   float = 1.0,
    console:       bool  = False,
) -> bool:
    """
    Initialize OTel tracing. Returns True if successfully configured.
    Safe to call multiple times — subsequent calls are no-ops.
    Called automatically from server.py lifespan.
    """
    global _provider, _tracer

    if not _OTEL_AVAILABLE:
        logger.info("otel_disabled", reason="opentelemetry-sdk not installed")
        return False

    if _provider is not None:
        return True  # Already configured

    if not otel_endpoint and not console:
        logger.info("otel_disabled",
                    reason="Set ARES_OTEL_ENDPOINT or ARES_OTEL_CONSOLE=true to enable")
        return False

    try:
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
        resource  = Resource(attributes={SERVICE_NAME: service_name})
        sampler   = TraceIdRatioBased(sample_rate)
        _provider = TracerProvider(resource=resource, sampler=sampler)

        if console:
            _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
            logger.info("otel_console_exporter_active")

        if otel_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(endpoint=otel_endpoint, insecure=True)
                _provider.add_span_processor(BatchSpanProcessor(exporter))
                logger.info("otel_otlp_exporter_active", endpoint=otel_endpoint)
            except ImportError:
                logger.warning("otel_grpc_exporter_missing",
                               hint="pip install opentelemetry-exporter-otlp-proto-grpc")

        trace.set_tracer_provider(_provider)
        _tracer = trace.get_tracer(
            "ares",
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        logger.info("otel_configured", service=service_name, sample_rate=sample_rate)
        return True

    except Exception as exc:
        logger.warning("otel_setup_failed", error=str(exc)[:200])
        return False


def instrument_fastapi(app: Any) -> None:
    """Auto-instrument FastAPI app: one span per request with route + status code."""
    if not _OTEL_AVAILABLE:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(
            app,
            excluded_urls="/health,/metrics",
        )
        logger.debug("otel_fastapi_instrumented")
    except ImportError:
        logger.debug("otel_fastapi_instrumentor_missing",
                     hint="pip install opentelemetry-instrumentation-fastapi")
    except Exception as exc:
        logger.warning("otel_fastapi_instrument_failed", error=str(exc)[:100])


# ── Accessors ─────────────────────────────────────────────────────────────────

def get_tracer() -> Any:
    """Return the configured tracer (or NoOp if tracing not active)."""
    if _tracer is not None:
        return _tracer
    if _OTEL_AVAILABLE:
        return trace.get_tracer("ares")
    return _NOOP_TRACER


def get_current_trace_id() -> str | None:
    """Return 32-char hex trace ID of the current span, or None."""
    if not _OTEL_AVAILABLE:
        return None
    try:
        ctx = trace.get_current_span().get_span_context()
        if ctx and ctx.trace_id and ctx.trace_id != 0:
            return format(ctx.trace_id, "032x")
    except (AttributeError, TypeError):
        pass
    return None


# Alias used by legacy telemetry/tracing.py callers
current_trace_id = get_current_trace_id


def get_current_span_id() -> str | None:
    """Return 16-char hex span ID of the current span, or None."""
    if not _OTEL_AVAILABLE:
        return None
    try:
        ctx = trace.get_current_span().get_span_context()
        if ctx and ctx.span_id:
            return format(ctx.span_id, "016x")
    except (AttributeError, TypeError):
        pass
    return None


# Alias
current_span_id = get_current_span_id


def inject_trace_context(headers: dict[str, str]) -> dict[str, str]:
    """
    Inject W3C traceparent header into outgoing HTTP request headers.
    Use this when making HTTP calls from within a traced span so
    downstream services can continue the trace.
    """
    if not _OTEL_AVAILABLE:
        return headers
    try:
        ctx = trace.get_current_span().get_span_context()
        if ctx and ctx.is_valid:
            headers["traceparent"] = (
                f"00-{format(ctx.trace_id, '032x')}"
                f"-{format(ctx.span_id, '016x')}"
                f"-{'01' if ctx.trace_flags else '00'}"
            )
    except (AttributeError, TypeError, ValueError):
        pass
    return headers


# ── Span context managers (inline use) ───────────────────────────────────────

@contextmanager
def span(
    name:       str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """
    Sync context manager for a child span.

    Usage:
        with tracing.span("ad.ldap_query", {"dc": dc, "domain": domain}):
            results = ldap_search(...)
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as s:
        if attributes:
            _set_span_attrs(s, attributes)
        try:
            yield s
        except Exception as exc:
            _mark_span_error(s, exc)
            raise


@asynccontextmanager
async def async_span(
    name:       str,
    attributes: dict[str, Any] | None = None,
) -> AsyncGenerator[Any, None]:
    """
    Async context manager for a child span.

    Usage:
        async with tracing.async_span("engine.run_module", {"module_id": mid}):
            result = await engine.run_module(...)
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as s:
        if attributes:
            _set_span_attrs(s, attributes)
        try:
            yield s
        except Exception as exc:
            _mark_span_error(s, exc)
            raise


def _set_span_attrs(s: Any, attrs: dict[str, Any]) -> None:
    for k, v in attrs.items():
        try:
            v = v if isinstance(v, (bool, int, float, str)) else str(v)
            s.set_attribute(k, v)
        except (TypeError, AttributeError):
            pass


def _mark_span_error(s: Any, exc: Exception) -> None:
    try:
        if _OTEL_AVAILABLE:
            s.set_status(StatusCode.ERROR, str(exc))
            s.record_exception(exc)
    except (AttributeError, TypeError):
        pass


# ── @trace_module decorator ───────────────────────────────────────────────────

def trace_module(module_id: str) -> Callable:
    """
    Decorator that wraps a module's run() method in a named OTel span.

    Apply to the run() method of every BaseModule subclass:

        class KerberoastModule(BaseModule):
            MODULE_ID = "ad.kerberoast"

            @trace_module("ad.kerberoast")
            async def run(self, dc, domain, ...):
                ...

    The span automatically records:
        ares.module_id      — module identifier
        ares.campaign_id    — campaign ID (from self.campaign.id if available)
        ares.findings_count — count of findings returned
        ares.status         — "success" or "error"
        error details       — exception type + message on failure
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer    = get_tracer()
            span_name = f"ares.module.{module_id}"
            with tracer.start_as_current_span(span_name) as s:
                s.set_attribute("ares.module_id", module_id)
                campaign_id = getattr(getattr(self, "campaign", None), "id", "")
                if campaign_id:
                    s.set_attribute("ares.campaign_id", str(campaign_id))

                try:
                    result = await fn(self, *args, **kwargs)
                    findings, raw = result
                    s.set_attribute("ares.findings_count", len(findings))
                    s.set_attribute("ares.status", "success")
                    if _OTEL_AVAILABLE:
                        s.set_status(StatusCode.OK)
                    return result

                except Exception as exc:
                    s.set_attribute("ares.status", "error")
                    s.set_attribute("ares.error_type", type(exc).__name__)
                    s.set_attribute("ares.error_msg", str(exc)[:300])
                    _mark_span_error(s, exc)
                    raise

        return wrapper
    return decorator


def record_module_event(
    span: Any,
    module_id: str,
    event: str,
    attrs: dict[str, Any] | None = None,
) -> None:
    """Record a named event on the current span (milestones within a module run)."""
    try:
        all_attrs = {"module_id": module_id, **(attrs or {})}
        span.add_event(event, attributes={str(k): str(v) for k, v in all_attrs.items()})
    except (AttributeError, TypeError, ValueError):
        pass


# ── Loguru integration ────────────────────────────────────────────────────────

class TraceIDLogFilter:
    """
    Loguru filter that injects trace_id + span_id into every log record.
    Add to your loguru sink so every log line carries trace context.

    Usage in logger setup (e.g. ares/core/logger.py):
        logger.add(sys.stderr, filter=TraceIDLogFilter(), format=TRACE_LOG_FORMAT)
    """
    def __call__(self, record: dict) -> bool:
        record["extra"].setdefault("trace_id", get_current_trace_id() or "—")
        record["extra"].setdefault("span_id",  get_current_span_id()  or "—")
        return True


TRACE_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{line}</cyan> | "
    "trace={extra[trace_id]} span={extra[span_id]} | "
    "<level>{message}</level>"
)


# ── Convenience: init from AresSettings ──────────────────────────────────────

def init_from_settings() -> None:
    """Read tracing settings from AresSettings and call setup_tracing()."""
    try:
        from ares.core.config import get_settings
        s = get_settings()
        setup_tracing(
            service_name  = getattr(s, "ares_otel_service",     "ares-api"),
            otel_endpoint = getattr(s, "ares_otel_endpoint",    ""),
            sample_rate   = getattr(s, "ares_otel_sample_rate", 1.0),
            console       = getattr(s, "ares_otel_console",     False),
        )
    except Exception as exc:
        logger.warning("otel_init_from_settings_failed", error=str(exc)[:100])
