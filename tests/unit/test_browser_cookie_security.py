"""Deterministic browser-cookie, Origin, and CSRF boundary tests."""
from __future__ import annotations

import base64
import io
import json
import threading
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType, SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ares.core.browser_sessions import (
    DEVELOPMENT_CSRF_COOKIE,
    DEVELOPMENT_REFRESH_COOKIE,
    MAX_REFRESH_COOKIE_AGE_SECONDS,
    PRELOGIN_CSRF_LIFETIME_SECONDS,
    PRODUCTION_CSRF_COOKIE,
    PRODUCTION_REFRESH_COOKIE,
    BrowserRequestContext,
    BrowserSessionBoundaryMiddleware,
    BrowserSessionConfigurationError,
    build_browser_session_policy,
    canonical_noncredentialed_origins,
    clear_session_cookies,
    generate_csrf_token,
    is_canonical_csrf_token,
    is_canonical_refresh_token,
    publish_prelogin_csrf,
    publish_session_cookies,
    remaining_cookie_seconds,
)
from scripts.validation_lab import (
    ApiClient,
    ApiResult,
    ValidationLabError,
    _fail,
    build_parser,
    run_lab,
)


def _settings(*, debug: bool, origin: str, trusted: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        ares_debug=debug,
        ares_browser_origin=origin,
        trusted_hosts_list=list(trusted),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _cookie_flags(response: Response) -> list[dict[str, bool]]:
    rows: list[dict[str, bool]] = []
    for value in response.headers.getlist("set-cookie"):
        lowered = value.lower()
        rows.append(
            {
                "host_refresh": value.startswith(f"{PRODUCTION_REFRESH_COOKIE}="),
                "host_csrf": value.startswith(f"{PRODUCTION_CSRF_COOKIE}="),
                "dev_refresh": value.startswith(f"{DEVELOPMENT_REFRESH_COOKIE}="),
                "dev_csrf": value.startswith(f"{DEVELOPMENT_CSRF_COOKIE}="),
                "secure": "; secure" in lowered,
                "httponly": "; httponly" in lowered,
                "strict": "samesite=strict" in lowered,
                "root": "path=/" in lowered,
                "domain": "domain=" in lowered,
                "cleared": "max-age=0" in lowered,
            }
        )
    return rows


def test_csrf_generation_is_canonical_and_unique() -> None:
    first = generate_csrf_token()
    second = generate_csrf_token()
    _require(is_canonical_csrf_token(first), "CSRF token was not canonical.")
    _require(is_canonical_csrf_token(second), "Second CSRF token was not canonical.")
    _require(first != second, "CSRF tokens were not independently generated.")


@pytest.mark.parametrize(
    "value",
    ["", "a" * 42, "a" * 44, "a" * 42 + "=", "a" * 42 + "%"],
)
def test_csrf_rejects_noncanonical_values(value: str) -> None:
    _require(not is_canonical_csrf_token(value), "Malformed CSRF value was accepted.")


def test_refresh_token_shape_is_exact() -> None:
    _require(is_canonical_refresh_token("a" * 64), "Canonical refresh shape rejected.")
    _require(not is_canonical_refresh_token("a" * 63), "Short refresh shape accepted.")


def test_production_policy_is_host_only_secure() -> None:
    policy = build_browser_session_policy(
        _settings(debug=False, origin="https://ares.example", trusted=("ares.example",))
    )
    _require(policy.refresh_cookie_name == PRODUCTION_REFRESH_COOKIE, "Wrong refresh cookie name.")
    _require(policy.csrf_cookie_name == PRODUCTION_CSRF_COOKIE, "Wrong CSRF cookie name.")
    _require(policy.secure, "Production cookie policy was not secure.")


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "http://ares.example",
        "https://ares.example/unsafe",
        "https://ares.example.",
        "null",
        "https://user@ares.example",
        "https://ares.example,https://other.example",
    ],
)
def test_production_policy_rejects_invalid_origins(origin: str) -> None:
    with pytest.raises(BrowserSessionConfigurationError, match="configuration invalid"):
        build_browser_session_policy(
            _settings(debug=False, origin=origin, trusted=("ares.example",))
        )


@pytest.mark.parametrize(
    ("origin", "host"),
    [("http://localhost:5173", "localhost"), ("http://127.0.0.1:5173", "127.0.0.1")],
)
def test_debug_policy_accepts_only_fixed_loopback(origin: str, host: str) -> None:
    policy = build_browser_session_policy(
        _settings(debug=True, origin=origin, trusted=(host,))
    )
    _require(not policy.secure, "Debug policy unexpectedly required Secure.")
    _require(policy.refresh_cookie_name == DEVELOPMENT_REFRESH_COOKIE, "Wrong debug refresh name.")


def test_debug_policy_rejects_nonloopback_host() -> None:
    with pytest.raises(BrowserSessionConfigurationError, match="configuration invalid"):
        build_browser_session_policy(
            _settings(debug=True, origin="http://localhost:5173", trusted=("example.test",))
        )


def test_noncredentialed_cors_origins_are_exact() -> None:
    values = canonical_noncredentialed_origins(
        ["http://localhost:3000", "https://integration.example"]
    )
    _require(len(values) == 2, "Exact CORS origins were not retained.")


@pytest.mark.parametrize("origin", ["*", "null", "https://example.test/path", "https://example.test,"])
def test_noncredentialed_cors_rejects_unsafe_values(origin: str) -> None:
    with pytest.raises(BrowserSessionConfigurationError, match="configuration invalid"):
        canonical_noncredentialed_origins([origin])


def test_remaining_cookie_lifetime_is_clamped() -> None:
    now = datetime.now(timezone.utc)
    long_lived = remaining_cookie_seconds(now + timedelta(days=60), now=now)
    expired = remaining_cookie_seconds(now - timedelta(seconds=1), now=now)
    _require(long_lived == MAX_REFRESH_COOKIE_AGE_SECONDS, "Cookie lifetime was not clamped.")
    _require(expired == 0, "Expired family produced a cookie lifetime.")


def test_prelogin_cookie_has_fixed_lifetime_and_no_refresh_cookie() -> None:
    policy = build_browser_session_policy(
        _settings(debug=False, origin="https://ares.example", trusted=("ares.example",))
    )
    response = Response()
    publish_prelogin_csrf(response, policy)
    flags = _cookie_flags(response)
    header = response.headers.getlist("set-cookie")[0].lower()
    _require(len(flags) == 1 and flags[0]["host_csrf"], "Prelogin CSRF cookie missing.")
    _require(not flags[0]["httponly"], "CSRF cookie was not browser-readable.")
    _require(f"max-age={PRELOGIN_CSRF_LIFETIME_SECONDS}" in header, "Wrong prelogin lifetime.")


def test_production_session_cookie_attributes_are_exact() -> None:
    policy = build_browser_session_policy(
        _settings(debug=False, origin="https://ares.example", trusted=("ares.example",))
    )
    response = Response()
    published = publish_session_cookies(
        response,
        policy,
        refresh_token="a" * 64,
        absolute_expiry=datetime.now(timezone.utc) + timedelta(days=30),
    )
    flags = _cookie_flags(response)
    _require(published and len(flags) == 2, "Session cookies were not both published.")
    secure = all(row["secure"] and row["strict"] and row["root"] for row in flags)
    _require(secure, "Cookie security attributes differ.")
    _require(all(not row["domain"] for row in flags), "A Domain attribute was emitted.")
    _require(sum(row["httponly"] for row in flags) == 1, "HttpOnly boundary is incorrect.")


def test_expired_family_publishes_no_cookie() -> None:
    policy = build_browser_session_policy(
        _settings(debug=False, origin="https://ares.example", trusted=("ares.example",))
    )
    response = Response()
    published = publish_session_cookies(
        response,
        policy,
        refresh_token="a" * 64,
        absolute_expiry=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    absent = not published and not response.headers.getlist("set-cookie")
    _require(absent, "Expired cookie was published.")


@pytest.mark.parametrize("debug", [False, True])
def test_cookie_clearing_matches_creation_policy(debug: bool) -> None:
    origin = "http://localhost:5173" if debug else "https://ares.example"
    host = "localhost" if debug else "ares.example"
    policy = build_browser_session_policy(
        _settings(debug=debug, origin=origin, trusted=(host,))
    )
    response = Response()
    clear_session_cookies(response, policy)
    flags = _cookie_flags(response)
    _require(len(flags) == 2 and all(row["cleared"] for row in flags), "Cookies were not cleared.")
    _require(all(row["secure"] is (not debug) for row in flags), "Clear security flag differed.")


def _boundary_app() -> Starlette:
    async def _endpoint(request: Request) -> JSONResponse:
        context = getattr(request.state, "browser_session", None)
        safe = (
            isinstance(context, BrowserRequestContext)
            and request.scope.get("query_string") == b""
            and not any(key.lower() == b"cookie" for key, _ in request.scope["headers"])
            and not any(key.lower() == b"origin" for key, _ in request.scope["headers"])
        )
        return JSONResponse({"safe": safe})

    app = Starlette(
        routes=[
            Route("/auth/csrf", _endpoint, methods=["GET"]),
            Route("/auth/token", _endpoint, methods=["POST"]),
            Route("/auth/refresh", _endpoint, methods=["POST"]),
            Route("/auth/logout", _endpoint, methods=["POST"]),
            Route("/auth/logout-all", _endpoint, methods=["POST"]),
        ]
    )
    settings = _settings(
        debug=True,
        origin="http://localhost:5173",
        trusted=("localhost", "127.0.0.1"),
    )
    app.add_middleware(
        BrowserSessionBoundaryMiddleware,
        settings_provider=lambda: settings,
    )
    return app


def _boundary_headers() -> dict[str, str]:
    return {
        "Origin": "http://localhost:5173",
        "Sec-Fetch-Site": "same-origin",
        "X-ARES-CSRF": "A" * 43,
        "Cookie": f"ares-dev-csrf={'A' * 43}; ares-dev-refresh={'r' * 64}",
    }


@pytest.mark.asyncio
async def test_boundary_scrubs_query_cookie_and_origin_before_handler() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.post("/auth/refresh", headers=_boundary_headers())
    _require(response.status_code == 200, "Canonical boundary request failed.")
    _require(response.json().get("safe") is True, "Sensitive scope was not scrubbed.")


@pytest.mark.asyncio
async def test_uvicorn_access_logging_receives_only_scrubbed_auth_scope() -> None:
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    import h11
    from uvicorn.protocols.http.h11_impl import RequestResponseCycle

    marker = "Z" * 43
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "server": ("localhost", 5173),
        "client": ("127.0.0.1", 41000),
        "scheme": "http",
        "method": "GET",
        "root_path": "",
        "path": "/auth/csrf",
        "raw_path": b"/auth/csrf",
        "query_string": f"legacy={marker}".encode("ascii"),
        "headers": (
            (b"host", b"localhost:5173"),
            (b"cookie", f"unrelated={marker}".encode("ascii")),
        ),
        "state": {},
    }
    received = False

    async def _receive() -> dict[str, object]:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[dict[str, object]] = []

    async def _send(message: dict[str, object]) -> None:
        sent.append(message)

    await BrowserSessionBoundaryMiddleware(
        _boundary_app(),
        settings_provider=lambda: _settings(
            debug=True,
            origin="http://localhost:5173",
            trusted=("localhost", "127.0.0.1"),
        ),
    )(scope, _receive, _send)

    access_logger = MagicMock()
    flow = MagicMock(write_paused=False)
    flow.drain = AsyncMock()
    transport = MagicMock()
    cycle = RequestResponseCycle(
        scope=scope,
        conn=h11.Connection(h11.SERVER),
        transport=transport,
        flow=flow,
        logger=MagicMock(),
        access_logger=access_logger,
        access_log=True,
        default_headers=[],
        message_event=asyncio.Event(),
        on_response=MagicMock(),
    )
    await cycle.send({"type": "http.response.start", "status": 400, "headers": []})
    logged = access_logger.info.call_args.args
    reduced = (
        bool(sent),
        scope["query_string"] == b"",
        not any(key.lower() == b"cookie" for key, _ in scope["headers"]),
        marker not in "".join(str(value) for value in logged),
    )
    del logged, marker
    _require(all(reduced), "Uvicorn observed unsanitized browser-auth scope.")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/auth/token", "/auth/refresh", "/auth/logout", "/auth/logout-all"],
)
async def test_boundary_rejects_missing_origin(path: str) -> None:
    headers = _boundary_headers()
    del headers["Origin"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.post(path, headers=headers)
    _require(response.status_code == 403, "Missing Origin was accepted.")


@pytest.mark.asyncio
async def test_csrf_bootstrap_allows_missing_origin_on_same_host() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.get("/auth/csrf")
    _require(response.status_code == 200, "Same-origin CSRF bootstrap was rejected.")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "untrusted-origin",
        "null-origin",
        "host-mismatch",
        "cross-site",
        "missing-csrf",
        "mismatched-csrf",
    ],
)
async def test_boundary_rejects_invalid_origin_host_and_csrf(mutation: str) -> None:
    headers = _boundary_headers()
    base_url = "http://localhost:5173"
    if mutation == "untrusted-origin":
        headers["Origin"] = "https://untrusted.example"
    elif mutation == "null-origin":
        headers["Origin"] = "null"
    elif mutation == "host-mismatch":
        base_url = "http://127.0.0.1:5173"
    elif mutation == "cross-site":
        headers["Sec-Fetch-Site"] = "cross-site"
    elif mutation == "missing-csrf":
        del headers["X-ARES-CSRF"]
    else:
        headers["X-ARES-CSRF"] = "B" * 43
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url=base_url,
    ) as client:
        response = await client.post("/auth/refresh", headers=headers)
    _require(response.status_code == 403, "Invalid browser boundary was accepted.")


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["query", "body", "header", "authorization"])
async def test_refresh_rejects_every_legacy_transport(transport: str) -> None:
    headers = _boundary_headers()
    path = "/auth/refresh"
    content: bytes | None = None
    if transport == "query":
        path += "?refresh_token=legacy"
    elif transport == "body":
        content = b"{}"
    elif transport == "header":
        headers["X-Refresh-Token"] = "legacy"
    else:
        headers["Authorization"] = "Bearer legacy"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.post(path, headers=headers, content=content)
    _require(response.status_code == 400, "Legacy refresh transport was accepted.")


@pytest.mark.asyncio
async def test_boundary_rejects_duplicate_canonical_cookie() -> None:
    headers = _boundary_headers()
    headers["Cookie"] += f"; ares-dev-refresh={'s' * 64}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.post("/auth/refresh", headers=headers)
    _require(response.status_code == 403, "Duplicate refresh cookie was accepted.")


@pytest.mark.asyncio
async def test_boundary_rejects_duplicate_origin_header() -> None:
    pairs = list(_boundary_headers().items())
    pairs.append(("Origin", "http://localhost:5173"))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_boundary_app()),
        base_url="http://localhost:5173",
    ) as client:
        response = await client.post("/auth/refresh", headers=pairs)
    _require(response.status_code == 403, "Duplicate Origin was accepted.")


_LAB_CSRF_INITIAL = "A" * 43
_LAB_CSRF_ROTATED = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode("ascii")
_LAB_REFRESH = "r" * 64
_LAB_ACCESS = "t" * 64


@contextmanager
def _validation_lab_server(mode: str = "normal") -> Any:
    state: dict[str, Any] = {"events": [], "checks": []}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

        def _empty(self, status: int, cookies: tuple[str, ...] = ()) -> None:
            self.send_response(status)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            path_ok = self.path == "/auth/csrf"
            origin_ok = self.headers.get_all("Origin", failobj=[]) == [
                "http://127.0.0.1:5173"
            ]
            state["events"].append("csrf")
            state["checks"].append(path_ok and origin_ok)
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "/auth/token")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if mode == "missing":
                self._empty(204)
                return
            if mode == "malformed":
                self._empty(204, ("ares-dev-csrf=short; Path=/; SameSite=Strict",))
                return
            if mode == "duplicate":
                self._empty(
                    204,
                    (
                        f"ares-dev-csrf={_LAB_CSRF_INITIAL}; Path=/; SameSite=Strict",
                        f"ares-dev-csrf={_LAB_CSRF_ROTATED}; Path=/auth; SameSite=Strict",
                    ),
                )
                return
            self._empty(
                204,
                (f"ares-dev-csrf={_LAB_CSRF_INITIAL}; Path=/; SameSite=Strict",),
            )

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            origin_ok = self.headers.get_all("Origin", failobj=[]) == [
                "http://127.0.0.1:5173"
            ]
            csrf_values = self.headers.get_all("X-ARES-CSRF", failobj=[])
            cookie_values = self.headers.get_all("Cookie", failobj=[])
            auth_values = self.headers.get_all("Authorization", failobj=[])
            forbidden_refresh_header = any(
                self.headers.get_all(name, failobj=[])
                for name in ("Refresh-Token", "X-Refresh-Token", "X-ARES-Refresh-Token")
            )
            if self.path == "/auth/token":
                form = parse_qs(body.decode("ascii"), strict_parsing=True)
                form_ok = set(form) == {"username", "password"} and all(
                    len(values) == 1 for values in form.values()
                )
                checks = (
                    origin_ok,
                    csrf_values == [_LAB_CSRF_INITIAL],
                    len(cookie_values) == 1
                    and _LAB_CSRF_INITIAL in cookie_values[0],
                    not auth_values,
                    not forbidden_refresh_header,
                    form_ok,
                    "?" not in self.path,
                )
                state["events"].append("login")
                state["checks"].extend(checks)
                payload = {
                    "access_token": _LAB_ACCESS,
                    "token_type": "bearer",
                    "refresh_generation": 0,
                    "session_coordination_key": "c" * 43,
                }
                encoded = json.dumps(payload).encode("ascii")
                self.send_response(200)
                self.send_header(
                    "Set-Cookie",
                    f"ares-dev-refresh={_LAB_REFRESH}; Path=/; HttpOnly; SameSite=Strict",
                )
                self.send_header(
                    "Set-Cookie",
                    f"ares-dev-csrf={_LAB_CSRF_ROTATED}; Path=/; SameSite=Strict",
                )
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            elif self.path == "/auth/logout":
                checks = (
                    origin_ok,
                    csrf_values == [_LAB_CSRF_ROTATED],
                    len(cookie_values) == 1
                    and _LAB_CSRF_ROTATED in cookie_values[0]
                    and _LAB_REFRESH in cookie_values[0],
                    not auth_values,
                    not forbidden_refresh_header,
                    body == b"",
                    "?" not in self.path,
                )
                state["events"].append("logout")
                state["checks"].extend(checks)
                self._empty(204)
            else:
                state["events"].append("unexpected")
                self._empty(404)
            del body, cookie_values, csrf_values, auth_values

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 5173), Handler)
    except OSError:
        pytest.fail("Validation-lab loopback listener was unavailable.", pytrace=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        state["settled"] = not thread.is_alive()


def test_validation_lab_client_uses_csrf_cookie_rotation_and_logout() -> None:
    with _validation_lab_server() as state:
        client = ApiClient(
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5173",
        )
        client.login("canary-user", "canary-password")
        access_in_memory = client.access_token == _LAB_ACCESS
        client.logout()
        cleared = client.access_token is None
    reduced = (
        state["events"] == ["csrf", "login", "logout"],
        all(state["checks"]),
        access_in_memory,
        cleared,
        state["settled"],
    )
    _require(all(reduced), "Validation-lab browser session sequence differed.")


@pytest.mark.parametrize("mode", ["missing", "duplicate", "malformed"])
def test_validation_lab_rejects_invalid_csrf_cookie_sets(mode: str) -> None:
    with _validation_lab_server(mode):
        client = ApiClient(
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5173",
        )
        with pytest.raises(ValidationLabError, match="csrf-cookie-invalid"):
            client.bootstrap_csrf()


def test_validation_lab_authentication_redirect_fails_closed() -> None:
    with _validation_lab_server("redirect") as state:
        client = ApiClient(
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5173",
        )
        with pytest.raises(ValidationLabError, match="request-status:status-302"):
            client.bootstrap_csrf()
    _require(state["events"] == ["csrf"], "Authentication redirect was followed.")
    _require(state["settled"], "Redirect test server did not settle.")


@pytest.mark.parametrize(
    ("base_url", "origin", "allow_remote"),
    [
        ("http://127.0.0.1:5173", "http://localhost:5173", False),
        ("http://example.test", "http://example.test", True),
        ("https://example.test/path", "https://example.test/path", True),
        ("https://user@example.test", "https://user@example.test", True),
        ("https://example.test.", "https://example.test.", True),
    ],
)
def test_validation_lab_rejects_unsafe_or_mismatched_origins(
    base_url: str, origin: str, allow_remote: bool
) -> None:
    with pytest.raises(ValidationLabError):
        ApiClient(base_url, origin, allow_remote=allow_remote)


def test_validation_lab_parser_has_no_password_argument() -> None:
    parser = build_parser()
    destinations = {action.dest for action in parser._actions}
    _require("password" not in destinations, "Password CLI argument still exists.")
    parsed = parser.parse_args(
        [
            "--base-url",
            "http://127.0.0.1:5173",
            "--browser-origin",
            "http://127.0.0.1:5173",
        ]
    )
    _require(parsed.browser_origin is not None, "Explicit browser origin was lost.")


def test_validation_lab_diagnostics_and_repr_hide_canaries() -> None:
    canaries = ("canary-password", "canary-access", "canary-csrf")
    result = ApiResult(200, {"access_token": canaries[1]})
    failure = ValidationLabError("request-unavailable")
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        _fail("fixed-operation", RuntimeError(canaries[0]))
        _fail("fixed-operation", failure)
    rendered = repr(result) + repr(failure) + stdout.getvalue() + stderr.getvalue()
    safe = all(canary not in rendered for canary in canaries)
    del rendered, stdout, stderr, result, failure, canaries
    _require(safe, "Validation-lab diagnostics exposed a canary.")


_LAB_BLOCKED_DRY_RUN_CONTRACT = MappingProxyType(
    {
        "dry_run": True,
        "status": "dry_run_blocked",
        "would_execute": False,
        "missing_params": ("canary-required-field",),
    }
)


def _module_payload_for_case(case: str) -> tuple[int, object]:
    payload: object = {
        "dry_run": _LAB_BLOCKED_DRY_RUN_CONTRACT["dry_run"],
        "status": _LAB_BLOCKED_DRY_RUN_CONTRACT["status"],
        "would_execute": _LAB_BLOCKED_DRY_RUN_CONTRACT["would_execute"],
        "missing_params": list(_LAB_BLOCKED_DRY_RUN_CONTRACT["missing_params"]),
        "warnings": ["canary-warning"],
        "operator_next_steps": ["canary-next-step"],
    }
    if case == "canonical":
        return 200, payload
    if case == "status-422":
        return 422, payload
    if case == "non-object":
        return 200, [payload]
    if not isinstance(payload, dict):
        pytest.fail("Validation-lab mutation setup was invalid.", pytrace=False)
    if case == "dry-run-missing":
        payload.pop("dry_run")
    elif case == "dry-run-false":
        payload["dry_run"] = False
    elif case == "status-wrong":
        payload["status"] = "dry_run_ok"
    elif case == "would-execute":
        payload["would_execute"] = True
    elif case == "missing-empty":
        payload["missing_params"] = []
    elif case == "missing-malformed":
        payload["missing_params"] = "canary-required-field"
    elif case == "execution-result":
        payload["execution_result"] = {"state": "canary-success"}
    elif case == "success-publication":
        payload["success"] = True
    elif case == "credential-publication":
        payload["credentials"] = ["canary-credential"]
    elif case == "finding-publication":
        payload["findings"] = ["canary-finding"]
    elif case == "artifact-publication":
        payload["artifacts"] = ["canary-artifact"]
    else:
        pytest.fail("Validation-lab mutation case was unknown.", pytrace=False)
    return 200, payload


@contextmanager
def _full_validation_lab_server(module_case: str) -> Any:
    module_status, module_payload = _module_payload_for_case(module_case)
    state: dict[str, Any] = {
        "events": [],
        "checks": [],
        "campaign_active": False,
        "api_key_active": False,
    }

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

        def _json(self, status: int, payload: object) -> None:
            encoded = json.dumps(payload).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _empty(self, status: int, cookies: tuple[str, ...] = ()) -> None:
            self.send_response(status)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            if self.path == "/auth/csrf":
                state["events"].append("csrf")
                state["checks"].append(
                    self.headers.get_all("Origin", failobj=[])
                    == ["http://127.0.0.1:5173"]
                )
                self._empty(
                    204,
                    (f"ares-dev-csrf={_LAB_CSRF_INITIAL}; Path=/; SameSite=Strict",),
                )
            elif self.path == "/health":
                state["events"].append("health")
                self._json(200, {"status": "ok"})
            elif self.path == "/auth/me":
                state["events"].append("profile")
                self._json(200, {"role": "admin"})
            elif self.path == "/campaigns":
                state["events"].append("campaign-list")
                rows = [{"id": "fixed-campaign"}] if state["campaign_active"] else []
                self._json(200, rows)
            elif self.path == "/reports/fixed-campaign":
                state["events"].append("report-list")
                self._json(200, [])
            elif self.path == "/auth/api-keys":
                state["events"].append("api-key-list")
                rows = [{"id": "fixed-key"}] if state["api_key_active"] else []
                self._json(200, rows)
            else:
                self._empty(404)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            body = self._body()
            if self.path == "/auth/token":
                form = parse_qs(body.decode("ascii"), strict_parsing=True)
                state["events"].append("login")
                state["checks"].extend(
                    (
                        set(form) == {"username", "password"},
                        self.headers.get_all("Origin", failobj=[])
                        == ["http://127.0.0.1:5173"],
                        self.headers.get_all("X-ARES-CSRF", failobj=[])
                        == [_LAB_CSRF_INITIAL],
                    )
                )
                payload = {
                    "access_token": _LAB_ACCESS,
                    "token_type": "bearer",
                    "refresh_generation": 0,
                    "session_coordination_key": "c" * 43,
                }
                encoded = json.dumps(payload).encode("ascii")
                self.send_response(200)
                self.send_header(
                    "Set-Cookie",
                    f"ares-dev-refresh={_LAB_REFRESH}; Path=/; HttpOnly; SameSite=Strict",
                )
                self.send_header(
                    "Set-Cookie",
                    f"ares-dev-csrf={_LAB_CSRF_ROTATED}; Path=/; SameSite=Strict",
                )
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            elif self.path == "/auth/logout":
                state["events"].append("logout")
                state["checks"].extend(
                    (
                        body == b"",
                        self.headers.get_all("Origin", failobj=[])
                        == ["http://127.0.0.1:5173"],
                        self.headers.get_all("X-ARES-CSRF", failobj=[])
                        == [_LAB_CSRF_ROTATED],
                    )
                )
                self._empty(204)
            elif self.path == "/campaigns":
                request_body = json.loads(body)
                if request_body.get("targets") == ["../not-a-target"]:
                    state["events"].append("campaign-rejected")
                    self._json(422, {})
                else:
                    state["events"].append("campaign-create")
                    state["campaign_active"] = True
                    self._json(200, {"id": "fixed-campaign"})
            elif self.path == "/campaigns/fixed-campaign/run":
                state["events"].append("plan-dry-run")
                self._json(200, {"param_validation": {"ok": False}})
            elif self.path == "/modules/ad.kerberoast/run":
                request_body = json.loads(body)
                state["events"].append("module-dry-run")
                state["module_request"] = {
                    "exact_keys": set(request_body)
                    == {"campaign_id", "params", "dry_run"},
                    "campaign_present": isinstance(request_body.get("campaign_id"), str),
                    "params_empty": request_body.get("params") == {},
                    "dry_run_true": request_body.get("dry_run") is True,
                    "query_empty": "?" not in self.path,
                }
                self._json(module_status, module_payload)
            elif self.path == "/reports/fixed-campaign?fmt=html":
                state["events"].append("report-create")
                self._json(200, {"filename": "fixed.html"})
            elif self.path == "/auth/api-keys":
                state["events"].append("api-key-create")
                state["api_key_active"] = True
                self._json(200, {"id": "fixed-key"})
            else:
                self._empty(404)
            del body

        def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            if self.path == "/auth/api-keys/fixed-key":
                state["events"].append("api-key-delete")
                state["api_key_active"] = False
                self._json(200, {})
            elif self.path == "/campaigns/fixed-campaign":
                state["events"].append("campaign-delete")
                state["campaign_active"] = False
                self._json(200, {})
            else:
                self._empty(404)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 5173), Handler)
    except OSError:
        pytest.fail("Full validation-lab listener was unavailable.", pytrace=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        state["settled"] = not thread.is_alive()


def _run_full_validation_lab(monkeypatch: pytest.MonkeyPatch, module_case: str) -> dict[str, Any]:
    monkeypatch.setenv("ARES_LAB_PASSWORD", "canary-password")
    stdout = io.StringIO()
    stderr = io.StringIO()
    with _full_validation_lab_server(module_case) as state:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = run_lab(
                SimpleNamespace(
                    base_url="http://127.0.0.1:5173",
                    browser_origin="http://127.0.0.1:5173",
                    username="canary-user",
                    idempotency_key="00000000-0000-4000-8000-000000000001",
                    allow_remote=False,
                )
            )
    rendered = stdout.getvalue() + stderr.getvalue()
    canaries = (
        "canary-password",
        "canary-required-field",
        "canary-warning",
        "canary-next-step",
        "canary-success",
        "canary-credential",
        "canary-finding",
        "canary-artifact",
    )
    reduced = {
        "exit_code": exit_code,
        "success_label": "[OK] dry-run blocked missing parameters" in rendered,
        "fixed_failure_label": (
            "[FAIL] dry-run blocked missing parameters - " in rendered
        ),
        "sensitive_output": any(canary in rendered for canary in canaries),
        "all_checks": all(state["checks"]),
        "module_request": state.get("module_request"),
        "continued_after_module": (
            "module-dry-run" in state["events"]
            and "report-create" in state["events"]
            and "api-key-create" in state["events"]
            and "campaign-delete" in state["events"]
        ),
        "logout": state["events"][-1:] == ["logout"],
        "settled": state["settled"],
        "ok_actions": rendered.count("[OK] "),
    }
    del rendered, stdout, stderr, canaries, state
    return reduced


def test_validation_lab_accepts_canonical_blocked_module_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run_full_validation_lab(monkeypatch, "canonical")
    request_contract = result["module_request"]
    _require(result["exit_code"] == 0, "Canonical validation lab did not pass.")
    _require(result["success_label"], "Blocked dry-run success label was absent.")
    _require(not result["fixed_failure_label"], "Canonical dry-run was rejected.")
    _require(not result["sensitive_output"], "Dry-run output exposed a canary.")
    _require(result["all_checks"], "Validation-lab request contract differed.")
    _require(
        isinstance(request_contract, dict) and all(request_contract.values()),
        "Module dry-run request contract differed.",
    )
    _require(result["continued_after_module"], "Lab stopped after module dry-run.")
    _require(result["logout"], "Lab logout cleanup did not run.")
    _require(result["settled"], "Full validation-lab server did not settle.")
    _require(result["ok_actions"] == 17, "Validation-lab action count differed.")


@pytest.mark.parametrize(
    "module_case",
    [
        "status-422",
        "dry-run-missing",
        "dry-run-false",
        "status-wrong",
        "would-execute",
        "missing-empty",
        "missing-malformed",
        "non-object",
        "execution-result",
        "success-publication",
        "credential-publication",
        "finding-publication",
        "artifact-publication",
    ],
)
def test_validation_lab_rejects_noncanonical_blocked_module_dry_run(
    monkeypatch: pytest.MonkeyPatch,
    module_case: str,
) -> None:
    result = _run_full_validation_lab(monkeypatch, module_case)
    _require(result["exit_code"] == 1, "Unsafe module response was accepted.")
    _require(not result["success_label"], "Unsafe module response reported success.")
    _require(result["fixed_failure_label"], "Fixed module failure label was absent.")
    _require(not result["sensitive_output"], "Module failure output exposed a canary.")
    _require(result["all_checks"], "Validation-lab request contract differed.")
    _require(result["continued_after_module"], "Lab stopped after rejected module result.")
    _require(result["logout"], "Rejected module result bypassed logout cleanup.")
    _require(result["settled"], "Rejected module test server did not settle.")
