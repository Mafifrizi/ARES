"""Same-origin browser refresh-cookie and CSRF security contracts."""
from __future__ import annotations

import base64
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.cookies import _is_legal_key
from typing import Any, Final
from urllib.parse import urlsplit

from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSRF_RANDOM_BYTES: Final[int] = 32
CSRF_TOKEN_LENGTH: Final[int] = 43
PRELOGIN_CSRF_LIFETIME_SECONDS: Final[int] = 600
MAX_REFRESH_COOKIE_AGE_SECONDS: Final[int] = 2_592_000

PRODUCTION_REFRESH_COOKIE: Final[str] = "__Host-ares-refresh"
PRODUCTION_CSRF_COOKIE: Final[str] = "__Host-ares-csrf"
DEVELOPMENT_REFRESH_COOKIE: Final[str] = "ares-dev-refresh"
DEVELOPMENT_CSRF_COOKIE: Final[str] = "ares-dev-csrf"

CSRF_HEADER: Final[bytes] = b"x-ares-csrf"
_AUTH_PATHS: Final[frozenset[str]] = frozenset(
    {"/auth/csrf", "/auth/token", "/auth/refresh", "/auth/logout", "/auth/logout-all"}
)
_PROTECTED_POST_PATHS: Final[frozenset[str]] = frozenset(
    {"/auth/token", "/auth/refresh", "/auth/logout", "/auth/logout-all"}
)
_REFRESH_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{64}\Z")
_CSRF_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_FORBIDDEN_REFRESH_HEADERS: Final[frozenset[bytes]] = frozenset(
    {b"refresh-token", b"x-refresh-token", b"x-ares-refresh-token"}
)
_DEV_ORIGINS: Final[frozenset[str]] = frozenset(
    {"http://127.0.0.1:5173", "http://localhost:5173"}
)


class BrowserSessionConfigurationError(RuntimeError):
    """Fixed startup failure for an invalid browser-auth boundary."""

    def __init__(self) -> None:
        super().__init__("browser session configuration invalid")


@dataclass(frozen=True, slots=True, eq=False)
class BrowserSessionPolicy:
    """Validated non-secret browser origin and immutable cookie policy."""

    origin: str = field(repr=False)
    authority: str = field(repr=False)
    refresh_cookie_name: str
    csrf_cookie_name: str
    secure: bool
    debug: bool


@dataclass(frozen=True, slots=True, eq=False)
class BrowserRequestContext:
    """Sanitized request decision installed by the outer ASGI boundary."""

    refresh_token: str | None = field(default=None, repr=False)


def _canonical_base64url(value: object, *, encoded_length: int, byte_length: int) -> bool:
    if not isinstance(value, str) or len(value) != encoded_length:
        return False
    pattern = _CSRF_TOKEN_RE if encoded_length == CSRF_TOKEN_LENGTH else _REFRESH_TOKEN_RE
    if pattern.fullmatch(value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    return len(decoded) == byte_length and hmac.compare_digest(canonical, value)


def is_canonical_csrf_token(value: object) -> bool:
    return _canonical_base64url(value, encoded_length=43, byte_length=32)


def is_canonical_refresh_token(value: object) -> bool:
    return _canonical_base64url(value, encoded_length=64, byte_length=48)


def generate_csrf_token() -> str:
    encoded = base64.urlsafe_b64encode(secrets.token_bytes(CSRF_RANDOM_BYTES))
    value = encoded.rstrip(b"=").decode("ascii")
    if not is_canonical_csrf_token(value):
        raise RuntimeError("csrf generation failed")
    return value


def _canonical_origin(raw: object, *, debug: bool) -> tuple[str, str]:
    if not isinstance(raw, str) or not raw or raw != raw.strip() or "," in raw:
        raise BrowserSessionConfigurationError
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError):
        raise BrowserSessionConfigurationError from None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.hostname is None
        or parsed.hostname.endswith(".")
    ):
        raise BrowserSessionConfigurationError
    try:
        host = parsed.hostname.encode("ascii").decode("ascii").lower()
    except UnicodeError:
        raise BrowserSessionConfigurationError from None
    if host != parsed.hostname.lower():
        raise BrowserSessionConfigurationError
    if debug:
        if parsed.scheme != "http" or raw not in _DEV_ORIGINS:
            raise BrowserSessionConfigurationError
    elif parsed.scheme != "https":
        raise BrowserSessionConfigurationError
    default_port = 80 if parsed.scheme == "http" else 443
    if port == default_port:
        raise BrowserSessionConfigurationError
    authority = host if port is None else f"{host}:{port}"
    canonical = f"{parsed.scheme}://{authority}"
    if canonical != raw:
        raise BrowserSessionConfigurationError
    return canonical, authority


def build_browser_session_policy(settings: Any) -> BrowserSessionPolicy:
    debug = bool(settings.ares_debug)
    configured = str(settings.ares_browser_origin or "")
    if debug and not configured:
        configured = "http://127.0.0.1:5173"
    origin, authority = _canonical_origin(configured, debug=debug)
    trusted_hosts = tuple(str(value).lower() for value in settings.trusted_hosts_list)
    origin_host = authority.rsplit(":", 1)[0]
    if debug:
        if any(value not in {"localhost", "127.0.0.1"} for value in trusted_hosts):
            raise BrowserSessionConfigurationError
    elif origin_host not in trusted_hosts:
        raise BrowserSessionConfigurationError
    return BrowserSessionPolicy(
        origin=origin,
        authority=authority,
        refresh_cookie_name=(DEVELOPMENT_REFRESH_COOKIE if debug else PRODUCTION_REFRESH_COOKIE),
        csrf_cookie_name=(DEVELOPMENT_CSRF_COOKIE if debug else PRODUCTION_CSRF_COOKIE),
        secure=not debug,
        debug=debug,
    )


def canonical_noncredentialed_origins(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip() or "," in value:
            raise BrowserSessionConfigurationError
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except (TypeError, ValueError):
            raise BrowserSessionConfigurationError from None
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.hostname.endswith(".")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise BrowserSessionConfigurationError
        try:
            host = parsed.hostname.encode("ascii").decode("ascii").lower()
        except UnicodeError:
            raise BrowserSessionConfigurationError from None
        default_port = 80 if parsed.scheme == "http" else 443
        if port == default_port:
            raise BrowserSessionConfigurationError
        authority = host if port is None else f"{host}:{port}"
        origin = f"{parsed.scheme}://{authority}"
        if origin != value:
            raise BrowserSessionConfigurationError
        if origin in result or origin == "null" or "*" in origin:
            raise BrowserSessionConfigurationError
        result.append(origin)
    return result


def remaining_cookie_seconds(absolute_expiry: datetime, *, now: datetime | None = None) -> int:
    current = now or datetime.now(timezone.utc)
    if absolute_expiry.tzinfo is None or absolute_expiry.utcoffset() is None:
        raise ValueError("family expiry must be timezone-aware")
    delta = absolute_expiry.astimezone(timezone.utc) - current.astimezone(timezone.utc)
    remaining = int(delta.total_seconds())
    return max(0, min(MAX_REFRESH_COOKIE_AGE_SECONDS, remaining))


def _set_cookie(
    response: Response,
    *,
    name: str,
    value: str,
    max_age: int,
    secure: bool,
    httponly: bool,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        expires=datetime.now(timezone.utc) + timedelta(seconds=max_age),
        path="/",
        secure=secure,
        httponly=httponly,
        samesite="strict",
    )


def publish_prelogin_csrf(response: Response, policy: BrowserSessionPolicy) -> None:
    _set_cookie(
        response,
        name=policy.csrf_cookie_name,
        value=generate_csrf_token(),
        max_age=PRELOGIN_CSRF_LIFETIME_SECONDS,
        secure=policy.secure,
        httponly=False,
    )


def publish_session_cookies(
    response: Response,
    policy: BrowserSessionPolicy,
    *,
    refresh_token: str,
    absolute_expiry: datetime,
) -> bool:
    if not is_canonical_refresh_token(refresh_token):
        raise ValueError("invalid refresh token")
    max_age = remaining_cookie_seconds(absolute_expiry)
    if max_age <= 0:
        return False
    _set_cookie(
        response,
        name=policy.refresh_cookie_name,
        value=refresh_token,
        max_age=max_age,
        secure=policy.secure,
        httponly=True,
    )
    _set_cookie(
        response,
        name=policy.csrf_cookie_name,
        value=generate_csrf_token(),
        max_age=max_age,
        secure=policy.secure,
        httponly=False,
    )
    return True


def clear_session_cookies(response: Response, policy: BrowserSessionPolicy) -> None:
    for name, httponly in (
        (policy.refresh_cookie_name, True),
        (policy.csrf_cookie_name, False),
    ):
        response.set_cookie(
            key=name,
            value="",
            max_age=0,
            expires=datetime(1970, 1, 1, tzinfo=timezone.utc),
            path="/",
            secure=policy.secure,
            httponly=httponly,
            samesite="strict",
        )


def _fixed_response(status: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"code": status, "detail": detail, "type": "api_error"},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _header_values(headers: tuple[tuple[bytes, bytes], ...], name: bytes) -> list[bytes]:
    return [value for key, value in headers if key.lower() == name]


def _decode_single_header(headers: tuple[tuple[bytes, bytes], ...], name: bytes) -> str | None:
    values = _header_values(headers, name)
    if len(values) != 1:
        return None
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError:
        return None


def _parse_canonical_cookies(
    headers: tuple[tuple[bytes, bytes], ...], policy: BrowserSessionPolicy
) -> tuple[str | None, str | None, bool]:
    found: dict[str, list[str]] = {
        policy.refresh_cookie_name: [],
        policy.csrf_cookie_name: [],
    }
    for raw in _header_values(headers, b"cookie"):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return None, None, False
        for part in text.split(";"):
            item = part.strip()
            if not item or "=" not in item:
                continue
            name, value = item.split("=", 1)
            if not name or not _is_legal_key(name):
                return None, None, False
            if name in found:
                found[name].append(value)
    if any(len(values) > 1 for values in found.values()):
        return None, None, False
    refresh = found[policy.refresh_cookie_name][0] if found[policy.refresh_cookie_name] else None
    csrf = found[policy.csrf_cookie_name][0] if found[policy.csrf_cookie_name] else None
    return refresh, csrf, True


def _canonical_host(value: str, *, scheme: str) -> str | None:
    if not value or value != value.strip() or "," in value or "@" in value:
        return None
    try:
        parsed = urlsplit(f"{scheme}://{value}")
        port = parsed.port
    except ValueError:
        return None
    if parsed.hostname is None or parsed.hostname.endswith("."):
        return None
    try:
        host = parsed.hostname.encode("ascii").decode("ascii").lower()
    except UnicodeError:
        return None
    default_port = 80 if scheme == "http" else 443
    if port == default_port:
        port = None
    return host if port is None else f"{host}:{port}"


class BrowserSessionBoundaryMiddleware:
    """Outermost sync-first browser-auth request boundary."""

    def __init__(self, app: ASGIApp, settings_provider: Any) -> None:
        self.app = app
        self._settings_provider = settings_provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in _AUTH_PATHS:
            await self.app(scope, receive, send)
            return

        path = str(scope["path"])
        method = str(scope.get("method", "")).upper()
        raw_query = bytes(scope.get("query_string", b""))
        scope["query_string"] = b""
        had_query = bool(raw_query)
        del raw_query

        headers = tuple(scope.get("headers", ()))
        scrubbed_names = {b"cookie", b"origin", CSRF_HEADER}
        if path != "/auth/logout-all":
            scrubbed_names.add(b"authorization")
        if path == "/auth/refresh":
            scrubbed_names.update(_FORBIDDEN_REFRESH_HEADERS)
        scope["headers"] = tuple(
            (key, value)
            for key, value in headers
            if key.lower() not in scrubbed_names
        )
        del scrubbed_names

        try:
            policy = build_browser_session_policy(self._settings_provider())
        except BrowserSessionConfigurationError:
            del headers
            await _fixed_response(503, "Browser authentication unavailable")(scope, receive, send)
            return

        origin_values = _header_values(headers, b"origin")
        allow_missing_origin = path == "/auth/csrf" and method == "GET"
        if len(origin_values) == 0 and allow_missing_origin:
            origin_ok = True
        elif len(origin_values) == 1:
            try:
                origin_ok = hmac.compare_digest(origin_values[0].decode("ascii"), policy.origin)
            except UnicodeDecodeError:
                origin_ok = False
        else:
            origin_ok = False
        host = _decode_single_header(headers, b"host")
        scheme = policy.origin.split(":", 1)[0]
        host_ok = (
            host is not None
            and _canonical_host(host, scheme=scheme) == policy.authority
        )
        fetch_site = _header_values(headers, b"sec-fetch-site")
        fetch_ok = not fetch_site or (len(fetch_site) == 1 and fetch_site[0] == b"same-origin")
        if not origin_ok or not host_ok or not fetch_ok:
            del headers
            await _fixed_response(403, "Browser request rejected")(scope, receive, send)
            return
        if had_query:
            del headers
            await _fixed_response(400, "Browser request format invalid")(scope, receive, send)
            return

        refresh, csrf_cookie, cookies_ok = _parse_canonical_cookies(headers, policy)
        if path in _PROTECTED_POST_PATHS:
            csrf_values = _header_values(headers, CSRF_HEADER)
            csrf_header: str | None = None
            if len(csrf_values) == 1:
                try:
                    csrf_header = csrf_values[0].decode("ascii")
                except UnicodeDecodeError:
                    csrf_header = None
            csrf_ok = (
                cookies_ok
                and is_canonical_csrf_token(csrf_cookie)
                and is_canonical_csrf_token(csrf_header)
                and hmac.compare_digest(str(csrf_cookie), str(csrf_header))
            )
            if not csrf_ok:
                del headers, refresh, csrf_cookie, csrf_header
                await _fixed_response(403, "Browser request rejected")(scope, receive, send)
                return

        if path == "/auth/refresh":
            forbidden_header = any(
                _header_values(headers, name)
                for name in _FORBIDDEN_REFRESH_HEADERS
            )
            authorization_present = bool(_header_values(headers, b"authorization"))
            if forbidden_header or authorization_present:
                del headers, refresh, csrf_cookie
                await _fixed_response(400, "Refresh transport invalid")(scope, receive, send)
                return
            if refresh is not None and not is_canonical_refresh_token(refresh):
                response = _fixed_response(401, "Session is not valid")
                clear_session_cookies(response, policy)
                del headers, refresh, csrf_cookie
                await response(scope, receive, send)
                return

        state = scope.setdefault("state", {})
        state["browser_session"] = BrowserRequestContext(refresh_token=refresh)
        state["browser_policy"] = policy
        del headers, refresh, csrf_cookie
        if path in {"/auth/refresh", "/auth/logout", "/auth/logout-all"}:
            body_present = False
            completed = False
            for _ in range(8):
                message = await receive()
                if message.get("type") != "http.request" or bool(
                    message.get("body", b"")
                ):
                    body_present = True
                completed = not bool(message.get("more_body", False))
                del message
                if completed or body_present:
                    break
            if not completed:
                body_present = True
            if body_present:
                await _fixed_response(400, "Browser request format invalid")(
                    scope, receive, send
                )
                return
            delivered = False

            async def _empty_receive() -> Message:
                nonlocal delivered
                if delivered:
                    return {"type": "http.disconnect"}
                delivered = True
                return {"type": "http.request", "body": b"", "more_body": False}

            receive = _empty_receive
        await self.app(scope, receive, send)


__all__ = [
    "BrowserRequestContext",
    "BrowserSessionBoundaryMiddleware",
    "BrowserSessionConfigurationError",
    "BrowserSessionPolicy",
    "CSRF_HEADER",
    "DEVELOPMENT_CSRF_COOKIE",
    "DEVELOPMENT_REFRESH_COOKIE",
    "MAX_REFRESH_COOKIE_AGE_SECONDS",
    "PRELOGIN_CSRF_LIFETIME_SECONDS",
    "PRODUCTION_CSRF_COOKIE",
    "PRODUCTION_REFRESH_COOKIE",
    "build_browser_session_policy",
    "canonical_noncredentialed_origins",
    "clear_session_cookies",
    "generate_csrf_token",
    "is_canonical_csrf_token",
    "is_canonical_refresh_token",
    "publish_prelogin_csrf",
    "publish_session_cookies",
    "remaining_cookie_seconds",
]
