"""Bounded validation lab using the real browser-cookie authentication contract."""
from __future__ import annotations

import argparse
import base64
import getpass
import hmac
import http.cookiejar
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib import error, parse, request

_LOOPBACK_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
}
_CSRF_COOKIE_NAMES = {"__Host-ares-csrf", "ares-dev-csrf"}
_CSRF_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_BLOCKED_DRY_RUN_FORBIDDEN_FIELDS = frozenset(
    {
        "artifact",
        "artifacts",
        "credential",
        "credentials",
        "executed",
        "execution",
        "execution_result",
        "execution_status",
        "finding",
        "findings",
        "output",
        "outputs",
        "result",
        "results",
        "succeeded",
        "success",
    }
)


class ValidationLabError(RuntimeError):
    """Fixed, non-sensitive validation-lab failure."""

    def __init__(self, operation: str, *, status: int | None = None) -> None:
        self.operation = operation
        self.status = status
        suffix = "" if status is None else f":status-{status}"
        super().__init__(f"validation-lab:{operation}{suffix}")


@dataclass(frozen=True, slots=True, eq=False)
class ApiResult:
    status: int
    body: Any = field(repr=False)


class _RejectRedirects(request.HTTPRedirectHandler):
    """Turn every redirect into an ordinary fixed-status failure."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _canonical_public_origin(value: object, *, allow_remote: bool) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "," in value:
        raise ValidationLabError("origin-invalid")
    try:
        parsed = parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValidationLabError("origin-invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.hostname.endswith(".")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationLabError("origin-invalid")
    try:
        host = parsed.hostname.encode("ascii").decode("ascii").lower()
    except UnicodeError:
        raise ValidationLabError("origin-invalid") from None
    if host != parsed.hostname.lower() or ":" in host:
        raise ValidationLabError("origin-invalid")
    default_port = 80 if parsed.scheme == "http" else 443
    if port == default_port:
        raise ValidationLabError("origin-invalid")
    authority = host if port is None else f"{host}:{port}"
    canonical = f"{parsed.scheme}://{authority}"
    if not hmac.compare_digest(canonical, value):
        raise ValidationLabError("origin-invalid")
    if parsed.scheme == "http" and canonical not in _LOOPBACK_ORIGINS:
        raise ValidationLabError("origin-insecure")
    if canonical not in _LOOPBACK_ORIGINS and not allow_remote:
        raise ValidationLabError("remote-not-authorized")
    return canonical


def _is_canonical_csrf(value: object) -> bool:
    if not isinstance(value, str) or _CSRF_PATTERN.fullmatch(value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (TypeError, ValueError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    return len(decoded) == 32 and hmac.compare_digest(canonical, value)


def _canonical_idempotency_key(value: object) -> str | None:
    """Accept only a non-secret canonical lowercase UUIDv4 header value."""
    if value in {None, ""}:
        return None
    if not isinstance(value, str):
        raise ValidationLabError("idempotency-key-invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        raise ValidationLabError("idempotency-key-invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise ValidationLabError("idempotency-key-invalid")
    return value


class ApiClient:
    """Cookie-aware client whose representations never contain credentials."""

    def __init__(self, base_url: str, browser_origin: str, *, allow_remote: bool = False) -> None:
        canonical_base = _canonical_public_origin(base_url, allow_remote=allow_remote)
        canonical_origin = _canonical_public_origin(browser_origin, allow_remote=allow_remote)
        if not hmac.compare_digest(canonical_base, canonical_origin):
            raise ValidationLabError("origin-mismatch")
        self.base_url = canonical_base
        self.browser_origin = canonical_origin
        self.access_token: str | None = None
        self._csrf_cookie_name = (
            "ares-dev-csrf"
            if canonical_origin in _LOOPBACK_ORIGINS
            else "__Host-ares-csrf"
        )
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = request.build_opener(
            request.HTTPCookieProcessor(self._cookie_jar),
            _RejectRedirects(),
        )

    def _current_csrf(self) -> str:
        matches: list[http.cookiejar.Cookie] = []
        for cookie in self._cookie_jar:
            if cookie.name in _CSRF_COOKIE_NAMES and not cookie.is_expired():
                matches.append(cookie)
        if len(matches) != 1 or matches[0].name != self._csrf_cookie_name:
            raise ValidationLabError("csrf-cookie-invalid")
        value = matches[0].value
        if not _is_canonical_csrf(value):
            raise ValidationLabError("csrf-cookie-invalid")
        return value

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        form: dict[str, str] | None = None,
        expect: set[int] | None = None,
        *,
        authenticated: bool = True,
        browser_headers: bool = False,
        empty_body: bool = False,
        idempotency_key: str | None = None,
    ) -> ApiResult:
        expected = expect or {200}
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {"Accept": "application/json"}
        data: bytes | None = b"" if empty_body else None
        if form is not None:
            data = parse.urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if browser_headers:
            headers["Origin"] = self.browser_origin
            if method.upper() != "GET":
                headers["X-ARES-CSRF"] = self._current_csrf()
        if authenticated:
            if self.access_token is None:
                raise ValidationLabError("access-authority-missing")
            headers["Authorization"] = f"Bearer {self.access_token}"
        canonical_key = _canonical_idempotency_key(idempotency_key)
        if canonical_key is not None:
            headers["Idempotency-Key"] = canonical_key

        outgoing = request.Request(  # noqa: S310 - URL origin was strictly validated
            url, data=data, headers=headers, method=method
        )
        try:
            with self._opener.open(outgoing, timeout=15) as response:  # noqa: S310
                raw = response.read().decode("utf-8", errors="replace")
                result = ApiResult(response.status, _parse_body(raw))
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            result = ApiResult(exc.code, _parse_body(raw))
        except (error.URLError, TimeoutError, OSError):
            raise ValidationLabError("request-unavailable") from None
        if result.status not in expected:
            raise ValidationLabError("request-status", status=result.status)
        return result

    def bootstrap_csrf(self) -> None:
        self.request(
            "GET",
            "/auth/csrf",
            expect={204},
            authenticated=False,
            browser_headers=True,
        )
        self._current_csrf()

    def login(self, username: str, password: str) -> None:
        self.bootstrap_csrf()
        result = self.request(
            "POST",
            "/auth/token",
            form={"username": username, "password": password},
            authenticated=False,
            browser_headers=True,
        )
        body = result.body
        if (
            not isinstance(body, dict)
            or "refresh_token" in body
            or not isinstance(body.get("access_token"), str)
            or not body["access_token"]
        ):
            raise ValidationLabError("login-contract-invalid")
        self.access_token = body["access_token"]
        self._current_csrf()

    def refresh(self) -> None:
        result = self.request(
            "POST",
            "/auth/refresh",
            expect={200},
            authenticated=False,
            browser_headers=True,
            empty_body=True,
        )
        body = result.body
        if (
            not isinstance(body, dict)
            or "refresh_token" in body
            or not isinstance(body.get("access_token"), str)
            or not body["access_token"]
        ):
            raise ValidationLabError("refresh-contract-invalid")
        self.access_token = body["access_token"]
        self._current_csrf()

    def logout(self) -> None:
        try:
            self.request(
                "POST",
                "/auth/logout",
                expect={204},
                authenticated=False,
                browser_headers=True,
                empty_body=True,
            )
        finally:
            self.access_token = None


def _parse_body(raw: str) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _password_from_env_or_prompt() -> str:
    password = os.getenv("ARES_LAB_PASSWORD") or os.getenv("ARES_DEFAULT_ADMIN_PASSWORD")
    if password:
        return password
    return getpass.getpass("Validation lab password: ")


def _ok(label: str) -> None:
    print(f"[OK] {label}")


def _fail(label: str, exc: Exception) -> None:
    if isinstance(exc, ValidationLabError) and exc.status is not None:
        print(f"[FAIL] {label} - status={exc.status}")
    else:
        print(f"[FAIL] {label} - type={type(exc).__name__}")


def _raise_fixed() -> None:
    raise ValidationLabError("contract-check-failed")


def _validate_blocked_module_dry_run(value: object) -> None:
    """Require the fixed, side-effect-free response for missing module parameters."""
    if not isinstance(value, dict):
        _raise_fixed()
    missing_params = value.get("missing_params")
    if (
        value.get("dry_run") is not True
        or value.get("status") != "dry_run_blocked"
        or value.get("would_execute") is not False
        or not isinstance(missing_params, list)
        or not missing_params
        or any(not isinstance(item, str) or not item for item in missing_params)
    ):
        _raise_fixed()

    pending: list[object] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if (
                    isinstance(key, str)
                    and key.casefold() in _BLOCKED_DRY_RUN_FORBIDDEN_FIELDS
                ):
                    _raise_fixed()
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)


def run_lab(args: argparse.Namespace) -> int:
    if not args.browser_origin:
        raise ValidationLabError("browser-origin-required")
    client = ApiClient(
        args.base_url,
        args.browser_origin,
        allow_remote=bool(args.allow_remote),
    )
    username = args.username
    password = _password_from_env_or_prompt()
    failures: list[str] = []

    def step(label: str, fn: Any) -> Any:
        try:
            result = fn()
            _ok(label)
            return result
        except Exception as exc:  # noqa: BLE001 - continue bounded independent checks
            failures.append(label)
            _fail(label, exc)
            return None

    try:
        step(
            "health endpoint",
            lambda: client.request(
                "GET", "/health", authenticated=False
            ).body.get("status"),
        )

        step("browser login", lambda: client.login(username, password))
        password = ""
        step("current profile", lambda: client.request("GET", "/auth/me").body)

        step(
            "campaign target validation",
            lambda: client.request(
                "POST",
                "/campaigns",
                body={
                    "name": "ARES Validation Bad Target",
                    "client": "Local Lab",
                    "targets": ["../not-a-target"],
                    "scope_cidrs": [],
                },
                expect={422},
            ),
        )

        campaign_id_holder: dict[str, str] = {}

        def create_campaign() -> None:
            campaign = client.request(
                "POST",
                "/campaigns",
                body={
                    "name": f"ARES Validation Lab {int(time.time())}",
                    "client": "Local Lab",
                    "targets": ["127.0.0.1"],
                    "scope_cidrs": ["127.0.0.1/32"],
                },
            ).body
            campaign_id = campaign.get("id") if isinstance(campaign, dict) else None
            if not isinstance(campaign_id, str) or not campaign_id:
                _raise_fixed()
            campaign_id_holder["id"] = campaign_id

        step("create local campaign", create_campaign)
        campaign_id = campaign_id_holder.get("id")
        if campaign_id:
            def campaign_present() -> None:
                rows = client.request("GET", "/campaigns").body
                if not isinstance(rows, list) or not any(
                    isinstance(row, dict) and row.get("id") == campaign_id for row in rows
                ):
                    _raise_fixed()

            step("campaign appears in list", campaign_present)

            def plan_dry_run_validation() -> None:
                result = client.request(
                    "POST",
                    f"/campaigns/{parse.quote(campaign_id)}/run",
                    body={
                        "plan": {
                            "stages": [
                                {"name": "validation-only", "modules": ["ad.kerberoast"]}
                            ]
                        },
                        "global_params": {},
                        "dry_run": True,
                    },
                    idempotency_key=args.idempotency_key,
                ).body
                if (
                    not isinstance(result, dict)
                    or result.get("param_validation", {}).get("ok") is not False
                ):
                    _raise_fixed()

            step("module dry-run validation", plan_dry_run_validation)
            def module_param_dry_run_validation() -> None:
                result = client.request(
                    "POST",
                    "/modules/ad.kerberoast/run",
                    body={"campaign_id": campaign_id, "params": {}, "dry_run": True},
                    expect={200},
                    idempotency_key=args.idempotency_key,
                ).body
                _validate_blocked_module_dry_run(result)

            step(
                "dry-run blocked missing parameters",
                module_param_dry_run_validation,
            )

            def generate_report() -> None:
                result = client.request(
                    "POST", f"/reports/{parse.quote(campaign_id)}?fmt=html"
                ).body
                filename = result.get("filename") if isinstance(result, dict) else None
                if not isinstance(filename, str) or not filename.endswith(".html"):
                    _raise_fixed()

            step("report generation", generate_report)
            step(
                "report list",
                lambda: client.request("GET", f"/reports/{parse.quote(campaign_id)}").body,
            )

        api_key_id_holder: dict[str, str] = {}

        def api_key_create() -> None:
            body = client.request(
                "POST",
                "/auth/api-keys",
                body={"name": f"validation-lab-{int(time.time())}", "scopes": "read"},
            ).body
            key_id = body.get("id") if isinstance(body, dict) else None
            if not isinstance(key_id, str) or not key_id:
                _raise_fixed()
            api_key_id_holder["id"] = key_id

        step("API key create", api_key_create)
        if api_key_id_holder.get("id"):
            def api_key_present() -> None:
                key_id = api_key_id_holder["id"]
                rows = client.request("GET", "/auth/api-keys").body
                if not isinstance(rows, list) or not any(
                    isinstance(row, dict) and row.get("id") == key_id for row in rows
                ):
                    _raise_fixed()

            step("API key list after create", api_key_present)
            step(
                "API key delete",
                lambda: client.request(
                    "DELETE",
                    f"/auth/api-keys/{parse.quote(api_key_id_holder['id'])}",
                ),
            )

            def api_key_absent() -> None:
                key_id = api_key_id_holder["id"]
                rows = client.request("GET", "/auth/api-keys").body
                if not isinstance(rows, list) or any(
                    isinstance(row, dict) and row.get("id") == key_id for row in rows
                ):
                    _raise_fixed()

            step("API key list after delete", api_key_absent)

        if campaign_id:
            step(
                "campaign delete",
                lambda: client.request(
                    "DELETE", f"/campaigns/{parse.quote(campaign_id)}"
                ),
            )

            def campaign_absent() -> None:
                rows = client.request("GET", "/campaigns").body
                if not isinstance(rows, list) or any(
                    isinstance(row, dict) and row.get("id") == campaign_id for row in rows
                ):
                    _raise_fixed()

            step("campaign list after delete", campaign_absent)
    finally:
        password = ""
        if client.access_token is not None:
            try:
                client.logout()
                _ok("browser logout cleanup")
            except Exception as exc:  # noqa: BLE001 - cleanup failure becomes a fixed gate
                failures.append("browser logout cleanup")
                _fail("browser logout cleanup", exc)
            finally:
                client.access_token = None

    print()
    if failures:
        print(f"Validation lab failed: {len(failures)} step(s)")
        for item in failures:
            print(f" - {item}")
        return 1
    print("Validation lab passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded ARES validation lab checks.")
    parser.add_argument("--base-url", default=os.getenv("ARES_LAB_BASE_URL"))
    parser.add_argument(
        "--browser-origin",
        default=os.getenv("ARES_LAB_BROWSER_ORIGIN") or os.getenv("ARES_BROWSER_ORIGIN"),
    )
    parser.add_argument("--username", default=os.getenv("ARES_LAB_USERNAME", "admin"))
    parser.add_argument(
        "--idempotency-key",
        default=os.getenv("ARES_LAB_IDEMPOTENCY_KEY"),
        help="Optional non-secret canonical UUIDv4 for preview requests.",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow one exact HTTPS origin for an explicitly authorized remote lab.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.base_url:
        raise ValidationLabError("base-url-required")
    return run_lab(args)


if __name__ == "__main__":
    sys.exit(main())
