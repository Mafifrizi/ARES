"""Local ARES validation lab.

This harness exercises safe localhost-only API flows:
- health check
- login + /auth/me
- campaign input validation
- campaign create/list/delete/list
- module dry-run validation
- API key create/list/delete/list
- report generate/list

It intentionally refuses non-localhost targets unless --allow-remote is passed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class ApiResult:
    status: int
    body: Any
    headers: dict[str, str]


class ApiClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.access_token: str | None = None

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        form: dict[str, str] | None = None,
        expect: set[int] | None = None,
    ) -> ApiResult:
        expect = expect or {200}
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {"Accept": "application/json"}
        data: bytes | None = None

        if form is not None:
            data = parse.urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed = _parse_body(raw)
                result = ApiResult(resp.status, parsed, dict(resp.headers.items()))
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            result = ApiResult(exc.code, _parse_body(raw), dict(exc.headers.items()))
        except error.URLError as exc:
            raise RuntimeError(f"Cannot reach {url}: {exc}") from exc

        if result.status not in expect:
            raise RuntimeError(
                f"{method} {path} expected {sorted(expect)}, got {result.status}: "
                f"{_compact(result.body)}"
            )
        return result


def _parse_body(raw: str) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)[:500]


def _require_localhost(base_url: str, allow_remote: bool) -> None:
    parsed = parse.urlparse(base_url)
    host = parsed.hostname or ""
    if allow_remote or host in LOCAL_HOSTS:
        return
    raise SystemExit(
        f"Refusing to run validation lab against non-local host {host!r}. "
        "Use --allow-remote only for an explicitly authorized lab."
    )


def _password_from_env_or_prompt(username: str) -> str:
    password = os.getenv("ARES_LAB_PASSWORD") or os.getenv("ARES_DEFAULT_ADMIN_PASSWORD")
    if password:
        return password
    return getpass.getpass(f"Password for {username}: ")


def _ok(label: str, detail: str = "") -> None:
    suffix = f" - {detail}" if detail else ""
    print(f"[OK] {label}{suffix}")


def _fail(label: str, exc: Exception) -> None:
    print(f"[FAIL] {label} - {exc}")


def run_lab(args: argparse.Namespace) -> int:
    _require_localhost(args.base_url, args.allow_remote)
    client = ApiClient(args.base_url)
    username = args.username
    password = args.password or _password_from_env_or_prompt(username)
    failures: list[str] = []

    def step(label: str, fn) -> Any:
        try:
            result = fn()
            _ok(label, result if isinstance(result, str) else "")
            return result
        except Exception as exc:  # noqa: BLE001 - lab should continue and report all failures
            failures.append(label)
            _fail(label, exc)
            return None

    step("health endpoint", lambda: client.request("GET", "/health").body.get("status"))

    def login() -> str:
        token = client.request(
            "POST",
            "/auth/token",
            form={"username": username, "password": password},
        ).body
        client.access_token = token["access_token"]
        return "token accepted"

    step("login", login)
    me = step("current profile", lambda: client.request("GET", "/auth/me").body)
    if isinstance(me, dict):
        _ok("profile role", f"{me.get('username')} / {me.get('role')}")

    def invalid_campaign_target() -> str:
        client.request(
            "POST",
            "/campaigns",
            body={
                "name": "ARES Validation Bad Target",
                "client": "Local Lab",
                "targets": ["../not-a-target"],
                "scope_cidrs": [],
            },
            expect={422},
        )
        return "422 rejected traversal-like target"

    step("campaign target validation", invalid_campaign_target)

    campaign_id_holder: dict[str, str] = {}

    def create_campaign() -> str:
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
        campaign_id_holder["id"] = campaign["id"]
        return campaign["id"]

    step("create local campaign", create_campaign)
    campaign_id = campaign_id_holder.get("id")

    if campaign_id:
        step(
            "campaign appears in list",
            lambda: "found"
            if any(c.get("id") == campaign_id for c in client.request("GET", "/campaigns").body)
            else (_raise("campaign not found in list")),
        )

        def plan_dry_run_validation() -> str:
            body = {
                "plan": {
                    "stages": [
                        {
                            "name": "validation-only",
                            "modules": ["ad.kerberoast"],
                        }
                    ]
                },
                "global_params": {},
                "dry_run": True,
            }
            result = client.request(
                "POST",
                f"/campaigns/{parse.quote(campaign_id)}/run",
                body=body,
            ).body
            if result.get("param_validation", {}).get("ok") is not False:
                raise RuntimeError("expected dry-run param_validation.ok=false")
            return "dry-run caught missing params"

        step("module dry-run validation", plan_dry_run_validation)

        def direct_module_param_validation() -> str:
            client.request(
                "POST",
                "/modules/ad.kerberoast/run",
                body={"campaign_id": campaign_id, "params": {}, "dry_run": True},
                expect={422},
            )
            return "422 rejected missing module params"

        step("module API param validation", direct_module_param_validation)

        def generate_report() -> str:
            result = client.request(
                "POST",
                f"/reports/{parse.quote(campaign_id)}?fmt=html",
            ).body
            filename = result.get("filename", "")
            if not filename.endswith(".html"):
                raise RuntimeError(f"unexpected report filename: {filename}")
            return filename

        step("report generation", generate_report)
        step(
            "report list",
            lambda: f"{len(client.request('GET', f'/reports/{parse.quote(campaign_id)}').body.get('reports', []))} report(s)",
        )

    api_key_id_holder: dict[str, str] = {}

    def api_key_create() -> str:
        result = client.request(
            "POST",
            "/auth/api-keys",
            body={"name": f"validation-lab-{int(time.time())}", "scopes": "read"},
        ).body
        key_id = result.get("id")
        if not key_id:
            raise RuntimeError(f"missing id in API key response: {_compact(result)}")
        api_key_id_holder["id"] = key_id
        return key_id

    step("API key create", api_key_create)

    def api_key_list_contains() -> str:
        key_id = api_key_id_holder["id"]
        keys = client.request("GET", "/auth/api-keys").body
        if not any(k.get("id") == key_id for k in keys):
            raise RuntimeError("new API key not visible in list")
        return "visible"

    if api_key_id_holder.get("id"):
        step("API key list after create", api_key_list_contains)
        step(
            "API key delete",
            lambda: client.request(
                "DELETE", f"/auth/api-keys/{parse.quote(api_key_id_holder['id'])}"
            ).body.get("status", ""),
        )

        def api_key_removed_from_list() -> str:
            key_id = api_key_id_holder["id"]
            keys = client.request("GET", "/auth/api-keys").body
            if any(k.get("id") == key_id for k in keys):
                raise RuntimeError("deleted API key is still visible")
            return "removed"

        step("API key list after delete", api_key_removed_from_list)

    if campaign_id:
        step(
            "campaign delete",
            lambda: client.request(
                "DELETE", f"/campaigns/{parse.quote(campaign_id)}"
            ).body.get("status", ""),
        )

        def campaign_removed_from_list() -> str:
            campaigns = client.request("GET", "/campaigns").body
            if any(c.get("id") == campaign_id for c in campaigns):
                raise RuntimeError("deleted campaign is still visible")
            return "removed"

        step("campaign list after delete", campaign_removed_from_list)

    print()
    if failures:
        print(f"Validation lab failed: {len(failures)} step(s)")
        for item in failures:
            print(f" - {item}")
        return 1
    print("Validation lab passed.")
    return 0


def _raise(message: str) -> None:
    raise RuntimeError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run local ARES validation lab checks.")
    parser.add_argument("--base-url", default=os.getenv("ARES_LAB_BASE_URL", "http://localhost:8080"))
    parser.add_argument("--username", default=os.getenv("ARES_LAB_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("ARES_LAB_PASSWORD"))
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow a non-localhost base URL. Use only for an authorized lab.",
    )
    return parser


def main() -> int:
    return run_lab(build_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())
