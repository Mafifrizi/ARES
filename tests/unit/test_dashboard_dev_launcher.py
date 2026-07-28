from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

import pytest
import typer


_LEGACY_DASHBOARD_DISABLED = (
    "Legacy dashboard ASGI application is disabled. "
    "Use the dashboard served by the main ARES application; "
    "explicit development opt-in is required."
)


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _set_legacy_dashboard_policy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: bool,
    debug: bool,
) -> None:
    from ares.core.config import clear_settings_cache

    monkeypatch.setenv(
        "ARES_LEGACY_DASHBOARD_ENABLED",
        "true" if enabled else "false",
    )
    monkeypatch.setenv("ARES_DEBUG", "true" if debug else "false")
    clear_settings_cache()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "debug", "expected_started"),
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
async def test_legacy_dashboard_lifespan_requires_both_opt_ins(
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
    debug: bool,
    expected_started: bool,
) -> None:
    from ares.api.dashboard.app import dashboard_app
    from ares.core.config import clear_settings_cache

    _set_legacy_dashboard_policy(monkeypatch, enabled=enabled, debug=debug)
    started = False
    error_type_ok = False
    error_message_ok = False
    try:
        try:
            async with dashboard_app.router.lifespan_context(dashboard_app):
                started = True
        except Exception as exc:
            error_type_ok = type(exc) is RuntimeError
            error_message_ok = str(exc) == _LEGACY_DASHBOARD_DISABLED

        if expected_started:
            _require_fixed(started, "expected opted-in legacy lifespan to start")
            _require_fixed(
                not error_type_ok and not error_message_ok,
                "opted-in legacy lifespan raised an unexpected startup error",
            )
        else:
            _require_fixed(not started, "legacy lifespan started without both opt-ins")
            _require_fixed(error_type_ok, "legacy lifespan raised the wrong error type")
            _require_fixed(
                error_message_ok,
                "legacy lifespan did not use the fixed startup error",
            )
    finally:
        clear_settings_cache()


@pytest.mark.asyncio
async def test_legacy_dashboard_enablement_defaults_to_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ares.api.dashboard.app import dashboard_app
    from ares.core.config import clear_settings_cache, get_settings

    monkeypatch.delenv("ARES_LEGACY_DASHBOARD_ENABLED", raising=False)
    monkeypatch.setenv("ARES_DEBUG", "true")
    clear_settings_cache()
    disabled_by_default = False
    denied = False
    try:
        disabled_by_default = not get_settings().ares_legacy_dashboard_enabled
        try:
            async with dashboard_app.router.lifespan_context(dashboard_app):
                pass
        except Exception as exc:
            denied = (
                type(exc) is RuntimeError
                and str(exc) == _LEGACY_DASHBOARD_DISABLED
            )

        _require_fixed(
            disabled_by_default,
            "legacy dashboard enablement did not default to false",
        )
        _require_fixed(denied, "debug mode enabled the legacy dashboard by default")
    finally:
        clear_settings_cache()


@pytest.mark.asyncio
async def test_invalid_legacy_dashboard_setting_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ares.api.dashboard.app import dashboard_app
    from ares.core.config import clear_settings_cache

    monkeypatch.setenv("ARES_LEGACY_DASHBOARD_ENABLED", "not-a-boolean")
    monkeypatch.setenv("ARES_DEBUG", "true")
    clear_settings_cache()
    started = False
    rejected = False
    try:
        try:
            async with dashboard_app.router.lifespan_context(dashboard_app):
                started = True
        except Exception:
            rejected = True

        _require_fixed(not started, "invalid legacy configuration started the app")
        _require_fixed(rejected, "invalid legacy configuration was not rejected")
    finally:
        clear_settings_cache()


@pytest.mark.asyncio
async def test_legacy_imports_and_main_topology_remain_available_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ares.core.config import clear_settings_cache

    _set_legacy_dashboard_policy(monkeypatch, enabled=False, debug=False)
    try:
        dashboard_package = importlib.import_module("ares.api.dashboard")
        dashboard_module = importlib.import_module("ares.api.dashboard.app")
        server_module = importlib.import_module("ares.api.server")

        import_ok = (
            dashboard_package.dashboard_app is dashboard_module.dashboard_app
            and callable(dashboard_package.broadcast_finding)
        )
        legacy_is_mounted = any(
            getattr(route, "app", None) is dashboard_module.dashboard_app
            for route in server_module.app.routes
        )
        separate_lifespans = (
            server_module.app.router.lifespan_context
            is not dashboard_module.dashboard_app.router.lifespan_context
        )

        _require_fixed(import_ok, "legacy imports were blocked by the execution guard")
        _require_fixed(
            not legacy_is_mounted,
            "main application unexpectedly mounted the legacy dashboard",
        )
        _require_fixed(
            separate_lifespans,
            "main application unexpectedly uses the legacy dashboard lifespan",
        )
    finally:
        clear_settings_cache()


@pytest.mark.asyncio
async def test_legacy_state_assignment_cannot_bypass_guard_or_open_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ares.api.dashboard import app as dashboard_module
    from ares.core.config import clear_settings_cache

    _set_legacy_dashboard_policy(monkeypatch, enabled=False, debug=False)
    state = dashboard_module.dashboard_app.state
    had_db = hasattr(state, "db")
    previous_db = getattr(state, "db", None)
    shared_db = object()
    resource_calls = 0

    async def resource_probe():
        nonlocal resource_calls
        resource_calls += 1

    monkeypatch.setattr(dashboard_module, "_get_db", resource_probe)
    state.db = shared_db
    denied = False
    try:
        try:
            async with dashboard_module.dashboard_app.router.lifespan_context(
                dashboard_module.dashboard_app
            ):
                pass
        except Exception as exc:
            denied = (
                type(exc) is RuntimeError
                and str(exc) == _LEGACY_DASHBOARD_DISABLED
            )

        _require_fixed(denied, "shared database state bypassed the legacy guard")
        _require_fixed(
            resource_calls == 0,
            "legacy resource initialization ran before the guard",
        )
        _require_fixed(
            state.db is shared_db,
            "denied legacy startup changed shared database ownership",
        )
    finally:
        if had_db:
            state.db = previous_db
        else:
            del state.db
        clear_settings_cache()


@pytest.mark.asyncio
async def test_legacy_enabled_lifecycle_preserves_shared_state_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ares.api.dashboard.app import dashboard_app
    from ares.core.config import clear_settings_cache

    state = dashboard_app.state
    had_db = hasattr(state, "db")
    previous_db = getattr(state, "db", None)
    shared_db = object()
    state.db = shared_db
    denied = False
    entered = 0
    try:
        _set_legacy_dashboard_policy(monkeypatch, enabled=False, debug=False)
        try:
            async with dashboard_app.router.lifespan_context(dashboard_app):
                pass
        except Exception as exc:
            denied = (
                type(exc) is RuntimeError
                and str(exc) == _LEGACY_DASHBOARD_DISABLED
            )

        _set_legacy_dashboard_policy(monkeypatch, enabled=True, debug=True)
        async with dashboard_app.router.lifespan_context(dashboard_app):
            entered += 1
            _require_fixed(
                state.db is shared_db,
                "enabled legacy startup replaced shared database state",
            )

        _require_fixed(denied, "default legacy startup was not denied")
        _require_fixed(entered == 1, "enabled legacy lifespan did not enter once")
        _require_fixed(
            state.db is shared_db,
            "legacy shutdown closed or replaced a resource it did not own",
        )
    finally:
        if had_db:
            state.db = previous_db
        else:
            del state.db
        clear_settings_cache()


def _make_repo(root: Path, *, node_modules: bool = True) -> None:
    (root / "pyproject.toml").write_text("[project]\nname='ares-test'\n", encoding="utf-8")
    frontend = root / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"scripts":{"dev":"vite"}}\n', encoding="utf-8")
    if node_modules:
        (frontend / "node_modules").mkdir()


def test_find_repo_root_discovers_parent(tmp_path, monkeypatch):
    from ares.cli.typer_main import find_repo_root

    _make_repo(tmp_path)
    child = tmp_path / "docs" / "nested"
    child.mkdir(parents=True)
    monkeypatch.chdir(child)

    assert find_repo_root() == tmp_path


def test_resolve_npm_command_windows_prefers_program_files(tmp_path):
    from ares.cli.typer_main import resolve_npm_command

    preferred = tmp_path / "npm.cmd"
    preferred.write_text("@echo off\n", encoding="utf-8")

    def fake_which(name: str) -> str | None:
        return f"fallback-{name}"

    assert resolve_npm_command(
        os_name="nt",
        program_files_npm=preferred,
        which=fake_which,
    ) == str(preferred)


def test_dashboard_dev_command_builders():
    from ares.cli.typer_main import build_backend_command, build_frontend_command

    assert build_backend_command(
        "127.0.0.1",
        8080,
        reload=False,
        python_executable="python-test",
    ) == [
        "python-test",
        "-m",
        "uvicorn",
        "ares.api.server:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8080",
    ]
    assert "--reload" in build_backend_command("127.0.0.1", 8080)
    assert build_frontend_command("npm.cmd", "127.0.0.1", 5173) == [
        "npm.cmd",
        "run",
        "dev",
        "--",
        "--host",
        "127.0.0.1",
        "--port",
        "5173",
        "--strictPort",
    ]


def test_dashboard_dev_missing_node_modules_prints_clear_instruction(tmp_path, capsys):
    from ares.cli.typer_main import _run_dashboard_dev

    _make_repo(tmp_path, node_modules=False)

    with pytest.raises(typer.Exit):
        _run_dashboard_dev(
            root=tmp_path,
            open_browser=False,
            port_in_use_func=lambda host, port: False,
        )

    output = capsys.readouterr().out
    assert "frontend/node_modules is missing" in output
    assert "npm ci" in output
    assert "--install" in output


def test_dashboard_dev_rejects_occupied_port_before_starting_processes(tmp_path, capsys):
    from ares.cli.typer_main import _run_dashboard_dev

    _make_repo(tmp_path)
    started = []

    def fail_if_started(*args, **kwargs):
        started.append((args, kwargs))
        raise AssertionError("dashboard process should not start")

    with pytest.raises(typer.Exit) as exc_info:
        _run_dashboard_dev(
            root=tmp_path,
            open_browser=False,
            popen_factory=fail_if_started,
            port_in_use_func=lambda host, port: port == 5173,
        )

    assert exc_info.value.exit_code == 1
    assert started == []
    output = capsys.readouterr().out
    assert "frontend port 127.0.0.1:5173 is already occupied" in output
    assert "stale Python or Node dashboard process" in output
    assert "Get-Process python,node" in output


def test_dashboard_dev_install_runs_npm_ci_when_requested(tmp_path):
    from ares.cli.typer_main import _ensure_frontend_dependencies

    _make_repo(tmp_path, node_modules=False)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    _ensure_frontend_dependencies(
        tmp_path / "frontend",
        "npm.cmd",
        install=True,
        run_func=fake_run,
    )

    assert calls == [
        (
            ["npm.cmd", "ci"],
            {"cwd": str(tmp_path / "frontend"), "check": False},
        )
    ]


def test_dashboard_dev_launches_both_processes_and_cleans_up(monkeypatch, tmp_path, capsys):
    from ares.cli import typer_main

    _make_repo(tmp_path, node_modules=True)
    (tmp_path / ".env").write_text(
        "ARES_DEFAULT_ADMIN_PASSWORD=DoNotPrintThisSecret123!\n",
        encoding="utf-8",
    )

    launched = []
    opened = []
    taskkill_calls = []

    class FakeProcess:
        _next_pid = 4000

        def __init__(self, command, **kwargs):
            self.command = command
            self.kwargs = kwargs
            self.pid = FakeProcess._next_pid
            FakeProcess._next_pid += 1
            self.stdout = ["frontend page reload src/api/client.test.ts\n"]
            self.stopped = False
            self.signals = []
            launched.append(self)

        def poll(self):
            return 0 if self.stopped else None

        def send_signal(self, sig):
            self.signals.append(sig)
            self.stopped = True

        def terminate(self):
            self.stopped = True

        def wait(self, timeout=None):
            self.stopped = True
            return 0

        def kill(self):
            self.stopped = True

    def fake_popen(command, **kwargs):
        return FakeProcess(command, **kwargs)

    def interrupt(_seconds: float):
        raise KeyboardInterrupt

    monkeypatch.setattr(typer_main, "resolve_npm_command", lambda os_name=None: "npm.cmd")

    def fake_run(command, **kwargs):
        taskkill_calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(typer_main.subprocess, "run", fake_run)

    exit_code = typer_main._run_dashboard_dev(
        root=tmp_path,
        os_name="nt",
        open_browser=False,
        popen_factory=fake_popen,
        port_in_use_func=lambda host, port: False,
        wait_for_port_func=lambda *args, **kwargs: True,
        open_browser_func=lambda url: opened.append(url),
        sleep_func=interrupt,
    )

    assert exit_code == 0
    assert len(launched) == 2
    assert launched[0].command[:4] == [
        typer_main.sys.executable,
        "-m",
        "uvicorn",
        "ares.api.server:app",
    ]
    assert launched[1].command == [
        "npm.cmd",
        "run",
        "dev",
        "--",
        "--host",
        "127.0.0.1",
        "--port",
        "5173",
        "--strictPort",
    ]
    assert launched[0].kwargs["cwd"] == str(tmp_path)
    assert launched[1].kwargs["cwd"] == str(tmp_path / "frontend")
    assert opened == []
    assert all(process.stopped for process in launched)
    assert [call[0][:2] for call in taskkill_calls] == [
        ["taskkill", "/PID"],
        ["taskkill", "/PID"],
    ]
    assert all("/T" in call[0] and "/F" in call[0] for call in taskkill_calls)

    output = capsys.readouterr().out
    assert "page reload src/api/client.test.ts" in output
    assert "Dashboard URL: http://127.0.0.1:5173/dashboard/" in output
    assert "Login username: admin" in output
    assert (
        "Password source: ARES_DEFAULT_ADMIN_PASSWORD from current environment or .env"
        in output
    )
    assert "DoNotPrintThisSecret123!" not in output


def test_dashboard_dev_backend_exit_terminates_frontend(monkeypatch, tmp_path, capsys):
    from ares.cli import typer_main

    _make_repo(tmp_path)
    launched = []
    taskkill_calls = []

    class FakeProcess:
        _next_pid = 5000

        def __init__(self, command, exit_code):
            self.command = command
            self.pid = FakeProcess._next_pid
            FakeProcess._next_pid += 1
            self.exit_code = exit_code
            self.stopped = False
            self.stdout = []

        def poll(self):
            if self.stopped:
                return 0
            return self.exit_code

        def wait(self, timeout=None):
            self.stopped = True
            return 0

        def kill(self):
            self.stopped = True

    def fake_popen(command, **kwargs):
        process = FakeProcess(command, 3 if not launched else None)
        launched.append(process)
        return process

    def fake_run(command, **kwargs):
        taskkill_calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(typer_main, "resolve_npm_command", lambda os_name=None: "npm.cmd")
    monkeypatch.setattr(typer_main.subprocess, "run", fake_run)

    exit_code = typer_main._run_dashboard_dev(
        root=tmp_path,
        os_name="nt",
        open_browser=False,
        popen_factory=fake_popen,
        port_in_use_func=lambda host, port: False,
    )

    assert exit_code == 3
    assert len(launched) == 2
    assert launched[1].stopped
    assert any(command[:2] == ["taskkill", "/PID"] for command in taskkill_calls)
    assert "Backend process exited with code 3" in capsys.readouterr().out


def test_dashboard_dev_frontend_exit_terminates_backend(monkeypatch, tmp_path, capsys):
    from ares.cli import typer_main

    _make_repo(tmp_path)
    launched = []
    taskkill_calls = []

    class FakeProcess:
        _next_pid = 6000

        def __init__(self, command, exit_code):
            self.command = command
            self.pid = FakeProcess._next_pid
            FakeProcess._next_pid += 1
            self.exit_code = exit_code
            self.stopped = False
            self.stdout = []

        def poll(self):
            if self.stopped:
                return 0
            return self.exit_code

        def wait(self, timeout=None):
            self.stopped = True
            return 0

        def kill(self):
            self.stopped = True

    def fake_popen(command, **kwargs):
        process = FakeProcess(command, None if not launched else 4)
        launched.append(process)
        return process

    def fake_run(command, **kwargs):
        taskkill_calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(typer_main, "resolve_npm_command", lambda os_name=None: "npm.cmd")
    monkeypatch.setattr(typer_main.subprocess, "run", fake_run)

    exit_code = typer_main._run_dashboard_dev(
        root=tmp_path,
        os_name="nt",
        open_browser=False,
        popen_factory=fake_popen,
        port_in_use_func=lambda host, port: False,
    )

    assert exit_code == 4
    assert len(launched) == 2
    assert launched[0].stopped
    assert any(command[:2] == ["taskkill", "/PID"] for command in taskkill_calls)
    assert "Frontend process exited with code 4" in capsys.readouterr().out
