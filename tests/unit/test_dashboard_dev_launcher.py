from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import typer


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
    ]


def test_dashboard_dev_missing_node_modules_prints_clear_instruction(tmp_path, capsys):
    from ares.cli.typer_main import _run_dashboard_dev

    _make_repo(tmp_path, node_modules=False)

    with pytest.raises(typer.Exit):
        _run_dashboard_dev(root=tmp_path, open_browser=False)

    output = capsys.readouterr().out
    assert "frontend/node_modules is missing" in output
    assert "npm ci" in output
    assert "--install" in output


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
            self.stdout = []
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
    assert "Dashboard URL: http://127.0.0.1:5173/dashboard/" in output
    assert "Login username: admin" in output
    assert (
        "Password source: ARES_DEFAULT_ADMIN_PASSWORD from current environment or .env"
        in output
    )
    assert "DoNotPrintThisSecret123!" not in output
