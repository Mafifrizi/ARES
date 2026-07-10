from __future__ import annotations

import importlib.metadata
import os
import sys
import types

import typer


def test_doctor_uses_distribution_metadata_for_impacket(monkeypatch, tmp_path, capsys):
    from ares.cli.typer_main import doctor

    fake_impacket = types.ModuleType("impacket")
    fake_paramiko = types.ModuleType("paramiko")
    fake_paramiko.__version__ = "3.4.0"

    def fake_version(package_name: str) -> str:
        if package_name == "impacket":
            return "0.13.1"
        raise importlib.metadata.PackageNotFoundError(package_name)

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    monkeypatch.setitem(sys.modules, "impacket", fake_impacket)
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    monkeypatch.setitem(sys.modules, "ldap3", None)

    doctor()

    output = capsys.readouterr().out
    assert "impacket 0.13.1" in output
    assert "too old (0.0.0)" not in output
    assert "ares-redteam[ad]" in output


def test_doctor_reports_broken_optional_import_and_continues(monkeypatch, tmp_path, capsys):
    import importlib

    from ares.cli.typer_main import doctor

    real_import_module = importlib.import_module
    fake_impacket = types.ModuleType("impacket")
    fake_impacket.__version__ = "0.13.1"

    def fake_version(package_name: str) -> str:
        if package_name == "impacket":
            return "0.13.1"
        raise importlib.metadata.PackageNotFoundError(package_name)

    def fake_import_module(import_name: str, package: str | None = None):
        if import_name == "impacket":
            raise OSError(22, "Invalid argument")
        return real_import_module(import_name, package)

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "impacket", fake_impacket)
    monkeypatch.setattr(importlib.metadata, "version", fake_version)
    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    try:
        doctor()
    except typer.Exit:
        pass

    output = capsys.readouterr().out
    assert "Traceback" not in output
    assert "impacket" in output
    assert "OSError" in output
    assert "Invalid argument" in output
    assert "paramiko" in output
    assert "socket AF_INET/389" in output


def test_setup_entrypoint_routes_to_python_native_setup(monkeypatch):
    from ares.cli import typer_main

    calls = []
    monkeypatch.setattr(typer_main, "_run_python_setup", lambda: calls.append("called"))

    typer_main.setup_entrypoint()

    assert calls == ["called"]


def test_python_setup_windows_skips_bash_and_uses_valid_paths(monkeypatch, tmp_path, capsys):
    from ares.cli.typer_main import _run_python_setup

    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "setup.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "ARES_SECRET_KEY=\nARES_ENCRYPTION_KEY=\nARES_DEFAULT_ADMIN_PASSWORD=\n",
        encoding="utf-8",
    )

    def forbidden_execv(*args):
        raise AssertionError("ares-setup must not exec bash")

    monkeypatch.setattr(os, "execv", forbidden_execv)

    _run_python_setup(root=tmp_path, platform_name="win32", os_name="nt")

    output = capsys.readouterr().out
    assert "ARES Setup" in output
    assert "Windows" in output
    assert "scripts/setup.sh is POSIX-only and was skipped on Windows" in output
    assert "/bin/bash" not in output
    assert "C:Users" not in output
    assert (tmp_path / ".env").exists()


def test_python_setup_posix_keeps_shell_helper_optional(tmp_path, capsys):
    from ares.cli.typer_main import _run_python_setup

    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "setup.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "ARES_SECRET_KEY=\nARES_ENCRYPTION_KEY=\nARES_DEFAULT_ADMIN_PASSWORD=\n",
        encoding="utf-8",
    )

    _run_python_setup(root=tmp_path, platform_name="linux", os_name="posix")

    output = capsys.readouterr().out
    assert "Linux" in output
    assert "Developer helper available: scripts/setup.sh (optional)." in output
    assert "/bin/bash" not in output
    assert (tmp_path / ".env").exists()
