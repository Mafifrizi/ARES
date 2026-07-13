from __future__ import annotations

import importlib.metadata
import os
import sys
import types
from collections import namedtuple
from pathlib import Path

import pytest
import typer


VersionInfo = namedtuple("version_info", "major minor micro releaselevel serial")


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


def test_doctor_guides_windows_ad_impacket_to_python_312(monkeypatch, tmp_path, capsys):
    from ares.cli.typer_main import doctor

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setattr(sys, "version_info", VersionInfo(3, 11, 9, "final", 0))

    try:
        doctor()
    except typer.Exit:
        pass

    output = capsys.readouterr().out
    assert "Python 3.11.9" in output
    assert "Package metadata permits Python 3.10-3.12" in output
    normalized = " ".join(output.split())
    assert "Windows AD/Impacket" in normalized
    assert "Python 3.12" in normalized
    assert "Windows AD/Impacket Python" in output
    assert "Python 3.12.x" in output


def test_doctor_reports_pdf_capability(monkeypatch, tmp_path, capsys):
    from ares.cli.typer_main import doctor
    from ares.modules.reporting import report_gen

    browser = tmp_path / "chrome.exe"
    browser.write_text("", encoding="utf-8")
    fake_weasyprint = types.ModuleType("weasyprint")
    fake_weasyprint.__version__ = "test-pdf"

    class FakeReportGenerator:
        def __init__(self) -> None:
            self.output_dir = tmp_path / "reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        @staticmethod
        def _pdf_browser_candidates() -> list[Path]:
            return [browser]

        @staticmethod
        def _probe_writable_dir(path: Path) -> None:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()

        def _create_pdf_browser_workspace(self) -> tuple[Path, Path, Path]:
            work_path = tmp_path / "pdf-work"
            profile_dir = work_path / "profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            return work_path, profile_dir, work_path / "report.html"

        @staticmethod
        def _windows_session_is_elevated() -> bool:
            return False

        def _pdf_browser_skip_reason(self, browser: Path) -> str:
            return ""

        def _run_pdf_browser(self, cmd: list[str]):  # pragma: no cover - must not run
            raise AssertionError("doctor must not launch a PDF browser")

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setenv("ARES_PDF_BROWSER", str(browser))
    monkeypatch.setitem(sys.modules, "weasyprint", fake_weasyprint)
    monkeypatch.setattr(report_gen, "ReportGenerator", FakeReportGenerator)

    try:
        doctor()
    except typer.Exit:
        pass

    output = capsys.readouterr().out
    assert "PDF WeasyPrint" in output
    assert "test-pdf" in output
    assert "PDF ARES_PDF_BROWSER" in output
    assert "chrome.exe" in output
    assert "exists=True" in output
    assert "PDF browser detected" in output
    assert "PDF browser profile temp dir writable" in output
    assert "PDF report output dir writable" in output


def test_doctor_reports_windows_weasyprint_native_dependency_hint(
    monkeypatch, tmp_path, capsys
):
    import importlib

    from ares.cli.typer_main import doctor
    from ares.modules.reporting import report_gen
    from ares.modules.reporting.report_gen import WINDOWS_WEASYPRINT_NATIVE_HINT

    real_import_module = importlib.import_module
    browser = tmp_path / "msedge.exe"
    browser.write_text("", encoding="utf-8")

    class FakeReportGenerator:
        def __init__(self) -> None:
            self.output_dir = tmp_path / "reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        @staticmethod
        def _pdf_browser_candidates() -> list[Path]:
            return [browser]

        @staticmethod
        def _pdf_backend_failure_detail(exc: BaseException) -> str:
            return f"{WINDOWS_WEASYPRINT_NATIVE_HINT} Original error: {exc}"

        @staticmethod
        def _probe_writable_dir(path: Path) -> None:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()

        @staticmethod
        def _windows_session_is_elevated() -> bool:
            return False

        def _pdf_browser_skip_reason(self, browser: Path) -> str:
            return ""

        def _create_pdf_browser_workspace(self) -> tuple[Path, Path, Path]:
            work_path = tmp_path / "pdf-work"
            profile_dir = work_path / "profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            return work_path, profile_dir, work_path / "report.html"

    def fake_import_module(import_name: str, package: str | None = None):
        if import_name == "weasyprint":
            raise OSError("cannot load library 'libgobject-2.0-0'")
        return real_import_module(import_name, package)

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setattr(report_gen, "ReportGenerator", FakeReportGenerator)
    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    try:
        doctor()
    except typer.Exit:
        pass

    output = capsys.readouterr().out
    assert "PDF WeasyPrint" in output
    assert "native GTK/Pango" in output
    assert "libgobject-2.0-0" in output


def test_doctor_pdf_smoke_uses_report_generator_and_verifies_pdf(
    tmp_path, capsys
):
    from ares.cli.typer_main import _run_pdf_smoke_check

    calls = {"smoke": 0}
    records: list[tuple[str, str, str]] = []

    class FakeReportGenerator:
        def __init__(self) -> None:
            self.output_dir = tmp_path / "reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        def generate_pdf_smoke(self) -> Path:
            calls["smoke"] += 1
            smoke_path = self.output_dir / "ares_pdf_smoke.pdf"
            smoke_path.write_bytes(b"%PDF-1.4\n% smoke\n")
            return smoke_path

    def fake_check(label: str, status: str, detail: str = "") -> None:
        records.append((label, status, detail))
        print(f"[{status.upper()}] {label} {detail}")

    _run_pdf_smoke_check(FakeReportGenerator(), fake_check)

    output = capsys.readouterr().out
    assert "PDF smoke" in output
    assert "ares_pdf_smoke.pdf" in output
    assert "[OK] PDF smoke" in output
    assert "bytes=" in output
    assert calls == {"smoke": 1}
    assert records[0][0] == "PDF smoke"
    assert records[0][1] == "ok"


def test_pdf_smoke_check_reports_invalid_pdf_artifact(tmp_path, capsys):
    from ares.cli.typer_main import _run_pdf_smoke_check

    records: list[tuple[str, str, str]] = []

    class FakeReportGenerator:
        def generate_pdf_smoke(self) -> Path:
            smoke_path = tmp_path / "ares_pdf_smoke.pdf"
            smoke_path.write_bytes(b"not-a-pdf\n")
            return smoke_path

    def fake_check(label: str, status: str, detail: str = "") -> None:
        records.append((label, status, detail))
        print(f"[{status.upper()}] {label} {detail}")

    _run_pdf_smoke_check(FakeReportGenerator(), fake_check)

    output = capsys.readouterr().out
    assert "PDF smoke" in output
    assert "ares_pdf_smoke.pdf" in output
    assert "[FAIL] PDF smoke" in output
    assert "not a PDF" in output
    assert records == [
        ("PDF smoke", "fail", f"{tmp_path / 'ares_pdf_smoke.pdf'} is not a PDF")
    ]


def test_doctor_pdf_smoke_option_calls_helper(monkeypatch, tmp_path):
    import importlib

    from ares.cli import typer_main
    from ares.modules.reporting import report_gen

    calls = {"helper": 0}
    real_import_module = importlib.import_module
    browser = tmp_path / "msedge.exe"
    browser.write_text("", encoding="utf-8")
    fake_weasyprint = types.ModuleType("weasyprint")
    fake_weasyprint.__version__ = "test-pdf"

    class FakeReportGenerator:
        def __init__(self) -> None:
            self.output_dir = tmp_path / "reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        @staticmethod
        def _pdf_browser_candidates() -> list[Path]:
            return [browser]

        @staticmethod
        def _probe_writable_dir(path: Path) -> None:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()

        @staticmethod
        def _windows_session_is_elevated() -> bool:
            return False

        def _pdf_browser_skip_reason(self, browser: Path) -> str:
            return ""

        def _create_pdf_browser_workspace(self) -> tuple[Path, Path, Path]:
            work_path = tmp_path / "pdf-work"
            profile_dir = work_path / "profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            return work_path, profile_dir, work_path / "report.html"

        def _run_pdf_browser(self, cmd: list[str]):  # pragma: no cover - must not run
            raise AssertionError("doctor must not launch a PDF browser directly")

    def fake_import_module(import_name: str, package: str | None = None):
        if import_name == "weasyprint":
            return fake_weasyprint
        return real_import_module(import_name, package)

    def fake_pdf_smoke_check(pdf_generator: object, check: object) -> None:
        calls["helper"] += 1
        assert isinstance(pdf_generator, FakeReportGenerator)

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ARES_SECRET_KEY=test\n", encoding="utf-8")
    monkeypatch.setattr(report_gen, "ReportGenerator", FakeReportGenerator)
    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    monkeypatch.setattr(typer_main, "_run_pdf_smoke_check", fake_pdf_smoke_check)

    try:
        typer_main.doctor(pdf_smoke=True)
    except typer.Exit:
        pass

    assert calls == {"helper": 1}


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


def test_python_setup_rejects_python_313_before_writing_env(tmp_path, capsys):
    from ares.cli.typer_main import _run_python_setup

    (tmp_path / ".env.example").write_text(
        "ARES_SECRET_KEY=\nARES_ENCRYPTION_KEY=\nARES_DEFAULT_ADMIN_PASSWORD=\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit):
        _run_python_setup(
            root=tmp_path,
            platform_name="win32",
            os_name="nt",
            version_info=VersionInfo(3, 13, 0, "final", 0),
        )

    output = capsys.readouterr().out
    assert "Python: 3.13.0" in output
    assert "Python 3.10-3.12 is required" in output
    assert "Python 3.12.x" in output
    assert not (tmp_path / ".env").exists()
