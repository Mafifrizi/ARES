"""Tests for ARES v6 — DB layer, plugin loader, and report generation.

Note: AresEngine tests are in tests/unit/test_engine.py
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from unittest.mock import AsyncMock, patch

import pytest

import ares.core.plugin.loader as plugin_loader_module
from ares.core.campaign import Campaign, Finding, NoiseProfile, Severity, ScopeEntry
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.plugin.loader import ModuleRegistry, PluginLoader
from ares.db.database import AresDatabase, Credential, Host, Loot
from ares.modules.base import BaseModule
from ares.modules.reporting.report_gen import (
    BROWSER_PDF_TIMEOUT_SECONDS,
    ReportDependencyError,
    ReportGenerator,
    WINDOWS_EDGE_ELEVATED_PDF_MESSAGE,
    WINDOWS_WEASYPRINT_NATIVE_HINT,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="test-secret-key-min32-chars-xxxxxx",
        ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
    )


@pytest.fixture
def campaign() -> Campaign:
    return Campaign(
        name="Test Campaign",
        client="ACME",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
        operator="tester",
    )


@pytest.fixture
def confirmed_finding() -> Finding:
    return Finding(
        title="Test Finding",
        description="A test finding for unit tests",
        severity=Severity.HIGH,
        mitre_technique="T1558.003",
        mitre_tactic="Credential Access",
        confidence=0.9,
        validated=True,
        module_id="ad.kerberoast",
        evidence={"count": 3},
    )


@pytest.fixture
async def db(settings: AresSettings, tmp_path: Path) -> AresDatabase:
    db_path = tmp_path / "test_ares.db"
    db = AresDatabase(str(db_path), settings.encryption_key_value)
    await db.connect()
    yield db
    await db.close()


# ── Plugin Loader Tests ───────────────────────────────────────────────────────

class TestPluginLoader:
    def test_loads_builtin_modules(self) -> None:
        loader = PluginLoader()
        registry = loader.load_all()
        assert len(registry) > 0

    def test_known_modules_present(self) -> None:
        loader = PluginLoader()
        registry = loader.load_all()
        expected = ["ad.kerberoast", "ad.asreproast", "linux.container", "cloud.aws"]
        for mid in expected:
            assert mid in registry, f"Expected module '{mid}' not found"

    def test_registry_by_category(self) -> None:
        loader = PluginLoader()
        registry = loader.load_all()
        ad_mods = registry.by_category("ad")
        assert len(ad_mods) >= 4

    def test_external_dir_empty_is_ok(self, tmp_path: Path) -> None:
        loader = PluginLoader()
        loader._load_external(str(tmp_path))  # Should not raise
        assert loader.errors == []

    def test_external_dir_containment_rejects_same_prefix_sibling(
        self, tmp_path: Path
    ) -> None:
        allowed_base = (tmp_path / "plugins").resolve()
        child_dir = (allowed_base / "child").resolve()
        sibling_dir = (tmp_path / "plugins_evil").resolve()

        child_dir.mkdir(parents=True)
        sibling_dir.mkdir()

        assert plugin_loader_module._is_path_within_base(allowed_base, allowed_base)
        assert plugin_loader_module._is_path_within_base(child_dir, allowed_base)
        assert not plugin_loader_module._is_path_within_base(
            sibling_dir, allowed_base
        )

    def test_external_plugin_loaded(self, tmp_path: Path) -> None:
        """Write a valid external plugin and verify it's discovered."""
        plugin_code = '''
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule
from typing import Any

class ExternalTestModule(BaseModule):
    MODULE_ID = "external.test"
    MODULE_NAME = "External Test"
    MODULE_CATEGORY = "test"
    MODULE_DESCRIPTION = "External plugin for testing"
    async def run(self, **kwargs: Any):
        return [], {}
'''
        (tmp_path / "external_test_module.py").write_text(plugin_code)
        loader = PluginLoader()
        registry = loader.load_all(external_dir=str(tmp_path))
        assert "external.test" in registry

    def test_invalid_plugin_does_not_crash_loader(self, tmp_path: Path) -> None:
        """Broken plugin should not crash the loader."""
        (tmp_path / "broken.py").write_text("this is not valid python }{}{")
        loader = PluginLoader()
        loader.load_all(external_dir=str(tmp_path))
        assert len(loader.errors) >= 1

    def test_metadata_has_required_fields(self) -> None:
        loader = PluginLoader()
        registry = loader.load_all()
        for m in registry.list_metadata():
            assert "id" in m
            assert "category" in m
            assert "description" in m
            assert "source" in m



# ── Database Tests ────────────────────────────────────────────────────────────

class TestDatabase:
    @pytest.mark.asyncio
    async def test_save_and_get_campaign(self, db: AresDatabase, campaign: Campaign) -> None:
        await db.save_campaign(campaign)
        result = await db.get_campaign(campaign.id)
        assert result is not None
        assert result["name"] == campaign.name
        assert result["client"] == campaign.client

    @pytest.mark.asyncio
    async def test_save_and_get_finding(
        self, db: AresDatabase, campaign: Campaign, confirmed_finding: Finding
    ) -> None:
        await db.save_campaign(campaign)
        await db.save_finding(campaign.id, confirmed_finding, confirmed_finding.module_id)
        findings, total = await db.list_findings(campaign.id)
        assert total == 1
        assert len(findings) == 1
        assert findings[0]["title"] == confirmed_finding.title
        assert findings[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_finding_stats(
        self, db: AresDatabase, campaign: Campaign, confirmed_finding: Finding
    ) -> None:
        await db.save_campaign(campaign)
        confirmed_finding.validated = True
        confirmed_finding.false_positive = False
        await db.save_finding(campaign.id, confirmed_finding, confirmed_finding.module_id)
        stats = await db.get_finding_stats(campaign.id)
        assert stats["total"] == 1
        assert stats["high"] == 1

    @pytest.mark.asyncio
    async def test_upsert_host(self, db: AresDatabase, campaign: Campaign) -> None:
        await db.save_campaign(campaign)
        host = Host(
            campaign_id=campaign.id,
            ip_address="10.0.0.1",
            hostname="dc01",
            os="Windows Server 2022",
            is_dc=True,
        )
        host_id = await db.upsert_host(host)
        hosts = await db.get_hosts(campaign.id)
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "dc01"
        assert hosts[0]["is_dc"] == 1

    @pytest.mark.asyncio
    async def test_credential_encryption(self, db: AresDatabase, campaign: Campaign) -> None:
        """Credential secrets must be encrypted at rest."""
        await db.save_campaign(campaign)
        cred = Credential(
            campaign_id=campaign.id,
            username="administrator",
            secret="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            cred_type="ntlm",
            domain="CORP",
        )
        await db.save_credential(cred)

        # Verify raw DB row is encrypted (not plaintext)
        async with db.conn.execute(
            "SELECT secret_enc FROM credentials WHERE username=?", ("administrator",)
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert "8846f7eaee8fb117" not in (row[0] or "")  # Must not be plaintext

        # Decrypt and verify
        decrypted = await db.get_credentials(campaign.id, decrypt=True)
        assert decrypted[0]["secret"] == cred.secret

    @pytest.mark.asyncio
    async def test_save_loot(self, db: AresDatabase, campaign: Campaign) -> None:
        await db.save_campaign(campaign)
        item = Loot(
            campaign_id=campaign.id,
            loot_type="hash",
            name="krbtgt_hash",
            content="$krb5tgs$23$*krbtgt*...",
            source_module="ad.kerberoast",
        )
        await db.save_loot(item)
        loot = await db.get_loot(campaign.id, decrypt=True)
        assert len(loot) == 1
        assert loot[0]["name"] == "krbtgt_hash"

    @pytest.mark.asyncio
    async def test_campaign_summary(
        self, db: AresDatabase, campaign: Campaign, confirmed_finding: Finding
    ) -> None:
        await db.save_campaign(campaign)
        confirmed_finding.validated = True
        await db.save_finding(campaign.id, confirmed_finding, confirmed_finding.module_id)
        summary = await db.campaign_summary(campaign.id)
        assert "findings" in summary
        assert "host_count" in summary
        assert "credential_count" in summary
        assert "loot_count" in summary

    @pytest.mark.asyncio
    async def test_save_finding_persists_validation_flags(
        self, db: AresDatabase, campaign: Campaign, confirmed_finding: Finding
    ) -> None:
        await db.save_campaign(campaign)
        confirmed_finding.validated = True
        confirmed_finding.false_positive = False
        await db.save_finding(campaign.id, confirmed_finding, confirmed_finding.module_id)

        confirmed = await db.get_findings(campaign.id, confirmed_only=True)

        assert len(confirmed) == 1
        assert confirmed[0]["id"] == confirmed_finding.id
        assert confirmed[0]["validated"] == 1
        assert confirmed[0]["false_positive"] == 0


# ── Reporting Tests ───────────────────────────────────────────────────────────

class TestReportGenerator:
    @pytest.fixture
    def campaign_with_findings(self, campaign: Campaign, confirmed_finding: Finding) -> Campaign:
        campaign.add_finding(confirmed_finding)
        return campaign

    def test_generate_json(self, campaign_with_findings: Campaign, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(campaign_with_findings, fmt="json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert "campaign" in data
        assert "findings" in data
        assert "summary" in data
        assert data["summary"]["total_confirmed"] >= 0

    def test_generate_html(self, campaign_with_findings: Campaign, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(campaign_with_findings, fmt="html")
        assert path.exists()
        html = path.read_text()
        assert "ARES" in html
        assert campaign_with_findings.name in html

    def test_generate_markdown(self, campaign_with_findings: Campaign, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(campaign_with_findings, fmt="markdown")
        assert path.exists()
        md = path.read_text()
        assert "# ARES Report" in md

    def test_generate_all(
        self,
        campaign_with_findings: Campaign,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_pdf(self: ReportGenerator, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
            path = self._out(campaign, "pdf")
            path.write_bytes(b"%PDF-1.4\n% unit fake\n")
            return path

        monkeypatch.setattr(ReportGenerator, "_gen_pdf", fake_pdf)
        gen = ReportGenerator(output_dir=str(tmp_path))
        paths = gen.generate_all(campaign_with_findings)
        assert "json" in paths
        assert "html" in paths
        assert "markdown" in paths
        for p in paths.values():
            assert p.exists()

    def test_pdf_browser_timeout_returns_false(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        browser = tmp_path / "chromium"
        browser.write_text("", encoding="utf-8")
        pdf_path = tmp_path / "report.pdf"

        with (
            patch.object(gen, "_pdf_browser_candidates", return_value=[browser]),
            patch.object(
                gen,
                "_run_pdf_browser",
                side_effect=subprocess.TimeoutExpired(
                    cmd=[str(browser)], timeout=BROWSER_PDF_TIMEOUT_SECONDS
                ),
            ) as run_browser,
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is False

        assert run_browser.call_args.args[0][0] == str(browser)
        assert f"{BROWSER_PDF_TIMEOUT_SECONDS}s" in gen._last_pdf_browser_error
        assert not pdf_path.exists()

    def test_pdf_browser_workspace_falls_back_when_first_root_unwritable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        bad_root = tmp_path / "bad-runtime-root"
        good_root = tmp_path / "good-runtime-root"

        def fake_probe(path: Path) -> None:
            if path == bad_root:
                raise OSError("not writable")
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()

        monkeypatch.setattr(
            gen, "_pdf_browser_workspace_roots", lambda: [bad_root, good_root]
        )
        monkeypatch.setattr(gen, "_probe_writable_dir", fake_probe)

        work_path, profile_dir, html_path = gen._create_pdf_browser_workspace()

        assert work_path.parent == good_root
        assert profile_dir == work_path / "profile"
        assert profile_dir.is_dir()
        assert html_path == work_path / "report.html"
        writable_probe = profile_dir / "writable.txt"
        writable_probe.write_text("ok", encoding="utf-8")
        assert writable_probe.read_text(encoding="utf-8") == "ok"

    def test_pdf_browser_fallback_keeps_stable_export_path(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        browser = tmp_path / "chromium"
        browser.write_text("", encoding="utf-8")
        pdf_path = tmp_path / "stable-report.pdf"

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            assert "--headless=new" in command
            assert "--disable-gpu" in command
            assert "--no-first-run" in command
            assert "--no-default-browser-check" in command
            assert "--disable-extensions" in command
            assert "--disable-background-networking" in command
            assert "--disable-sync" in command
            assert "--disable-crash-reporter" in command
            assert "--disable-features=TranslateUI" in command
            assert "--print-to-pdf-no-header" in command
            profile_arg = next(arg for arg in command if arg.startswith("--user-data-dir="))
            profile_path = Path(profile_arg.split("=", 1)[1])
            profile_probe = profile_path / "probe.txt"
            profile_probe.write_text("ok", encoding="utf-8")
            profile_probe.unlink()
            html_uri = command[-1]
            parsed_html_path = unquote(urlparse(html_uri).path)
            if len(parsed_html_path) >= 3 and parsed_html_path[0] == "/" and parsed_html_path[2] == ":":
                parsed_html_path = parsed_html_path[1:]
            assert Path(parsed_html_path).exists()
            pdf_arg = next(arg for arg in command if arg.startswith("--print-to-pdf="))
            Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n%stable\n")
            assert "ares-pdf-browser-" in html_uri
            assert Path(pdf_arg.split("=", 1)[1]) == pdf_path.resolve()
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(gen, "_pdf_browser_candidates", return_value=[browser]),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is True

        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
        assert "ares-pdf-browser-" not in str(pdf_path)

    def test_windows_pdf_browser_order_prefers_edge_before_chrome(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ares.modules.reporting.report_gen as report_gen_module

        edge = tmp_path / "msedge.exe"
        chrome = tmp_path / "chrome.exe"
        edge.write_text("", encoding="utf-8")
        chrome.write_text("", encoding="utf-8")
        monkeypatch.delenv("ARES_PDF_BROWSER", raising=False)
        monkeypatch.setattr(ReportGenerator, "_is_windows_host", staticmethod(lambda: True))
        monkeypatch.setattr(
            ReportGenerator,
            "_windows_browser_default_paths",
            staticmethod(lambda: [edge, chrome]),
        )
        monkeypatch.setattr(report_gen_module.shutil, "which", lambda name: None)

        candidates = ReportGenerator._pdf_browser_candidates()

        assert candidates[:2] == [edge.resolve(), chrome.resolve()]

    def test_pdf_browser_uses_configured_path_first_and_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        configured = tmp_path / "configured-chrome.exe"
        fallback = tmp_path / "msedge.exe"
        configured.write_text("", encoding="utf-8")
        fallback.write_text("", encoding="utf-8")
        monkeypatch.setenv("ARES_PDF_BROWSER", str(configured))
        gen = ReportGenerator(output_dir=str(tmp_path))
        pdf_path = tmp_path / "report.pdf"
        calls: list[Path] = []

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append(Path(command[0]))
            if Path(command[0]) == fallback:
                pdf_arg = next(arg for arg in command if arg.startswith("--print-to-pdf="))
                Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n%fallback\n")
            return subprocess.CompletedProcess(command, 0, "", "")

        def fast_artifact_ready(path: Path) -> bool:
            return path.exists() and path.read_bytes().startswith(b"%PDF-")

        with (
            patch.object(gen, "_pdf_browser_candidates", return_value=[configured, fallback]),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
            patch.object(gen, "_pdf_artifact_ready", side_effect=fast_artifact_ready),
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is True

        assert calls == [configured, fallback]
        assert pdf_path.read_bytes().startswith(b"%PDF-")
        assert "configured-chrome.exe" in gen._last_pdf_browser_error
        assert "no downloadable PDF was created" in gen._last_pdf_browser_error

    def test_strict_configured_pdf_browser_does_not_fall_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        configured = tmp_path / "configured-chrome.exe"
        fallback = tmp_path / "msedge.exe"
        configured.write_text("", encoding="utf-8")
        fallback.write_text("", encoding="utf-8")
        monkeypatch.setenv("ARES_PDF_BROWSER", str(configured))
        gen = ReportGenerator(output_dir=str(tmp_path), strict_pdf_browser=True)
        pdf_path = tmp_path / "report.pdf"
        calls: list[Path] = []

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append(Path(command[0]))
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(gen, "_pdf_browser_candidates", return_value=[configured, fallback]),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
            patch.object(gen, "_pdf_artifact_ready", return_value=False),
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is False

        assert calls == [configured]
        assert not pdf_path.exists()

    def test_pdf_smoke_uses_browser_runtime_and_requires_pdf_header(
        self, tmp_path: Path
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        browser = tmp_path / "msedge.exe"
        browser.write_text("", encoding="utf-8")
        commands: list[list[str]] = []

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            pdf_arg = next(arg for arg in command if arg.startswith("--print-to-pdf="))
            Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n%smoke\n")
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.dict("sys.modules", {"weasyprint": None}),
            patch.object(gen, "_pdf_browser_candidates", return_value=[browser]),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
        ):
            smoke_path = gen.generate_pdf_smoke()

        assert smoke_path == tmp_path / "ares_pdf_smoke.pdf"
        assert smoke_path.read_bytes().startswith(b"%PDF-")
        assert commands

    def test_pdf_browser_profile_unwritable_tries_next_browser(self, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        edge = tmp_path / "msedge.exe"
        chrome = tmp_path / "chrome.exe"
        edge.write_text("", encoding="utf-8")
        chrome.write_text("", encoding="utf-8")
        pdf_path = tmp_path / "report.pdf"
        work_path = tmp_path / "chrome-work"
        profile_dir = work_path / "profile"
        html_path = work_path / "report.html"
        workspace_calls = 0
        commands: list[list[str]] = []

        def fake_workspace() -> tuple[Path, Path, Path]:
            nonlocal workspace_calls
            workspace_calls += 1
            if workspace_calls == 1:
                raise OSError("profile not writable")
            profile_dir.mkdir(parents=True, exist_ok=True)
            return work_path, profile_dir, html_path

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            pdf_arg = next(arg for arg in command if arg.startswith("--print-to-pdf="))
            Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n%chrome\n")
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(gen, "_pdf_browser_candidates", return_value=[edge, chrome]),
            patch.object(gen, "_create_pdf_browser_workspace", side_effect=fake_workspace),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is True

        assert workspace_calls == 2
        assert len(commands) == 1
        assert commands[0][0] == str(chrome)
        assert pdf_path.exists()

    def test_pdf_browser_skips_edge_in_elevated_windows_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        edge = tmp_path / "msedge.exe"
        chrome = tmp_path / "chrome.exe"
        monkeypatch.setattr(ReportGenerator, "_is_windows_host", staticmethod(lambda: True))
        monkeypatch.setattr(gen, "_windows_session_is_elevated", lambda: True)

        assert gen._pdf_browser_skip_reason(edge) == WINDOWS_EDGE_ELEVATED_PDF_MESSAGE
        assert gen._pdf_browser_skip_reason(chrome) == ""

    def test_pdf_browser_does_not_skip_edge_in_normal_windows_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        edge = tmp_path / "msedge.exe"
        monkeypatch.setattr(ReportGenerator, "_is_windows_host", staticmethod(lambda: True))
        monkeypatch.setattr(gen, "_windows_session_is_elevated", lambda: False)

        assert gen._pdf_browser_skip_reason(edge) == ""

    def test_windows_weasyprint_native_failure_is_actionable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ReportGenerator, "_is_windows_host", staticmethod(lambda: True))

        message = ReportGenerator._pdf_backend_failure_detail(
            OSError("cannot load library 'libgobject-2.0-0'")
        )

        assert WINDOWS_WEASYPRINT_NATIVE_HINT in message
        assert "libgobject-2.0-0" in message

    def test_pdf_browser_success_without_artifact_raises_actionable_error(
        self, campaign_with_findings: Campaign, tmp_path: Path
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        browser = tmp_path / "msedge"
        browser.write_text("", encoding="utf-8")

        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.dict("sys.modules", {"weasyprint": None}),
            patch.object(gen, "_pdf_browser_candidates", return_value=[browser]),
            patch.object(gen, "_run_pdf_browser", side_effect=fake_run),
        ):
            with pytest.raises(ReportDependencyError) as exc_info:
                gen.generate(campaign_with_findings, fmt="pdf")

        message = str(exc_info.value)
        assert str(browser) in message
        assert str(tmp_path.resolve()) in message
        assert "User data dir" in message
        assert "HTML input" in message
        assert "Command was:" in message
        assert "no downloadable PDF was created" in message
        assert "ARES_PDF_BROWSER" in message

    def test_unit_guard_blocks_unmocked_real_pdf_browser_launch(
        self, tmp_path: Path
    ) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        browser = tmp_path / "chrome.exe"
        browser.write_text("", encoding="utf-8")
        pdf_path = tmp_path / "report.pdf"

        with patch.object(gen, "_pdf_browser_candidates", return_value=[browser]):
            with pytest.raises(AssertionError, match="must mock PDF browser execution"):
                gen._write_pdf_with_browser("<html></html>", pdf_path)

        assert not pdf_path.exists()

    def test_json_structure_valid(self, campaign_with_findings: Campaign, tmp_path: Path) -> None:
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(campaign_with_findings, fmt="json")
        data = json.loads(path.read_text())
        assert "meta" in data
        assert data["meta"]["schema_version"] == 1
        for f in data["findings"]:
            assert "severity" in f
            assert "confidence" in f
            assert "mitre_technique" in f

    def test_default_reports_redact_full_kerberos_hash_evidence(
        self, campaign: Campaign, tmp_path: Path
    ) -> None:
        full_asrep = "$krb5asrep$23$user@LAB.LOCAL:abcdef0123456789"
        full_tgs = "$krb5tgs$23$*svc-sql$LAB.LOCAL$svc/sql*abcdef0123456789"
        campaign.add_finding(
            Finding(
                title="ASREPRoast Hashes Captured (1)",
                description="Captured one AS-REP hash.",
                severity=Severity.HIGH,
                validated=True,
                module_id="ad.asreproast",
                evidence={"hash_count": 1, "sample_hash": full_asrep},
            )
        )
        campaign.add_finding(
            Finding(
                title="Kerberoast Hashes Captured (1)",
                description="Captured one TGS hash.",
                severity=Severity.CRITICAL,
                validated=True,
                module_id="ad.kerberoast",
                evidence={"hash_count": 1, "accounts": ["svc-sql"], "sample_hash": full_tgs},
            )
        )

        gen = ReportGenerator(output_dir=str(tmp_path))
        json_path = gen.generate(campaign, fmt="json")
        html_path = gen.generate(campaign, fmt="html")

        json_text = json_path.read_text(encoding="utf-8")
        html_text = html_path.read_text(encoding="utf-8")
        assert full_asrep not in json_text
        assert full_tgs not in json_text
        assert full_asrep not in html_text
        assert full_tgs not in html_text
        assert "ASREPRoast Hashes Captured" in json_text
        assert "Kerberoast Hashes Captured" in json_text
        assert "svc-sql" in json_text
        assert "[REDACTED sensitive evidence]" in json_text

    def test_explicit_sensitive_report_option_preserves_hash_evidence(
        self, campaign: Campaign, tmp_path: Path
    ) -> None:
        full_tgs = "$krb5tgs$23$*svc-sql$LAB.LOCAL$svc/sql*abcdef0123456789"
        campaign.add_finding(
            Finding(
                title="Kerberoast Hashes Captured (1)",
                description="Captured one TGS hash.",
                severity=Severity.CRITICAL,
                validated=True,
                module_id="ad.kerberoast",
                evidence={"sample_hash": full_tgs},
            )
        )

        gen = ReportGenerator(
            output_dir=str(tmp_path),
            include_sensitive_evidence=True,
        )
        path = gen.generate(campaign, fmt="json")

        assert full_tgs in path.read_text(encoding="utf-8")

    def test_invalid_format_raises(self, campaign: Campaign) -> None:
        gen = ReportGenerator()
        with pytest.raises(ValueError, match="Unknown format"):
            gen.generate(campaign, fmt="excel")
