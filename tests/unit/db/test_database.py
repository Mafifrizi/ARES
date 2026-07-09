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
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.campaign import Campaign, Finding, NoiseProfile, Severity, ScopeEntry
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.plugin.loader import ModuleRegistry, PluginLoader
from ares.db.database import AresDatabase, Credential, Host, Loot
from ares.modules.base import BaseModule
from ares.modules.reporting.report_gen import (
    BROWSER_PDF_TIMEOUT_SECONDS,
    ReportGenerator,
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

    def test_generate_all(self, campaign_with_findings: Campaign, tmp_path: Path) -> None:
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
            patch(
                "ares.modules.reporting.report_gen.subprocess.run",
                side_effect=subprocess.TimeoutExpired(
                    cmd=[str(browser)], timeout=BROWSER_PDF_TIMEOUT_SECONDS
                ),
            ) as run_browser,
        ):
            assert gen._write_pdf_with_browser("<html></html>", pdf_path) is False

        assert run_browser.call_args.kwargs["timeout"] == BROWSER_PDF_TIMEOUT_SECONDS
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

    def test_invalid_format_raises(self, campaign: Campaign) -> None:
        gen = ReportGenerator()
        with pytest.raises(ValueError, match="Unknown format"):
            gen.generate(campaign, fmt="excel")
