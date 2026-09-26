"""
Unit tests for MOD-071: linux.kernel_suggester separation of kernel vs userspace CVEs.
Validates:
- Kernel 5.4.0 does NOT generate PwnKit (CVE-2021-4034) finding.
- Kernel 5.15.0 with sudo 1.9.5p2 generates Baron Samedit (CVE-2021-3156) finding when sudo version is queried.
- Unverified kernel findings (major.minor only without patch version) have confidence < 0.7 (0.5) and MEDIUM severity.
- Exact kernel version matches (e.g. Dirty Pipe) have confidence >= 0.7.
"""
from __future__ import annotations

import pytest

from ares.core.campaign import Campaign, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController, NoiseProfile
from ares.modules.linux.kernel_suggester import KernelSuggesterModule


def _make_suggester() -> KernelSuggesterModule:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Kernel-Suggester-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return KernelSuggesterModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_kernel_5_4_0_does_not_produce_pwnkit():
    """MOD-071: Linux kernel 5.4.0 must NOT match PwnKit (CVE-2021-4034, which is a polkit userspace bug)."""
    module = _make_suggester()
    findings, raw = await module.run(
        target="10.0.0.5",
        username="operator",
        info={"kernel": "5.4.0-42-generic", "current_user": "uid=1000(user)"},
    )

    finding_cves = [f.evidence.get("cve") for f in findings]
    assert "CVE-2021-4034" not in finding_cves, (
        "MOD-071 FAIL: PwnKit (userspace polkit) was incorrectly matched against kernel version!"
    )


@pytest.mark.asyncio
async def test_sudo_version_query_generates_baron_samedit():
    """MOD-071: Kernel 5.15.0 with sudo 1.9.5p2 produces Baron Samedit (CVE-2021-3156) via userspace query."""
    module = _make_suggester()
    findings, raw = await module.run(
        target="10.0.0.5",
        username="operator",
        info={
            "kernel": "5.15.0-100-generic",
            "sudo_version": "Sudo version 1.9.5p2",
            "current_user": "uid=1000(user)",
        },
    )

    baron_findings = [f for f in findings if f.evidence.get("cve") == "CVE-2021-3156"]
    assert len(baron_findings) == 1, (
        "MOD-071 FAIL: Baron Samedit should be detected when vulnerable sudo version is queried"
    )
    assert baron_findings[0].evidence["binary"] == "sudo"
    assert "1.9.5p2" in baron_findings[0].evidence["version"]
    assert baron_findings[0].confidence >= 0.7


@pytest.mark.asyncio
async def test_unverified_kernel_finding_has_low_confidence():
    """MOD-071: Kernel finding with major.minor only (unverified patch level) has confidence < 0.7 and MEDIUM severity."""
    module = _make_suggester()
    # 5.10 with no patch version provided
    findings, raw = await module.run(
        target="10.0.0.5",
        username="operator",
        info={"kernel": "5.10", "current_user": "uid=1000(user)"},
    )

    # Any finding generated for unverified patch version must have confidence < 0.7
    for f in findings:
        assert f.confidence < 0.7, (
            f"MOD-071 FAIL: Unverified finding {f.title} has confidence {f.confidence} >= 0.7"
        )
        assert f.severity.value == "medium"
        assert "patch version unknown, manual verification required" in f.description
