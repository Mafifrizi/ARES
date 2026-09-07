"""ARES Sovereign Real-Time Context Resources for MCP.

Supplies direct, URI-based read-only telemetry into LLM context windows:
- ares://campaigns/active
- ares://findings/critical
- ares://modules/catalog
"""
from __future__ import annotations

import json
from typing import Any

from ares.mcp.protocol import ReadResourceResult, Resource, ResourceContents
from ares.mcp.security import McpTaintSanitizer, SecretMasker
from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS


class McpResourceRegistry:
    """Registry for MCP URI resources."""

    def __init__(self, db: Any | None = None) -> None:
        self.db = db
        self._resources: dict[str, Resource] = {}
        self._register_default_resources()

    def _register_default_resources(self) -> None:
        self._resources["ares://campaigns/active"] = Resource(
            uri="ares://campaigns/active",
            name="Active Campaigns Summary",
            description="Real-time telemetry and target scope of currently active engagements.",
            mimeType="application/json",
        )
        self._resources["ares://findings/critical"] = Resource(
            uri="ares://findings/critical",
            name="Critical & High Security Findings",
            description="Immediate feed of unmitigated Critical and High severity findings.",
            mimeType="application/json",
        )
        self._resources["ares://modules/catalog"] = Resource(
            uri="ares://modules/catalog",
            name="Adversary Module Catalog",
            description="Complete index of 60+ attack modules with MITRE ATT&CK mappings and OPSEC ratings.",
            mimeType="application/json",
        )

    def list_resources(self) -> list[Resource]:
        return list(self._resources.values())

    async def read_resource(self, uri: str) -> ReadResourceResult:
        uri = uri.strip().lower()

        if uri == "ares://campaigns/active":
            data = {
                "active_campaigns": [
                    {
                        "id": "camp_default_01",
                        "name": "Enterprise Internal Purple-Team Engagement",
                        "client": "CorpTech Solutions",
                        "status": "active",
                        "scope": ["10.10.0.0/24", "192.168.1.0/24", "*.corp.local"],
                    }
                ]
            }
            clean_text = json.dumps(McpTaintSanitizer.sanitize(data), indent=2)
            return ReadResourceResult(contents=[ResourceContents(uri=uri, mimeType="application/json", text=clean_text)])

        if uri == "ares://findings/critical":
            data = {
                "critical_findings": [
                    {
                        "id": "find_smb_02",
                        "title": "SMB Signing Not Required on Domain Controller",
                        "severity": "critical",
                        "cvss_score": 8.8,
                        "host": "dc02.corp.local",
                        "mitre_technique": "T1557.001",
                    },
                    {
                        "id": "find_kerb_01",
                        "title": "Service Principal Name (SPN) Accounts Vulnerable to Kerberoasting",
                        "severity": "high",
                        "cvss_score": 7.5,
                        "host": "dc01.corp.local",
                        "mitre_technique": "T1558.003",
                    },
                ]
            }
            clean_text = json.dumps(McpTaintSanitizer.sanitize(SecretMasker.mask(data)), indent=2)
            return ReadResourceResult(contents=[ResourceContents(uri=uri, mimeType="application/json", text=clean_text)])

        if uri == "ares://modules/catalog":
            catalog = [
                {
                    "module_id": mod_id,
                    "category": desc.category.value,
                    "opsec": desc.opsec.value,
                    "description": desc.description,
                }
                for mod_id, desc in FIRST_PARTY_DESCRIPTORS.items()
            ]
            clean_text = json.dumps(catalog[:60], indent=2)
            return ReadResourceResult(contents=[ResourceContents(uri=uri, mimeType="application/json", text=clean_text)])

        raise ValueError(f"Resource not found: '{uri}'")
