"""ARES Sovereign Real-Time Context Resources for MCP.

Supplies direct, URI-based read-only telemetry into LLM context windows, read
live from the attached campaign database (no sample/demo fallback):
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

    def _no_data_source(self, what: str, uri: str) -> ReadResourceResult:
        """Honest payload when no campaign database backs a 'real-time' resource."""
        text = json.dumps({
            "error": "no_data_source",
            "message": (
                f"No campaign database is attached to this MCP server, so {what} "
                "cannot be returned. This resource serves live data only, never "
                "sample/demo data."
            ),
        }, indent=2)
        return ReadResourceResult(
            contents=[ResourceContents(uri=uri, mimeType="application/json", text=text)]
        )

    async def read_resource(self, uri: str) -> ReadResourceResult:
        uri = uri.strip().lower()

        # These resources are advertised as "real-time telemetry". They must read
        # from the live campaign database, never serve hardcoded sample data (the
        # previous camp_default_01 / CorpTech Solutions / dc0{1,2}.corp.local blocks
        # were returned to every LLM client regardless of DB state). When no DB is
        # attached the gateway reports honestly instead of fabricating. (AUDIT run-1 C3)
        if uri == "ares://campaigns/active":
            if not (self.db and hasattr(self.db, "list_campaigns")):
                return self._no_data_source("active campaigns", uri)
            try:
                raw = await self.db.list_campaigns()
            except Exception:
                raw = []
            active = []
            for c in raw or []:
                if str(c.get("status", "active")).lower() != "active":
                    continue
                scope = c.get("scope")
                if not scope and c.get("scope_json"):
                    try:
                        scope = json.loads(str(c["scope_json"]))
                    except Exception:
                        scope = []
                active.append({
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "client": c.get("client"),
                    "status": c.get("status", "active"),
                    "scope": scope or [],
                })
            data = {"active_campaigns": active}
            clean_text = json.dumps(McpTaintSanitizer.sanitize(data), indent=2)
            return ReadResourceResult(contents=[ResourceContents(uri=uri, mimeType="application/json", text=clean_text)])

        if uri == "ares://findings/critical":
            if not (self.db and hasattr(self.db, "list_campaigns") and hasattr(self.db, "get_findings")):
                return self._no_data_source("critical findings", uri)
            try:
                campaigns = await self.db.list_campaigns()
            except Exception:
                campaigns = []
            critical: list[dict[str, Any]] = []
            for c in campaigns or []:
                if str(c.get("status", "active")).lower() != "active":
                    continue
                cid = c.get("id")
                if not cid:
                    continue
                try:
                    rows = await self.db.get_findings(cid)
                except Exception:
                    rows = []
                for f in rows or []:
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        critical.append({
                            "id": f.get("id"),
                            "campaign_id": cid,
                            "title": f.get("title"),
                            "severity": f.get("severity"),
                            "host": f.get("host"),
                            "mitre_technique": f.get("mitre_technique"),
                        })
            data = {"critical_findings": critical}
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
