"""ARES Sovereign Operational Tools Registry for MCP.

Provides 9+ enterprise purple-teaming tools divided into:
- Tier 1: Read-Only, Diagnostics, Remediation, and Pre-Flight Simulation (Autonomous)
- Tier 2: Governed Live Execution requiring cryptographic confirmation_token and ScopeGuard
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from ares.mcp.protocol import CallToolResult, TextContent, Tool, ToolInputSchema
from ares.mcp.security import (
    ConfirmationTokenManager,
    McpScopeGate,
    McpSecurityViolation,
    McpTaintSanitizer,
    SecretMasker,
)
from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS, get_descriptor
from ares.sdk import LockoutCircuitBreaker

logger = logging.getLogger("ares.mcp.tools")


class McpToolRegistry:
    """Registry and execution dispatcher for ARES MCP tools."""

    def __init__(
        self,
        token_manager: ConfirmationTokenManager,
        db: Any | None = None,
        ws_broadcast: Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        self.token_manager = token_manager
        self.db = db
        self.ws_broadcast = ws_broadcast
        self.circuit_breaker = LockoutCircuitBreaker()
        self._tools: dict[str, Tool] = {}
        self._handlers: dict[str, Callable[[dict[str, Any]], Coroutine[Any, Any, CallToolResult]]] = {}
        self._register_default_tools()

    def register(
        self,
        tool: Tool,
        handler: Callable[[dict[str, Any]], Coroutine[Any, Any, CallToolResult]],
    ) -> None:
        self._tools[tool.name] = tool
        self._handlers[tool.name] = handler

    def list_tools(self) -> list[Tool]:
        return list(self._tools.values())

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> CallToolResult:
        handler = self._handlers.get(name)
        if not handler:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: '{name}'")],
                isError=True,
            )
        try:
            return await handler(arguments or {})
        except McpSecurityViolation as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"SECURITY VIOLATION: {str(e)}")],
                isError=True,
            )
        except Exception as e:
            logger.exception("Error executing tool %s: %s", name, e)
            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool Execution Error ({name}): {str(e)}")],
                isError=True,
            )

    async def _broadcast(self, campaign_id: str, event_data: dict[str, Any]) -> None:
        if self.ws_broadcast and campaign_id:
            try:
                await self.ws_broadcast(campaign_id, event_data)
            except Exception as e:
                logger.warning("Failed to broadcast MCP event to WebSocket: %s", e)

    def _no_data_source_result(self, what: str) -> CallToolResult:
        """Honest response when no campaign database is attached.

        This gateway returns real data only; it must never substitute sample/demo
        data for a live query, which would deceive the operator and any AI client
        consuming the response as authentic telemetry. (AUDIT run-1 C3)
        """
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps({
                "error": "no_data_source",
                "message": (
                    f"No campaign database is attached to this MCP server, so {what} "
                    "cannot be returned. The gateway does not serve sample/demo data."
                ),
            }, indent=2))],
            isError=True,
        )

    # ── Tool Registrations ───────────────────────────────────────────────────

    def _register_default_tools(self) -> None:
        # 1. ares_list_campaigns
        self.register(
            Tool(
                name="ares_list_campaigns",
                description="List all engagements/campaigns with client name, status, and target scope.",
                inputSchema=ToolInputSchema(
                    properties={
                        "status": {
                            "type": "string",
                            "description": "Filter by status: 'active', 'paused', 'completed', or 'all'",
                            "default": "all",
                        },
                        "limit": {"type": "integer", "description": "Maximum campaigns to return", "default": 20},
                    },
                    required=[],
                ),
            ),
            self._handle_list_campaigns,
        )

        # 2. ares_get_campaign_status
        self.register(
            Tool(
                name="ares_get_campaign_status",
                description="Get detailed health metrics, target census, and finding distribution for a campaign.",
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The unique campaign ID"},
                    },
                    required=["campaign_id"],
                ),
            ),
            self._handle_get_campaign_status,
        )

        # 3. ares_list_findings
        self.register(
            Tool(
                name="ares_list_findings",
                description="Query security vulnerabilities/findings with severity and MITRE technique filters.",
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The campaign ID"},
                        "min_severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Minimum severity threshold",
                            "default": "info",
                        },
                        "host": {"type": "string", "description": "Optional host filter"},
                    },
                    required=["campaign_id"],
                ),
            ),
            self._handle_list_findings,
        )

        # 4. ares_get_remediation_guidance
        self.register(
            Tool(
                name="ares_get_remediation_guidance",
                description="Get verified remediation playbooks and MITRE D3FEND mitigations for a specific finding.",
                inputSchema=ToolInputSchema(
                    properties={
                        "finding_id": {"type": "string", "description": "The unique finding ID"},
                        "campaign_id": {"type": "string", "description": "The campaign ID (optional)"},
                    },
                    required=["finding_id"],
                ),
            ),
            self._handle_get_remediation_guidance,
        )

        # 5. ares_query_attack_graph
        self.register(
            Tool(
                name="ares_query_attack_graph",
                description="Query the lateral movement attack graph to find shortest attack paths to Domain Admin.",
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The campaign ID"},
                        "target_node": {
                            "type": "string",
                            "description": "Target high-value entity (e.g. 'Domain Admins')",
                            "default": "Domain Admins",
                        },
                    },
                    required=["campaign_id"],
                ),
            ),
            self._handle_query_attack_graph,
        )

        # 6. ares_inspect_module_catalog
        self.register(
            Tool(
                name="ares_inspect_module_catalog",
                description="Search and inspect 60+ attack modules, parameter schemas, OPSEC noise levels, and capabilities.",
                inputSchema=ToolInputSchema(
                    properties={
                        "category": {
                            "type": "string",
                            "description": "Filter by category: ad, network, credential, lateral, persistence, recon, web, windows, linux",
                        },
                        "query": {"type": "string", "description": "Search keyword in module name or description"},
                    },
                    required=[],
                ),
            ),
            self._handle_inspect_module_catalog,
        )

        # 7. ares_verify_target_scope
        self.register(
            Tool(
                name="ares_verify_target_scope",
                description="Verify deterministically if a target IP, CIDR, or hostname is within the authorized scope.",
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The campaign ID"},
                        "target": {"type": "string", "description": "Target IP, hostname, or domain to verify"},
                    },
                    required=["campaign_id", "target"],
                ),
            ),
            self._handle_verify_target_scope,
        )

        # 8. ares_dry_run_module (Tier 1 Pre-flight + Token Issuer)
        self.register(
            Tool(
                name="ares_dry_run_module",
                description=(
                    "Simulate module execution in pre-flight mode (zero network packets). "
                    "Validates parameters, verifies ScopeGuard, evaluates OPSEC noise, and issues a 60-second "
                    "cryptographic confirmation_token required for live execution."
                ),
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The campaign ID"},
                        "module_id": {"type": "string", "description": "Module ID (e.g. 'ad.kerberoast')"},
                        "target": {"type": "string", "description": "Target IP or hostname"},
                        "params": {"type": "object", "description": "Module parameters dictionary", "default": {}},
                    },
                    required=["campaign_id", "module_id", "target"],
                ),
            ),
            self._handle_dry_run_module,
        )

        # 9. ares_execute_module (Tier 2 Governed Live Execution)
        self.register(
            Tool(
                name="ares_execute_module",
                description=(
                    "Execute an attack module live under strict governance. "
                    "REQUIRES a valid confirmation_token produced by a prior ares_dry_run_module call. "
                    "Enforces ScopeGuard, CapabilitySandbox, and AD Lockout Circuit Breaker."
                ),
                inputSchema=ToolInputSchema(
                    properties={
                        "campaign_id": {"type": "string", "description": "The campaign ID"},
                        "module_id": {"type": "string", "description": "Module ID"},
                        "target": {"type": "string", "description": "Target IP or hostname"},
                        "confirmation_token": {
                            "type": "string",
                            "description": "Cryptographic HMAC token issued by ares_dry_run_module (TTL 60s)",
                        },
                        "params": {"type": "object", "description": "Module parameters dictionary", "default": {}},
                    },
                    required=["campaign_id", "module_id", "target", "confirmation_token"],
                ),
            ),
            self._handle_execute_module,
        )

    # ── Tool Implementations ─────────────────────────────────────────────────

    async def _get_campaign_scope(self, campaign_id: str) -> list[str]:
        """Fetch scope rules from database or fallback to default test scope."""
        if self.db and hasattr(self.db, "get_campaign"):
            try:
                camp = await self.db.get_campaign(campaign_id)
                if not camp:
                    raise McpSecurityViolation(f"Campaign '{campaign_id}' not found in database.")

                raw_scope = camp.get("scope_json") or camp.get("scope")
                if raw_scope:
                    parsed = json.loads(raw_scope) if isinstance(raw_scope, str) else raw_scope
                    if isinstance(parsed, list):
                        extracted_rules = []
                        for item in parsed:
                            if isinstance(item, str):
                                extracted_rules.append(item)
                            elif isinstance(item, dict) and "cidr" in item:
                                extracted_rules.append(item["cidr"])
                        if extracted_rules:
                            return extracted_rules

                raw_targets = camp.get("targets_json") or camp.get("targets")
                if raw_targets:
                    parsed_tgt = json.loads(raw_targets) if isinstance(raw_targets, str) else raw_targets
                    if isinstance(parsed_tgt, list) and parsed_tgt:
                        return [t for t in parsed_tgt if isinstance(t, str)]

                return []  # Fail-closed: campaign exists but has zero authorized scope
            except McpSecurityViolation:
                raise
            except Exception as exc:
                logger.warning("mcp_fetch_campaign_scope_failed", campaign_id=campaign_id, error=str(exc))
                raise McpSecurityViolation(f"Failed to resolve scope for campaign '{campaign_id}': {exc}")  # noqa: B904

        # Default fallback only when DB is not bound (standalone mock/demo mode)
        return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "*.corp.local", "*.lab.local", "localhost", "127.0.0.1"]

    async def _handle_list_campaigns(self, args: dict[str, Any]) -> CallToolResult:
        status_filter = args.get("status", "all")
        limit = args.get("limit", 20)
        items = []

        if not (self.db and hasattr(self.db, "list_campaigns")):
            return self._no_data_source_result("the campaign list")

        if self.db and hasattr(self.db, "list_campaigns"):
            try:
                raw_campaigns = await self.db.list_campaigns()
                for c in raw_campaigns[:limit]:
                    c_status = c.get("status", "active")
                    if status_filter == "all" or c_status == status_filter:
                        scope = c.get("scope")
                        if not scope and c.get("scope_json"):
                            try:
                                scope = json.loads(str(c["scope_json"]))
                            except Exception:
                                scope = []
                        targets = c.get("targets")
                        if not targets and c.get("targets_json"):
                            try:
                                targets = json.loads(str(c["targets_json"]))
                            except Exception:
                                targets = []
                        items.append({
                            "id": c.get("id"),
                            "name": c.get("name"),
                            "client": c.get("client"),
                            "status": c_status,
                            "scope": scope or [],
                            "targets_count": len(targets or []),
                        })
            except Exception as e:
                logger.warning("DB query failed: %s", e)

        clean_data = McpTaintSanitizer.sanitize(items)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(clean_data, indent=2))]
        )

    async def _handle_get_campaign_status(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        if not (self.db and hasattr(self.db, "get_campaign")):
            return self._no_data_source_result("campaign status")

        # Resolve real status + a findings summary computed from the live findings,
        # never the previous hardcoded {critical:2, high:5, ...} / "Lateral Movement"
        # placeholders. (AUDIT run-1 C3)
        try:
            campaign = await self.db.get_campaign(campaign_id)
        except Exception as exc:
            logger.warning("mcp_get_campaign_failed", campaign_id=campaign_id, error=str(exc))
            campaign = None
        if not campaign:
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps({
                    "error": "campaign_not_found",
                    "campaign_id": campaign_id,
                }, indent=2))],
                isError=True,
            )

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if hasattr(self.db, "get_findings"):
            try:
                raw_findings = await self.db.get_findings(campaign_id)
                for f in raw_findings or []:
                    sev = str(f.get("severity", "info")).lower()
                    if sev in summary:
                        summary[sev] += 1
            except Exception as exc:
                logger.warning("mcp_status_findings_failed", campaign_id=campaign_id, error=str(exc))

        scope = await self._get_campaign_scope(campaign_id)
        status_data = {
            "campaign_id": campaign_id,
            "status": campaign.get("status", "unknown"),
            "findings_summary": summary,
            "scope": scope,
            "circuit_breaker_state": self.circuit_breaker.state.value,
        }
        clean_data = McpTaintSanitizer.sanitize(status_data)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(clean_data, indent=2))]
        )

    async def _handle_list_findings(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        min_severity = args.get("min_severity", "info").lower()
        host_filter = args.get("host")

        if not (self.db and hasattr(self.db, "get_findings")):
            return self._no_data_source_result("campaign findings")

        findings = []
        try:
            raw_findings = await self.db.get_findings(campaign_id)
            if isinstance(raw_findings, list):
                findings = raw_findings
        except Exception as exc:
            logger.warning("mcp_fetch_findings_failed", campaign_id=campaign_id, error=str(exc))

        severity_ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_rank = severity_ranks.get(min_severity, 0)

        filtered = [
            f for f in findings
            if severity_ranks.get(str(f.get("severity", "")).lower(), 0) >= min_rank
            and (not host_filter or f.get("host") == host_filter)
        ]

        clean_data = McpTaintSanitizer.sanitize(SecretMasker.mask(filtered))
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(clean_data, indent=2))]
        )

    async def _handle_get_remediation_guidance(self, args: dict[str, Any]) -> CallToolResult:
        # Previously this ignored finding_id entirely and returned a fixed
        # Kerberoasting playbook for EVERY finding — wrong (and dangerous) remediation
        # for any non-Kerberoast finding. Remediation is carried on each finding
        # record (its own `remediation` field and MITRE technique); the gateway
        # cannot synthesize per-finding guidance from an opaque id alone, so it must
        # not fabricate one. Direct the caller to the authoritative source rather
        # than returning a canned playbook. (AUDIT run-1 C3)
        finding_id = args["finding_id"]
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps({
                "error": "remediation_not_synthesizable",
                "finding_id": finding_id,
                "message": (
                    "Per-finding remediation is recorded on the finding itself. Call "
                    "ares_list_findings for the campaign and read the finding's "
                    "'remediation' field and 'mitre_technique'; this gateway does not "
                    "generate remediation guidance independently of the finding record."
                ),
            }, indent=2))],
            isError=True,
        )

    async def _handle_query_attack_graph(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        target_node = args.get("target_node", "Domain Admins")

        if self.db and hasattr(self.db, "get_attack_graph"):
            try:
                g = await self.db.get_attack_graph(campaign_id, target_goal=target_node)
                if g:
                    clean_data = McpTaintSanitizer.sanitize(g)
                    return CallToolResult(
                        content=[TextContent(type="text", text=json.dumps(clean_data, indent=2))]
                    )
            except Exception as exc:
                logger.warning("mcp_query_attack_graph_failed", error=str(exc))

        # No attack-graph source is available here. The previous fallback returned a
        # fully scripted WS01 -> jdoe -> Server02 -> svc_backup -> DC01 ->
        # Domain Admins chain for ANY campaign, which an LLM would read as a real
        # compromise path. Report honestly instead of fabricating a kill chain.
        # (AUDIT run-1 C3)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps({
                "error": "attack_graph_unavailable",
                "campaign_id": campaign_id,
                "target_goal": target_node,
                "message": (
                    "No attack-graph data source is attached to this MCP gateway. Use "
                    "the dashboard Graph view or the '/graph/{campaign_id}' API, which "
                    "build the graph from real campaign findings and host data."
                ),
            }, indent=2))],
            isError=True,
        )

    async def _handle_inspect_module_catalog(self, args: dict[str, Any]) -> CallToolResult:
        category_filter = args.get("category")
        query_filter = (args.get("query") or "").lower()

        results = []
        for mod_id, desc in FIRST_PARTY_DESCRIPTORS.items():
            category_val = desc.category.value if hasattr(desc.category, "value") else str(desc.category)
            if category_filter and category_val.lower() != category_filter.lower():
                continue
            if query_filter and query_filter not in mod_id.lower() and query_filter not in str(desc.source_class).lower() and query_filter not in category_val.lower():
                continue

            results.append({
                "module_id": mod_id,
                "category": category_val,
                "opsec_level": desc.opsec.value if hasattr(desc.opsec, "value") else str(desc.opsec),
                "source_class": desc.source_class,
                "required_capabilities": [c.value if hasattr(c, "value") else str(c) for c in desc.required_capabilities],
                "parameters_count": len(desc.parameter_fields),
                "requires_approval": desc.explicit_attempt_approval,
            })

        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(results[:50], indent=2))]
        )

    async def _handle_verify_target_scope(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        target = args["target"]
        scope = await self._get_campaign_scope(campaign_id)
        in_scope = McpScopeGate.is_in_scope(target, scope)

        result = {
            "campaign_id": campaign_id,
            "target": target,
            "in_scope": in_scope,
            "authorized_rules": scope,
            "status": "APPROVED_FOR_TESTING" if in_scope else "REJECTED_OUT_OF_SCOPE",
        }
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )

    async def _handle_dry_run_module(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        module_id = args["module_id"]
        target = args["target"]
        params = args.get("params", {})

        # 1. Scope Verification Gate
        scope = await self._get_campaign_scope(campaign_id)
        McpScopeGate.verify_target(target, scope)

        # 2. Module Validation
        descriptor = get_descriptor(module_id)
        if not descriptor:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Module '{module_id}' not found in descriptor catalog.")],
                isError=True,
            )

        # 3. Issue Single-Use 60s Confirmation Token
        token = self.token_manager.issue_token(
            campaign_id=campaign_id,
            module_id=module_id,
            target=target,
            params=params,
            ttl_seconds=60.0,
        )

        # 4. Broadcast Simulation Event to WebSocket Live Dashboard & Local TUI Monitor
        await self._broadcast(
            campaign_id,
            {
                "type": "mcp_dry_run",
                "module_id": module_id,
                "target": target,
                "opsec_noise": descriptor.opsec.value,
                "status": "simulation_ready",
            },
        )
        try:
            from ares.mcp.events import McpEventBus
            McpEventBus.emit("STAGED", {
                "call": f"ares_dry_run_module(module={module_id})",
                "module": module_id,
                "target": target,
                "action": descriptor.description[:40] if descriptor.description else "Dry-Run Simulation",
                "risk": f"{descriptor.opsec.value.upper()} (Safe Pre-flight)",
                "status": "STAGED",
                "style": "blue",
            })
        except Exception as exc:
            logger.debug("mcp_event_bus_staged_emit_failed", error=str(exc))

        simulation_result = {
            "status": "SIMULATION_SUCCESS",
            "campaign_id": campaign_id,
            "module_id": module_id,
            "target": target,
            "opsec_level": descriptor.opsec.value,
            "risk_assessment": "Low collateral risk. Verified in-scope.",
            "confirmation_token": token,
            "token_ttl_seconds": 60,
            "instruction_for_operator": (
                "Simulation complete. To proceed with LIVE execution, call ares_execute_module "
                f"with confirmation_token='{token}' before the 60-second TTL expires."
            ),
        }
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(simulation_result, indent=2))]
        )

    async def _handle_execute_module(self, args: dict[str, Any]) -> CallToolResult:
        campaign_id = args["campaign_id"]
        module_id = args["module_id"]
        target = args["target"]
        confirmation_token = args["confirmation_token"]
        params = args.get("params", {})

        # 1. Circuit Breaker Check
        if self.circuit_breaker.state.value == "open":
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text="CIRCUIT BREAKER IS OPEN: Prior Active Directory lockout detected. All attacks halted.",
                )],
                isError=True,
            )

        # 2. Scope Verification Gate — BEFORE burning the token. A scope change or a
        #    DB flap must not consume the operator's single-use token and force a
        #    fresh dry-run. (AUDIT run-1 M6)
        scope = await self._get_campaign_scope(campaign_id)
        McpScopeGate.verify_target(target, scope)

        # 3. Validate and Burn Confirmation Token (Single-Use, Anti-Replay)
        is_valid = self.token_manager.validate_and_burn(
            token=confirmation_token,
            campaign_id=campaign_id,
            module_id=module_id,
            target=target,
            params=params,
        )
        if not is_valid:
            raise McpSecurityViolation(
                "INVALID OR EXPIRED CONFIRMATION TOKEN: Live execution rejected. "
                "You must run ares_dry_run_module first to obtain a fresh token."
            )

        # 4. This MCP gateway authorizes execution but does not run modules itself:
        #    no execution engine is wired into the tool registry. The previous
        #    behaviour fabricated a SUCCESS report (fixed duration, invented findings
        #    count, a constant merkle hash) and broadcast a fake "completed" event,
        #    which lied to the operator, the live dashboard, and any downstream
        #    auditor. Report honestly instead: the request was scope-checked and the
        #    token consumed, but the module must be run through the real engine.
        #    (AUDIT run-1 C2)
        await self._broadcast(
            campaign_id,
            {
                "type": "mcp_execute_authorized",
                "module_id": module_id,
                "target": target,
                "status": "authorized_not_executed",
            },
        )
        report = {
            "status": "NOT_EXECUTED",
            "reason": "mcp_execution_engine_not_wired",
            "campaign_id": campaign_id,
            "module_id": module_id,
            "target": target,
            "message": (
                "Scope and the single-use confirmation token were validated, but this "
                "MCP gateway does not execute modules itself — no execution engine is "
                "attached to it. Run the module through the ARES engine (the "
                "'/modules/{module_id}/run' API, or 'ares module run' on the CLI), "
                "which performs the real execution, findings capture, and audit "
                "provenance. This gateway never reports results it did not produce."
            ),
        }
        clean_report = McpTaintSanitizer.sanitize(report)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(clean_report, indent=2))],
            isError=True,
        )
