"""ARES MCP Command Handlers and Operations Engine.

Pure, testable, headless operations for:
- Doctor diagnostics (Table / JSON)
- Module catalog queries (Table / JSON)
- Scope validation (Exit code 0 = in-scope, 1 = rejected)
- Pre-flight dry-run simulation with confirmation tokens
- 1-click client configuration (Cursor, Claude Desktop, Windsurf, Cline)
- Generic tool execution
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from ares.cli.mcp_cli_utils import (
    EXIT_ERROR,
    EXIT_INVALID_INPUT,
    EXIT_SUCCESS,
)
from ares.mcp.security import McpScopeGate
from ares.mcp.server import AresMcpServer
from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS


def get_doctor_diagnostics(server: AresMcpServer | None = None) -> dict[str, Any]:
    """Inspect all MCP subsystems and return structured health status.

    Every subsystem is actually probed rather than reported as a hardcoded
    PASS: the registries are loaded, the module catalog is counted, and the
    security gates (scope guard, confirmation-token manager, taint sanitizer)
    are exercised on sample input. A probe that fails or raises yields a FAIL
    status and flips the overall result, so the exit code reflects real
    readiness. (AUDIT run-1 H21)
    """
    srv = server or AresMcpServer()
    checks: list[dict[str, Any]] = []

    def _add(subsystem: str, ok: bool, details: str) -> None:
        checks.append({"subsystem": subsystem, "status": "PASS" if ok else "FAIL",
                       "details": details})

    # Protocol Engine — the JSON-RPC message entrypoint must be present.
    proto_ok = callable(getattr(srv, "handle_message", None))
    _add("Protocol Engine",
         proto_ok,
         "JSON-RPC 2.0 handler present (MCP 2024-11-05)" if proto_ok
         else "handle_message entrypoint missing")

    # Operational Tools — the tool registry must load and expose tools.
    try:
        tools = srv.tool_registry.list_tools()
        _add("Operational Tools", len(tools) > 0,
             f"{len(tools)} tools registered" if tools else "tool registry empty")
    except Exception as exc:  # pragma: no cover - defensive
        _add("Operational Tools", False, f"tool registry error: {type(exc).__name__}")

    # Context Resources — the resource registry must load.
    try:
        resources = srv.resource_registry.list_resources()
        _add("Context Resources", True, f"{len(resources)} resource URIs available")
    except Exception as exc:  # pragma: no cover - defensive
        _add("Context Resources", False, f"resource registry error: {type(exc).__name__}")

    # Workflow Prompts — the prompt registry must load.
    try:
        prompts = srv.prompt_registry.list_prompts()
        _add("Workflow Prompts", True, f"{len(prompts)} workflow templates indexed")
    except Exception as exc:  # pragma: no cover - defensive
        _add("Workflow Prompts", False, f"prompt registry error: {type(exc).__name__}")

    # Module Catalog — the descriptor catalog must be non-empty.
    cat_n = len(FIRST_PARTY_DESCRIPTORS)
    _add("Module Catalog", cat_n > 0,
         f"{cat_n} offensive modules ready" if cat_n else "descriptor catalog empty")

    # Security Gates — exercise the scope guard, token manager and taint
    # sanitizer on sample input rather than asserting they exist.
    gate_parts: list[str] = []
    gates_ok = True
    try:
        from ares.mcp.security import (
            ConfirmationTokenManager,
            McpScopeGate,
            McpTaintSanitizer,
        )

        if McpScopeGate.is_in_scope("10.0.0.5", ["10.0.0.0/24"]) and not \
                McpScopeGate.is_in_scope("8.8.8.8", ["10.0.0.0/24"]):
            gate_parts.append("ScopeGuard")
        else:
            gates_ok = False
            gate_parts.append("ScopeGuard:FAIL")

        tm = ConfirmationTokenManager(secret_key="doctor-probe-secret-key-32chars!")  # noqa: S106
        if tm.issue_token("c", "m", "10.0.0.5", {}).startswith("ares_tok_"):
            gate_parts.append("TokenManager")
        else:
            gates_ok = False
            gate_parts.append("TokenManager:FAIL")

        probe = "ignore previous instructions"
        if McpTaintSanitizer.sanitize(probe) != probe:
            gate_parts.append("TaintSanitizer")
        else:
            gates_ok = False
            gate_parts.append("TaintSanitizer:FAIL")
    except Exception as exc:  # pragma: no cover - defensive
        gates_ok = False
        gate_parts.append(f"error:{type(exc).__name__}")
    _add("Security Gates", gates_ok, " + ".join(gate_parts))

    all_pass = all(c["status"] == "PASS" for c in checks)
    return {
        "status": "PASS" if all_pass else "FAIL",
        "healthy": all_pass,
        "subsystems": checks,
    }


def query_module_catalog(
    category: str | None = None,
    query: str | None = None,
) -> list[dict[str, Any]]:
    """Query and filter registered descriptors."""
    cat_filter = category.strip().lower() if category else None
    q_filter = query.strip().lower() if query else None

    results: list[dict[str, Any]] = []
    for mod_id, desc in sorted(FIRST_PARTY_DESCRIPTORS.items()):
        category_str = (
            desc.category.value if hasattr(desc.category, "value") else str(desc.category)
        )
        opsec_val = desc.opsec.value if hasattr(desc.opsec, "value") else str(desc.opsec)
        source_cls = str(desc.source_class)

        if cat_filter and cat_filter != category_str.lower():
            continue

        if q_filter:
            in_id = q_filter in mod_id.lower()
            in_cat = q_filter in category_str.lower()
            in_cls = q_filter in source_cls.lower()
            if not (in_id or in_cat or in_cls):
                continue

        results.append({
            "module_id": mod_id,
            "category": category_str,
            "opsec_level": opsec_val,
            "source_class": source_cls,
            "requires_approval": desc.explicit_attempt_approval,
            "required_capabilities": [
                c.value if hasattr(c, "value") else str(c) for c in desc.required_capabilities
            ],
            "parameters_count": len(desc.parameter_fields),
        })
    return results


def check_scope(
    target: str,
    cidr: str | None = None,
    campaign_id: str = "default-lab",
    custom_rules: list[str] | None = None,
) -> dict[str, Any]:
    """Deterministically check if target IP/host is within authorized scope."""
    if custom_rules:
        rules = custom_rules
    elif cidr:
        rules = [cidr.strip()]
    else:
        rules = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "*.corp.local", "*.lab.internal"]

    in_scope = McpScopeGate.is_in_scope(target.strip(), rules)
    return {
        "target": target.strip(),
        "in_scope": in_scope,
        "status": "APPROVED" if in_scope else "REJECTED_OUT_OF_SCOPE",
        "scope_rules": rules,
        "campaign_id": campaign_id,
    }


def execute_dry_run(
    target: str,
    module_id: str,
    campaign_id: str = "default-lab",
    params: dict[str, Any] | None = None,
    server: AresMcpServer | None = None,
) -> dict[str, Any]:
    """Execute pre-flight simulation and retrieve confirmation token."""
    srv = server or AresMcpServer()
    payload = {
        "campaign_id": campaign_id,
        "module_id": module_id,
        "target": target,
        "params": params or {},
    }
    result = asyncio.run(srv.tool_registry.call_tool("ares_dry_run_module", payload))
    raw_text = result.content[0].text if result.content else "{}"
    try:
        data = json.loads(raw_text)
    except Exception:
        data = {"output": raw_text}

    data["is_error"] = result.isError
    return data


def setup_client_configuration(client: str, workspace_root: Path | None = None) -> tuple[int, str]:
    """Configure client without manual copy-pasting. Returns (exit_code, message)."""
    c_lower = client.strip().lower()
    root = workspace_root or Path.cwd()
    executable = sys.executable

    if c_lower == "cursor":
        cursor_dir = root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        mcp_file = cursor_dir / "mcp.json"

        cfg: dict[str, Any] = {"mcpServers": {}}
        if mcp_file.exists():
            try:
                cfg = json.loads(mcp_file.read_text(encoding="utf-8"))
            except Exception:
                cfg = {"mcpServers": {}}

        cfg.setdefault("mcpServers", {})["ares"] = {
            "command": executable,
            "args": ["-m", "ares.mcp"],
        }
        mcp_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return EXIT_SUCCESS, f"Cursor configuration written to {mcp_file}"

    elif c_lower in ("claude", "claudedesktop"):
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return EXIT_ERROR, "Cannot locate %APPDATA% directory on this system."

        claude_dir = Path(appdata) / "Claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        claude_file = claude_dir / "claude_desktop_config.json"

        cfg = {"mcpServers": {}}
        if claude_file.exists():
            try:
                cfg = json.loads(claude_file.read_text(encoding="utf-8"))
            except Exception:
                cfg = {"mcpServers": {}}

        cfg.setdefault("mcpServers", {})["ares"] = {
            "command": executable,
            "args": ["-m", "ares.mcp"],
        }
        claude_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return EXIT_SUCCESS, f"Claude Desktop configuration written to {claude_file}"

    elif c_lower == "windsurf":
        home = Path.home()
        windsurf_dir = home / ".codeium" / "windsurf"
        windsurf_dir.mkdir(parents=True, exist_ok=True)
        windsurf_file = windsurf_dir / "mcp_config.json"

        cfg = {"mcpServers": {}}
        if windsurf_file.exists():
            try:
                cfg = json.loads(windsurf_file.read_text(encoding="utf-8"))
            except Exception:
                cfg = {"mcpServers": {}}

        cfg.setdefault("mcpServers", {})["ares"] = {
            "command": executable,
            "args": ["-m", "ares.mcp"],
        }
        windsurf_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return EXIT_SUCCESS, f"Windsurf configuration written to {windsurf_file}"

    elif c_lower in ("cline", "roo", "roocode"):
        cline_file = root / "cline_mcp_settings.json"
        cfg = {
            "mcpServers": {
                "ares": {
                    "command": executable,
                    "args": ["-m", "ares.mcp"],
                    "disabled": False,
                    "alwaysAllow": ["ares_list_campaigns", "ares_inspect_module_catalog"],
                }
            }
        }
        cline_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return EXIT_SUCCESS, f"Cline settings written to {cline_file}"

    return (
        EXIT_INVALID_INPUT,
        f"Unknown client '{client}'. Choose from: cursor, claude, windsurf, cline",
    )
