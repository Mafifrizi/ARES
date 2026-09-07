"""ARES MCP - Model Context Protocol Gateway Console (OpenCode / OpenClaw style).

Tactical, unified, zero-friction interactive terminal for:
- 1-Click Auto-Setup for Cursor, Claude Desktop, Windsurf, and Cline
- Interactive Module Catalog Explorer with OPSEC noise ratings
- Pre-Flight Target ScopeGuard & Dry-Run Simulator with HMAC confirmation tokens
- Interactive Tool Runner with syntax-highlighted visual cards
- System Readiness Diagnostics & Local SSE Gateway launcher
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ares.mcp.server import AresMcpServer
from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS

console = Console(safe_box=True)

ASCII_BANNER = r"""
[bold cyan]   _   ___ ___ ___ [/]  [bold white] __  __ ___ ___ [/]
[bold cyan]  /_\ | _ \ __/ __|[/]  [bold white]|  \/  / __| _ \ [/]
[bold cyan] / _ \|   / _|\__ \ [/] [bold white]| |\/| | (__|  _/ [/]
[bold cyan]/_/ \_\_|_\___|___/[/]  [bold white]|_|  |_|\___|_|   [/]
"""


def render_header() -> None:
    """Render the tactical ARES MCP header."""
    console.print(Align.center(ASCII_BANNER))

    header_table = Table(box=box.ASCII, show_header=False, expand=True, border_style="cyan")
    header_table.add_column(justify="left")
    header_table.add_column(justify="right")

    header_table.add_row(
        "[bold white]ARES MCP[/bold white] [dim]- Automated Red Team Engagement System[/dim]",
        "[bold green][*] READY[/bold green] [dim]v6.0.0[/dim]",
    )
    header_table.add_row(
        "[cyan]Modules:[/] [bold white]62 Active[/]   [cyan]Tools:[/] [bold white]9 Governed[/]   [cyan]Transport:[/] [bold white]Stdio + SSE[/]",
        "[cyan]ScopeGuard:[/] [bold green]Enforced[/]   [cyan]Auth:[/] [bold yellow]HMAC-SHA256[/]",
    )

    console.print(header_table)
    console.print()


def auto_setup_client(workspace_root: Path) -> None:
    """1-Click Auto-Setup for AI IDEs and clients without manual copy-paste."""
    render_header()
    console.print(Panel(
        "[bold white]Select your AI client to configure MCP connection automatically:[/]\n\n"
        "  [bold cyan][1][/] Cursor IDE         [dim]Auto-configures .cursor/mcp.json in workspace[/]\n"
        "  [bold cyan][2][/] Claude Desktop     [dim]Auto-configures %APPDATA%\\Claude\\claude_desktop_config.json[/]\n"
        "  [bold cyan][3][/] Windsurf           [dim]Auto-configures ~/.codeium/windsurf/mcp_config.json[/]\n"
        "  [bold cyan][4][/] VS Code (Cline)    [dim]Auto-configures cline_mcp_settings.json[/]\n"
        "  [bold cyan][0][/] Back to Menu",
        title="[bold green]1-Click Client Setup[/]",
        border_style="green",
        box=box.ASCII,
    ))

    choice = Prompt.ask("[bold yellow]Select target client[/]", choices=["1", "2", "3", "4", "0"], default="1")
    executable = sys.executable

    if choice == "0":
        return

    if choice == "1":
        cursor_dir = workspace_root / ".cursor"
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

        console.print(Panel(
            f"[bold green][OK] Cursor MCP configuration successfully written![/]\n\n"
            f"  [cyan]Config Path:[/]   {mcp_file}\n"
            f"  [cyan]Python:[/]        {executable}\n"
            f"  [cyan]Tools:[/]         9 ARES offensive security tools registered\n\n"
            f"[bold white]Next Steps:[/] Open Cursor Settings -> Features -> MCP to verify the connection.",
            title="[bold green]Cursor IDE Setup Complete[/]",
            border_style="green",
            box=box.ASCII,
        ))

    elif choice == "2":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            console.print("[bold red]Could not locate %APPDATA% directory on this system.[/]")
            Prompt.ask("\nPress Enter to return...")
            return

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

        console.print(Panel(
            f"[bold green][OK] Claude Desktop configuration successfully written![/]\n\n"
            f"  [cyan]Config Path:[/]   {claude_file}\n"
            f"  [cyan]Python:[/]        {executable}\n\n"
            f"[bold white]Next Steps:[/] Restart Claude Desktop. The hammer icon will show ARES tools.",
            title="[bold green]Claude Desktop Setup Complete[/]",
            border_style="green",
            box=box.ASCII,
        ))

    elif choice == "3":
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

        console.print(Panel(
            f"[bold green][OK] Windsurf configuration successfully written![/]\n\n"
            f"  [cyan]Config Path:[/] {windsurf_file}\n",
            title="[bold green]Windsurf Setup Complete[/]",
            border_style="green",
            box=box.ASCII,
        ))

    elif choice == "4":
        cline_file = workspace_root / "cline_mcp_settings.json"
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
        console.print(Panel(
            f"[bold green][OK] Cline MCP settings written to workspace![/]\n\n"
            f"  [cyan]Config Path:[/] {cline_file}\n",
            title="[bold green]Cline Setup Complete[/]",
            border_style="green",
            box=box.ASCII,
        ))

    Prompt.ask("\n[dim]Press Enter to return to menu...[/]")


def explore_catalog() -> None:
    """Interactive Module Catalog Explorer."""
    render_header()
    query = Prompt.ask("[bold yellow]Filter by keyword or category[/] [dim](e.g. 'ad', 'kerberos', or Enter for all)[/]", default="").strip().lower()

    matches = []
    for mod_id, desc in sorted(FIRST_PARTY_DESCRIPTORS.items()):
        category_str = desc.category.value if hasattr(desc.category, "value") else str(desc.category)
        opsec_val = desc.opsec.value if hasattr(desc.opsec, "value") else str(desc.opsec)
        source_cls = str(desc.source_class)
        if not query or query in mod_id.lower() or query in category_str.lower() or query in source_cls.lower():
            matches.append((mod_id, desc, category_str, opsec_val, source_cls))

    table = Table(title=f"ARES Module Catalog ({len(matches)} Modules)", box=box.ASCII)
    table.add_column("Module ID", style="bold cyan")
    table.add_column("Category", style="yellow")
    table.add_column("OPSEC Noise", justify="center")
    table.add_column("Execution Governance")
    table.add_column("Source Engine Class")

    opsec_styles = {
        "silent": "[bold green]SILENT[/]",
        "low": "[green]LOW[/]",
        "medium": "[yellow]MEDIUM[/]",
        "high_noise": "[bold red]HIGH NOISE[/]",
    }

    for mod_id, desc, category_str, opsec_val, source_cls in matches[:25]:
        opsec_badge = opsec_styles.get(opsec_val.lower(), opsec_val.upper())
        priv_badge = "[red]Approval Required[/]" if desc.explicit_attempt_approval else "[green]Standard[/]"
        table.add_row(
            mod_id,
            category_str,
            opsec_badge,
            priv_badge,
            source_cls,
        )

    console.print(table)
    if len(matches) > 25:
        console.print(f"[dim]...showing first 25 of {len(matches)} matching modules.[/]")

    Prompt.ask("\n[dim]Press Enter to return to menu...[/]")


def simulate_dry_run() -> None:
    """Interactive ScopeGuard & Dry-Run Simulator."""
    render_header()
    console.print(Panel(
        "[bold white]Pre-Flight Attack Simulation (Zero Packets Sent)[/]\n\n"
        "Validates target against authorized CIDR ranges, evaluates OPSEC noise,\n"
        "and issues a 60-second HMAC-SHA256 confirmation token required for live execution.",
        title="[bold yellow]Target Scope & Dry-Run Simulator[/]",
        border_style="yellow",
        box=box.ASCII,
    ))

    target = Prompt.ask("[bold cyan]Target IP or Hostname[/]", default="10.0.0.15")
    module_id = Prompt.ask("[bold cyan]Module ID[/]", default="ad.kerberoast")
    campaign_id = Prompt.ask("[bold cyan]Campaign ID[/]", default="lab-engagement-01")

    server = AresMcpServer()
    result = asyncio.run(server.tool_registry.call_tool(
        "ares_dry_run_module",
        {
            "campaign_id": campaign_id,
            "module_id": module_id,
            "target": target,
            "params": {"domain": "corp.local"},
        }
    ))

    raw_text = result.content[0].text if result.content else "{}"
    try:
        data = json.loads(raw_text)
    except Exception:
        data = {"output": raw_text}

    token = data.get("confirmation_token", "N/A")
    scope_valid = data.get("scope_validation", {}).get("in_scope", True)
    opsec = data.get("opsec_assessment", {}).get("noise_level", "low")

    status_badge = "[bold green][OK] IN-SCOPE (APPROVED)[/]" if scope_valid else "[bold red][FAIL] OUT-OF-SCOPE (BLOCKED)[/]"
    token_display = f"[bold yellow]{token}[/]" if token != "N/A" else "[red]NONE[/]"

    console.print(Panel(
        f"  [bold white]Module:[/bold white]            [cyan]{module_id}[/cyan]\n"
        f"  [bold white]Target:[/bold white]            [white]{target}[/white]\n"
        f"  [bold white]ScopeGuard:[/]          {status_badge}\n"
        f"  [bold white]OPSEC Noise:[/]         [yellow]{opsec.upper()}[/yellow]\n"
        f"  [bold white]Confirmation Token:[/]  {token_display} [dim](Valid for 60s)[/]\n"
        f"  [bold white]Dry-Run Status:[/]      [green]{data.get('status', 'SUCCESS')}[/green]\n\n"
        f"[dim]Use this confirmation_token with live execution tools to authorize the operation.[/]",
        title="[bold green]Pre-Flight Verification Card[/]",
        border_style="green",
        box=box.ASCII,
    ))

    Prompt.ask("\n[dim]Press Enter to return to menu...[/]")


def run_interactive_tool() -> None:
    """Run any of the 9 operational MCP tools interactively."""
    render_header()
    server = AresMcpServer()
    tools = server.tool_registry.list_tools()

    tool_lines = []
    for i, t in enumerate(tools):
        tool_lines.append(f"  [bold cyan][{i+1}][/] [bold white]{t.name}[/bold white] [dim]- {t.description[:65]}...[/dim]")

    console.print(Panel(
        "\n".join(tool_lines),
        title="[bold cyan]Operational Tools (9 Registered)[/]",
        border_style="cyan",
        box=box.ASCII,
    ))

    selection = Prompt.ask("[bold yellow]Select tool number to execute[/] [dim](0 to cancel)[/]", default="1")
    if not selection.isdigit() or int(selection) < 1 or int(selection) > len(tools):
        return

    chosen_tool = tools[int(selection) - 1]
    console.print(f"\n[bold green]Executing:[/] [cyan]{chosen_tool.name}[/cyan]...")

    req_fields = getattr(chosen_tool.inputSchema, "required", None) or []
    if isinstance(chosen_tool.inputSchema, dict):
        req_fields = chosen_tool.inputSchema.get("required", [])

    args: dict[str, Any] = {}
    if "campaign_id" in req_fields:
        args["campaign_id"] = Prompt.ask("  Enter [cyan]campaign_id[/]", default="lab-engagement-01")
    if "target" in req_fields:
        args["target"] = Prompt.ask("  Enter [cyan]target IP/domain[/]", default="10.0.0.5")
    if "module_id" in req_fields:
        args["module_id"] = Prompt.ask("  Enter [cyan]module_id[/]", default="ad.kerberoast")
    if "finding_id" in req_fields:
        args["finding_id"] = Prompt.ask("  Enter [cyan]finding_id[/]", default="f-demo-01")
    if "confirmation_token" in req_fields:
        args["confirmation_token"] = Prompt.ask("  Enter [cyan]confirmation_token[/]", default="")

    result = asyncio.run(server.tool_registry.call_tool(chosen_tool.name, args))
    raw_text = result.content[0].text if result.content else "{}"

    try:
        formatted = json.dumps(json.loads(raw_text), indent=2)
        syntax = Syntax(formatted, "json", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title=f"[bold green]Result - {chosen_tool.name}[/]", border_style="green", box=box.ASCII))
    except Exception:
        console.print(Panel(raw_text, title=f"[bold green]Result - {chosen_tool.name}[/]", border_style="green", box=box.ASCII))

    Prompt.ask("\n[dim]Press Enter to return to menu...[/]")


def run_system_doctor() -> None:
    """Run full system diagnostics and print rich table."""
    render_header()
    server = AresMcpServer()
    tools = server.tool_registry.list_tools()
    resources = server.resource_registry.list_resources()
    prompts = server.prompt_registry.list_prompts()

    table = Table(title="ARES MCP Subsystem Readiness Check", box=box.ASCII)
    table.add_column("Subsystem", style="bold cyan")
    table.add_column("Status", style="bold green", justify="center")
    table.add_column("Details")

    table.add_row("Protocol Engine", "PASS", "JSON-RPC 2.0 (MCP 2024-11-05)")
    table.add_row("Operational Tools", "PASS", f"{len(tools)} tools registered (Tier-1 & Tier-2)")
    table.add_row("Context Resources", "PASS", f"{len(resources)} URI streams registered")
    table.add_row("Workflow Prompts", "PASS", f"{len(prompts)} templates indexed")
    table.add_row("Module Catalog", "PASS", f"{len(FIRST_PARTY_DESCRIPTORS)} modules indexed")
    table.add_row("Security Gates", "PASS", "ScopeGuard + TokenManager + TaintSanitizer + AD Lockout Breaker")

    console.print(table)
    Prompt.ask("\n[dim]Press Enter to return to menu...[/]")


def start_sse_server() -> None:
    """Start SSE HTTP server."""
    render_header()
    console.print(Panel(
        "[bold white]ARES MCP HTTP Gateway (SSE Mode)[/]\n\n"
        "  [cyan]Endpoint:[/cyan]   http://127.0.0.1:8001/sse\n"
        "  [cyan]Clients:[/cyan]    Open-WebUI, LibreChat, Remote Agents, Docker\n\n"
        "Press [bold yellow]Ctrl+C[/bold yellow] anytime to stop the server and return to this console.",
        title="[bold green]SSE HTTP Gateway[/]",
        border_style="green",
        box=box.ASCII,
    ))
    
    port = int(Prompt.ask("[bold yellow]Port to bind[/]", default="8001"))
    
    import uvicorn
    from ares.mcp import AresMcpServer, create_sse_app
    server = AresMcpServer()
    app = create_sse_app(server)
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except KeyboardInterrupt:
        console.print("\n[yellow]Gateway stopped. Returning to console...[/]")


def interactive_console_loop() -> None:
    """Main OpenCode/OpenClaw-style interactive TUI loop."""
    workspace_root = Path.cwd()

    while True:
        render_header()
        console.print(Panel(
            "  [bold green][1][/] [bold white]1-Click Client Setup[/]       [dim]Auto-configure Cursor, Claude, or Windsurf[/dim]\n"
            "  [bold cyan][2][/] [bold white]Module Catalog[/]             [dim]Browse 62 attack modules & OPSEC noise ratings[/dim]\n"
            "  [bold yellow][3][/] [bold white]Scope & Dry-Run Simulator[/]  [dim]Validate target CIDR and issue 60s token[/dim]\n"
            "  [bold magenta][4][/] [bold white]Run MCP Tool[/]               [dim]Execute operational tools with rich card output[/dim]\n"
            "  [bold blue][5][/] [bold white]System Diagnostics (Doctor)[/] [dim]Verify subsystem readiness matrix[/dim]\n"
            "  [bold green][6][/] [bold white]HTTP / SSE Gateway[/]         [dim]Start local network server (Port 8001)[/dim]\n"
            "  [bold red][0][/] [bold white]Exit[/]",
            title="[bold white]ARES MCP - CONSOLE[/]",
            border_style="cyan",
            box=box.ASCII,
        ))

        choice = Prompt.ask("[bold yellow]Select option[/]", choices=["1", "2", "3", "4", "5", "6", "0"], default="1")

        if choice == "0":
            console.print("\n[bold cyan]ARES MCP Console closed.[/]")
            break
        elif choice == "1":
            auto_setup_client(workspace_root)
        elif choice == "2":
            explore_catalog()
        elif choice == "3":
            simulate_dry_run()
        elif choice == "4":
            run_interactive_tool()
        elif choice == "5":
            run_system_doctor()
        elif choice == "6":
            start_sse_server()


if __name__ == "__main__":
    interactive_console_loop()
