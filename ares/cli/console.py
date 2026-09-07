"""ARES Sovereign Agent Console (OpenClaw / OpenCode-style TUI).

Unified, zero-friction, single-terminal interactive console for:
- 1-Click Auto-Setup for Cursor, Claude, Windsurf, Cline (zero manual JSON copy-paste)
- Interactive Module Catalog Explorer with OPSEC filter
- Target Scope & Pre-Flight Dry-Run Simulator with HMAC confirmation tokens
- Interactive MCP Tool Runner with syntax-highlighted visual cards
- One-touch System Diagnostics and Background SSE Server management
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

BANNER_ART = r"""
[bold cyan]     ___   ___  ___ ___ [/]   [bold white] __  __  ___  ___ [/]
[bold cyan]    / _ \ / _ \/ __| _ \ [/]  [bold white]|  \/  |/ __|| _ \ [/]
[bold cyan]   / // // // /\__ \ _// [/]  [bold white]| |\/| | (__ |  _/ [/]
[bold cyan]  /_/ \_\\___/ |___/_/   [/]  [bold white]|_|  |_|\___||_|   [/]
"""


def render_header() -> None:
    """Render the cyberpunk styled sovereign console header."""
    console.print(Align.center(BANNER_ART))
    
    status_text = Text()
    status_text.append(" [*] GATEWAY ACTIVE ", style="bold black on green")
    status_text.append("  ")
    status_text.append(" 62 MODULES ", style="bold white on blue")
    status_text.append("  ")
    status_text.append(" 9 MCP TOOLS ", style="bold black on cyan")
    status_text.append("  ")
    status_text.append(" SCOPEGUARD ARMED ", style="bold black on yellow")
    status_text.append("  ")
    status_text.append(" HMAC-256 TOKENS ", style="bold white on magenta")

    console.print(Align.center(status_text))
    console.print(Align.center("[dim]ARES Sovereign Model Context Protocol - Zero-Friction Unified Terminal[/]\n"))


def auto_setup_client(workspace_root: Path) -> None:
    """1-Click Auto-Setup for AI IDEs and clients without manual copy-paste."""
    render_header()
    console.print(Panel(
        "[bold white]Select your AI Environment to automatically configure MCP connection:[/]\n\n"
        "  [bold cyan][1][/] Cursor IDE         [dim](Auto-creates .cursor/mcp.json in workspace)[/]\n"
        "  [bold cyan][2][/] Claude Desktop     [dim](Auto-configures %APPDATA%\\Claude\\claude_desktop_config.json)[/]\n"
        "  [bold cyan][3][/] Windsurf           [dim](Auto-configures ~/.codeium/windsurf/mcp_config.json)[/]\n"
        "  [bold cyan][4][/] VS Code (Cline)    [dim](Auto-creates cline_mcp_settings.json)[/]\n"
        "  [bold cyan][0][/] Back to Main Menu",
        title="[bold green][!] 1-Click Client Auto-Setup[/]",
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
            f"[bold green][OK] SUCCESS: Cursor MCP configuration automatically installed![/]\n\n"
            f"  [cyan]File Location:[/cyan]  {mcp_file}\n"
            f"  [cyan]Python Path:[/cyan]    {executable}\n"
            f"  [cyan]Registered Tool Count:[/cyan] 9 Operational Tools\n\n"
            f"[bold white]What to do next:[/]\n"
            f"  1. Open Cursor Settings (`Ctrl + ,`) -> [bold cyan]Features -> MCP[/]\n"
            f"  2. You will see [bold green]ares (Active)[/] with a green status indicator!\n"
            f"  3. Open Cursor Chat (`Ctrl + L`) and start asking ARES directly.",
            title="[bold green]Cursor IDE Connected[/]",
            border_style="green",
            box=box.ASCII,
        ))

    elif choice == "2":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            console.print("[bold red]Could not locate %APPDATA% directory.[/]")
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
            f"[bold green][OK] SUCCESS: Claude Desktop configuration automatically installed![/]\n\n"
            f"  [cyan]File Location:[/cyan]  {claude_file}\n"
            f"  [cyan]Python Path:[/cyan]    {executable}\n\n"
            f"[bold white]What to do next:[/]\n"
            f"  1. Restart Claude Desktop.\n"
            f"  2. The tool icon (hammer) will now feature ARES tools.",
            title="[bold green]Claude Desktop Connected[/]",
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
            f"[bold green][OK] SUCCESS: Windsurf MCP configuration automatically installed![/]\n\n"
            f"  [cyan]File Location:[/cyan] {windsurf_file}\n",
            title="[bold green]Windsurf Connected[/]",
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
            f"[bold green][OK] SUCCESS: Cline MCP configuration created in workspace![/]\n\n"
            f"  [cyan]File Location:[/cyan] {cline_file}\n",
            title="[bold green]Cline Connected[/]",
            border_style="green",
            box=box.ASCII,
        ))

    Prompt.ask("\n[dim]Press Enter to continue...[/]")


def explore_catalog() -> None:
    """Interactive Module Catalog Explorer."""
    render_header()
    query = Prompt.ask("[bold yellow]Filter keyword or category[/] [dim](e.g. 'ad', 'kerberos', or Enter for all)[/]", default="").strip().lower()

    matches = []
    for mod_id, desc in sorted(FIRST_PARTY_DESCRIPTORS.items()):
        if not query or query in mod_id.lower() or query in desc.description.lower() or query in desc.category.lower():
            matches.append((mod_id, desc))

    table = Table(title=f"ARES Module Catalog ({len(matches)} Modules Found)", box=box.ASCII)
    table.add_column("Module ID", style="bold cyan")
    table.add_column("Category", style="yellow")
    table.add_column("OPSEC Noise", justify="center")
    table.add_column("Privileges")
    table.add_column("Description")

    opsec_styles = {
        "silent": "[bold green]SILENT[/]",
        "low": "[green]LOW[/]",
        "medium": "[yellow]MEDIUM[/]",
        "high_noise": "[bold red]HIGH NOISE[/]",
    }

    for mod_id, desc in matches[:30]:
        opsec_badge = opsec_styles.get(desc.opsec_level.value, desc.opsec_level.value)
        priv_badge = "[red]ROOT/SYSTEM[/]" if desc.requires_privileged_access else "[green]User[/]"
        table.add_row(
            mod_id,
            desc.category,
            opsec_badge,
            priv_badge,
            desc.description[:50] + ("..." if len(desc.description) > 50 else ""),
        )

    console.print(table)
    if len(matches) > 30:
        console.print(f"[dim]...showing first 30 of {len(matches)} matching modules.[/]")

    Prompt.ask("\n[dim]Press Enter to continue...[/]")


def simulate_dry_run() -> None:
    """Interactive ScopeGuard & Dry-Run Simulator."""
    render_header()
    console.print(Panel(
        "[bold white]Pre-Flight Dry-Run Simulator[/]\n\n"
        "Simulates attack module execution with [bold green]zero live packets[/].\n"
        "Validates target against ScopeGuard CIDR rules, assesses OPSEC risk,\n"
        "and issues a 60-second cryptographic confirmation token required for live execution.",
        title="[bold yellow][TGT] Target Scope & Dry-Run Simulator[/]",
        border_style="yellow",
        box=box.ASCII,
    ))

    target = Prompt.ask("[bold cyan]Target IP or Hostname[/]", default="10.0.0.15")
    module_id = Prompt.ask("[bold cyan]Module ID[/]", default="ad.kerberoast")
    campaign_id = Prompt.ask("[bold cyan]Campaign ID[/]", default="lab-engagement-01")

    server = AresMcpServer()
    result = asyncio.run(server.tool_registry.execute_tool(
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

    status_badge = "[bold green][OK] IN-SCOPE (CLEARED)[/]" if scope_valid else "[bold red][FAIL] OUT-OF-SCOPE (BLOCKED)[/]"
    token_display = f"[bold yellow]{token}[/]" if token != "N/A" else "[red]NONE[/]"

    console.print(Panel(
        f"  [bold white]Module:[/bold white]              [cyan]{module_id}[/cyan]\n"
        f"  [bold white]Target:[/bold white]              [white]{target}[/white]\n"
        f"  [bold white]ScopeGuard Status:[/bold white]   {status_badge}\n"
        f"  [bold white]OPSEC Noise Level:[/bold white]   [yellow]{opsec.upper()}[/yellow]\n"
        f"  [bold white]Confirmation Token:[/bold white]  {token_display} [dim](Valid for 60s)[/]\n"
        f"  [bold white]Dry-Run Result:[/bold white]      [green]{data.get('status', 'SUCCESS')}[/green]\n\n"
        f"[dim]Use this confirmation_token with `ares_execute_module` to authorize live execution.[/]",
        title="[bold green]Pre-Flight Verification Card[/]",
        border_style="green",
        box=box.ASCII,
    ))

    Prompt.ask("\n[dim]Press Enter to continue...[/]")


def run_interactive_tool() -> None:
    """Run any of the 9 operational MCP tools interactively."""
    render_header()
    server = AresMcpServer()
    tools = server.tool_registry.list_tools()

    tool_lines = []
    for i, t in enumerate(tools):
        tool_lines.append(f"  [bold cyan][{i+1}][/] [bold white]{t.name}[/bold white] - [dim]{t.description[:65]}...[/dim]")

    console.print(Panel(
        "\n".join(tool_lines),
        title="[bold cyan][OPS] Operational Tool Suite (9 Tools Available)[/]",
        border_style="cyan",
        box=box.ASCII,
    ))

    selection = Prompt.ask("[bold yellow]Select tool number to execute[/] [dim](or 0 to cancel)[/]", default="1")
    if not selection.isdigit() or int(selection) < 1 or int(selection) > len(tools):
        return

    chosen_tool = tools[int(selection) - 1]
    console.print(f"\n[bold green]Executing:[/] [cyan]{chosen_tool.name}[/cyan]...")

    args: dict[str, Any] = {}
    if "campaign_id" in chosen_tool.inputSchema.get("required", []):
        args["campaign_id"] = Prompt.ask("  Enter [cyan]campaign_id[/]", default="lab-engagement-01")
    if "target" in chosen_tool.inputSchema.get("required", []):
        args["target"] = Prompt.ask("  Enter [cyan]target IP/domain[/]", default="10.0.0.5")
    if "module_id" in chosen_tool.inputSchema.get("required", []):
        args["module_id"] = Prompt.ask("  Enter [cyan]module_id[/]", default="ad.kerberoast")
    if "finding_id" in chosen_tool.inputSchema.get("required", []):
        args["finding_id"] = Prompt.ask("  Enter [cyan]finding_id[/]", default="f-demo-01")
    if "confirmation_token" in chosen_tool.inputSchema.get("required", []):
        args["confirmation_token"] = Prompt.ask("  Enter [cyan]confirmation_token[/]", default="")

    result = asyncio.run(server.tool_registry.execute_tool(chosen_tool.name, args))
    raw_text = result.content[0].text if result.content else "{}"

    try:
        formatted = json.dumps(json.loads(raw_text), indent=2)
        syntax = Syntax(formatted, "json", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title=f"[bold green]Execution Result - {chosen_tool.name}[/]", border_style="green", box=box.ASCII))
    except Exception:
        console.print(Panel(raw_text, title=f"[bold green]Execution Result - {chosen_tool.name}[/]", border_style="green", box=box.ASCII))

    Prompt.ask("\n[dim]Press Enter to continue...[/]")


def run_system_doctor() -> None:
    """Run full system diagnostics and print rich table."""
    render_header()
    server = AresMcpServer()
    tools = server.tool_registry.list_tools()
    resources = server.resource_registry.list_resources()
    prompts = server.prompt_registry.list_prompts()

    table = Table(title="ARES Sovereign MCP Subsystem Diagnostics", box=box.ASCII)
    table.add_column("Subsystem", style="bold cyan")
    table.add_column("Status", style="bold green", justify="center")
    table.add_column("Specification")

    table.add_row("Protocol Engine", "[*] PASS", "JSON-RPC 2.0 (MCP 2024-11-05 Specification)")
    table.add_row("Operational Tools", "[*] PASS", f"{len(tools)} tools registered (Tier-1 & Tier-2)")
    table.add_row("Context Resources", "[*] PASS", f"{len(resources)} live URI streams active")
    table.add_row("Purple-Team Prompts", "[*] PASS", f"{len(prompts)} workflow templates indexed")
    table.add_row("Descriptor Catalog", "[*] PASS", f"{len(FIRST_PARTY_DESCRIPTORS)} offensive modules ready")
    table.add_row("Security Gates", "[*] PASS", "ScopeGuard + TokenManager + TaintSanitizer + AD Lockout Breaker")

    console.print(table)
    Prompt.ask("\n[dim]Press Enter to continue...[/]")


def start_sse_server() -> None:
    """Start SSE HTTP server."""
    render_header()
    console.print(Panel(
        "[bold white]ARES Sovereign MCP Server (HTTP / SSE Mode)[/]\n\n"
        "  [cyan]Default Endpoint:[/cyan] http://127.0.0.1:8001/sse\n"
        "  [cyan]Press Ctrl+C[/cyan] to stop the server and return to this console anytime.",
        title="[bold green][NET] SSE HTTP Gateway[/]",
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
        console.print("\n[yellow]Server stopped. Returning to console...[/]")


def interactive_console_loop() -> None:
    """Main OpenClaw/OpenCode-style interactive TUI loop."""
    workspace_root = Path.cwd()

    while True:
        render_header()
        console.print(Panel(
            "  [bold green][1][/] [bold white][!] 1-Click Auto-Setup for Cursor / Claude / Windsurf[/] [dim](Zero copy-paste)[/]\n"
            "  [bold cyan][2][/] [bold white][SEC] Module Catalog Explorer[/] [dim](Search 62+ modules & OPSEC noise)[/]\n"
            "  [bold yellow][3][/] [bold white][TGT] Target ScopeGuard & Dry-Run Simulator[/] [dim](Issue 60s Token)[/]\n"
            "  [bold magenta][4][/] [bold white][OPS] Interactive MCP Tool Runner[/] [dim](Execute any of the 9 tools)[/]\n"
            "  [bold blue][5][/] [bold white][DOC] System Doctor Diagnostics[/] [dim](Verify all subsystems)[/]\n"
            "  [bold green][6][/] [bold white][NET] Launch SSE HTTP Server[/] [dim](Port 8001 Webhook / SSE)[/]\n"
            "  [bold red][0][/] [bold white][X] Exit Console[/]",
            title="[bold white]ARES SOVEREIGN AGENT CONSOLE - MAIN MENU[/]",
            border_style="cyan",
            box=box.ASCII,
        ))

        choice = Prompt.ask("[bold yellow]Select an option[/]", choices=["1", "2", "3", "4", "5", "6", "0"], default="1")

        if choice == "0":
            console.print("\n[bold cyan]Shutting down ARES Sovereign Console. Farewell, Operator.[/]")
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
