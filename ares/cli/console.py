"""ARES MCP - Model Context Protocol Gateway Console (OpenCode / OpenClaw style).

Tactical, unified, product-grade interactive terminal for:
- 1-Click Auto-Setup for Cursor, Claude Desktop, Windsurf, and Cline
- Interactive Module Catalog Explorer with OPSEC noise ratings
- Pre-Flight Target ScopeGuard & Dry-Run Simulator with HMAC confirmation tokens
- Interactive Tool Runner with syntax-highlighted visual cards
- System Readiness Diagnostics & Local SSE Gateway launcher
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from rich import box
from rich.align import Align
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table

from ares.cli.mcp_cli_utils import (
    COLOR_ERROR,
    COLOR_INDEX,
    COLOR_LABEL,
    COLOR_NEUTRAL,
    COLOR_SUCCESS,
    COLOR_VALUE,
    COLOR_WARNING,
    EXIT_SIGINT,
    EXIT_SUCCESS,
    get_mcp_console,
)
from ares.cli.mcp_commands import (
    execute_dry_run,
    get_doctor_diagnostics,
    query_module_catalog,
    setup_client_configuration,
)
from ares.mcp.server import AresMcpServer

console = get_mcp_console()

ASCII_BANNER = r"""
[bold cyan]   _   ___ ___ ___ [/]  [bold white] __  __ ___ ___ [/]
[bold cyan]  /_\ | _ \ __/ __|[/]  [bold white]|  \/  / __| _ \ [/]
[bold cyan] / _ \|   / _|\__ \ [/] [bold white]| |\/| | (__|  _/ [/]
[bold cyan]/_/ \_\_|_\___|___/[/]  [bold white]|_|  |_|\___|_|   [/]
"""


def render_header() -> None:
    """Render the tactical ARES MCP header with clean spacing."""
    console.print()
    console.print(Align.center(ASCII_BANNER))

    header_table = Table(box=box.ROUNDED, show_header=False, expand=True, border_style="cyan")
    header_table.add_column(justify="left")
    header_table.add_column(justify="right")

    header_table.add_row(
        f"[{COLOR_VALUE}]ARES MCP[/] [{COLOR_NEUTRAL}]- Automated Red Team System[/]",
        f"[{COLOR_SUCCESS}][*] READY[/] [{COLOR_NEUTRAL}]v6.0.0[/]",
    )
    stat_left = (
        f"[{COLOR_LABEL}]Modules:[/] [{COLOR_VALUE}]62 Active[/]   "
        f"[{COLOR_LABEL}]Tools:[/] [{COLOR_VALUE}]9 Governed[/]   "
        f"[{COLOR_LABEL}]Transport:[/] [{COLOR_VALUE}]Stdio + SSE[/]"
    )
    stat_right = (
        f"[{COLOR_LABEL}]ScopeGuard:[/] [{COLOR_SUCCESS}]Enforced[/]   "
        f"[{COLOR_LABEL}]Auth:[/] [{COLOR_WARNING}]HMAC-SHA256[/]"
    )
    header_table.add_row(stat_left, stat_right)

    console.print(header_table)
    console.print()


def auto_setup_client(workspace_root: Path) -> None:
    """1-Click Auto-Setup for AI IDEs and clients without manual copy-paste."""
    render_header()
    setup_lines = [
        f"[{COLOR_VALUE}]Select your AI client to configure MCP automatically:[/]\n",
        f"  [{COLOR_INDEX}][1][/] Cursor IDE         "
        f"[{COLOR_NEUTRAL}]Auto-configures .cursor/mcp.json in workspace[/]",
        f"  [{COLOR_INDEX}][2][/] Claude Desktop     "
        f"[{COLOR_NEUTRAL}]Auto-configures Claude desktop config[/]",
        f"  [{COLOR_INDEX}][3][/] Windsurf           "
        f"[{COLOR_NEUTRAL}]Auto-configures ~/.codeium/windsurf/mcp_config.json[/]",
        f"  [{COLOR_INDEX}][4][/] VS Code (Cline)    "
        f"[{COLOR_NEUTRAL}]Auto-configures cline_mcp_settings.json[/]",
        f"  [{COLOR_ERROR}][0][/] Back to Menu",
    ]
    console.print(Panel(
        "\n".join(setup_lines),
        title=f"[{COLOR_SUCCESS}]1-Click Client Setup[/]",
        border_style="green",
        box=box.ROUNDED,
    ))

    choice = Prompt.ask(
        f"[{COLOR_LABEL}]Select target client[/]",
        choices=["1", "2", "3", "4", "0"],
        default="1",
    )
    client_map = {"1": "cursor", "2": "claude", "3": "windsurf", "4": "cline"}

    if choice == "0":
        return

    client_name = client_map.get(choice, "cursor")
    code, msg = setup_client_configuration(client_name, workspace_root=workspace_root)

    status_color = COLOR_SUCCESS if code == EXIT_SUCCESS else COLOR_ERROR
    status_icon = "[OK]" if code == EXIT_SUCCESS else "[ERR]"
    console.print()
    verification_msg = "Restart your client or check MCP settings to verify connection."
    console.print(Panel(
        f"[{status_color}]{status_icon} {msg}[/]\n\n"
        f"[{COLOR_LABEL}]Client Target:[/]  [{COLOR_VALUE}]{client_name.upper()}[/]\n"
        f"[{COLOR_LABEL}]Tools Ready:[/]    [{COLOR_VALUE}]9 ARES operational tools[/]\n\n"
        f"[{COLOR_VALUE}]Verification:[/] {verification_msg}",
        title=f"[{status_color}]{client_name.capitalize()} Setup Status[/]",
        border_style="green" if code == EXIT_SUCCESS else "red",
        box=box.ROUNDED,
    ))

    Prompt.ask(f"\n[{COLOR_NEUTRAL}]Press Enter to return to menu...[/]")


def explore_catalog() -> None:
    """Interactive Module Catalog Explorer with OPSEC and Governance ratings."""
    render_header()
    query_prompt = (
        f"[{COLOR_LABEL}]Filter by keyword or category[/] "
        f"[{COLOR_NEUTRAL}](e.g. 'ad', 'kerberos', or Enter for all)[/]"
    )
    query = Prompt.ask(query_prompt, default="").strip()

    matches = query_module_catalog(query=query if query else None)

    table = Table(title=f"ARES Module Catalog ({len(matches)} Modules)", box=box.ROUNDED)
    table.add_column("Module ID", style=COLOR_LABEL)
    table.add_column("Category", style=COLOR_VALUE)
    table.add_column("OPSEC Noise", justify="center")
    table.add_column("Governance")
    table.add_column("Source Engine Class")

    opsec_styles = {
        "silent": f"[{COLOR_SUCCESS}]SILENT[/]",
        "low": f"[{COLOR_SUCCESS}]LOW[/]",
        "medium": f"[{COLOR_WARNING}]MEDIUM[/]",
        "high_noise": f"[{COLOR_ERROR}]HIGH NOISE[/]",
    }

    for item in matches[:25]:
        opsec_val = item["opsec_level"].lower()
        opsec_badge = opsec_styles.get(opsec_val, f"[{COLOR_VALUE}]{opsec_val.upper()}[/]")
        gov_badge = (
            f"[{COLOR_WARNING}]Approval Required[/]"
            if item["requires_approval"]
            else f"[{COLOR_SUCCESS}]Standard[/]"
        )
        table.add_row(
            item["module_id"],
            item["category"],
            opsec_badge,
            gov_badge,
            item["source_class"],
        )

    console.print()
    console.print(table)
    if len(matches) > 25:
        more_msg = (
            f"...showing first 25 of {len(matches)} matching modules. "
            "Use filter to narrow search."
        )
        console.print(f"[{COLOR_NEUTRAL}]{more_msg}[/]")

    Prompt.ask(f"\n[{COLOR_NEUTRAL}]Press Enter to return to menu...[/]")


def simulate_dry_run() -> None:
    """Interactive ScopeGuard & Dry-Run Simulator."""
    render_header()
    console.print(Panel(
        f"[{COLOR_VALUE}]Pre-Flight Attack Simulation (Zero Network Packets)[/]\n\n"
        f"Validates target against authorized CIDR ranges, evaluates OPSEC noise,\n"
        f"and issues a 60-second HMAC-SHA256 confirmation token required for live execution.",
        title=f"[{COLOR_WARNING}]Target Scope & Dry-Run Simulator[/]",
        border_style="yellow",
        box=box.ROUNDED,
    ))

    target = Prompt.ask(f"[{COLOR_LABEL}]Target IP or Hostname[/]", default="10.0.0.15")
    module_id = Prompt.ask(f"[{COLOR_LABEL}]Module ID[/]", default="ad.kerberoast")
    campaign_id = Prompt.ask(f"[{COLOR_LABEL}]Campaign ID[/]", default="lab-engagement-01")

    data = execute_dry_run(target=target, module_id=module_id, campaign_id=campaign_id)

    receipt_code = data.get("confirmation_token", "N/A")
    scope_valid = data.get("scope_validation", {}).get("in_scope", True)
    opsec = data.get("opsec_assessment", {}).get("noise_level", "low")

    status_badge = (
        f"[{COLOR_SUCCESS}][OK] IN-SCOPE (APPROVED)[/]"
        if scope_valid
        else f"[{COLOR_ERROR}][FAIL] OUT-OF-SCOPE (BLOCKED)[/]"
    )
    token_display = (
        f"[{COLOR_WARNING}]{receipt_code}[/]"
        if receipt_code != "N/A"
        else f"[{COLOR_ERROR}]NONE[/]"
    )

    status_val = data.get("status", "SUCCESS")
    card_hint = (
        "Use this confirmation_token with live execution tools to authorize the operation."
    )
    console.print()
    console.print(Panel(
        f"  [{COLOR_LABEL}]Module:[/]             [{COLOR_VALUE}]{module_id}[/]\n"
        f"  [{COLOR_LABEL}]Target:[/]             [{COLOR_VALUE}]{target}[/]\n"
        f"  [{COLOR_LABEL}]ScopeGuard:[/]         {status_badge}\n"
        f"  [{COLOR_LABEL}]OPSEC Noise:[/]        [{COLOR_WARNING}]{opsec.upper()}[/]\n"
        f"  [{COLOR_LABEL}]Confirmation Token:[/] {token_display} [{COLOR_NEUTRAL}](60s TTL)[/]\n"
        f"  [{COLOR_LABEL}]Dry-Run Status:[/]     [{COLOR_SUCCESS}]{status_val}[/]\n\n"
        f"[{COLOR_NEUTRAL}]{card_hint}[/]",
        title=f"[{COLOR_SUCCESS}]Pre-Flight Verification Card[/]",
        border_style="green" if scope_valid else "red",
        box=box.ROUNDED,
    ))

    Prompt.ask(f"\n[{COLOR_NEUTRAL}]Press Enter to return to menu...[/]")


def run_interactive_tool() -> None:
    """Run any of the 9 operational MCP tools interactively."""
    render_header()
    server = AresMcpServer()
    tools = server.tool_registry.list_tools()

    tool_lines = []
    for i, t in enumerate(tools):
        t_desc = t.description[:55]
        tool_lines.append(
            f"  [{COLOR_INDEX}][{i+1}][/] [{COLOR_VALUE}]{t.name}[/] "
            f"[{COLOR_NEUTRAL}]- {t_desc}...[/]"
        )

    console.print(Panel(
        "\n".join(tool_lines),
        title=f"[{COLOR_LABEL}]Operational Tools (9 Registered)[/]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    select_prompt = (
        f"[{COLOR_LABEL}]Select tool number to execute[/] [{COLOR_NEUTRAL}](0 to cancel)[/]"
    )
    selection = Prompt.ask(select_prompt, default="1")
    if not selection.isdigit() or int(selection) < 1 or int(selection) > len(tools):
        return

    chosen_tool = tools[int(selection) - 1]
    console.print(f"\n[{COLOR_SUCCESS}]Executing:[/] [{COLOR_LABEL}]{chosen_tool.name}[/]...")

    req_fields = getattr(chosen_tool.inputSchema, "required", None) or []
    if isinstance(chosen_tool.inputSchema, dict):
        req_fields = chosen_tool.inputSchema.get("required", [])

    args: dict[str, Any] = {}
    if "campaign_id" in req_fields:
        args["campaign_id"] = Prompt.ask(
            f"  Enter [{COLOR_LABEL}]campaign_id[/]", default="lab-engagement-01"
        )
    if "target" in req_fields:
        args["target"] = Prompt.ask(
            f"  Enter [{COLOR_LABEL}]target IP/domain[/]", default="10.0.0.5"
        )
    if "module_id" in req_fields:
        args["module_id"] = Prompt.ask(
            f"  Enter [{COLOR_LABEL}]module_id[/]", default="ad.kerberoast"
        )
    if "finding_id" in req_fields:
        args["finding_id"] = Prompt.ask(
            f"  Enter [{COLOR_LABEL}]finding_id[/]", default="f-demo-01"
        )
    if "confirmation_token" in req_fields:
        args["confirmation_token"] = Prompt.ask(
            f"  Enter [{COLOR_LABEL}]confirmation_token[/]", password=True
        )

    for field in req_fields:
        if field not in args:
            is_secret = any(
                k in field.lower()
                for k in ("secret", "token", "key", "password", "credential")
            )
            args[field] = Prompt.ask(f"  Enter [{COLOR_LABEL}]{field}[/]", password=is_secret)

    result = asyncio.run(server.tool_registry.call_tool(chosen_tool.name, args))
    raw_text = result.content[0].text if result.content else "{}"

    console.print()
    try:
        formatted = json.dumps(json.loads(raw_text), indent=2)
        syntax = Syntax(formatted, "json", theme="monokai", line_numbers=True)
        console.print(
            Panel(
                syntax,
                title=f"[{COLOR_SUCCESS}]Result - {chosen_tool.name}[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
    except Exception:
        console.print(
            Panel(
                raw_text,
                title=f"[{COLOR_SUCCESS}]Result - {chosen_tool.name}[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    Prompt.ask(f"\n[{COLOR_NEUTRAL}]Press Enter to return to menu...[/]")


def run_system_doctor() -> None:
    """Run full system diagnostics and print rich table."""
    render_header()
    diag = get_doctor_diagnostics()

    table = Table(title="ARES MCP Subsystem Readiness Check", box=box.ROUNDED)
    table.add_column("Subsystem", style=COLOR_LABEL)
    table.add_column("Status", justify="center")
    table.add_column("Details")

    for item in diag["subsystems"]:
        status_badge = (
            f"[{COLOR_SUCCESS}]PASS[/]" if item["status"] == "PASS" else f"[{COLOR_ERROR}]FAIL[/]"
        )
        table.add_row(item["subsystem"], status_badge, item["details"])

    console.print()
    console.print(table)
    Prompt.ask(f"\n[{COLOR_NEUTRAL}]Press Enter to return to menu...[/]")


def start_sse_server() -> None:
    """Start SSE HTTP server with clean shutdown."""
    import uvicorn

    from ares.mcp import AresMcpServer, create_sse_app

    render_header()
    console.print(Panel(
        f"[{COLOR_VALUE}]ARES MCP HTTP Gateway (SSE Mode)[/]\n\n"
        f"  [{COLOR_LABEL}]Endpoint:[/]   http://127.0.0.1:8001/sse\n"
        f"  [{COLOR_LABEL}]Clients:[/]    Open-WebUI, LibreChat, Remote Agents, Docker\n\n"
        f"Press [{COLOR_WARNING}]Ctrl+C[/] anytime to stop the server and return to this console.",
        title=f"[{COLOR_SUCCESS}]SSE HTTP Gateway[/]",
        border_style="green",
        box=box.ROUNDED,
    ))

    port = int(Prompt.ask(f"[{COLOR_LABEL}]Port to bind[/]", default="8001"))

    server = AresMcpServer()
    app = create_sse_app(server)
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except KeyboardInterrupt:
        console.print(f"\n[{COLOR_WARNING}]Gateway stopped. Returning to console...[/]")


def interactive_console_loop() -> None:
    """Main OpenCode/OpenClaw-style interactive TUI loop with graceful SIGINT handling."""
    workspace_root = Path.cwd()

    # Non-TTY guard: if piped, do not hang on interactive input
    if not sys.stdin.isatty():
        diag = get_doctor_diagnostics()
        console.print(f"[{COLOR_VALUE}]ARES MCP (Non-interactive mode)[/]: {diag['status']}")
        return

    try:
        while True:
            render_header()
            menu_lines = [
                f"  [{COLOR_INDEX}][1][/] [{COLOR_VALUE}]1-Click Client Setup[/]       "
                f"[{COLOR_NEUTRAL}]Auto-configure Cursor, Claude, or Windsurf[/]",
                f"  [{COLOR_INDEX}][2][/] [{COLOR_VALUE}]Module Catalog[/]             "
                f"[{COLOR_NEUTRAL}]Browse 62 attack modules & OPSEC noise ratings[/]",
                f"  [{COLOR_INDEX}][3][/] [{COLOR_VALUE}]Scope & Dry-Run Simulator[/]  "
                f"[{COLOR_NEUTRAL}]Validate target CIDR and issue 60s token[/]",
                f"  [{COLOR_INDEX}][4][/] [{COLOR_VALUE}]Run MCP Tool[/]               "
                f"[{COLOR_NEUTRAL}]Execute operational tools with rich card output[/]",
                f"  [{COLOR_INDEX}][5][/] [{COLOR_VALUE}]System Diagnostics (Doctor)[/] "
                f"[{COLOR_NEUTRAL}]Verify subsystem readiness matrix[/]",
                f"  [{COLOR_INDEX}][6][/] [{COLOR_VALUE}]HTTP / SSE Gateway[/]         "
                f"[{COLOR_NEUTRAL}]Start local network server (Port 8001)[/]",
                f"  [{COLOR_ERROR}][0][/] [{COLOR_ERROR}]Exit[/]",
            ]
            console.print(Panel(
                "\n".join(menu_lines),
                title=f"[{COLOR_VALUE}]ARES MCP * CONSOLE[/]",
                border_style="cyan",
                box=box.ROUNDED,
            ))

            choice = Prompt.ask(
                f"[{COLOR_LABEL}]Select option[/]",
                choices=["1", "2", "3", "4", "5", "6", "0"],
                default="1",
            )

            if choice == "0":
                console.print(
                    f"\n[{COLOR_LABEL}]ARES MCP Console closed. Operator session finished.[/]"
                )
                sys.exit(EXIT_SUCCESS)
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

    except KeyboardInterrupt:
        console.print(f"\n[{COLOR_NEUTRAL}]Cancelled[/]")
        sys.exit(EXIT_SIGINT)


if __name__ == "__main__":
    interactive_console_loop()
