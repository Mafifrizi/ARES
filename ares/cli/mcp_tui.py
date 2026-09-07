"""
ARES MCP Two-Pane Split Terminal User Interface (OpenClaw Style).
Provides real-time, zero-emoji telemetry and interactive confirmation token authorization.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Any, Dict, List, Optional

# Non-blocking keyboard check
try:
    import msvcrt

    def check_keypress() -> Optional[str]:
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            try:
                return ch.decode("utf-8").lower()
            except UnicodeDecodeError:
                return None
        return None

except ImportError:
    import select

    def check_keypress() -> Optional[str]:
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if r:
            ch = sys.stdin.read(1)
            return ch.lower()
        return None

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ares.mcp.events import McpEventBus, McpEventListener


class TuiState:
    """Operational state for the ARES MCP Two-Pane Split TUI."""

    def __init__(self, campaign: str = "Internal-Audit-2026", scope: str = "10.0.1.0/24, 192.168.10.0/24") -> None:
        self.events: List[Dict[str, Any]] = []
        self.campaign_name: str = campaign
        self.scope_cidrs: str = scope
        self.strict_mode: bool = True
        self.opsec_profile: str = "STEALTH (Jitter: 2.5s)"

        # Staged action state
        self.staged_module: Optional[str] = None
        self.staged_target: Optional[str] = None
        self.staged_action: Optional[str] = None
        self.staged_risk: Optional[str] = None

        # Pending authorization token
        self.pending_token: Optional[str] = None
        self.token_module: Optional[str] = None
        self.token_expiry: float = 0.0
        self.token_status: str = "IDLE"  # IDLE, PENDING, APPROVED, REJECTED, EXPIRED

    def add_event(self, timestamp: str, event_type: str, details: str, status: str, status_style: str = "green") -> None:
        self.events.append({
            "time": timestamp,
            "type": event_type,
            "details": details,
            "status": status,
            "status_style": status_style,
        })
        if len(self.events) > 100:
            self.events.pop(0)

    def set_pending_token(self, token: str, module: str, ttl_seconds: int = 60) -> None:
        self.pending_token = token
        self.token_module = module
        self.token_expiry = time.time() + ttl_seconds
        self.token_status = "PENDING"

    def approve_token(self) -> Optional[str]:
        if self.pending_token and self.token_status == "PENDING":
            self.token_status = "APPROVED"
            token = self.pending_token
            return token
        return None

    def reject_token(self) -> Optional[str]:
        if self.pending_token and self.token_status == "PENDING":
            self.token_status = "REJECTED"
            token = self.pending_token
            return token
        return None


def build_tui_layout(state: TuiState) -> Layout:
    """Build the root Two-Pane Split Layout (OpenClaw style)."""
    root = Layout(name="root")
    root.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3),
    )

    root["body"].split_row(
        Layout(name="left_stream", ratio=6),
        Layout(name="right_posture", ratio=4),
    )

    # 1. Header: Minimalist single-line metadata bar
    header_text = Text.assemble(
        (" ARES MCP ", "bold black on cyan"),
        ("  GATEWAY LISTENING  ", "bold white"),
        ("|  TRANSPORT: ", "dim"),
        ("stdio / sse", "cyan"),
        ("  |  CAMPAIGN: ", "dim"),
        (state.campaign_name, "bold white"),
        ("  |  SCOPE: ", "dim"),
        (state.scope_cidrs.split(",")[0], "bold yellow"),
    )
    root["header"].update(
        Panel(header_text, box=box.ROUNDED, style="dim white")
    )

    # 2. Left Stream: Chronological MCP Tool Invocations
    stream_table = Table(
        box=None,
        show_header=True,
        header_style="bold dim white",
        expand=True,
        pad_edge=False,
    )
    stream_table.add_column("TIME", width=9, style="dim white")
    stream_table.add_column("EVENT", width=9)
    stream_table.add_column("DETAILS", ratio=1)
    stream_table.add_column("STATUS", width=22, justify="right")

    visible_events = state.events[-15:] if state.events else []
    if not visible_events:
        stream_table.add_row(
            time.strftime("%H:%M:%S"),
            Text("[INIT]", style="dim cyan"),
            Text("Gateway ready. Waiting for AI client tool calls...", style="dim white"),
            Text("[IDLE]", style="dim green"),
        )
    else:
        for ev in visible_events:
            type_style = "bold cyan"
            if ev["type"] == "AUTH":
                type_style = "bold yellow"
            elif ev["type"] == "WARN":
                type_style = "bold red"

            stream_table.add_row(
                ev["time"],
                Text(f"[{ev['type']}]", style=type_style),
                Text(ev["details"], style="white"),
                Text(f"[{ev['status']}]", style=f"bold {ev['status_style']}"),
            )

    root["left_stream"].update(
        Panel(
            stream_table,
            title="[bold white]ARES MCP LIVE STREAM[/bold white]",
            subtitle="[dim]Real-time tool invocations by LLM[/dim]",
            box=box.ROUNDED,
            style="white",
        )
    )

    # 3. Right Posture: Scope, Staged Dry-Run, and Authorization Gateway
    right_elements = []

    # Section A: Active Campaign & Scope
    scope_table = Table(box=None, show_header=False, expand=True, pad_edge=False)
    scope_table.add_column("Key", width=14, style="dim white")
    scope_table.add_column("Val", style="bold white")
    scope_table.add_row("Campaign", state.campaign_name)
    scope_table.add_row("Scope CIDRs", state.scope_cidrs)
    scope_table.add_row("ScopeGuard", "ENFORCED (Strict Mode)" if state.strict_mode else "PERMISSIVE")
    scope_table.add_row("OPSEC Profile", state.opsec_profile)

    right_elements.append(
        Panel(
            scope_table,
            title="[bold white]TARGET & GOVERNANCE POSTURE[/bold white]",
            box=box.ROUNDED,
            style="dim white",
        )
    )

    # Section B: Staged Action (Dry-Run Preview)
    staged_table = Table(box=None, show_header=False, expand=True, pad_edge=False)
    staged_table.add_column("Key", width=14, style="dim white")
    staged_table.add_column("Val", style="bold white")
    if state.staged_module:
        staged_table.add_row("Module", state.staged_module)
        staged_table.add_row("Target", state.staged_target or "-")
        staged_table.add_row("Action", state.staged_action or "-")
        staged_table.add_row("Noise Risk", state.staged_risk or "LOW")
    else:
        staged_table.add_row("State", "[dim]No active dry-run staged[/dim]")
        staged_table.add_row("Safety", "Zero pending executions")

    right_elements.append(
        Panel(
            staged_table,
            title="[bold white]STAGED ACTIONS (DRY-RUN)[/bold white]",
            box=box.ROUNDED,
            style="dim white",
        )
    )

    # Section C: Authorization Gateway (Confirmation Token)
    auth_table = Table(box=None, show_header=False, expand=True, pad_edge=False)
    auth_table.add_column("Key", width=14, style="dim white")
    auth_table.add_column("Val")

    if state.token_status == "PENDING":
        remaining = max(0, int(state.token_expiry - time.time()))
        if remaining == 0:
            state.token_status = "EXPIRED"

    if state.token_status == "PENDING":
        remaining = max(0, int(state.token_expiry - time.time()))
        auth_table.add_row("Status", Text("WAITING OPERATOR CONFIRMATION", style="bold yellow"))
        auth_table.add_row("Token", Text(f"#{state.pending_token}", style="bold white on yellow"))
        auth_table.add_row("Module", Text(str(state.token_module), style="cyan"))
        auth_table.add_row("Expires In", Text(f"{remaining}s remaining", style="bold yellow"))
        auth_table.add_row("Controls", Text("Press [A] to Approve  |  [R] to Reject", style="bold green"))
        auth_panel_style = "bold yellow"
    elif state.token_status == "APPROVED":
        auth_table.add_row("Status", Text("APPROVED BY OPERATOR", style="bold green"))
        auth_table.add_row("Token", Text(f"#{state.pending_token} (Consumed)", style="dim white"))
        auth_table.add_row("State", Text("Execution signal dispatched to MCP", style="green"))
        auth_panel_style = "bold green"
    elif state.token_status == "REJECTED":
        auth_table.add_row("Status", Text("REJECTED / ABORTED BY OPERATOR", style="bold red"))
        auth_table.add_row("Token", Text(f"#{state.pending_token} (Revoked)", style="dim white"))
        auth_table.add_row("State", Text("Execution blocked. Returned error to client.", style="red"))
        auth_panel_style = "bold red"
    elif state.token_status == "EXPIRED":
        auth_table.add_row("Status", Text("TOKEN EXPIRED (TTL Elapsed)", style="dim red"))
        auth_table.add_row("Token", Text(f"#{state.pending_token} (Invalidated)", style="dim white"))
        auth_panel_style = "dim red"
    else:
        auth_table.add_row("Status", Text("IDLE | No pending authorization", style="dim green"))
        auth_table.add_row("ScopeGuard", Text("All live mutations require confirmation token", style="dim white"))
        auth_panel_style = "dim white"

    right_elements.append(
        Panel(
            auth_table,
            title="[bold white]AUTHORIZATION GATEWAY[/bold white]",
            box=box.ROUNDED,
            style=auth_panel_style,
        )
    )

    root["right_posture"].update(Group(*right_elements))

    # 4. Footer: Keybindings statusline
    footer_text = Text.assemble(
        ("  [A] ", "bold green"),
        ("Approve Token    ", "white"),
        ("[R] ", "bold red"),
        ("Reject Token    ", "white"),
        ("[C] ", "bold cyan"),
        ("Clear Stream    ", "white"),
        ("[Q] ", "bold white"),
        ("Quit Monitor    ", "dim white"),
        ("                  [Transport: Local UDP Port 27890]", "dim"),
    )
    root["footer"].update(
        Panel(footer_text, box=box.ROUNDED, style="dim white")
    )

    return root


def run_demo_feeder(state: TuiState) -> None:
    """Dispatches realistic automated events for demo testing."""
    time.sleep(1.0)
    McpEventBus.emit("CALL", {
        "call": "ares_list_campaigns()",
        "status": "OK: 1 active",
        "style": "green",
    })
    time.sleep(1.8)

    McpEventBus.emit("CALL", {
        "call": "ares_scope_check(target=10.0.1.50)",
        "status": "ALLOW: in-scope",
        "style": "green",
    })
    time.sleep(1.5)

    McpEventBus.emit("CALL", {
        "call": "ares_scope_check(target=8.8.8.8)",
        "status": "BLOCKED: out-of-scope",
        "style": "red",
    })
    time.sleep(2.0)

    McpEventBus.emit("STAGED", {
        "call": "ares_dry_run_module(module=ad_kerberoast)",
        "module": "ad_kerberoast",
        "target": "DC01.corp.local (10.0.1.10)",
        "action": "LDAP SPN Query & TGS-REQ Request",
        "risk": "MEDIUM (Noise: 2.5s jitter)",
        "status": "STAGED",
        "style": "blue",
    })
    time.sleep(2.0)

    token = "d8a1f4"
    McpEventBus.emit("AUTH", {
        "call": f"Token issued for ad_kerberoast: #{token}",
        "token": token,
        "module": "ad_kerberoast",
        "ttl": 60,
        "status": "PENDING: 60s",
        "style": "yellow",
    })


def run_mcp_monitor(campaign: str = "Internal-Audit-2026", scope: str = "10.0.1.0/24", demo: bool = False) -> int:
    """Main execution loop for ARES MCP Two-Pane TUI Monitor."""
    console = Console()
    state = TuiState(campaign=campaign, scope=scope)
    listener = McpEventListener()

    if demo:
        t = threading.Thread(target=run_demo_feeder, args=(state,), daemon=True)
        t.start()

    console.clear()

    try:
        with Live(build_tui_layout(state), console=console, screen=True, refresh_per_second=10) as live:
            while True:
                # 1. Process keyboard events
                key = check_keypress()
                if key == "q":
                    break
                elif key == "c":
                    state.events.clear()
                elif key == "a":
                    approved = state.approve_token()
                    if approved:
                        McpEventBus.set_token_decision(approved, "APPROVED")
                        state.add_event(
                            time.strftime("%H:%M:%S"),
                            "AUTH",
                            f"Operator approved execution token #{approved}",
                            "APPROVED",
                            "green",
                        )
                elif key == "r":
                    rejected = state.reject_token()
                    if rejected:
                        McpEventBus.set_token_decision(rejected, "REJECTED")
                        state.add_event(
                            time.strftime("%H:%M:%S"),
                            "AUTH",
                            f"Operator rejected execution token #{rejected}",
                            "REJECTED",
                            "red",
                        )

                # 2. Poll incoming events from UDP listener
                incoming = listener.poll_events()
                for ev in incoming:
                    ev_type = ev.get("type", "INFO")
                    data = ev.get("data", {})
                    ts = ev.get("timestamp", time.strftime("%H:%M:%S"))

                    if ev_type == "CALL":
                        state.add_event(
                            ts,
                            "CALL",
                            data.get("call", ""),
                            data.get("status", "OK"),
                            data.get("style", "green"),
                        )
                    elif ev_type == "STAGED":
                        state.staged_module = data.get("module")
                        state.staged_target = data.get("target")
                        state.staged_action = data.get("action")
                        state.staged_risk = data.get("risk")
                        state.add_event(
                            ts,
                            "CALL",
                            data.get("call", ""),
                            data.get("status", "STAGED"),
                            data.get("style", "blue"),
                        )
                    elif ev_type == "AUTH":
                        token = data.get("token", "none")
                        module = data.get("module", "unknown")
                        ttl = int(data.get("ttl", 60))
                        state.set_pending_token(token, module, ttl)
                        state.add_event(
                            ts,
                            "AUTH",
                            data.get("call", f"Token #{token} pending"),
                            data.get("status", "PENDING"),
                            data.get("style", "yellow"),
                        )

                # 3. Update rendered layout
                live.update(build_tui_layout(state))
                time.sleep(0.08)

    except KeyboardInterrupt:
        pass
    finally:
        listener.close()

    console.print("\n[dim]ARES MCP Terminal Monitor terminated cleanly.[/dim]")
    return 0
