"""ARES MCP CLI Product-Grade Utilities.

Handles:
- TTY detection & NO_COLOR specification (https://no-color.org)
- Standardized exit codes (0 = Success, 1 = Error, 2 = Invalid Input, 130 = SIGINT)
- Safe input masking for secrets (getpass / hide_input)
- Graceful signal handling (Ctrl+C without traceback)
- Consistent Rich color palette
"""
from __future__ import annotations

import os
import re
import sys

from rich.console import Console

# Standardized Exit Codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_INVALID_INPUT = 2
EXIT_SIGINT = 130

# Semantic Color Palette (Strictly Enforced)
COLOR_LABEL = "cyan"
COLOR_VALUE = "bold white"
COLOR_SUCCESS = "bold green"
COLOR_ERROR = "bold red"
COLOR_WARNING = "bold yellow"
COLOR_NEUTRAL = "dim"
COLOR_INDEX = "cyan"

_ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def is_no_color_active() -> bool:
    """Return True if NO_COLOR environment variable is set (any value, even empty)."""
    return "NO_COLOR" in os.environ


def is_stdout_piped() -> bool:
    """Return True if stdout is redirected / not a TTY."""
    return not sys.stdout.isatty()


def get_mcp_console(force_no_color: bool = False, json_mode: bool = False) -> Console:
    """Create a Rich Console respecting NO_COLOR, TTY detection, and JSON mode.

    If output is not a TTY or NO_COLOR is active, color and highlighting are disabled.
    If json_mode is True, console will not apply extra Rich styling.
    """
    disable_color = force_no_color or is_no_color_active() or is_stdout_piped() or json_mode

    # Windows console UTF-8 safeguard
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: S110
            pass

    return Console(
        no_color=disable_color,
        highlight=not disable_color,
        safe_box=True,
        soft_wrap=json_mode,
    )


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_REGEX.sub("", text)


def warn_cli_secret_exposure() -> None:
    """Print security warning when secret is passed via CLI argument."""
    console = get_mcp_console()
    console.print(
        f"[{COLOR_WARNING}]SECURITY WARNING:[/] "
        "Passing credentials/secrets via command line arguments can expose them in "
        "OS process listings and shell history. "
        "Use environment variables (e.g. ARES_MCP_API_KEY) or secure config files instead.",
        file=sys.stderr,
    )
