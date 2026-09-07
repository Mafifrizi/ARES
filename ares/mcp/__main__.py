"""ARES Sovereign MCP Server executable module.

Allows running the server directly via:
    python -m ares.mcp
"""
from __future__ import annotations

import asyncio
import sys

from ares.mcp import run_stdio_server


def main() -> None:
    try:
        asyncio.run(run_stdio_server())
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)


if __name__ == "__main__":
    main()
