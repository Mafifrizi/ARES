"""
ARES CLI entry point shim.

pyproject.toml references ``ares.cli.main:cli`` for the ``ares`` console script.
The actual implementation lives in ``ares.cli.typer_main``; this module simply
re-exports everything so that both import paths work.
"""
from ares.cli.typer_main import app, cli  # noqa: F401  (re-exported for entry point)

__all__ = ["app", "cli"]
