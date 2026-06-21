"""ARES version — single source of truth from pyproject.toml."""
try:
    from importlib.metadata import version
    __version__: str = version("ares-redteam")
except Exception:
    __version__ = "6.0.0"  # fallback for editable installs / development
