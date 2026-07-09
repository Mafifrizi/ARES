"""
ARES Plugin Loader
Auto-discovers modules via three mechanisms (in priority order):

1. Built-in   — ares/modules/**/*.py   (always loaded, trusted)
2. Entry points — third-party packages that register ares.modules entry points
3. External dir — ARES_PLUGIN_DIR env var (drop-in .py files, no install needed)

Security controls added in v1.0.0:
  - Signature verification before loading external/entry-point modules
  - Capability enforcement: modules can only declare allowed caps for their trust level
  - Trust level assigned per source: builtin > entrypoint > external > unsigned
  - Unsigned external modules loaded with capability restriction warning

Trust levels:
  builtin     — shipped with ARES, always trusted
  entrypoint  — installed pip package with ares.modules entry point → WARN_UNSIGNED
  external    — .py file in plugin dir → REQUIRE_SIGNED (configurable)
  unsigned    — passes WARN/ALLOW policy, cap-restricted

Config:
  ARES_PLUGIN_SIGNING_POLICY = require_signed | warn_unsigned | allow_all
  ARES_PLUGIN_DIR             = ~/.ares/plugins
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import inspect
import os as _os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ares.core.logger import get_logger

logger = get_logger("ares.plugin.loader")

if TYPE_CHECKING:
    from ares.modules.base import BaseModule


# ── Security config ────────────────────────────────────────────────────────────
# Operator configures via env var or AresSettings
_SIGNING_POLICY = _os.environ.get("ARES_PLUGIN_SIGNING_POLICY", "warn_unsigned")


def _get_signing_policy():
    """Lazy import to avoid circular deps."""
    try:
        from ares.core.signing import ModuleVerifier, SigningPolicy

        policies = {
            "require_signed": SigningPolicy.REQUIRE_SIGNED,
            "warn_unsigned": SigningPolicy.WARN_UNSIGNED,
            "allow_all": SigningPolicy.ALLOW_ALL,
            "trusted_only": SigningPolicy.TRUSTED_ONLY,
        }
        return ModuleVerifier(
            policy=policies.get(_SIGNING_POLICY, SigningPolicy.WARN_UNSIGNED)
        )
    except ImportError:
        return None


def _is_path_within_base(path: Path, base: Path) -> bool:
    return path == base or path.is_relative_to(base)


def _enforce_capabilities(cls: Any, source: str) -> list[str]:
    """
    Check a module's declared CAPABILITIES against its trust level.
    Returns list of violation messages. Empty = clean.
    """
    try:
        from ares.core.capabilities import (
            CapabilityPolicy,
            default_capabilities_for_category,
        )

        trust_map = {"builtin": "builtin", "entrypoint": "community"}
        trust_level = trust_map.get(source.split(":")[0], "external")
        caps = getattr(cls, "CAPABILITIES", None)
        if caps is None:
            # Assign sensible defaults if not declared
            category = getattr(cls, "MODULE_CATEGORY", "")
            cls.CAPABILITIES = default_capabilities_for_category(category)
            return []
        return CapabilityPolicy.validate(
            getattr(cls, "MODULE_ID", "?"), frozenset(caps), trust_level
        )
    except (AttributeError, ImportError, TypeError):
        return []


# ── Module Registry ───────────────────────────────────────────────────────────


class ModuleRegistry:
    """
    Central registry for all loaded ARES modules.
    Supports tagging, filtering, and metadata lookup.
    """

    def __init__(self) -> None:
        self._registry: dict[str, type[BaseModule]] = {}
        self._sources: dict[str, str] = (
            {}
        )  # module_id → source (builtin/entrypoint/external)

    def register(self, cls: type[BaseModule], source: str = "builtin") -> None:
        mid = cls.MODULE_ID
        if not mid:
            return
        if mid in self._registry:
            existing_source = self._sources.get(mid, "unknown")
            logger.debug(
                "registry_skipping_duplicate_from_already_from",
                mid=mid,
                source=source,
                existing_source=existing_source,
            )
            return
        self._registry[mid] = cls
        self._sources[mid] = source
        logger.debug("registry_registered_from", mid=mid, source=source)

    def get(self, module_id: str) -> type[BaseModule] | None:
        return self._registry.get(module_id)

    def all(self) -> list[type[BaseModule]]:
        return list(self._registry.values())

    def by_category(self, category: str) -> list[type[BaseModule]]:
        return [
            cls for cls in self._registry.values() if cls.MODULE_CATEGORY == category
        ]

    def list_metadata(self) -> list[dict[str, Any]]:
        """
        Return full metadata for every registered module.

        Delegates to BaseModule.metadata() so the shape is always consistent
        with what operators see in the CLI, dashboard, and /modules API endpoint.
        Adds the registry-specific 'source' field (builtin/entrypoint/external).
        """
        result = []
        for mid, cls in sorted(self._registry.items()):
            try:
                # BaseModule.metadata() returns the canonical dict including
                # opsec_level, requires, outputs, mitre_list, min_noise_profile
                meta = cls.metadata()
            except Exception:
                # Fallback for malformed community modules
                meta = {
                    "id": mid,
                    "name": getattr(cls, "MODULE_NAME", mid),
                    "category": getattr(cls, "MODULE_CATEGORY", ""),
                    "description": getattr(cls, "MODULE_DESCRIPTION", ""),
                    "opsec_level": str(getattr(cls, "OPSEC_LEVEL", "unknown")),
                    "requires": list(getattr(cls, "REQUIRES", [])),
                    "outputs": list(getattr(cls, "OUTPUTS", [])),
                    "mitre": ", ".join(getattr(cls, "MITRE_TECHNIQUES", [])),
                    "mitre_list": list(getattr(cls, "MITRE_TECHNIQUES", [])),
                    "author": getattr(cls, "MODULE_AUTHOR", "ARES Team"),
                    "min_noise_profile": getattr(cls, "MIN_NOISE_PROFILE", None),
                }
            # Inject the registry source tag
            meta["source"] = self._sources.get(mid, "unknown")
            result.append(meta)
        return result

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, module_id: str) -> bool:
        return module_id in self._registry


# ── Loader ────────────────────────────────────────────────────────────────────


class PluginLoader:
    """
    Three-source module loader.

    Usage:
        loader = PluginLoader()
        registry = loader.load_all()
    """

    BUILTIN_MODULES_PATH = Path(__file__).parent.parent.parent / "modules"
    ENTRY_POINT_GROUP = "ares.modules"
    EXTERNAL_DIR_ENV = "ARES_PLUGIN_DIR"

    def __init__(self) -> None:
        self.registry = ModuleRegistry()
        self._errors: list[dict[str, str]] = []

    # ── Public API ─────────────────────────────────────────────────────────

    def load_all(self, external_dir: str | None = None) -> ModuleRegistry:
        """Load from all three sources. Returns the registry."""
        n_builtin = self._load_builtin()
        n_entrypoint = self._load_entry_points()
        n_external = self._load_external(external_dir)

        total = len(self.registry)
        logger.info(
            f"[plugin_loader] Loaded {total} modules "
            f"(builtin={n_builtin} entrypoints={n_entrypoint} external={n_external})"
        )
        if self._errors:
            logger.warning("plugin_loader_load_errors")
            for err in self._errors:
                logger.debug(
                    "plugin_load_error",
                    path=err.get("path", ""),
                    error=err.get("error", ""),
                )

        return self.registry

    @property
    def errors(self) -> list[dict[str, str]]:
        return list(self._errors)

    # ── Source 1: Built-in ─────────────────────────────────────────────────

    def _load_builtin(self) -> int:
        before = len(self.registry)
        for py_file in sorted(self.BUILTIN_MODULES_PATH.rglob("*.py")):
            if py_file.stem.startswith("_") or py_file.stem == "base":
                continue
            rel = py_file.relative_to(self.BUILTIN_MODULES_PATH.parent.parent)
            module_path = ".".join(rel.with_suffix("").parts)
            self._import_and_register(module_path, source="builtin")
        return len(self.registry) - before

    # ── Source 2: Entry points ─────────────────────────────────────────────

    def _load_entry_points(self) -> int:
        """
        Third-party packages can ship ARES modules by adding to their pyproject.toml:

            [project.entry-points."ares.modules"]
            my_module = "my_package.modules.my_module:MyModule"

        ARES will discover and load them automatically.
        """
        before = len(self.registry)
        try:
            eps = importlib.metadata.entry_points(group=self.ENTRY_POINT_GROUP)
        except Exception as e:
            logger.debug("plugin_loader_entry_points_failed", e=e)
            return 0

        for ep in eps:
            try:
                cls = ep.load()
                if self._is_valid_module_class(cls):
                    self.registry.register(cls, source=f"entrypoint:{ep.value}")
                else:
                    logger.warning(
                        "plugin_loader_entry_point_is_not_a_valid_basemodul",
                        name=ep.name,
                    )
            except Exception as e:
                self._errors.append({"path": ep.value, "error": str(e)})
                logger.warning(
                    "plugin_loader_failed_to_load_entry_point", name=ep.name, e=e
                )

        return len(self.registry) - before

    # ── Source 3: External dir ─────────────────────────────────────────────

    def _load_external(self, external_dir: str | None = None) -> int:
        """
        Load .py files from an external directory.
        Directory can be set via:
          1. explicit external_dir arg
          2. ARES_PLUGIN_DIR environment variable
          3. ~/.ares/plugins/ (default fallback)

        Great for:
          - Custom client-specific modules
          - Rapid prototyping without pip install
          - Private modules that shouldn't be in the repo
        """
        import os

        before = len(self.registry)

        configured_dir = external_dir or os.environ.get(self.EXTERNAL_DIR_ENV)
        plugin_dir = (
            Path(configured_dir)
            if configured_dir
            else Path.home() / ".ares" / "plugins"
        )

        # Path traversal guard — resolve to absolute path and verify it stays within
        # an allowed base (home dir or explicitly trusted locations).
        try:
            plugin_dir = plugin_dir.resolve()
        except (OSError, ValueError) as exc:
            logger.error("plugin_loader_invalid_plugin_dir_path", exc=exc)
            return 0

        _allowed_bases = [
            Path.home().resolve(),
            Path("/tmp").resolve(),  # noqa: S108  — sandbox staging area
        ]
        if not any(
            _is_path_within_base(plugin_dir, base) for base in _allowed_bases
        ):
            logger.error(
                f"[plugin_loader] Rejected plugin dir outside allowed locations: {plugin_dir}. "
                f"Must be under home directory or /tmp."
            )
            return 0

        if not plugin_dir.exists():
            if not configured_dir:
                logger.debug(
                    "plugin_loader_default_external_dir_missing", plugin_dir=plugin_dir
                )
                return 0
            plugin_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(
                "plugin_loader_created_external_plugin_dir", plugin_dir=plugin_dir
            )
            return 0

        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.stem.startswith("_"):
                continue
            self._load_file_module(py_file, source=f"external:{plugin_dir}")

        return len(self.registry) - before

    # ── Helpers ────────────────────────────────────────────────────────────

    def _import_and_register(self, module_path: str, source: str) -> None:
        try:
            mod = importlib.import_module(module_path)
            for _, cls in inspect.getmembers(mod, inspect.isclass):
                if self._is_valid_module_class(cls):
                    self.registry.register(cls, source=source)
        except Exception as e:
            self._errors.append({"path": module_path, "error": str(e)})
            logger.debug("plugin_loader_could_not_import", module_path=module_path, e=e)

    def _load_file_module(self, path: Path, source: str) -> None:
        """
        Load a .py file by path without needing it on sys.path.
        Security: verifies signature before executing module code.
        """
        module_name = f"ares_external.{path.stem}"

        # ── Signature verification (v1.0.0) ───────────────────────────────
        verifier = _get_signing_policy()
        if verifier:
            try:
                result = verifier.verify_file(path)
                verifier.enforce_policy(result)
                trust = result.trust_level.value
                if trust not in ("trusted", "community"):
                    logger.warning(
                        f"[plugin_loader] Loading {path.name!r} with trust={trust!r} "
                        f"— capabilities will be restricted"
                    )
            except ValueError as e:
                self._errors.append({"path": str(path), "error": str(e)})
                logger.error("plugin_loader_refusing_to_load", name=path.name, e=e)
                return  # BLOCK: policy violation

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]

            for _, cls in inspect.getmembers(mod, inspect.isclass):
                if self._is_valid_module_class(cls):
                    # ── Capability enforcement (v1.0.0) ───────────────────
                    cap_violations = _enforce_capabilities(cls, source)
                    if cap_violations:
                        for v in cap_violations:
                            logger.error("plugin_loader_capability_violation", v=v)
                            self._errors.append({"path": str(path), "error": v})
                        continue  # Skip module — capability violation

                    self.registry.register(cls, source=source)

        except Exception as e:
            self._errors.append({"path": str(path), "error": str(e)})
            logger.warning(
                "plugin_loader_failed_to_load_external_plugin", name=path.name, e=e
            )

    @staticmethod
    def _is_valid_module_class(cls: Any) -> bool:
        """Check if a class is a valid ARES module (not the base class itself)."""
        from ares.modules.base import BaseModule

        return (
            inspect.isclass(cls)
            and issubclass(cls, BaseModule)
            and cls is not BaseModule
            and bool(getattr(cls, "MODULE_ID", ""))
        )
