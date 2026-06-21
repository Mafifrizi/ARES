"""
ARES Dependency Injection Container
Lightweight service locator that wires Engine, Registry, ExecutionService,
StateStore, and all other core components.

Why DI:
  - Makes testing trivial (swap real services for mocks)
  - Plugin external modules can request services without import magic
  - Engine doesn't need to know HOW to build each dependency
  - Swapping Redis for in-process queue = one line change in container config

Design: Service Locator pattern (explicit registration, no magic reflection).
Not a full IoC container — ARES is a CLI tool, not a web server.

Usage:
    # Production setup (in cli/main.py or api/server.py)
    container = AresContainer.production(settings)
    engine    = container.engine()
    registry  = container.registry()

    # Testing setup
    container = AresContainer.for_test()
    container.register("vault", MockVault())
    module = container.build_module("ad.kerberoast", campaign)

    # Plugin modules requesting services
    class MyModule(BaseModule):
        def execute(self, ctx: ExecutionContext):
            vault = ctx.vault   # injected by engine via context
"""
from __future__ import annotations

from typing import Any, Callable, TypeVar

from ares.core.logger import get_logger

logger = get_logger("ares.di")

T = TypeVar("T")


class ServiceNotFound(Exception):
    def __init__(self, service_name: str) -> None:
        super().__init__(
            f"Service {service_name!r} not registered in AresContainer. "
            f"Register it before requesting."
        )
        self.service_name = service_name


class AresContainer:
    """
    Central service registry.
    Supports both singletons (built once, reused) and factories (built on demand).

    Services registered by name:
        "settings"    — AresSettings
        "registry"    — ModuleRegistry
        "engine"      — AresEngine
        "db"          — AresDatabase
        "vault"       — CredentialVault
        "telemetry"   — TelemetryCollector
        "cluster"     — ClusterController
        "collab"      — CollaborationManager
        "guardrail"   — CampaignGuardrail
        "sandbox"     — SandboxRunner
        "fingerprint" — EnvironmentFingerprinter
        "kb"          — AttackKnowledgeBase
    """

    def __init__(self) -> None:
        self._singletons:  dict[str, Any] = {}
        self._factories:   dict[str, Callable[[], Any]] = {}
        self._overrides:   dict[str, Any] = {}   # test overrides

    # ── Registration ───────────────────────────────────────────────────────

    def register(self, name: str, instance: Any) -> "AresContainer":
        """Register a singleton instance. Returns self for chaining."""
        self._singletons[name] = instance
        logger.debug("service_registered", name=name, type=type(instance).__name__)
        return self

    def register_factory(self, name: str, factory: Callable[[], Any]) -> "AresContainer":
        """Register a factory (called lazily on first get). Returns self for chaining."""
        self._factories[name] = factory
        return self

    def override(self, name: str, instance: Any) -> "AresContainer":
        """Override a service for testing. Takes priority over singletons."""
        self._overrides[name] = instance
        return self

    def clear_overrides(self) -> None:
        self._overrides.clear()

    # ── Retrieval ──────────────────────────────────────────────────────────

    def get(self, name: str) -> Any:
        """
        Retrieve a service by name.
        Raises ServiceNotFound if not registered.
        """
        # Test overrides have highest priority
        if name in self._overrides:
            return self._overrides[name]

        # Singletons
        if name in self._singletons:
            return self._singletons[name]

        # Lazy factories — build and cache as singleton
        if name in self._factories:
            instance = self._factories[name]()
            self._singletons[name] = instance
            del self._factories[name]
            logger.debug("service_built_from_factory", name=name,
                         type=type(instance).__name__)
            return instance

        raise ServiceNotFound(name)

    def has(self, name: str) -> bool:
        """Return True if service is registered."""
        return (
            name in self._overrides
            or name in self._singletons
            or name in self._factories
        )

    def require(self, *names: str) -> list[Any]:
        """Retrieve multiple services at once. Raises if any missing."""
        return [self.get(n) for n in names]

    # ── Typed accessors (convenience, avoids string typos) ─────────────────

    def settings(self) -> Any:
        return self.get("settings")

    def registry(self) -> Any:
        return self.get("registry")

    def engine(self) -> Any:
        return self.get("engine")

    def db(self) -> Any:
        return self.get("db")

    def vault(self) -> Any:
        return self.get("vault")

    def telemetry(self) -> Any:
        return self.get("telemetry")

    def sandbox(self) -> Any:
        return self.get("sandbox")

    def guardrail(self) -> Any:
        return self.get("guardrail")

    def kb(self) -> Any:
        return self.get("kb")

    # ── Module construction ────────────────────────────────────────────────

    def build_module(self, module_id: str, campaign: Any) -> Any:
        """
        Construct a module instance with all services injected.
        Used by engine instead of direct instantiation.
        """
        from ares.core.noise import NoiseController

        registry = self.get("registry")
        settings = self.get("settings")
        module_cls = registry.get(module_id)
        if not module_cls:
            from ares.core.errors import ModuleNotFoundError
            raise ModuleNotFoundError(
                f"Module {module_id!r} not in registry",
                module_id=module_id,
            )
        noise = NoiseController(campaign)
        return module_cls(settings=settings, campaign=campaign, noise=noise)

    def build_context(self, campaign: Any, target: str, module_id: str,
                      **kwargs: Any) -> Any:
        """
        Build an ExecutionContext with container services injected.
        This is the canonical way for the engine to create contexts.
        """
        from ares.core.context import ExecutionContext

        return ExecutionContext.build(
            campaign    = campaign,
            target      = target,
            module_id   = module_id,
            settings    = self._singletons.get("settings"),
            vault       = self._singletons.get("vault"),
            session     = kwargs.pop("session", None),
            telemetry   = self._singletons.get("telemetry"),
            noise       = None,   # built per module
            **kwargs,
        )

    # ── Factory methods ────────────────────────────────────────────────────

    @classmethod
    def production(cls, settings: Any | None = None) -> "AresContainer":
        """
        Build a fully-wired production container.
        Call this once at process startup.
        """
        from ares.core.config import AresSettings
        from ares.core.plugin.loader import ModuleRegistry
        from ares.telemetry.collector import TelemetryCollector
        from ares.knowledge import AttackKnowledgeBase
        from ares.core.sandbox import SandboxRunner

        s = settings or AresSettings()
        c = cls()

        c.register("settings", s)
        c.register_factory("registry",  ModuleRegistry)
        c.register_factory("telemetry", TelemetryCollector)
        c.register_factory("kb",        AttackKnowledgeBase)
        c.register_factory("sandbox",   SandboxRunner)

        # Vault needs encryption key from settings
        c.register_factory("vault", lambda: cls._build_vault(s))

        logger.info("container_production_ready")
        return c

    @classmethod
    def for_test(cls) -> "AresContainer":
        """
        Build a minimal container for unit/integration testing.
        Uses in-memory implementations; no network or disk I/O.
        """
        from ares.core.config import AresSettings
        from ares.core.plugin.loader import ModuleRegistry
        from ares.telemetry.collector import TelemetryCollector
        from ares.knowledge import AttackKnowledgeBase

        c = cls()
        c.register("settings",  AresSettings())
        c.register("registry",  ModuleRegistry())
        c.register("telemetry", TelemetryCollector())
        c.register("kb",        AttackKnowledgeBase())
        return c

    @staticmethod
    def _build_vault(settings: Any) -> Any:
        from ares.credential.vault import CredentialVault
        # Use the dedicated encryption key, not the JWT secret_key.
        # CredentialVault.__init__ handles key derivation internally.
        raw_key = settings.encryption_key_value  # type: ignore[attr-defined]
        return CredentialVault(raw_key)

    def list_services(self) -> dict[str, str]:
        """Return dict of service_name → type_name for debugging."""
        out: dict[str, str] = {}
        for name, inst in self._singletons.items():
            out[name] = type(inst).__name__
        for name in self._factories:
            out[name] = "<factory (lazy)>"
        return out

    def __repr__(self) -> str:
        registered = list(self._singletons) + list(self._factories)
        return f"AresContainer(services={registered})"


# ── Global container ───────────────────────────────────────────────────────────
# One container per process. Initialized by CLI or API startup.

_global_container: AresContainer | None = None


def get_container() -> AresContainer:
    """Return the global container. Raises if not initialized."""
    global _global_container
    if _global_container is None:
        raise RuntimeError(
            "AresContainer not initialized. "
            "Call init_container() at startup or use AresContainer.for_test()."
        )
    return _global_container


def init_container(container: AresContainer) -> AresContainer:
    """Set the global container. Call once at process startup."""
    global _global_container
    _global_container = container
    logger.info("global_container_initialized")
    return container
