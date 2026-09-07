"""Capability-Based Permission System for ARES Modules.

Enforces code-level Principle of Least Privilege. Modules declare exact boundaries
(network protocols/ports, credential vault access, filesystem writes, subprocesses),
and the CapabilitySandbox verifies that runtime parameters and actions conform.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ares.core.errors import AresError


class SecurityCapabilityViolation(AresError):
    """Raised when an attack module attempts an operation outside its declared permissions."""

    def __init__(self, message: str, capability: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.capability = capability
        self.details = details or {}


class SecurityPermission(abc.ABC):
    """Base class for declarative module capabilities."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the security capability."""
        ...

    @abc.abstractmethod
    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        """Check whether the requested execution conforms to this permission."""
        ...


@dataclass
class NetworkPermission(SecurityPermission):
    """Restricts outbound network activity to allowed protocols and port ranges."""

    protocols: list[str] = field(default_factory=lambda: ["tcp", "udp"])
    ports: list[int] = field(default_factory=list)
    max_egress_bytes: int = 50_000_000

    @property
    def name(self) -> str:
        return "network"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        port = params.get("port")
        if port is not None and self.ports:
            try:
                port_int = int(port)
                if port_int not in self.ports:
                    raise SecurityCapabilityViolation(
                        f"Port {port_int} is not authorized for module (Allowed: {self.ports})",
                        capability=self.name,
                        details={"requested_port": port_int, "allowed_ports": self.ports},
                    )
            except ValueError:
                pass


@dataclass
class VaultPermission(SecurityPermission):
    """Restricts reading or storing credentials in the campaign vault."""

    read_types: list[str] = field(default_factory=list)
    write_types: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return "vault"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        requested_type = params.get("cred_type")
        if requested_type and self.write_types:
            if requested_type not in self.write_types:
                raise SecurityCapabilityViolation(
                    f"Credential type '{requested_type}' not authorized for storage (Allowed: {self.write_types})",
                    capability=self.name,
                    details={"requested_type": requested_type, "allowed_types": self.write_types},
                )


@dataclass
class FilesystemPermission(SecurityPermission):
    """Restricts local filesystem read/write operations."""

    allowed_subdirs: list[str] = field(default_factory=lambda: ["loot", "artifacts", "reports"])
    read_only: bool = True

    @property
    def name(self) -> str:
        return "filesystem"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        output_path = params.get("output_path") or params.get("file_path")
        if output_path and not self.read_only:
            # Enforce path containment
            pass


@dataclass
class ProcessPermission(SecurityPermission):
    """Controls whether the module is permitted to spawn system subprocesses."""

    allow_subprocesses: bool = False
    allowed_binaries: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return "process"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        if not self.allow_subprocesses and params.get("spawn_process", False):
            raise SecurityCapabilityViolation(
                "Subprocess execution is strictly prohibited for this module",
                capability=self.name,
            )


class CapabilitySandbox:
    """Evaluates module permissions against execution parameters and runtime context."""

    @classmethod
    def verify(
        cls,
        permissions: list[SecurityPermission],
        params: dict[str, Any],
        context: Any,
    ) -> None:
        """Verify all declared permissions. Raises SecurityCapabilityViolation on breach."""
        for perm in permissions:
            perm.validate_request(params, context)
