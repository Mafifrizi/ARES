"""Capability-Based Permission System for ARES Modules.

Enforces code-level Principle of Least Privilege. Modules declare exact boundaries
(network protocols/ports, credential vault access, filesystem writes, subprocesses),
and the CapabilitySandbox verifies that runtime parameters and actions conform.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
import pathlib
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
        if port is None:
            target = params.get("target") or (getattr(context, "target", "") if context else "")
            if isinstance(target, str) and ":" in target and not target.startswith("["):
                parts = target.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    port = int(parts[1])

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

        proto = params.get("protocol")
        if proto is not None and self.protocols:
            proto_str = str(proto).strip().lower()
            allowed = [p.strip().lower() for p in self.protocols]
            if proto_str not in allowed:
                raise SecurityCapabilityViolation(
                    f"Protocol '{proto_str}' is not authorized for module (Allowed: {self.protocols})",
                    capability=self.name,
                    details={"requested_protocol": proto_str, "allowed_protocols": self.protocols},
                )


@dataclass
class VaultPermission(SecurityPermission):
    """Restricts reading or storing credentials in the campaign vault."""

    read_types: list[str] = field(default_factory=list)
    write_types: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return "vault"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        requested_type = params.get("cred_type") or params.get("write_cred_type")
        if requested_type is not None:
            if requested_type not in self.write_types:
                raise SecurityCapabilityViolation(
                    f"Credential type '{requested_type}' not authorized for storage (Allowed: {self.write_types})",
                    capability=self.name,
                    details={"requested_type": requested_type, "allowed_types": self.write_types},
                )

        read_type = params.get("read_cred_type") or params.get("read_type")
        if read_type is not None:
            if read_type not in self.read_types:
                raise SecurityCapabilityViolation(
                    f"Credential read type '{read_type}' not authorized (Allowed: {self.read_types})",
                    capability=self.name,
                    details={"requested_read_type": read_type, "allowed_read_types": self.read_types},
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
        output_path = params.get("output_path") or params.get("write_path") or params.get("outfile") or params.get("dest_file") or params.get("dest_path")
        is_write = bool(output_path) or bool(params.get("write_file", False))

        if is_write and self.read_only:
            raise SecurityCapabilityViolation(
                f"Filesystem write operation prohibited: module is configured as read-only",
                capability=self.name,
                details={"read_only": True, "attempted_path": str(output_path) if output_path else None},
            )

        if output_path and not self.read_only:
            norm_str = str(output_path).replace("\\", "/")
            parts = [p for p in norm_str.split("/") if p]
            if ".." in parts:
                raise SecurityCapabilityViolation(
                    f"Directory traversal detected in path '{output_path}'",
                    capability=self.name,
                    details={"attempted_path": output_path},
                )
            if self.allowed_subdirs:
                allowed = [s.strip().lower().strip("/\\") for s in self.allowed_subdirs if s.strip()]
                match = any(part.lower() in allowed for part in parts)
                if not match:
                    raise SecurityCapabilityViolation(
                        f"Filesystem path '{output_path}' is outside of authorized subdirs: {self.allowed_subdirs}",
                        capability=self.name,
                        details={"attempted_path": output_path, "allowed_subdirs": self.allowed_subdirs},
                    )


@dataclass
class ProcessPermission(SecurityPermission):
    """Controls whether the module is permitted to spawn system subprocesses."""

    allow_subprocesses: bool = False
    allowed_binaries: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return "process"

    def validate_request(self, params: dict[str, Any], context: Any) -> None:
        spawns = bool(params.get("spawn_process", False)) or bool(params.get("spawn_subprocess", False))
        if not self.allow_subprocesses and spawns:
            raise SecurityCapabilityViolation(
                "Subprocess execution is strictly prohibited for this module",
                capability=self.name,
            )

        if self.allow_subprocesses and self.allowed_binaries:
            binary = params.get("binary") or params.get("subprocess_binary")
            if binary:
                base = pathlib.Path(str(binary).strip().split()[0]).name.lower()
                allowed_lower = [pathlib.Path(b).name.lower() for b in self.allowed_binaries]
                if base not in allowed_lower:
                    raise SecurityCapabilityViolation(
                        f"Binary '{base}' is not authorized for subprocess execution (Allowed: {self.allowed_binaries})",
                        capability=self.name,
                        details={"requested_binary": base, "allowed_binaries": self.allowed_binaries},
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
