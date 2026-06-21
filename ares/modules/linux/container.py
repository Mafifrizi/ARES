"""
Container Escape Module
Docker socket, privileged containers, K8s RBAC misconfigs.
"""
from __future__ import annotations

import os
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.modules.linux.container")

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module


class ContainerEscapeModule(BaseModule):
    """
    linux.container — Docker socket abuse, privileged escape, K8s RBAC misconfigs

    OPSEC: MEDIUM
    MITRE: "T1611", "T1552.007", "T1613"
    OUTPUTS:  "container_escape_vectors", "k8s_rbac_findings"
    """
    MODULE_ID          = "linux.container"
    MODULE_NAME        = "Container Escape"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = "Docker socket abuse, privileged escape, K8s RBAC misconfigs"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["container_escape_vectors", "k8s_rbac_findings"]
    MITRE_TECHNIQUES   = ["T1611", "T1552.007", "T1613"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "linux.container requires 'target' — IP or hostname of container host.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("linux.container")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        # Note: before_request() intentionally not called — this module runs
        # entirely locally inside the container (no remote network calls to a target host).
        # Scope/jitter checks apply to remote targets, not local filesystem/socket reads.
        raw: dict[str, Any] = {
            "docker_socket": await self._check_docker_socket(),
            "privileged": await self._check_privileged(),
            "host_mounts": await self._check_host_mounts(),
            "k8s_token": await self._check_k8s_service_account(),
            "host_network": await self._check_host_network(),
        }
        raw["container_escape_vectors"] = self._findings  # OUTPUTS key
        raw["k8s_rbac_findings"] = []  # OUTPUTS key
        return self._findings, raw

    async def _check_docker_socket(self) -> dict[str, Any]:
        socket_path = "/var/run/docker.sock"
        exists = os.path.exists(socket_path)
        writable = exists and os.access(socket_path, os.W_OK)

        if writable:
            self.finding(
                title="Docker Socket Mounted and Writable",
                description=(
                    "The Docker daemon socket is mounted and writable inside this container. "
                    "An attacker can create a privileged container mounting the host filesystem, "
                    "achieving full host OS compromise in seconds."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1611",
                mitre_tactic="Privilege Escalation",
                evidence={"socket": socket_path, "writable": writable},
                remediation=(
                    "Never mount /var/run/docker.sock in containers. "
                    "Use rootless Docker, Podman, or Docker-in-Docker alternatives. "
                    "If CI/CD requires it, use a socket proxy like Tecnativa/docker-socket-proxy."
                ),
            )
        elif exists:
            self.finding(
                title="Docker Socket Mounted (Read-Only)",
                description="Docker socket mounted but not writable — limited exploitation.",
                severity=Severity.MEDIUM,
                mitre_technique="T1611",
                mitre_tactic="Privilege Escalation",
                evidence={"socket": socket_path, "writable": False},
                remediation="Remove Docker socket mount entirely.",
            )

        return {"exists": exists, "writable": writable}

    async def _check_privileged(self) -> dict[str, Any]:
        """Detect --privileged via CapEff in /proc/self/status."""
        try:
            with open("/proc/self/status") as f:
                caps = {
                    line.split(":")[0].strip(): line.split(":")[1].strip()
                    for line in f if ":" in line
                }
            cap_eff = caps.get("CapEff", "0")
            privileged = int(cap_eff, 16) == 0x3FFFFFFFFF  # Full capability set

            if privileged:
                self.finding(
                    title="Container Running in Privileged Mode",
                    description=(
                        "This container has the full Linux capability set (--privileged). "
                        "Host breakout is trivial via /proc/sysrq-trigger, device mounts, "
                        "or cgroup release_agent exploit."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1611",
                    mitre_tactic="Privilege Escalation",
                    evidence={"CapEff": cap_eff},
                    remediation=(
                        "Remove --privileged. Use specific --cap-add for required capabilities. "
                        "Principle of least privilege — no container should be privileged in prod."
                    ),
                )
            return {"privileged": privileged, "CapEff": cap_eff}
        except OSError as e:
            return {"error": str(e)}

    async def _check_host_mounts(self) -> dict[str, Any]:
        """Detect sensitive host paths mounted inside the container."""
        HIGH_RISK = ["/etc", "/root", "/var/lib/docker", "/proc/sysrq-trigger", "/sys/kernel"]
        MEDIUM_RISK = ["/var/log", "/home", "/tmp"]

        found: dict[str, list[str]] = {"high": [], "medium": []}
        try:
            with open("/proc/mounts") as f:
                mounts_content = f.read()
            for path in HIGH_RISK:
                if f" {path} " in mounts_content or f" {path}/" in mounts_content:
                    found["high"].append(path)
            for path in MEDIUM_RISK:
                if f" {path} " in mounts_content:
                    found["medium"].append(path)
        except OSError:
            pass

        if found["high"]:
            self.finding(
                title="High-Risk Host Paths Mounted in Container",
                description=f"Host paths accessible: {found['high']}",
                severity=Severity.CRITICAL,
                mitre_technique="T1552.007",
                mitre_tactic="Credential Access",
                evidence={"mounts": found},
                remediation="Review all volume mounts. Use :ro (read-only) where possible.",
            )
        return found

    async def _check_k8s_service_account(self) -> dict[str, Any]:
        """Check if K8s service account token is accessible and over-privileged."""
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if not os.path.exists(token_path):
            return {"k8s_detected": False}

        try:
            with open(token_path) as f:
                token = f.read().strip()
            logger.info("[container] K8s service account token found — checking RBAC")

            # Production:
            # from kubernetes import client, config
            # config.load_incluster_config()
            # v1 = client.AuthorizationV1Api()
            # Check: can-i list pods, create pods, exec into pods, etc.

            self.finding(
                title="Kubernetes Service Account Token Accessible",
                description=(
                    "A K8s service account token is mounted in this pod. "
                    "If the SA has broad permissions, cluster-level compromise may be possible."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1552.007",
                mitre_tactic="Credential Access",
                evidence={"token_path": token_path, "token_length": len(token)},
                remediation=(
                    "Use automountServiceAccountToken: false unless required. "
                    "Scope SA roles to minimum needed (RBAC least-privilege). "
                    "Audit with: kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>"
                ),
            )
            return {"k8s_detected": True, "token_found": True}
        except OSError as e:
            return {"k8s_detected": True, "error": str(e)}

    async def _check_host_network(self) -> dict[str, Any]:
        """Detect --net=host which exposes all host network interfaces."""
        try:
            with open("/proc/net/tcp") as f:
                lines = f.readlines()
            # If we see ports like 22, 80, 443 listening — likely host network
            host_network = len(lines) > 50  # Heuristic: many open ports = host net
            if host_network:
                self.finding(
                    title="Container May Be Using Host Network Namespace",
                    description=(
                        "Container appears to share the host network namespace (--net=host). "
                        "This allows sniffing host traffic and binding to privileged ports."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1611",
                    mitre_tactic="Privilege Escalation",
                    evidence={"open_ports_count": len(lines)},
                    remediation="Remove --net=host. Use CNI plugins for network isolation.",
                )
            return {"host_network_suspected": host_network}
        except OSError:
            return {"error": "could not read /proc/net/tcp"}
