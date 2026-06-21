"""
ARES Artifact Intelligence Engine
Bridges artifact discovery to automatic module queuing.

When a module produces normalized artifacts, this engine analyzes them
and automatically queues follow-up attack modules.

Rules:
  UserArtifact with spns          → queue ad.kerberoast
  UserArtifact with no_preauth    → queue ad.asreproast
  PermissionArtifact with WriteDACL → queue ad.dcsync
  HostArtifact with is_dc         → queue ad.enum_acl, ad.enum_computers
  CloudResourceArtifact public    → flag for review, queue deeper enum
  CredentialArtifact cracked      → queue credential_reuse
  HashArtifact (any)              → add to crack queue
  ServiceEntry port 22            → queue lateral.ssh_pivot
  ServiceEntry port 445           → queue lateral.psexec
  ServiceEntry port 5985          → queue lateral.winrm

Engine provides:
  ArtifactIntelEngine.process(artifact_store) → list[QueuedAttack]
  QueuedAttack is fed to GoalEngine or WorkerController
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ares.core.logger import get_logger
from ares.normalize.artifacts import (
    ArtifactStore, ArtifactType,
    CloudResourceArtifact, CredentialArtifact,
    HashArtifact, HostArtifact, PermissionArtifact, UserArtifact,
)

if TYPE_CHECKING:
    from ares.core.plugin.loader import ModuleRegistry

logger = get_logger("ares.artifact_intel")


@dataclass
class QueuedAttack:
    """An attack queued by artifact intelligence."""
    module_id:   str
    trigger_uid: str           # artifact UID that triggered this
    trigger_type: str          # artifact type name
    reason:      str
    params:      dict[str, Any] = field(default_factory=dict)
    priority:    int = 5       # 1 = highest, 10 = lowest
    confidence:  float = 0.9
    queued_at:   float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id":   self.module_id,
            "trigger_uid": self.trigger_uid,
            "reason":      self.reason,
            "priority":    self.priority,
            "confidence":  self.confidence,
        }


# ── Intelligence rules ─────────────────────────────────────────────────────────

class ArtifactIntelEngine:
    """
    Analyzes normalized artifacts and queues follow-up attacks.
    Each rule is explicit, auditable, and independently testable.
    """

    def __init__(
        self,
        registry: "ModuleRegistry | None" = None,
        context:  dict[str, Any] | None = None,
    ) -> None:
        self.registry  = registry
        self.context   = context or {}
        self._queued:  set[str] = set()   # (module_id, trigger_uid) dedup

    def process(self, store: ArtifactStore) -> list[QueuedAttack]:
        """
        Analyze all artifacts in store and return queued attacks.
        Call this after each module completes.
        """
        attacks: list[QueuedAttack] = []

        attacks.extend(self._analyze_users(store.users()))
        attacks.extend(self._analyze_permissions(store.permissions()))
        attacks.extend(self._analyze_hosts(store.hosts()))
        attacks.extend(self._analyze_credentials(store.credentials()))
        attacks.extend(self._analyze_hashes(store.hashes()))
        attacks.extend(self._analyze_cloud(
            [a for a in store.get(ArtifactType.CLOUD_RESOURCE)
             if isinstance(a, CloudResourceArtifact)]
        ))

        # Deduplicate
        seen: set[str] = set()
        unique: list[QueuedAttack] = []
        for a in attacks:
            k = f"{a.module_id}:{a.trigger_uid}"
            if k not in seen and k not in self._queued:
                seen.add(k)
                self._queued.add(k)
                unique.append(a)

        if unique:
            logger.info(
                "artifact_intel_queued",
                count=len(unique),
                modules=list({a.module_id for a in unique}),
            )

        return sorted(unique, key=lambda a: a.priority)

    # ── Rule sets ──────────────────────────────────────────────────────────

    def _analyze_users(self, users: list[UserArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for user in users:
            if not user.enabled:
                continue

            # SPN → kerberoast
            if user.is_kerberoastable and self._module_available("ad.kerberoast"):
                attacks.append(QueuedAttack(
                    module_id   = "ad.kerberoast",
                    trigger_uid = user.uid,
                    trigger_type = "user",
                    reason      = (
                        f"User {user.username} has SPNs: {user.spns[:2]} "
                        f"→ kerberoastable"
                    ),
                    params      = {
                        **self.context,
                        "target_user": user.username,
                        "spns":        user.spns,
                    },
                    priority    = 1,   # high priority
                    confidence  = 0.95,
                ))

            # No pre-auth → ASREPRoast
            if user.is_asreproastable and self._module_available("ad.asreproast"):
                attacks.append(QueuedAttack(
                    module_id   = "ad.asreproast",
                    trigger_uid = user.uid,
                    trigger_type = "user",
                    reason      = (
                        f"User {user.username} has pre-auth disabled "
                        f"→ ASREPRoastable (no creds needed)"
                    ),
                    params      = {**self.context, "target_user": user.username},
                    priority    = 1,
                    confidence  = 0.98,
                ))

        return attacks

    def _analyze_permissions(self, perms: list[PermissionArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for perm in perms:
            if not perm.is_dangerous:
                continue

            # WriteDACL / GenericAll / AllExtendedRights → DCSync possible
            if perm.right in ("WriteDACL", "GenericAll", "DS-Replication-Get-Changes-All",
                               "AllExtendedRights") and self._module_available("ad.dcsync"):
                attacks.append(QueuedAttack(
                    module_id   = "ad.dcsync",
                    trigger_uid = perm.uid,
                    trigger_type = "permission",
                    reason      = (
                        f"{perm.principal} has {perm.right} on {perm.target} "
                        f"→ DCSync attack path exists"
                    ),
                    params      = {**self.context, "username": perm.principal},
                    priority    = 2,
                    confidence  = 0.85,
                ))

        return attacks

    def _analyze_hosts(self, hosts: list[HostArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for host in hosts:
            target = host.fqdn or host.hostname or host.ip_address

            # DC found → deep AD enumeration
            if host.is_dc:
                for module_id in ("ad.enum_acl", "ad.enum_computers"):
                    if self._module_available(module_id):
                        attacks.append(QueuedAttack(
                            module_id   = module_id,
                            trigger_uid = host.uid,
                            trigger_type = "host",
                            reason      = f"DC {target} discovered → deep enumeration",
                            params      = {**self.context, "dc": target},
                            priority    = 2,
                            confidence  = 0.90,
                        ))

            # SMB open → lateral movement possible
            if 445 in host.open_ports and self._module_available("lateral.psexec"):
                attacks.append(QueuedAttack(
                    module_id   = "lateral.psexec",
                    trigger_uid = host.uid,
                    trigger_type = "host",
                    reason      = f"Port 445 open on {target} → PsExec possible",
                    params      = {**self.context, "target": target},
                    priority    = 3,
                    confidence  = 0.70,
                ))

            # WinRM open → WinRM lateral
            if host.open_ports and any(p in host.open_ports for p in (5985, 5986)):
                if self._module_available("lateral.winrm"):
                    attacks.append(QueuedAttack(
                        module_id   = "lateral.winrm",
                        trigger_uid = host.uid,
                        trigger_type = "host",
                        reason      = f"WinRM port open on {target}",
                        params      = {**self.context, "target": target},
                        priority    = 3,
                        confidence  = 0.75,
                    ))

            # SSH open → pivot
            if 22 in host.open_ports and self._module_available("lateral.ssh_pivot"):
                attacks.append(QueuedAttack(
                    module_id   = "lateral.ssh_pivot",
                    trigger_uid = host.uid,
                    trigger_type = "host",
                    reason      = f"SSH port 22 open on {target} → pivot possible",
                    params      = {**self.context, "target": target},
                    priority    = 4,
                    confidence  = 0.65,
                ))

        return attacks

    def _analyze_credentials(self, creds: list[CredentialArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for cred in creds:
            if cred.cracked:
                # Cracked credential → credential reuse across all hosts
                attacks.append(QueuedAttack(
                    module_id   = "credential.reuse",
                    trigger_uid = cred.uid,
                    trigger_type = "credential",
                    reason      = (
                        f"Credential {cred.username}@{cred.domain} cracked "
                        f"→ reuse against all discovered services"
                    ),
                    params      = {"credential_id": cred.uid},
                    priority    = 1,
                    confidence  = 0.90,
                ))
        return attacks

    def _analyze_hashes(self, hashes: list[HashArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for h in hashes:
            # Any hash → add to crack queue
            attacks.append(QueuedAttack(
                module_id   = "credential.crack",
                trigger_uid = h.uid,
                trigger_type = "hash",
                reason      = (
                    f"{h.hash_type} hash for {h.username}@{h.domain} "
                    f"→ offline cracking (hashcat mode {h.hashcat_mode})"
                ),
                params      = {
                    "hash_id":      h.uid,
                    "hashcat_mode": h.hashcat_mode,
                    "crack_cmd":    h.crack_command,
                },
                priority    = 2,
                confidence  = 0.80,
            ))
        return attacks

    def _analyze_cloud(self, resources: list[CloudResourceArtifact]) -> list[QueuedAttack]:
        attacks: list[QueuedAttack] = []
        for res in resources:
            if res.is_public:
                module_map = {"aws": "cloud.aws", "azure": "cloud.azure", "gcp": "cloud.gcp"}
                module_id = module_map.get(res.provider, "")
                if module_id and self._module_available(module_id):
                    attacks.append(QueuedAttack(
                        module_id   = module_id,
                        trigger_uid = res.uid,
                        trigger_type = "cloud_resource",
                        reason      = (
                            f"Public {res.provider} {res.resource_type} "
                            f"'{res.resource_id}' found → expand cloud enumeration"
                        ),
                        params      = {
                            "resource_id":   res.resource_id,
                            "resource_type": res.resource_type,
                            "region":        res.region,
                        },
                        priority    = 2,
                        confidence  = 0.85,
                    ))
        return attacks

    def _module_available(self, module_id: str) -> bool:
        if self.registry is None:
            return True   # assume available if no registry provided
        return module_id in self.registry
