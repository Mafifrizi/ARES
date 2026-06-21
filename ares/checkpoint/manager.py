"""
ARES Campaign Checkpoint System
Persists full campaign state to disk for pause/resume and crash recovery.

CLI usage:
    ares campaign pause  <campaign_id>   → saves checkpoint
    ares campaign resume <campaign_id>   → restores and continues

Checkpoint includes:
    - Campaign config + findings so far
    - OperatorSession (all hosts, compromise levels, history)
    - CredentialVault (all credentials, encrypted)
    - GoalEngine plan + completed steps
    - PivotManager tunnels
    - Execution queue (pending tasks)
    - Attack timeline events

Storage:
    ~/.ares/checkpoints/<campaign_id>/<timestamp>.ares_ckpt  (JSON+Fernet)
    ~/.ares/checkpoints/<campaign_id>/latest -> symlink to newest

Security:
    All checkpoints are Fernet-encrypted with the operator's key.
    Plaintext secrets never touch disk.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from ares.core.logger import audit, get_logger

logger = get_logger("ares.checkpoint")

CHECKPOINT_DIR = Path.home() / ".ares" / "checkpoints"
CHECKPOINT_EXT = ".ares_ckpt"


@dataclass
class CheckpointManifest:
    """Metadata stored unencrypted in the checkpoint header."""
    checkpoint_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    campaign_id:     str = ""
    campaign_name:   str = ""
    operator:        str = ""
    created_at:      float = field(default_factory=time.time)
    schema_version:  str = "1.0"
    ares_version:    str = ""  # Set at creation time from ares.__version__
    hosts_captured:  int = 0
    findings_count:  int = 0
    goal:            str = ""
    goal_achieved:   bool = False
    notes:           str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id":  self.checkpoint_id,
            "campaign_id":    self.campaign_id,
            "campaign_name":  self.campaign_name,
            "operator":       self.operator,
            "created_at":     self.created_at,
            "schema_version": self.schema_version,
            "ares_version":   self.ares_version,
            "hosts_captured": self.hosts_captured,
            "findings_count": self.findings_count,
            "goal":           self.goal,
            "goal_achieved":  self.goal_achieved,
            "notes":          self.notes,
        }


@dataclass
class CheckpointData:
    """Full serialized campaign state."""
    manifest:      CheckpointManifest = field(default_factory=CheckpointManifest)
    campaign_id:   str = ""          # convenience field — mirrors manifest.campaign_id
    vault:         dict[str, Any] = field(default_factory=dict)  # encrypted credential store
    campaign:      dict[str, Any]         = field(default_factory=dict)
    session:       dict[str, Any]         = field(default_factory=dict)  # OperatorSession.snapshot()
    credential_ids: list[str]             = field(default_factory=list)  # vault IDs (secrets excluded)
    pending_tasks: list[dict[str, Any]]   = field(default_factory=list)  # cluster tasks not yet run
    completed_steps: list[str]            = field(default_factory=list)  # module IDs done
    timeline:      list[dict[str, Any]]   = field(default_factory=list)  # attack timeline events
    pivot_tunnels: list[dict[str, Any]]   = field(default_factory=list)  # active tunnels
    extra:         dict[str, Any]         = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Sync campaign_id ↔ manifest
        if self.campaign_id and not self.manifest.campaign_id:
            self.manifest.campaign_id = self.campaign_id
        elif self.manifest.campaign_id and not self.campaign_id:
            self.campaign_id = self.manifest.campaign_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest":       self.manifest.to_dict(),
            "vault":          self.vault,
            "campaign":       self.campaign,
            "session":        self.session,
            "credential_ids": self.credential_ids,
            "pending_tasks":  self.pending_tasks,
            "completed_steps": self.completed_steps,
            "timeline":       self.timeline,
            "pivot_tunnels":  self.pivot_tunnels,
            "extra":          self.extra,
        }


class CheckpointManager:
    """
    Saves and restores campaign state.
    Encrypts all data at rest.

    Usage:
        mgr = CheckpointManager(encryption_key)
        ckpt_path = mgr.save(data)
        data = mgr.load(campaign_id)
    """

    # Fixed salt for checkpoint key derivation — deterministic so same key always
    # produces same Fernet key across restarts (no salt storage required).
    _KDF_SALT = b"ares-checkpoint-manager-v1-salt"

    def __init__(self, encryption_key: bytes | str) -> None:
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes

        # Normalise to bytes
        if isinstance(encryption_key, str):
            key_bytes = encryption_key.encode()
        elif isinstance(encryption_key, (bytes, bytearray)):
            key_bytes = bytes(encryption_key)
        else:
            raise TypeError(f"encryption_key must be str or bytes, got {type(encryption_key)}")

        # PBKDF2-HMAC-SHA256 — consistent with security.DataEncryptor (100k iterations)
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=self._KDF_SALT,
            iterations=100_000,
        )
        derived = kdf.derive(key_bytes)
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    def save(self, data: CheckpointData, notes: str = "") -> Path:
        """
        Serialize, encrypt, and write checkpoint to disk.
        Returns path to checkpoint file.
        """
        # Always generate a fresh checkpoint_id and timestamp per save
        import uuid as _uuid
        data.manifest.checkpoint_id = str(_uuid.uuid4())[:8]
        data.manifest.created_at    = time.time()
        data.manifest.notes = notes
        raw      = json.dumps(data.to_dict(), default=str).encode()
        encrypted = self._fernet.encrypt(raw)

        campaign_dir = CHECKPOINT_DIR / (data.campaign_id or data.manifest.campaign_id)
        campaign_dir.mkdir(parents=True, exist_ok=True)

        ts       = int(data.manifest.created_at)
        ckpt_id  = data.manifest.checkpoint_id
        filename = f"{ts}_{ckpt_id}{CHECKPOINT_EXT}"
        ckpt_path = campaign_dir / filename

        ckpt_path.write_bytes(encrypted)

        # Update "latest" pointer — use a regular file copy (Windows doesn't always support symlinks)
        latest = campaign_dir / f"latest{CHECKPOINT_EXT}"
        try:
            import shutil as _shutil
            _shutil.copy2(ckpt_path, latest)
        except Exception:
            # Fallback: try symlink
            try:
                if latest.is_symlink() or latest.exists():
                    latest.unlink()
                latest.symlink_to(ckpt_path.name)
            except Exception:
                pass

        audit("checkpoint_saved", actor=data.manifest.operator,
              campaign=data.manifest.campaign_id,
              checkpoint_id=ckpt_id,
              path=str(ckpt_path))
        logger.info("checkpoint_saved",
                    campaign=data.manifest.campaign_id,
                    checkpoint_id=ckpt_id,
                    size_kb=len(encrypted) // 1024)
        return ckpt_path

    def load(self, campaign_id: str, checkpoint_id: str = "latest") -> CheckpointData:
        """
        Decrypt and deserialize the latest (or specific) checkpoint.
        Raises FileNotFoundError if no checkpoint exists.
        """
        campaign_dir = CHECKPOINT_DIR / campaign_id
        if not campaign_dir.exists():
            raise FileNotFoundError(f"No checkpoints for campaign {campaign_id!r}")

        if checkpoint_id == "latest":
            path = campaign_dir / "latest.ares_ckpt"
            if path.is_symlink():
                path = path.resolve()
            else:
                # Fallback: newest file
                files = sorted(campaign_dir.glob(f"*{CHECKPOINT_EXT}"),
                                key=lambda p: p.stat().st_mtime, reverse=True)
                if not files:
                    raise FileNotFoundError(f"No checkpoint files in {campaign_dir}")
                path = files[0]
        else:
            matches = list(campaign_dir.glob(f"*{checkpoint_id}*{CHECKPOINT_EXT}"))
            if not matches:
                raise FileNotFoundError(f"Checkpoint {checkpoint_id!r} not found")
            path = matches[0]

        encrypted = path.read_bytes()
        raw       = self._fernet.decrypt(encrypted)
        d         = json.loads(raw)

        manifest = CheckpointManifest(**d["manifest"])
        data = CheckpointData(
            manifest        = manifest,
            campaign_id     = manifest.campaign_id,
            vault           = d.get("vault", {}),
            campaign        = d.get("campaign", {}),
            session         = d.get("session", {}),
            credential_ids  = d.get("credential_ids", []),
            pending_tasks   = d.get("pending_tasks", []),
            completed_steps = d.get("completed_steps", []),
            timeline        = d.get("timeline", []),
            pivot_tunnels   = d.get("pivot_tunnels", []),
            extra           = d.get("extra", {}),
        )
        audit("checkpoint_loaded", actor="engine",
              campaign=campaign_id, checkpoint_id=manifest.checkpoint_id)
        logger.info("checkpoint_loaded",
                    campaign=campaign_id, checkpoint_id=manifest.checkpoint_id,
                    hosts=manifest.hosts_captured, findings=manifest.findings_count)
        return data

    def list_checkpoints(self, campaign_id: str) -> list[dict[str, Any]]:
        """Return metadata for all checkpoints of a campaign."""
        campaign_dir = CHECKPOINT_DIR / campaign_id
        if not campaign_dir.exists():
            return []
        results = []
        files = []
        for f in campaign_dir.glob(f"*{CHECKPOINT_EXT}"):
            if f.name.startswith("latest"):
                continue
            try:
                files.append((f.stat().st_mtime, f))
            except (OSError, FileNotFoundError):
                pass  # broken symlink or deleted file
        for _, f in sorted(files, key=lambda t: -t[0]):
            try:
                enc = f.read_bytes()
                raw = self._fernet.decrypt(enc)
                d   = json.loads(raw)
                results.append(d["manifest"])
            except (ValueError, KeyError, OSError):
                results.append({"file": f.name, "error": "decrypt_failed"})
        return results

    def delete_checkpoint(self, campaign_id: str, checkpoint_id: str) -> bool:
        """Delete a specific checkpoint file."""
        campaign_dir = CHECKPOINT_DIR / campaign_id
        matches = list(campaign_dir.glob(f"*{checkpoint_id}*{CHECKPOINT_EXT}"))
        if not matches:
            return False
        for f in matches:
            f.unlink()
        logger.info("checkpoint_deleted", campaign=campaign_id, checkpoint_id=checkpoint_id)
        return True

    def purge_old(self, campaign_id: str, keep_last: int = 5) -> int:
        """Delete old checkpoints, keeping the N most recent."""
        campaign_dir = CHECKPOINT_DIR / campaign_id
        if not campaign_dir.exists():
            return 0
        files = sorted(
            [f for f in campaign_dir.glob(f"*{CHECKPOINT_EXT}")
             if "latest" not in f.name],
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        to_delete = files[keep_last:]
        for f in to_delete:
            f.unlink()
        if to_delete:
            logger.info("checkpoints_purged", campaign=campaign_id, deleted=len(to_delete))
        return len(to_delete)


def _build_checkpoint_full(
    campaign_id:     str,
    campaign_name:   str,
    operator:        str,
    session_snapshot: dict[str, Any],
    findings:        list[Any],
    pending_tasks:   list[dict[str, Any]] | None = None,
    completed_steps: list[str] | None = None,
    timeline:        list[dict[str, Any]] | None = None,
    pivot_summary:   list[dict[str, Any]] | None = None,
    goal:            str = "",
    goal_achieved:   bool = False,
    extra:           dict[str, Any] | None = None,
) -> CheckpointData:
    """
    Helper to build a CheckpointData from live engine state.
    Call before ares campaign pause or on crash handler.
    """
    from ares.__version__ import __version__ as _ares_ver
    manifest = CheckpointManifest(
        campaign_id    = campaign_id,
        campaign_name  = campaign_name,
        operator       = operator,
        ares_version   = _ares_ver,
        hosts_captured = len(session_snapshot.get("hosts", {})),
        findings_count = len(findings),
        goal           = goal,
        goal_achieved  = goal_achieved,
    )
    return CheckpointData(
        manifest        = manifest,
        session         = session_snapshot,
        campaign        = {"id": campaign_id, "name": campaign_name},
        credential_ids  = [],   # IDs only — secrets stay in vault
        pending_tasks   = pending_tasks or [],
        completed_steps = completed_steps or [],
        timeline        = timeline or [],
        pivot_tunnels   = pivot_summary or [],
        extra           = extra or {},
    )


def build_checkpoint(
    session_or_campaign_id: "Any" = None,
    vault: "Any | None" = None,
    **kwargs: "Any",
) -> "CheckpointData":
    """
    Flexible checkpoint builder. Accepts:
      build_checkpoint(session)                           — unit test style
      build_checkpoint(campaign_id=..., operator=..., ...) — integration style
    """
    from ares.state.target_state import OperatorSession

    # Style 1: first arg is an OperatorSession
    if isinstance(session_or_campaign_id, OperatorSession):
        sess = session_or_campaign_id
        return CheckpointData(
            campaign_id = sess.campaign_id,
            session     = sess.snapshot(),
            vault       = vault if isinstance(vault, dict) else {},
        )

    # Style 2: kwargs-only (integration test style)
    campaign_id   = kwargs.get("campaign_id") or (str(session_or_campaign_id) if session_or_campaign_id else "")
    campaign_name = kwargs.get("campaign_name", "")
    operator      = kwargs.get("operator", "unknown")
    goal          = kwargs.get("goal", "")
    goal_achieved = kwargs.get("goal_achieved", False)
    session_snap  = kwargs.get("session_snapshot", {})
    findings      = kwargs.get("findings", [])

    manifest = CheckpointManifest(
        campaign_id   = campaign_id,
        campaign_name = campaign_name,
        operator      = operator,
        goal          = goal,
        goal_achieved = goal_achieved,
        findings_count = len(findings),
    )
    return CheckpointData(
        manifest    = manifest,
        campaign_id = campaign_id,
        session     = session_snap,
        vault       = vault if isinstance(vault, dict) else {},
    )
