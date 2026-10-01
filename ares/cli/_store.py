"""
Shared CLI persistence helpers - campaign JSON store on local disk.
Used by typer_main.py for all campaign read/write operations.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def campaigns_dir() -> Path:
    p = Path.home() / ".ares" / "campaigns"
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_campaign(campaign: Any) -> None:
    path = campaigns_dir() / f"{campaign.id}.json"
    path.write_text(campaign.model_dump_json(indent=2), encoding="utf-8")


def load_campaign(partial_id: str) -> dict[str, Any] | None:
    for p in campaigns_dir().glob("*.json"):
        data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
        if data["id"].startswith(partial_id):
            return data
    return None


def load_all_campaigns() -> list[dict[str, Any]]:
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(
            campaigns_dir().glob("*.json"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
    ]


def calc_risk(c: dict[str, Any]) -> float:
    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return sum(
        sev_map.get(f.get("severity", "info"), 1) * f.get("confidence", 1.0)
        for f in c.get("findings", [])
        if not f.get("false_positive")
    )


# ── Campaign Store class (returned by get_store()) ────────────────────────────

class CampaignStore:
    """
    Simple file-based campaign store.
    Wraps the module-level helpers for use as an object.
    """

    def list_campaigns(self) -> list[dict]:
        return load_all_campaigns()

    def get_campaign(self, partial_id: str) -> dict | None:
        return load_campaign(partial_id)

    def save_campaign(self, campaign: Any) -> None:
        save_campaign(campaign)

    def active_campaign_id(self) -> str | None:
        """Return ID of most recently modified campaign, or None."""
        all_c = load_all_campaigns()
        return all_c[0]["id"] if all_c else None

    def add_target(self, campaign_partial_id: str, target: "str | dict") -> bool:
        """Append a target entry to a campaign and re-save. Returns True if found."""
        import json
        from pathlib import Path

        # Normalise: accept either a plain string or a dict like {"target": ip, "tags": [...]}
        if isinstance(target, dict):
            entry = target
            ip_str = entry.get("target", "")
        else:
            entry  = {"target": str(target), "tags": [], "notes": ""}
            ip_str = str(target)

        for p in campaigns_dir().glob("*.json"):
            data: dict = json.loads(p.read_text(encoding="utf-8"))
            if data["id"].startswith(campaign_partial_id):
                targets = data.get("targets", [])
                # Avoid duplicate IPs
                existing_ips = [
                    (t["target"] if isinstance(t, dict) else t)
                    for t in targets
                ]
                if ip_str not in existing_ips:
                    targets.append(entry)
                    data["targets"] = targets
                    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
                return True
        return False

    def list_targets(self, campaign_partial_id: str) -> list[dict]:
        """Return targets (as dicts) for a campaign, or [] if not found."""
        c = load_campaign(campaign_partial_id)
        raw = c.get("targets", []) if c else []
        # Normalise old string entries
        result = []
        for t in raw:
            if isinstance(t, dict):
                result.append(t)
            else:
                result.append({"target": str(t), "tags": [], "notes": ""})
        return result

    # ── Checkpoint management ─────────────────────────────────────────────

    def save_checkpoint(self, campaign_partial_id: str, notes: str = "") -> dict | None:
        """Snapshot a campaign state as an AES-256-GCM encrypted checkpoint."""
        import json, time, os
        c = load_campaign(campaign_partial_id)
        if not c:
            return None

        from ares.core.config import get_settings
        from ares.checkpoint.manager import CheckpointManager

        settings = get_settings()
        enc_key = getattr(settings, "ares_encryption_key", "") or getattr(settings, "ares_secret_key", "")
        if not enc_key:
            enc_key = "ares-default-local-checkpoint-key-32b"

        mgr = CheckpointManager(enc_key)

        cp_dir = campaigns_dir() / "checkpoints" / c["id"]
        cp_dir.mkdir(parents=True, exist_ok=True)

        ts = int(time.time())
        cp_id = f"cp_{ts}"
        checkpoint = {
            "checkpoint_id": cp_id,
            "campaign_id":   c["id"],
            "saved_at":      time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)),
            "notes":         notes,
            "state":         c,
        }
        raw_bytes = json.dumps(checkpoint, indent=2, default=str).encode("utf-8")
        nonce = os.urandom(mgr._GCM_NONCE_LEN)
        ct = mgr._aesgcm.encrypt(nonce, raw_bytes, None)
        encrypted = mgr._V2_MAGIC + nonce + ct

        cp_path = cp_dir / f"{cp_id}.json"
        cp_path.write_bytes(encrypted)

        # Mark campaign as paused
        for p in campaigns_dir().glob("*.json"):
            try:
                data_raw = json.loads(p.read_text(encoding="utf-8"))
                if data_raw.get("id") == c["id"]:
                    data_raw["status"] = "paused"
                    data_raw["last_checkpoint"] = cp_id
                    p.write_text(json.dumps(data_raw, indent=2), encoding="utf-8")
                    break
            except Exception:
                continue

        return {"checkpoint_id": cp_id, "path": str(cp_path), "saved_at": checkpoint["saved_at"]}

    def load_checkpoint(self, campaign_partial_id: str, cp_id: str = "latest") -> dict | None:
        """Load an AES-256-GCM encrypted checkpoint. cp_id='latest' returns the most recent."""
        import json
        c = load_campaign(campaign_partial_id)
        if not c:
            return None

        cp_dir = campaigns_dir() / "checkpoints" / c["id"]
        if not cp_dir.exists():
            return None

        checkpoints = sorted(cp_dir.glob("cp_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not checkpoints:
            return None

        if cp_id == "latest":
            target = checkpoints[0]
        else:
            matches = [p for p in checkpoints if cp_id in p.name]
            target = matches[0] if matches else checkpoints[0]

        data_bytes = target.read_bytes()
        from ares.core.config import get_settings
        from ares.checkpoint.manager import CheckpointManager

        settings = get_settings()
        enc_key = getattr(settings, "ares_encryption_key", "") or getattr(settings, "ares_secret_key", "")
        if not enc_key:
            enc_key = "ares-default-local-checkpoint-key-32b"

        mgr = CheckpointManager(enc_key)
        try:
            decrypted = mgr._decrypt_checkpoint(data_bytes)
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            # Fallback: legacy unencrypted JSON
            return json.loads(data_bytes.decode("utf-8"))

    def list_reports(self, campaign_partial_id: str = "") -> list[dict]:
        """List generated report files from ~/.ares/reports/."""
        from pathlib import Path
        reports_dir = Path.home() / ".ares" / "reports"
        if not reports_dir.exists():
            return []

        results = []
        for p in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.suffix in (".html", ".json", ".md", ".pdf"):
                results.append({
                    "filename": p.name,
                    "format":   p.suffix.lstrip("."),
                    "size_kb":  round(p.stat().st_size / 1024, 1),
                    "path":     str(p),
                })
        return results


_store_instance: CampaignStore | None = None


def get_store() -> CampaignStore:
    """Return singleton CampaignStore instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = CampaignStore()
    return _store_instance
