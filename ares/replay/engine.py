"""
ARES Campaign Replay Engine
Replays a past campaign for training, purple team exercises, and forensic analysis.

Modes:
  FULL      — re-execute all attacks (real network, real targets)
  SIMULATE  — replay attack sequence without network connections (safe for demos)
  TIMELINE  — stream events chronologically for visualization
  PURPLE    — replay with defender notifications (detection testing)

Usage:
    replay = CampaignReplay.load(campaign_id, db)
    result = await replay.run(mode=ReplayMode.SIMULATE, speed=2.0)

    # Timeline streaming (for dashboard)
    async for event in replay.stream_timeline():
        dashboard.broadcast(event)
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator

from ares.core.logger import audit, get_logger
from ares.state.target_state import AttackHistoryEntry

logger = get_logger("ares.replay")


class ReplayMode(str, Enum):
    FULL     = "full"       # real execution on live network
    SIMULATE = "simulate"   # no network — event simulation only
    TIMELINE = "timeline"   # stream events at original timing
    PURPLE   = "purple"     # run + alert defender team


@dataclass
class ReplayEvent:
    """A single event in the replay timeline."""
    event_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:   float = 0.0
    module_id:   str = ""
    technique:   str = ""
    target:      str = ""
    username:    str = ""
    success:     bool = False
    finding_title: str = ""
    description: str = ""
    mitre:       str = ""
    severity:    str = ""
    is_simulated: bool = True
    findings:    list[str] = field(default_factory=list)  # finding IDs
    details:     dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id":    self.event_id,
            "timestamp":   self.timestamp,
            "module_id":   self.module_id,
            "technique":   self.technique,
            "target":      self.target,
            "username":    self.username,
            "success":     self.success,
            "description": self.description,
            "mitre":       self.mitre,
            "severity":    self.severity,
            "simulated":   self.is_simulated,
            "findings":    self.findings,
        }


@dataclass
class ReplayResult:
    replay_id:     str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    campaign_id:   str = ""
    mode:          ReplayMode = ReplayMode.SIMULATE
    events_total:  int = 0
    total_events:  int = 0   # alias for events_total
    events_played: int = 0
    duration_s:    float = 0.0
    original_duration_s: float = 0.0
    speed_factor:  float = 1.0
    started_at:    float = field(default_factory=time.time)
    timeline:      list["ReplayEvent"] = field(default_factory=list)
    replayed_events: list["ReplayEvent"] = field(default_factory=list)  # alias for timeline

    def __post_init__(self) -> None:
        if self.total_events and not self.events_total:
            self.events_total = self.total_events
        elif self.events_total and not self.total_events:
            self.total_events = self.events_total
        if self.replayed_events and not self.timeline:
            self.timeline = self.replayed_events
        elif self.timeline and not self.replayed_events:
            self.replayed_events = self.timeline

    def summary(self) -> dict[str, Any]:
        return {
            "replay_id":       self.replay_id,
            "campaign_id":     self.campaign_id,
            "mode":            self.mode.value,
            "events_total":    self.events_total,
            "events_played":   self.events_played,
            "duration_s":      round(self.duration_s, 2),
            "original_s":      round(self.original_duration_s, 2),
            "speed_factor":    self.speed_factor,
        }


class CampaignReplay:
    """
    Replays a campaign from its attack history.
    Reconstructs the full attack timeline from DB findings and history.
    """

    def __init__(
        self,
        campaign_id:  str = "",
        history:      list[AttackHistoryEntry] | None = None,
        findings:     list[Any] | None = None,  # list of Finding objects
        campaign:     Any = None,   # accept campaign object directly
        operator:     str = "replay",
    ) -> None:
        if campaign is not None and not campaign_id:
            campaign_id = getattr(campaign, "id", "") or getattr(campaign, "campaign_id", "") or str(campaign)
        self.campaign_id = campaign_id
        history   = history or []
        findings  = findings or []
        self.history     = sorted(history, key=lambda e: e.timestamp)
        self.findings    = findings
        self.operator    = operator
        self._callbacks: list[Any] = []   # async callbacks for purple mode

    @classmethod
    def from_snapshot(
        cls,
        campaign_id:      str,
        session_snapshot: dict[str, Any],
        findings:         list[Any],
    ) -> "CampaignReplay":
        """Build replay from OperatorSession.snapshot()."""
        history = [
            AttackHistoryEntry(
                module_id=e.get("module_id", ""),
                target_host=e.get("target", ""),
                success=e.get("success", False),
                technique=e.get("technique", ""),
                username=e.get("username", ""),
                timestamp=e.get("timestamp", time.time()),
            )
            for e in session_snapshot.get("history", [])
        ]
        return cls(campaign_id=campaign_id, history=history, findings=findings)

    def on_event(self, callback: Any) -> None:
        """Register async callback called on each event during replay."""
        self._callbacks.append(callback)

    def build_timeline(self) -> list[ReplayEvent]:
        """Build ordered event timeline from history + findings."""
        events: list[ReplayEvent] = []

        # Build finding lookup by module_id
        finding_map: dict[str, Any] = {}
        for f in self.findings:
            fid = getattr(f, "module_id", "")
            finding_map.setdefault(fid, []).append(f)

        for entry in self.history:
            related_findings = finding_map.get(entry.module_id, [])

            if related_findings:
                # One event per finding
                for finding in related_findings:
                    events.append(ReplayEvent(
                        timestamp    = entry.timestamp,
                        module_id    = entry.module_id,
                        technique    = entry.technique,
                        target       = entry.target_host,
                        username     = entry.username,
                        success      = entry.success,
                        finding_title = getattr(finding, "title", ""),
                        description  = getattr(finding, "description", ""),
                        mitre        = getattr(finding, "mitre_technique", "") or "",
                        severity     = getattr(getattr(finding, "severity", None), "value", ""),
                    ))
            else:
                # Module ran but no findings
                events.append(ReplayEvent(
                    timestamp    = entry.timestamp,
                    module_id    = entry.module_id,
                    technique    = entry.technique,
                    target       = entry.target_host,
                    username     = entry.username,
                    success      = entry.success,
                    description  = f"Module {entry.module_id} ran on {entry.target_host}",
                ))

        return sorted(events, key=lambda e: e.timestamp)

    async def run(
        self,
        mode:  ReplayMode = ReplayMode.SIMULATE,
        speed: float = 1.0,   # 1.0 = original timing, 2.0 = 2× faster, 0 = no delays
    ) -> ReplayResult:
        """
        Execute the replay.
        Returns ReplayResult with full timeline.
        """
        timeline = self.build_timeline()
        result   = ReplayResult(
            campaign_id=self.campaign_id,
            mode=mode,
            events_total=len(timeline),
            speed_factor=speed,
        )

        if not timeline:
            logger.warning("replay_empty_timeline", campaign=self.campaign_id)
            return result

        t0 = time.monotonic()
        original_start = timeline[0].timestamp

        audit(
            "campaign_replay_start",
            actor=self.operator,
            campaign=self.campaign_id,
            mode=mode.value,
            events=len(timeline),
            speed=speed,
        )

        logger.info(
            "replay_start",
            campaign=self.campaign_id,
            mode=mode.value,
            events=len(timeline),
            speed=speed,
        )

        for event in timeline:
            event.is_simulated = mode in (ReplayMode.SIMULATE, ReplayMode.PURPLE)

            if speed > 0 and mode != ReplayMode.SIMULATE:
                # Wait proportional to original timing
                elapsed_original = event.timestamp - original_start
                elapsed_real     = time.monotonic() - t0
                delay            = (elapsed_original / speed) - elapsed_real
                if delay > 0:
                    await asyncio.sleep(delay)

            result.timeline.append(event)
            result.events_played += 1

            # Notify callbacks (purple mode: alert defender team)
            for cb in self._callbacks:
                try:
                    await cb(event)
                except Exception as exc:
                    logger.warning("replay_callback_error", error=str(exc)[:100])

            if mode == ReplayMode.PURPLE and event.success:
                await self._purple_team_alert(event)

            logger.debug(
                "replay_event",
                module=event.module_id,
                target=event.target,
                success=event.success,
            )

        result.duration_s         = round(time.monotonic() - t0, 2)
        result.original_duration_s = (
            timeline[-1].timestamp - timeline[0].timestamp
            if len(timeline) > 1 else 0.0
        )

        audit(
            "campaign_replay_complete",
            actor=self.operator,
            campaign=self.campaign_id,
            events_played=result.events_played,
            duration_s=result.duration_s,
        )
        logger.info(
            "replay_complete",
            events=result.events_played,
            duration_s=result.duration_s,
        )
        return result

    async def stream_timeline(
        self,
        speed: float = 1.0,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Async generator: yields timeline events one by one for dashboard streaming.

        Usage:
            async for event_dict in replay.stream_timeline(speed=5.0):
                await websocket.send_json(event_dict)
        """
        timeline = self.build_timeline()
        if not timeline:
            return

        t0 = time.monotonic()
        original_start = timeline[0].timestamp

        for event in timeline:
            if speed > 0:
                elapsed_original = event.timestamp - original_start
                elapsed_real     = time.monotonic() - t0
                delay            = (elapsed_original / speed) - elapsed_real
                if delay > 0:
                    await asyncio.sleep(delay)
            yield event.to_dict()

    async def _purple_team_alert(self, event: ReplayEvent) -> None:
        """
        Purple team mode: notify the defender team of a successful attack.
        In production, this sends a webhook/email/Slack message.
        """
        logger.info(
            "purple_team_alert",
            module=event.module_id,
            technique=event.technique,
            target=event.target,
            mitre=event.mitre,
            severity=event.severity,
        )
        # Production:
        # await send_webhook(PURPLE_WEBHOOK_URL, {
        #     "text": f"[ARES Purple] {event.module_id} succeeded on {event.target}",
        #     "mitre": event.mitre,
        #     "severity": event.severity,
        # })
