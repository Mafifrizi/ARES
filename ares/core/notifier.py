"""
ARES Webhook Notifier — v1.0.0

Sends real-time alerts to Slack / Teams / generic webhook endpoints
when findings above a configured severity threshold are discovered.

Configuration (.env):
    ARES_WEBHOOK_URL=https://hooks.slack.com/services/...
    ARES_WEBHOOK_ON_SEVERITY=critical,high   # thresholds (comma-separated)
    ARES_WEBHOOK_TIMEOUT=5                   # HTTP timeout in seconds
    ARES_WEBHOOK_RETRY=2                     # max retries on failure

The notifier detects payload format from URL:
    - *.slack.com/*   → Slack Block Kit format
    - *.office.com/*  → MS Teams Adaptive Card format
    - anything else   → generic JSON (works with n8n, Zapier, custom webhooks)

Engine calls:
    if self.notifier and notifier.should_notify(finding.severity):
        await self.notifier.notify_finding(finding, campaign)
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.core.notifier")


# Severity ordering for threshold comparison
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class WebhookNotifier:
    """
    Async webhook notifier. Sends one HTTP POST per qualifying finding.
    Fire-and-forget: errors are logged, never raised to the caller.
    """

    def __init__(
        self,
        webhook_url: str,
        on_severity:  list[str] | None = None,
        timeout:      float = 5.0,
        max_retries:  int   = 2,
    ) -> None:
        self.webhook_url  = self._validate_webhook_url(webhook_url.strip())
        self.on_severity  = {s.lower() for s in (on_severity or ["critical", "high"])}
        self.timeout      = timeout
        self.max_retries  = max_retries
        self._client: Any = None

    @staticmethod
    def _validate_webhook_url(url: str) -> str:
        """
        Validate webhook URL to prevent SSRF attacks.

        Enforces:
          - https:// scheme only (no http://, file://, ftp://, etc.)
          - Blocks RFC-1918 private ranges and link-local (169.254.x.x cloud metadata)
          - Blocks localhost variants
        """
        import ipaddress
        from urllib.parse import urlparse

        if not url:
            return url  # empty = disabled; caught at call time

        parsed = urlparse(url)

        if parsed.scheme != "https":
            raise ValueError(
                f"Webhook URL must use https:// (got {parsed.scheme!r}). "
                "http:// is rejected to prevent credential interception and SSRF."
            )

        hostname = parsed.hostname or ""

        # Block localhost variants
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            raise ValueError(f"Webhook URL hostname {hostname!r} is not allowed (localhost).")

        # Block RFC-1918 private ranges + link-local (cloud metadata endpoints)
        _BLOCKED_NETWORKS = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),   # AWS/Azure/GCP metadata
            ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
            ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
            ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
        ]
        try:
            addr = ipaddress.ip_address(hostname)
            for net in _BLOCKED_NETWORKS:
                if addr in net:
                    raise ValueError(
                        f"Webhook URL resolves to a private/internal address {hostname!r}. "
                        "SSRF protection: only public HTTPS endpoints are allowed."
                    )
        except ValueError as exc:
            if "not allowed" in str(exc) or "private" in str(exc) or "SSRF" in str(exc):
                raise
            # Not a bare IP literal — resolve hostname now and check all returned addresses.
            # This prevents SSRF via internal hostnames like `internal.corp.local` that would
            # otherwise only be DNS-resolved at request time, bypassing the IP blocklist above.
            import socket
            try:
                resolved = socket.getaddrinfo(hostname, None)
            except socket.gaierror:
                # Unresolvable at config time — reject to be safe; DNS may resolve later
                # to a private IP, and we cannot verify it is safe.
                raise ValueError(
                    f"Webhook hostname {hostname!r} could not be resolved at configuration "
                    "time. Provide a resolvable public hostname or a direct HTTPS URL."
                ) from None
            for _family, _type, _proto, _canon, sockaddr in resolved:
                raw_ip = sockaddr[0]
                try:
                    resolved_addr = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                for net in _BLOCKED_NETWORKS:
                    if resolved_addr in net:
                        raise ValueError(
                            f"Webhook hostname {hostname!r} resolves to private/internal "
                            f"address {raw_ip!r}. SSRF protection: only public HTTPS "
                            "endpoints are allowed."
                        )
        return url

    def should_notify(self, severity: Any) -> bool:
        """Return True if this severity meets the notification threshold."""
        sev_str = severity.value if hasattr(severity, "value") else str(severity).lower()
        return sev_str in self.on_severity

    async def _get_client(self) -> Any:
        """Lazy-init httpx.AsyncClient (avoids import if notifier unused)."""
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False)
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def notify_finding(self, finding: Any, campaign: Any) -> None:
        """
        Send a webhook alert for a finding.
        Automatically picks Slack / Teams / generic format based on URL.
        """
        try:
            payload = self._build_payload(finding, campaign)
            await self._post_with_retry(payload)
        except Exception as exc:
            logger.warning("webhook_notify_error", error=str(exc)[:120],
                           module=getattr(finding, "module_id", "?"))

    def _build_payload(self, finding: Any, campaign: Any) -> dict[str, Any]:
        """Build notification payload — auto-detects Slack vs Teams vs generic."""
        sev   = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        score = getattr(finding, "cvss_score", 0.0) or 0.0
        mitre = getattr(finding, "mitre_technique", None) or "—"
        tid   = getattr(finding, "trace_id", "") or ""
        host  = getattr(finding, "host", None) or "—"
        mod   = getattr(finding, "module_id", "?")
        cname = getattr(campaign, "name", str(getattr(campaign, "id", "?")))

        color_map = {
            "critical": "#ef4444",
            "high":     "#f97316",
            "medium":   "#f59e0b",
            "low":      "#22c55e",
            "info":     "#94a3b8",
        }
        color = color_map.get(sev, "#94a3b8")
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")

        if "slack.com" in self.webhook_url:
            return self._slack_payload(finding, cname, sev, score, mitre, tid, host, mod, emoji, color)
        if "office.com" in self.webhook_url or "webhook.office" in self.webhook_url:
            return self._teams_payload(finding, cname, sev, score, mitre, tid, host, mod, emoji, color)
        return self._generic_payload(finding, cname, sev, score, mitre, tid, host, mod)

    def _slack_payload(self, finding: Any, cname: str, sev: str, score: float,
                       mitre: str, tid: str, host: str, mod: str,
                       emoji: str, color: str) -> dict[str, Any]:
        return {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{emoji} *{finding.title}*\n"
                                    f"Campaign: `{cname}` | Severity: *{sev.upper()}*",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*CVSS Score*\n{score:.1f}"},
                            {"type": "mrkdwn", "text": f"*MITRE*\n{mitre}"},
                            {"type": "mrkdwn", "text": f"*Module*\n`{mod}`"},
                            {"type": "mrkdwn", "text": f"*Host*\n`{host}`"},
                        ],
                    },
                    *([{
                        "type": "context",
                        "elements": [{"type": "mrkdwn", "text": f"trace: `{tid}`"}],
                    }] if tid else []),
                ],
            }],
        }

    def _teams_payload(self, finding: Any, cname: str, sev: str, score: float,
                       mitre: str, tid: str, host: str, mod: str,
                       emoji: str, color: str) -> dict[str, Any]:
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.lstrip("#"),
            "summary": f"ARES Alert: {finding.title}",
            "sections": [{
                "activityTitle": f"{emoji} **{finding.title}**",
                "activitySubtitle": f"Campaign: {cname} | {sev.upper()}",
                "facts": [
                    {"name": "CVSS Score", "value": f"{score:.1f}"},
                    {"name": "MITRE Technique", "value": mitre},
                    {"name": "Module", "value": mod},
                    {"name": "Host", "value": host},
                    *([ {"name": "Trace ID", "value": tid}] if tid else []),
                ],
            }],
        }

    def _generic_payload(self, finding: Any, cname: str, sev: str, score: float,
                         mitre: str, tid: str, host: str, mod: str) -> dict[str, Any]:
        return {
            "event":       "ares_finding",
            "campaign":    cname,
            "title":       finding.title,
            "description": getattr(finding, "description", ""),
            "severity":    sev,
            "cvss_score":  score,
            "cvss_vector": getattr(finding, "cvss_vector", ""),
            "mitre":       mitre,
            "module":      mod,
            "host":        host,
            "trace_id":    tid,
            "remediation": getattr(finding, "remediation", ""),
        }

    async def _post_with_retry(self, payload: dict[str, Any]) -> None:
        client = await self._get_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                resp = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                logger.debug("webhook_sent", status=resp.status_code,
                             attempt=attempt + 1)
                return

            except Exception as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)  # 1s, 2s backoff

        logger.warning("webhook_failed_after_retries", retries=self.max_retries,
                       error=str(last_exc)[:200])


def build_notifier_from_settings(settings: Any) -> WebhookNotifier | None:
    """
    Build a WebhookNotifier from AresSettings.
    Returns None if ARES_WEBHOOK_URL is not configured.
    """
    url = getattr(settings, "ares_webhook_url", "") or ""
    if not url:
        return None
    sev_str = getattr(settings, "ares_webhook_on_severity", "critical,high") or "critical,high"
    severities = [s.strip().lower() for s in sev_str.split(",") if s.strip()]
    timeout  = float(getattr(settings, "ares_webhook_timeout",  5))
    retries  = int(getattr(settings, "ares_webhook_retry",      2))
    notifier = WebhookNotifier(url, on_severity=severities, timeout=timeout, max_retries=retries)
    logger.info("webhook_notifier_active", url=url[:40] + "...", on_severity=severities)
    return notifier
