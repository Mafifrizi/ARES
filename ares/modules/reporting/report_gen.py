"""
ARES Smart Report Generator
Professional pentest report with:
  - MITRE ATT&CK heatmap (which tactics/techniques were demonstrated)
  - Attack timeline (chronological finding sequence)
  - Attack path narrative (graph → human-readable story)
  - Executive summary auto-generated
  - Per-finding remediation with severity-based SLA
  - JSON structured output (machine-readable)
  - HTML dark-theme client report
  - Markdown for GitHub/Confluence
  - PDF via weasyprint
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Environment

from ares.core.campaign import Campaign
from ares.core.cvss import CVSSSummary, enrich_finding_with_cvss
from ares.core.logger import get_logger

logger = get_logger("ares.reporting")

# ── MITRE ATT&CK tactic order (kill chain order) ──────────────────────────────
MITRE_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# SLA for remediation based on severity (days)
REMEDIATION_SLA = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}

BROWSER_PDF_TIMEOUT_SECONDS = 15
PDF_ARTIFACT_WAIT_SECONDS = 3.0
WINDOWS_EDGE_ELEVATED_PDF_MESSAGE = (
    "PDF browser fallback is not supported from elevated Windows sessions with "
    "Edge. Run PowerShell normally, set ARES_PDF_BROWSER to a working browser, "
    "or install WeasyPrint native GTK/Pango dependencies."
)
WINDOWS_WEASYPRINT_NATIVE_HINT = (
    "WeasyPrint imported from pip, but Windows native GTK/Pango libraries are "
    "missing. Install the native GTK/Pango runtime or use the Edge/Chrome "
    "browser fallback from normal non-Administrator PowerShell."
)
_PDF_SMOKE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ARES PDF smoke</title></head>
<body><h1>ARES PDF smoke</h1><p>PDF export preflight.</p></body></html>"""
_REDACTED_EVIDENCE = "[REDACTED sensitive evidence]"
_SENSITIVE_EVIDENCE_KEYS = {
    "hash",
    "hashes",
    "sample_hash",
    "raw_hash",
    "kerberos_hashes",
    "asrep_hashes",
    "ntlm_hashes",
    "nt_hash",
    "lm_hash",
    "krbtgt_hash",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
    "key_material",
    "ccache",
    "ticket",
}
_SAFE_HASH_METADATA_KEYS = {"hash_count", "hashcat_cmd", "hashcat_mode"}
_KERBEROS_HASH_RE = re.compile(r"\$krb5(?:asrep|tgs)\$", re.IGNORECASE)
_NTLM_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


# ── Context builder ───────────────────────────────────────────────────────────


def build_report_context(
    campaign: Campaign,
    graph_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = campaign.confirmed_findings()
    # Auto-assign CVSS scores to any finding that doesn't have one yet
    for f in findings:
        enrich_finding_with_cvss(f)
    # Auto-assign compliance framework mappings (PCI-DSS, ISO 27001, NIST, CIS)
    try:
        from ares.core.cvss import (
            enrich_finding_with_compliance,
            get_compliance_for_finding,
        )

        compliance_summary: dict[str, set[str]] = {}
        for f in findings:
            enrich_finding_with_compliance(f)
            mapping = get_compliance_for_finding(f)
            for framework, controls in mapping.items():
                if framework not in compliance_summary:
                    compliance_summary[framework] = set()
                compliance_summary[framework].update(controls)
        # Convert sets to sorted lists for JSON serialization
        compliance_report = {
            fw: sorted(ctrls) for fw, ctrls in compliance_summary.items()
        }
    except Exception:
        compliance_report = {}
    cvss_summary = CVSSSummary.from_findings(findings)
    sorted_finds = sorted(
        findings, key=lambda f: -(f.cvss_score or _sev_score(f.severity.value))
    )
    timeline = sorted(findings, key=lambda f: f.discovered_at)
    mitre_map = _build_mitre_map(findings)
    attack_path = _build_attack_path_narrative(graph_json) if graph_json else []
    exec_summary = _build_exec_summary(campaign, findings)

    # Watermark image path for PDF/HTML reports
    import os as _os

    _wm_candidates = [
        _os.path.join(
            _os.path.dirname(__file__), "..", "..", "..", "static", "dragon-full.png"
        ),
        _os.path.expanduser("~/.ares/assets/dragon-full.png"),
    ]
    watermark_path = next((p for p in _wm_candidates if _os.path.exists(p)), "")
    repo_root = Path(__file__).resolve().parents[3]
    _brand_candidates = [
        repo_root / "frontend" / "public" / "brand" / "ares-logo.png",
        repo_root / "frontend" / "dist" / "brand" / "ares-logo.png",
        Path.home() / ".ares" / "assets" / "ares-logo.png",
    ]
    brand_logo_path = next(
        (p.resolve().as_uri() for p in _brand_candidates if p.exists()), ""
    )

    return {
        "campaign": campaign,
        "watermark_path": watermark_path,
        "brand_logo_path": brand_logo_path,
        "findings": sorted_finds,
        "timeline": timeline,
        "mitre_map": mitre_map,
        "mitre_tactics": MITRE_TACTIC_ORDER,
        "attack_path": attack_path,
        "exec_summary": exec_summary,
        "risk_label": _risk_label(campaign.risk_score()),
        "report_scope": _build_scope_summary(campaign),
        "methodology": _DEFAULT_METHODOLOGY,
        "key_findings": sorted_finds[:5],
        "remediation_roadmap": _build_remediation_roadmap(sorted_finds),
        "summary": campaign.summary(),
        "risk_score": campaign.risk_score(),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_findings": len(sorted_finds),
        "fp_filtered": len([f for f in campaign.findings if f.false_positive]),
        "sla": REMEDIATION_SLA,
        "cvss_summary": cvss_summary.to_dict(),
        "compliance": compliance_report,
        "graph_json": json.dumps(graph_json or {}, default=str),
    }


def _sev_score(sev: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 1)


def _build_mitre_map(findings: list[Any]) -> dict[str, list[dict[str, Any]]]:
    """Group findings by MITRE tactic → list of techniques demonstrated."""
    tactic_map: dict[str, list[dict[str, Any]]] = {t: [] for t in MITRE_TACTIC_ORDER}
    tactic_map["Unknown"] = []

    for f in findings:
        tactic = f.mitre_tactic or "Unknown"
        if tactic not in tactic_map:
            tactic_map[tactic] = []
        tactic_map[tactic].append(
            {
                "technique": f.mitre_technique or "—",
                "title": f.title,
                "severity": f.severity.value,
            }
        )

    return {k: v for k, v in tactic_map.items() if v}


def _build_attack_path_narrative(graph_json: dict[str, Any]) -> list[str]:
    """Convert graph shortest paths to a human-readable step list."""
    nodes = {n["id"]: n for n in graph_json.get("nodes", [])}
    links = graph_json.get("links", [])
    steps: list[str] = []

    # Find paths to high-value targets
    targets = [n for n in graph_json.get("nodes", []) if n.get("is_target")]
    for t in targets[:3]:  # top 3 targets
        steps.append(f"🎯 Target: **{t['label']}** ({t['type']})")

    # Describe notable edges
    for link in sorted(links, key=lambda l: l.get("weight", 1.0))[:10]:
        src = nodes.get(link["source"], {})
        tgt = nodes.get(link["target"], {})
        if src and tgt:
            steps.append(f"  {src['label']} → [{link['label']}] → {tgt['label']}")

    return steps


def _build_exec_summary(campaign: Campaign, findings: list[Any]) -> str:
    """Auto-generate executive summary paragraph."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    crit = sev_counts["critical"]
    high = sev_counts["high"]
    risk = campaign.risk_score()

    level = (
        "critical"
        if risk > 20
        else "high" if risk > 10 else "medium" if risk > 5 else "low"
    )

    return (
        f"The red team engagement against {campaign.client} identified a **{level.upper()} overall risk posture** "
        f"with a composite risk score of {risk:.1f}. "
        f"The assessment discovered {len(findings)} confirmed security findings, "
        f"including {crit} critical and {high} high severity issues. "
        + (
            "Critical findings require immediate remediation within 7 days. "
            if crit > 0
            else ""
        )
        + f"The engagement was conducted using a {campaign.noise_profile.value} noise profile "
        f"to simulate realistic threat actor behavior."
    )


# ── HTML Template ─────────────────────────────────────────────────────────────

_DEFAULT_METHODOLOGY = [
    "Confirm authorization, campaign scope, and operational noise profile.",
    "Validate module parameters and dry-run behavior before execution.",
    "Execute approved modules against declared targets only.",
    "Collect evidence, enrich confirmed findings, and filter false positives.",
    "Map observations to MITRE ATT&CK and assign remediation priority.",
    "Prepare executive, technical, and retest-ready reporting outputs.",
]


def _risk_label(score: float) -> str:
    if score > 20:
        return "Critical"
    if score > 10:
        return "High"
    if score > 5:
        return "Medium"
    return "Low"


def _build_scope_summary(campaign: Campaign) -> dict[str, Any]:
    return {
        "targets": campaign.targets,
        "scope_entries": [s.cidr for s in campaign.scope],
        "target_count": len(campaign.targets),
        "scope_count": len(campaign.scope),
        "authorization_note": (
            "All testing activity in this report is intended for authorized "
            "security validation inside the declared campaign scope."
        ),
    }


def _build_remediation_roadmap(findings: list[Any]) -> list[dict[str, Any]]:
    severities = ("critical", "high", "medium", "low", "info")
    roadmap: list[dict[str, Any]] = []
    for severity in severities:
        items = [f for f in findings if f.severity.value == severity]
        if not items:
            continue
        roadmap.append(
            {
                "severity": severity,
                "count": len(items),
                "sla_days": REMEDIATION_SLA.get(severity, 365),
                "titles": [f.title for f in items[:5]],
            }
        )
    return roadmap


def _is_sensitive_evidence_key(key: Any) -> bool:
    normalized = str(key).strip().lower()
    if normalized in _SAFE_HASH_METADATA_KEYS:
        return False
    return (
        normalized in _SENSITIVE_EVIDENCE_KEYS
        or normalized.endswith("_hash")
        or normalized.endswith("_hashes")
    )


def _redact_sensitive_evidence(
    value: Any,
    *,
    include_sensitive_evidence: bool = False,
    key: Any = "",
) -> Any:
    if include_sensitive_evidence:
        return value
    if _is_sensitive_evidence_key(key):
        return _REDACTED_EVIDENCE
    if isinstance(value, dict):
        return {
            item_key: _redact_sensitive_evidence(
                item_value,
                include_sensitive_evidence=include_sensitive_evidence,
                key=item_key,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_sensitive_evidence(
                item,
                include_sensitive_evidence=include_sensitive_evidence,
                key=key,
            )
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_sensitive_evidence(
                item,
                include_sensitive_evidence=include_sensitive_evidence,
                key=key,
            )
            for item in value
        )
    if isinstance(value, str) and (
        _KERBEROS_HASH_RE.search(value) or _NTLM_HASH_RE.search(value)
    ):
        return _REDACTED_EVIDENCE
    return value


def _evidence_rows(
    evidence: Any,
    include_sensitive_evidence: bool = False,
) -> list[dict[str, str]]:
    """Normalize finding evidence into report-friendly key/value rows."""
    if isinstance(evidence, dict):
        items = evidence.items()
    elif isinstance(evidence, list):
        items = ((f"item_{index + 1}", value) for index, value in enumerate(evidence))
    else:
        items = (("evidence", evidence),)

    rows: list[dict[str, str]] = []
    for key, value in items:
        safe_value = _redact_sensitive_evidence(
            value,
            include_sensitive_evidence=include_sensitive_evidence,
            key=key,
        )
        rendered = _format_evidence_value(safe_value)
        rows.append({"key": str(key).replace("_", " ").title(), "value": rendered})
    return rows


def _format_evidence_value(value: Any) -> str:
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            label = str(key).replace("_", " ").upper()
            if isinstance(item, dict):
                nested = "; ".join(
                    f"{str(nested_key).replace('_', ' ')}: {_format_evidence_value(nested_value)}"
                    for nested_key, nested_value in item.items()
                )
                lines.append(f"{label}: {nested}")
            elif isinstance(item, (list, tuple, set)):
                lines.append(f"{label}: {', '.join(str(part) for part in item)}")
            else:
                lines.append(f"{label}: {item}")
        return "\n".join(lines)
    if isinstance(value, (list, tuple, set)):
        return "\n".join(str(item) for item in value)
    return str(value)


def _build_mitre_map(findings: list[Any]) -> dict[str, list[dict[str, Any]]]:
    """Group findings by MITRE tactic and demonstrated technique."""
    tactic_map: dict[str, list[dict[str, Any]]] = {t: [] for t in MITRE_TACTIC_ORDER}
    tactic_map["Unknown"] = []

    for finding in findings:
        tactic = finding.mitre_tactic or "Unknown"
        if tactic not in tactic_map:
            tactic_map[tactic] = []
        tactic_map[tactic].append(
            {
                "technique": finding.mitre_technique or "N/A",
                "title": finding.title,
                "severity": finding.severity.value,
            }
        )

    return {k: v for k, v in tactic_map.items() if v}


def _build_attack_path_narrative(graph_json: dict[str, Any]) -> list[str]:
    """Convert graph paths to a human-readable attack narrative."""
    nodes = {n["id"]: n for n in graph_json.get("nodes", [])}
    links = graph_json.get("links", [])
    steps: list[str] = []

    targets = [n for n in graph_json.get("nodes", []) if n.get("is_target")]
    for target in targets[:3]:
        steps.append(f"Target: **{target['label']}** ({target['type']})")

    for link in sorted(links, key=lambda l: l.get("weight", 1.0))[:10]:
        src = nodes.get(link["source"], {})
        tgt = nodes.get(link["target"], {})
        if src and tgt:
            steps.append(f"  {src['label']} -> [{link['label']}] -> {tgt['label']}")

    return steps


def _build_exec_summary(campaign: Campaign, findings: list[Any]) -> str:
    """Auto-generate a concise executive summary paragraph."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev_counts[finding.severity.value] = (
            sev_counts.get(finding.severity.value, 0) + 1
        )

    crit = sev_counts["critical"]
    high = sev_counts["high"]
    risk = campaign.risk_score()
    level = _risk_label(risk)

    urgent = (
        " Critical findings should be remediated within 7 days and validated "
        "through focused retesting."
        if crit > 0
        else ""
    )
    return (
        f"ARES assessed {campaign.client} under the {campaign.name} campaign and "
        f"identified a {level.upper()} overall risk posture with a composite risk "
        f"score of {risk:.1f}. The engagement produced {len(findings)} confirmed "
        f"security findings, including {crit} critical and {high} high severity "
        f"issues.{urgent} The campaign used a {campaign.noise_profile.value} "
        "noise profile to keep testing aligned with the declared authorization "
        "and operational limits."
    )


def _render_markdown_report(campaign: Campaign, ctx: dict[str, Any]) -> list[str]:
    lines: list[str] = [
        f"# ARES Report - {campaign.name}",
        "",
        f"**Client:** {campaign.client}",
        f"**Operator:** {campaign.operator}",
        f"**Generated:** {ctx['generated_at']}",
        f"**Risk:** {ctx['risk_label']} ({ctx['risk_score']:.1f})",
        f"**Confirmed Findings:** {ctx['total_findings']}",
        "",
        "## Executive Summary",
        "",
        ctx["exec_summary"],
        "",
        "## Engagement Overview",
        "",
        f"- Noise profile: `{campaign.noise_profile.value}`",
        f"- Targets declared: {ctx['report_scope']['target_count']}",
        f"- Scope entries declared: {ctx['report_scope']['scope_count']}",
        f"- False positives filtered: {ctx['fp_filtered']}",
        "",
        "## Scope and Authorization",
        "",
        ctx["report_scope"]["authorization_note"],
        "",
        "### Targets",
    ]
    if ctx["report_scope"]["targets"]:
        lines.extend(f"- `{target}`" for target in ctx["report_scope"]["targets"])
    else:
        lines.append("- No explicit targets were declared.")

    lines += ["", "### Scope CIDRs"]
    if ctx["report_scope"]["scope_entries"]:
        lines.extend(f"- `{scope}`" for scope in ctx["report_scope"]["scope_entries"])
    else:
        lines.append("- No CIDR scope entries were declared.")

    lines += ["", "## Methodology", ""]
    lines.extend(f"{index}. {step}" for index, step in enumerate(ctx["methodology"], 1))

    lines += [
        "",
        "## Key Findings",
        "",
        "| Severity | Finding | Module | MITRE |",
        "|----------|---------|--------|-------|",
    ]
    if ctx["key_findings"]:
        for finding in ctx["key_findings"]:
            lines.append(
                "| "
                f"{finding.severity.value.upper()} | {finding.title} | "
                f"`{finding.module_id}` | `{finding.mitre_technique or 'N/A'}` |"
            )
    else:
        lines.append("| INFO | No confirmed findings | N/A | N/A |")

    lines += [
        "",
        "## Severity Summary",
        "",
        "| Severity | Count | SLA (days) |",
        "|----------|-------|------------|",
    ]
    for sev, count in ctx["summary"].items():
        lines.append(f"| {sev.upper()} | {count} | {REMEDIATION_SLA.get(sev, 365)} |")

    lines += [
        "",
        "## MITRE ATT&CK Coverage",
        "",
        "| Tactic | Techniques |",
        "|--------|------------|",
    ]
    if ctx["mitre_map"]:
        for tactic, techs in ctx["mitre_map"].items():
            techs_str = ", ".join(f'`{t["technique"]}`' for t in techs)
            lines.append(f"| {tactic} | {techs_str} |")
    else:
        lines.append("| N/A | No MITRE-mapped findings |")

    lines += ["", "## Attack Narrative", ""]
    if ctx["attack_path"]:
        lines.extend(ctx["attack_path"])
    else:
        lines.append("No graph-derived attack path was supplied for this report.")

    lines += ["", "## Attack Timeline", ""]
    if ctx["timeline"]:
        for finding in ctx["timeline"]:
            ts = finding.discovered_at.strftime("%Y-%m-%d %H:%M")
            lines.append(
                f"- `{ts}` [{finding.severity.value.upper()}] "
                f"{finding.title} (`{finding.module_id}`)"
            )
    else:
        lines.append("- No confirmed findings yet.")

    lines += ["", "## Findings", ""]
    for finding in ctx["findings"]:
        lines += [
            f"### [{finding.severity.value.upper()}] {finding.title}",
            "",
            f"**Module:** `{finding.module_id}`",
            f"**Confidence:** `{finding.confidence * 100:.0f}%`",
            f"**MITRE:** `{finding.mitre_technique or 'N/A'}`",
            f"**Host:** `{finding.host or 'N/A'}`",
            "",
            finding.description,
            "",
        ]
        if finding.evidence:
            evidence = _redact_sensitive_evidence(
                finding.evidence,
                include_sensitive_evidence=ctx.get("include_sensitive_evidence", False),
            )
            lines += ["**Evidence:**", "", "```json", json.dumps(evidence, indent=2, default=str), "```", ""]
        if finding.remediation:
            lines += [
                f"**Remediation (SLA: {REMEDIATION_SLA.get(finding.severity.value, 365)} days):**",
                "",
                finding.remediation,
                "",
            ]

    lines += ["## Remediation Roadmap", ""]
    if ctx["remediation_roadmap"]:
        for item in ctx["remediation_roadmap"]:
            lines.append(
                f"- {item['severity'].upper()}: {item['count']} finding(s), "
                f"SLA {item['sla_days']} days."
            )
    else:
        lines.append("- No remediation items were generated.")

    lines += [
        "",
        "## Appendix",
        "",
        "This report is intended for authorized security testing, lab use, and defensive validation only.",
    ]
    return lines


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARES Report — {{ campaign.name }}</title>
<style>
:root{--red:#e94560;--dark:#0a0f1e;--card:#111827;--border:#1e293b;--text:#e2e8f0;--muted:#6b7280}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--dark);color:var(--text);line-height:1.6}
.page{max-width:1100px;margin:0 auto;padding:2rem}
h1{color:var(--red);font-size:2.2rem;font-weight:900}h2{color:#f1f5f9;margin:2.5rem 0 1rem;font-size:1.25rem;border-left:4px solid var(--red);padding-left:.75rem}h3{color:#cbd5e1;margin:.75rem 0 .5rem}
.cover{background:var(--card);border-radius:12px;padding:2rem;margin-bottom:2rem;border:1px solid var(--border)}
.cover .meta{display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-top:1.5rem}
.meta-item span{color:var(--muted);font-size:.8em;display:block}.meta-item strong{font-size:1em}
.exec{background:#0d1b2a;border-left:4px solid var(--red);padding:1.25rem 1.5rem;border-radius:0 8px 8px 0;margin:1.5rem 0;line-height:1.8}
.stat-row{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0 2rem}
.stat{padding:.7rem 1.5rem;border-radius:24px;font-weight:700;font-size:.9rem;text-align:center}
.critical{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.high{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.medium{background:#422006;color:#fbbf24;border:1px solid #78350f}
.low{background:#052e16;color:#4ade80;border:1px solid #14532d}
.info{background:#0c1a3a;color:#60a5fa;border:1px solid #1e3a5f}
.risk-score{font-size:4rem;font-weight:900;color:var(--red);text-align:center;padding:1rem 0 .25rem}
.risk-label{text-align:center;color:var(--muted);margin-bottom:1.5rem}

/* MITRE heatmap */
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.5rem;margin:1rem 0}
.tactic-cell{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.6rem .75rem}
.tactic-cell.active{border-color:var(--red)}
.tactic-name{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.technique-tag{display:inline-block;margin:.2rem .1rem;padding:.1rem .4rem;background:#1e293b;border-radius:3px;font-family:monospace;font-size:.72rem;color:#7dd3fc}

/* Timeline */
.timeline{position:relative;padding-left:2rem;margin:1rem 0}
.timeline::before{content:'';position:absolute;left:.5rem;top:0;bottom:0;width:2px;background:var(--border)}
.tl-item{position:relative;margin-bottom:1.25rem}
.tl-dot{position:absolute;left:-1.65rem;top:.3rem;width:10px;height:10px;border-radius:50%;border:2px solid var(--card)}
.tl-dot.critical{background:#ef4444}.tl-dot.high{background:#f97316}.tl-dot.medium{background:#f59e0b}.tl-dot.low{background:#10b981}
.tl-time{font-size:.75rem;color:var(--muted)}.tl-title{font-weight:600;margin:.1rem 0}

/* Findings */
.finding{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin:1rem 0;border-left-width:4px}
.finding.critical{border-left-color:#ef4444}.finding.high{border-left-color:#f97316}
.finding.medium{border-left-color:#f59e0b}.finding.low{border-left-color:#10b981}
.finding-header{display:flex;justify-content:space-between;align-items:start;gap:1rem;margin-bottom:.75rem}
.mitre-badge{font-family:monospace;background:#0c1a3a;color:#7dd3fc;padding:.2rem .6rem;border-radius:4px;font-size:.82rem}
.evidence{background:#0a0f1e;border:1px solid var(--border);border-radius:6px;padding:1rem;font-family:monospace;font-size:.8rem;color:#7dd3fc;overflow-x:auto;margin:.75rem 0;white-space:pre-wrap}
.remediation{background:#052e16;border-left:3px solid #22c55e;padding:.75rem 1rem;border-radius:0 6px 6px 0;color:#86efac;margin-top:.75rem}
.sla-tag{font-size:.78rem;color:var(--muted);margin-left:.5rem}

/* Attack path */
.attack-path{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin:1rem 0}
.path-step{padding:.4rem 0;font-family:monospace;font-size:.85rem;border-bottom:1px solid var(--border)}

/* Attack graph canvas container */
#graph-container{background:var(--card);border:1px solid var(--border);border-radius:8px;height:500px;display:flex;align-items:center;justify-content:center;color:var(--muted);margin:1rem 0}

footer{margin-top:3rem;color:var(--muted);font-size:.82rem;border-top:1px solid var(--border);padding-top:1rem;text-align:center}

/* ── ARES Watermark ── */
.ares-watermark{
  position:fixed;
  bottom:24px;
  right:24px;
  width:200px;
  opacity:0.08;
  pointer-events:none;
  z-index:0;
  filter:grayscale(40%) brightness(1.5);
}

/* ── Report Page Header (every page) ── */
.report-page-header{
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:.75rem 0 .75rem;
  border-bottom:2px solid var(--red);
  margin-bottom:1.5rem;
}
.rph-brand{
  display:flex;
  align-items:center;
  gap:.5rem;
}
.rph-logo{
  width:28px;
  height:28px;
  object-fit:contain;
}
.rph-name{
  font-weight:900;
  font-size:1.1rem;
  letter-spacing:.08em;
}
.rph-name span{color:var(--red);}
.rph-meta{
  text-align:right;
  font-size:.75rem;
  color:var(--muted);
  line-height:1.6;
}
.rph-campaign{
  font-weight:600;
  color:#e2e8f0;
  font-size:.85rem;
}

/* ── Report Page Footer (every page) ── */
.report-page-footer{
  margin-top:2.5rem;
  padding-top:.75rem;
  border-top:1px solid var(--border);
  display:flex;
  align-items:center;
  justify-content:space-between;
  font-size:.75rem;
  color:var(--muted);
}
.rpf-left{display:flex;align-items:center;gap:.35rem;}
.rpf-dot{width:4px;height:4px;border-radius:50%;background:var(--red);}
.rpf-meta{white-space:nowrap;}
.rpf-page::after{content:"Page";}
.rpf-logo{width:132px;height:auto;object-fit:contain;display:block;}
.rpf-wordmark{font-size:1.1rem;font-weight:900;letter-spacing:.08em;color:#cbd5e1;}
.rpf-wordmark span{color:var(--red);}
.confidential-badge{
  background:#450a0a;
  color:#f87171;
  border:1px solid #7f1d1d;
  padding:.15rem .5rem;
  border-radius:3px;
  font-size:.7rem;
  font-weight:700;
  letter-spacing:.06em;
  text-transform:uppercase;
}

/* PDF @page rules */
@media print {
  @page {
    margin: 20mm 18mm 20mm 18mm;
    size: A4;
  }
  body { padding-bottom: 24mm; }
  .report-page-footer {
    position: fixed;
    left: 18mm;
    right: 18mm;
    bottom: 8mm;
    margin-top: 0;
    padding-top: 4mm;
    background: rgba(10,15,30,.96);
    z-index: 5;
  }
  .rpf-page::after { content: "Page " counter(page); }
  .report-page-header { position: running(header); }
}
</style>
</head>
<body>

<div class="page">

<!-- Cover -->
<div class="cover">
  <h1>🔴 ARES Red Team Report</h1>
  <div class="meta">
    <div class="meta-item"><span>Campaign</span><strong>{{ campaign.name }}</strong></div>
    <div class="meta-item"><span>Client</span><strong>{{ campaign.client }}</strong></div>
    <div class="meta-item"><span>Operator</span><strong>{{ campaign.operator }}</strong></div>
    <div class="meta-item"><span>Noise Profile</span><strong>{{ campaign.noise_profile.upper() }}</strong></div>
    <div class="meta-item"><span>Scope</span><strong>{{ campaign.scope | map(attribute='cidr') | join(', ') or 'N/A' }}</strong></div>
    <div class="meta-item"><span>Generated</span><strong>{{ generated_at }}</strong></div>
  </div>
</div>

<!-- Risk score -->
<div class="risk-score">{{ "%.1f"|format(risk_score) }}</div>
<div class="risk-label">Overall Risk Score · {{ total_findings }} confirmed findings · {{ fp_filtered }} FP filtered</div>

<!-- Exec summary -->
<h2>Executive Summary</h2>
<div class="exec">{{ exec_summary }}</div>

<!-- Severity summary -->
<h2>Severity Breakdown</h2>
<div class="stat-row">
{% for sev, count in summary.items() %}
<div class="stat {{ sev }}">{{ sev.upper() }}<br><span style="font-size:1.5rem">{{ count }}</span></div>
{% endfor %}
</div>

<!-- MITRE ATT&CK Heatmap -->
<h2>MITRE ATT&CK Coverage</h2>
<div class="mitre-grid">
{% for tactic in mitre_tactics %}
  {% if tactic in mitre_map %}
  <div class="tactic-cell active">
    <div class="tactic-name">{{ tactic }}</div>
    {% for t in mitre_map[tactic][:4] %}
    <span class="technique-tag {{ t.severity }}">{{ t.technique }}</span>
    {% endfor %}
    {% if mitre_map[tactic]|length > 4 %}
    <span class="technique-tag">+{{ mitre_map[tactic]|length - 4 }}</span>
    {% endif %}
  </div>
  {% else %}
  <div class="tactic-cell">
    <div class="tactic-name">{{ tactic }}</div>
    <span style="font-size:.75rem;color:var(--muted)">—</span>
  </div>
  {% endif %}
{% endfor %}
</div>

<!-- Attack Timeline -->
<h2>Attack Timeline</h2>
<div class="timeline">
{% for f in timeline %}
<div class="tl-item">
  <div class="tl-dot {{ f.severity }}"></div>
  <div class="tl-time">{{ f.discovered_at.strftime('%Y-%m-%d %H:%M UTC') }}</div>
  <div class="tl-title">{{ f.title }}</div>
  <div style="font-size:.82rem;color:var(--muted)">
    {{ f.severity.upper() }} · {{ f.module_id }}
    {% if f.mitre_technique %} · <span class="mitre-badge">{{ f.mitre_technique }}</span>{% endif %}
  </div>
</div>
{% endfor %}
</div>

<!-- Attack Path -->
{% if attack_path %}
<h2>Attack Path</h2>
<div class="attack-path">
{% for step in attack_path %}
<div class="path-step">{{ step }}</div>
{% endfor %}
</div>
{% endif %}

<!-- Attack Graph — vanilla Canvas force-directed layout (no external deps) -->
<h2>Attack Graph</h2>
<div id="graph-container">
  <canvas id="gc" width="1060" height="490" style="width:100%;border-radius:8px;background:#0a0f1e"></canvas>
</div>
<script>
(function() {
  const graphData = {{ graph_json }};
  const canvas = document.getElementById('gc');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!graphData || !graphData.nodes || !graphData.nodes.length) {
    ctx.fillStyle = '#6b7280';
    ctx.font = '14px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText('No attack graph data available', canvas.width/2, canvas.height/2);
    return;
  }

  const W = canvas.width, H = canvas.height;
  const nodes = graphData.nodes.map((n, i) => ({
    ...n,
    x: W/2 + (Math.random()-0.5)*W*0.7,
    y: H/2 + (Math.random()-0.5)*H*0.7,
    vx: 0, vy: 0,
  }));
  const nodeIdx = Object.fromEntries(nodes.map((n,i) => [n.id, i]));
  const links = (graphData.links || []).map(l => ({
    ...l,
    source: typeof l.source === 'object' ? l.source.id : l.source,
    target: typeof l.target === 'object' ? l.target.id : l.target,
  }));

  // Colour map
  const nodeColor = n => {
    if (n.is_target) return '#ef4444';
    if (n.type === 'domain_controller') return '#f97316';
    if (n.type === 'credential')        return '#a78bfa';
    if (n.type === 'user')              return '#60a5fa';
    if (n.type === 'finding')           return '#fbbf24';
    return '#4ade80';
  };

  // Force simulation (repulsion + attraction + centering)
  const REPEL = 3500, ATTRACT = 0.06, DAMP = 0.82, CENTER = 0.015;
  let tick = 0;

  function step() {
    tick++;
    // Repulsion between all node pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i+1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x || 0.01;
        const dy = nodes[j].y - nodes[i].y || 0.01;
        const d2 = dx*dx + dy*dy + 1;
        const f  = REPEL / d2;
        nodes[i].vx -= f*dx/Math.sqrt(d2);
        nodes[i].vy -= f*dy/Math.sqrt(d2);
        nodes[j].vx += f*dx/Math.sqrt(d2);
        nodes[j].vy += f*dy/Math.sqrt(d2);
      }
    }
    // Spring attraction along edges
    links.forEach(l => {
      const si = nodeIdx[l.source], ti = nodeIdx[l.target];
      if (si == null || ti == null) return;
      const dx = nodes[ti].x - nodes[si].x;
      const dy = nodes[ti].y - nodes[si].y;
      nodes[si].vx += ATTRACT * dx;
      nodes[si].vy += ATTRACT * dy;
      nodes[ti].vx -= ATTRACT * dx;
      nodes[ti].vy -= ATTRACT * dy;
    });
    // Centering
    nodes.forEach(n => {
      n.vx += CENTER * (W/2 - n.x);
      n.vy += CENTER * (H/2 - n.y);
      n.vx *= DAMP; n.vy *= DAMP;
      n.x  = Math.max(20, Math.min(W-20, n.x + n.vx));
      n.y  = Math.max(20, Math.min(H-20, n.y + n.vy));
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Edges
    links.forEach(l => {
      const si = nodeIdx[l.source], ti = nodeIdx[l.target];
      if (si == null || ti == null) return;
      ctx.beginPath();
      ctx.moveTo(nodes[si].x, nodes[si].y);
      ctx.lineTo(nodes[ti].x, nodes[ti].y);
      ctx.strokeStyle = 'rgba(100,116,139,0.5)';
      ctx.lineWidth   = 1;
      ctx.stroke();
    });

    // Nodes
    nodes.forEach(n => {
      const r = n.is_target ? 12 : 8;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI*2);
      ctx.fillStyle   = nodeColor(n);
      ctx.fill();
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth   = 1.5;
      ctx.stroke();
      // Label
      ctx.fillStyle = '#e2e8f0';
      ctx.font      = '9px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText((n.label||n.id||'').slice(0, 16), n.x, n.y + r + 10);
    });
  }

  // Run 80 ticks to settle, then draw static result
  for (let i = 0; i < 80; i++) step();
  draw();

  // Legend
  const legend = [
    ['#ef4444','High-value target'], ['#f97316','Domain controller'],
    ['#a78bfa','Credential'],        ['#60a5fa','User'],
    ['#fbbf24','Finding'],           ['#4ade80','Host'],
  ];
  let lx = 10, ly = H - 14;
  legend.forEach(([color, label]) => {
    ctx.beginPath();
    ctx.arc(lx+5, ly-4, 5, 0, Math.PI*2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.fillStyle = '#6b7280';
    ctx.font      = '9px system-ui';
    ctx.textAlign = 'left';
    ctx.fillText(label, lx+13, ly);
    lx += ctx.measureText(label).width + 28;
  });
})();
</script>

<!-- CVSS Summary -->
<h2>CVSS v3.1 Risk Summary</h2>
<div class="cvss-section">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem">
    <div>
      <div style="font-size:1rem;font-weight:600">Overall Risk Rating</div>
      <div style="font-size:2rem;font-weight:800;color:{% if cvss_summary.risk_rating == 'CRITICAL' %}#ef4444{% elif cvss_summary.risk_rating == 'HIGH' %}#f97316{% elif cvss_summary.risk_rating == 'MEDIUM' %}#f59e0b{% else %}#22c55e{% endif %}">{{ cvss_summary.risk_rating }}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:.85rem;color:var(--muted)">Max CVSS Score</div>
      <div style="font-size:1.6rem;font-weight:700">{{ "%.1f"|format(cvss_summary.max_score) }}</div>
      <div style="font-size:.78rem;color:var(--muted)">Avg: {{ "%.1f"|format(cvss_summary.avg_score) }} · {{ cvss_summary.total }} findings</div>
    </div>
  </div>
  <div class="cvss-grid">
    <div class="cvss-stat" style="border-left:3px solid #ef4444">
      <div class="num" style="color:#ef4444">{{ cvss_summary.critical }}</div><div class="lbl">Critical (9.0–10.0)</div>
    </div>
    <div class="cvss-stat" style="border-left:3px solid #f97316">
      <div class="num" style="color:#f97316">{{ cvss_summary.high }}</div><div class="lbl">High (7.0–8.9)</div>
    </div>
    <div class="cvss-stat" style="border-left:3px solid #f59e0b">
      <div class="num" style="color:#f59e0b">{{ cvss_summary.medium }}</div><div class="lbl">Medium (4.0–6.9)</div>
    </div>
    <div class="cvss-stat" style="border-left:3px solid #22c55e">
      <div class="num" style="color:#22c55e">{{ cvss_summary.low }}</div><div class="lbl">Low (0.1–3.9)</div>
    </div>
  </div>
</div>

<!-- Findings -->
<h2>Detailed Findings</h2>
{% for f in findings %}
<div class="finding {{ f.severity }}">
  <div class="finding-header">
    <h3>{{ f.title }}</h3>
    <div>
      <span class="stat {{ f.severity }}">{{ f.severity.upper() }}</span>
      {% if f.cvss_score %}<span class="cvss-badge cvss-{{ f.severity }}" title="{{ f.cvss_vector }}">CVSS {{ "%.1f"|format(f.cvss_score) }}</span>{% endif %}
      <span class="sla-tag">SLA: {{ sla[f.severity] }}d</span>
    </div>
  </div>
  {% if f.mitre_technique %}
  <div style="margin-bottom:.6rem">
    <span class="mitre-badge">{{ f.mitre_technique }}</span>
    {% if f.mitre_tactic %}<span style="color:var(--muted);font-size:.85rem;margin-left:.5rem">{{ f.mitre_tactic }}</span>{% endif %}
    <span style="color:var(--muted);font-size:.8rem;margin-left:.75rem">confidence: {{ "%.0f"|format(f.confidence*100) }}%</span>
  </div>
  {% endif %}
  <p style="margin:.5rem 0;color:#cbd5e1">{{ f.description }}</p>
  {% if f.evidence %}
  <div class="evidence">{{ f.evidence|tojson }}</div>
  {% endif %}
  {% if f.remediation %}
  <div class="remediation"><strong>🛡 Remediation:</strong> {{ f.remediation }}</div>
  {% endif %}
  <div style="margin-top:.75rem;font-size:.78rem;color:var(--muted)">
    Module: {{ f.module_id }} · Host: {{ f.host or 'N/A' }} · {{ f.discovered_at.strftime('%Y-%m-%d %H:%M UTC') }}
  </div>
</div>
{% endfor %}

<!-- ARES Report Footer -->
<div class="report-page-footer">
  <div class="rpf-left">
    <div class="rpf-dot"></div>
    <span class="rpf-meta">Confidential | ARES v6 | <span class="rpf-page"></span></span>
    <div class="rpf-dot"></div>
    <span>For authorized use only</span>
  </div>
  {% if brand_logo_path %}
  <img src="{{ brand_logo_path }}" alt="ARES" class="rpf-logo" onerror="this.style.display='none'" />
  {% else %}
  <span class="rpf-wordmark"><span>A</span>RES</span>
  {% endif %}
</div>
</div>
</body>
</html>"""


# ── Report Generator ──────────────────────────────────────────────────────────


_PDF_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ARES Report - {{ campaign.name }}</title>
<style>
@page { size: A4; margin: 16mm 14mm 20mm; }
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #ffffff;
  color: #111827;
  font-family: Arial, "Segoe UI", sans-serif;
  font-size: 10.5px;
  line-height: 1.45;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}
main { padding-bottom: 18mm; }
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding-bottom: 10px;
  border-bottom: 3px solid #c1121f;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand img { width: 86px; height: auto; object-fit: contain; }
.brand-name { font-size: 22px; font-weight: 900; letter-spacing: .04em; }
.brand-name span { color: #c1121f; }
.meta { text-align: right; color: #475569; font-size: 9.5px; }
h1 { margin: 18px 0 4px; font-size: 26px; line-height: 1.1; }
h2 {
  margin: 18px 0 8px;
  padding-left: 8px;
  border-left: 4px solid #c1121f;
  font-size: 15px;
}
h3 { margin: 0 0 5px; font-size: 12px; }
.subtitle { color: #475569; font-size: 11px; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin: 14px 0;
}
.card {
  border: 1px solid #d7dee8;
  border-radius: 6px;
  padding: 9px;
  background: #f8fafc;
}
.label { display: block; color: #64748b; font-size: 8.5px; text-transform: uppercase; letter-spacing: .05em; }
.value { display: block; margin-top: 2px; font-size: 13px; font-weight: 800; }
.risk-card {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 12px;
  align-items: center;
  border: 1px solid #d7dee8;
  border-radius: 8px;
  padding: 12px;
  background: #fff7ed;
}
.risk-score { color: #c1121f; font-size: 38px; font-weight: 900; text-align: center; }
.exec {
  border-left: 4px solid #c1121f;
  background: #f8fafc;
  border-radius: 0 6px 6px 0;
  padding: 10px 12px;
}
.severity-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 7px; }
.severity {
  border-radius: 5px;
  padding: 5px 7px;
  text-align: center;
  font-weight: 800;
  border: 1px solid #d7dee8;
}
.critical { color: #991b1b; background: #fee2e2; }
.high { color: #9a3412; background: #ffedd5; }
.medium { color: #854d0e; background: #fef3c7; }
.low { color: #166534; background: #dcfce7; }
.info { color: #1e40af; background: #dbeafe; }
table { width: 100%; border-collapse: collapse; margin-top: 6px; }
th, td { border-bottom: 1px solid #e2e8f0; padding: 6px 5px; vertical-align: top; text-align: left; }
th { background: #f1f5f9; color: #334155; font-size: 9px; text-transform: uppercase; letter-spacing: .04em; }
.badge {
  display: inline-block;
  border-radius: 4px;
  padding: 2px 5px;
  background: #eef2ff;
  color: #3730a3;
  font-family: Consolas, monospace;
  font-size: 9px;
}
.finding {
  break-inside: avoid;
  margin-top: 10px;
  border: 1px solid #d7dee8;
  border-left: 4px solid #c1121f;
  border-radius: 7px;
  padding: 10px;
}
.finding-head { display: flex; justify-content: space-between; gap: 8px; align-items: flex-start; }
.evidence {
  margin-top: 6px;
  padding: 7px;
  border-radius: 5px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: Consolas, monospace;
  font-size: 8.5px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.remediation {
  margin-top: 6px;
  padding: 7px;
  border-left: 3px solid #16a34a;
  border-radius: 0 5px 5px 0;
  background: #f0fdf4;
}
.small { color: #64748b; font-size: 9px; }
.footer {
  position: fixed;
  right: 14mm;
  bottom: 7mm;
  display: flex;
  align-items: center;
  gap: 8px;
  color: #64748b;
  font-size: 8px;
}
.footer img { width: 82px; height: auto; object-fit: contain; }
</style>
</head>
<body>
<main>
  <header class="topbar">
    <div class="brand">
      {% if brand_logo_path %}<img src="{{ brand_logo_path }}" alt="ARES">{% endif %}
      <div class="brand-name"><span>A</span>RES</div>
    </div>
    <div class="meta">
      <strong>Authorized Security Report</strong><br>
      Generated {{ generated_at }}
    </div>
  </header>

  <h1>{{ campaign.name }}</h1>
  <div class="subtitle">{{ campaign.client }} - {{ campaign.operator }} - {{ campaign.noise_profile.value|upper }}</div>

  <section class="summary-grid">
    <div class="card"><span class="label">Campaign</span><span class="value">{{ campaign.name }}</span></div>
    <div class="card"><span class="label">Client</span><span class="value">{{ campaign.client }}</span></div>
    <div class="card"><span class="label">Findings</span><span class="value">{{ total_findings }}</span></div>
    <div class="card"><span class="label">Filtered FP</span><span class="value">{{ fp_filtered }}</span></div>
  </section>

  <section class="risk-card">
    <div class="risk-score">{{ "%.1f"|format(risk_score) }}</div>
    <div>
      <h3>Overall Risk Score</h3>
      <p class="small">Composite score based on confirmed findings, CVSS enrichment, severity, and campaign context.</p>
    </div>
  </section>

  <h2>Executive Summary</h2>
  <div class="exec">{{ exec_summary }}</div>

  <h2>Severity Breakdown</h2>
  <div class="severity-row">
    {% for sev, count in summary.items() %}
    <div class="severity {{ sev }}">{{ sev.upper() }}<br><span style="font-size:18px">{{ count }}</span></div>
    {% endfor %}
  </div>

  <h2>MITRE ATT&CK Coverage</h2>
  <table>
    <thead><tr><th>Tactic</th><th>Techniques Demonstrated</th></tr></thead>
    <tbody>
      {% for tactic, techs in mitre_map.items() %}
      <tr>
        <td><strong>{{ tactic }}</strong></td>
        <td>{% for t in techs %}<span class="badge">{{ t.technique }}</span> {% endfor %}</td>
      </tr>
      {% endfor %}
      {% if not mitre_map %}<tr><td colspan="2" class="small">No MITRE-mapped findings yet.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Attack Timeline</h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Finding</th><th>Module</th></tr></thead>
    <tbody>
      {% for f in timeline %}
      <tr>
        <td>{{ f.discovered_at.strftime('%Y-%m-%d %H:%M UTC') }}</td>
        <td><span class="severity {{ f.severity.value }}">{{ f.severity.value.upper() }}</span></td>
        <td>{{ f.title }}</td>
        <td>{{ f.module_id }}</td>
      </tr>
      {% endfor %}
      {% if not timeline %}<tr><td colspan="4" class="small">No confirmed findings yet.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Detailed Findings</h2>
  {% for f in findings %}
  <article class="finding">
    <div class="finding-head">
      <div>
        <h3>{{ f.title }}</h3>
        <div class="small">
          Module: {{ f.module_id }} - Host: {{ f.host or 'N/A' }}
          {% if f.mitre_technique %} - MITRE: <span class="badge">{{ f.mitre_technique }}</span>{% endif %}
        </div>
      </div>
      <span class="severity {{ f.severity.value }}">{{ f.severity.value.upper() }}</span>
    </div>
    <p>{{ f.description }}</p>
    {% if f.evidence %}<div class="evidence">{{ f.evidence|tojson }}</div>{% endif %}
    {% if f.remediation %}<div class="remediation"><strong>Remediation:</strong> {{ f.remediation }}</div>{% endif %}
    <div class="small">SLA: {{ sla[f.severity.value] }} days - Confidence: {{ "%.0f"|format(f.confidence*100) }}%</div>
  </article>
  {% endfor %}
  {% if not findings %}<p class="small">No detailed findings available for this report.</p>{% endif %}

  <div class="footer">
    <span>Confidential - Authorized use only</span>
    {% if brand_logo_path %}<img src="{{ brand_logo_path }}" alt="ARES">{% endif %}
  </div>
</main>
</body>
</html>"""


_PROFESSIONAL_REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ARES Report - {{ campaign.name }}</title>
<style>
@page { size: A4; margin: 16mm 14mm 22mm; }
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #ffffff;
  color: #111827;
  font-family: Arial, "Segoe UI", sans-serif;
  font-size: 10.5px;
  line-height: 1.5;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}
main { padding-bottom: 18mm; }
.topbar {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 10px;
  border-bottom: 3px solid #b91c1c;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand img { width: 86px; height: auto; object-fit: contain; }
.brand-title { font-size: 23px; font-weight: 900; letter-spacing: .03em; }
.brand-title span { color: #b91c1c; }
.meta { text-align: right; color: #475569; font-size: 9.5px; }
h1 { margin: 18px 0 3px; font-size: 27px; line-height: 1.1; }
h2 {
  margin: 18px 0 8px;
  padding-left: 8px;
  border-left: 4px solid #b91c1c;
  font-size: 15px;
}
h3 { margin: 0 0 5px; font-size: 12px; }
p { margin: 6px 0; }
.subtitle { color: #475569; font-size: 11px; }
.grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin: 14px 0;
}
.card {
  border: 1px solid #d7dee8;
  border-radius: 6px;
  padding: 9px;
  background: #f8fafc;
}
.label {
  display: block;
  color: #64748b;
  font-size: 8.5px;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.value { display: block; margin-top: 2px; font-size: 13px; font-weight: 800; }
.risk-band {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 12px;
  align-items: center;
  border: 1px solid #f1c7c7;
  border-radius: 8px;
  padding: 12px;
  background: #fff7f7;
}
.risk-score { color: #b91c1c; font-size: 38px; font-weight: 900; text-align: center; }
.risk-label { color: #7f1d1d; font-weight: 900; text-transform: uppercase; }
.exec {
  border-left: 4px solid #b91c1c;
  background: #f8fafc;
  border-radius: 0 6px 6px 0;
  padding: 10px 12px;
}
table { width: 100%; border-collapse: collapse; margin-top: 6px; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th, td {
  border-bottom: 1px solid #e2e8f0;
  padding: 6px 5px;
  vertical-align: top;
  text-align: left;
}
th {
  background: #f1f5f9;
  color: #334155;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: .04em;
}
.pill {
  display: inline-block;
  border-radius: 4px;
  padding: 2px 5px;
  background: #eef2ff;
  color: #3730a3;
  font-family: Consolas, monospace;
  font-size: 9px;
}
.sev {
  display: inline-block;
  min-width: 54px;
  border-radius: 4px;
  padding: 2px 5px;
  text-align: center;
  font-size: 8.5px;
  font-weight: 800;
  border: 1px solid #d7dee8;
}
.critical { color: #991b1b; background: #fee2e2; }
.high { color: #9a3412; background: #ffedd5; }
.medium { color: #854d0e; background: #fef3c7; }
.low { color: #166534; background: #dcfce7; }
.info { color: #1e40af; background: #dbeafe; }
.finding {
  break-inside: avoid;
  margin-top: 10px;
  border: 1px solid #d7dee8;
  border-left: 4px solid #b91c1c;
  border-radius: 7px;
  padding: 10px;
}
.finding-head {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  align-items: flex-start;
}
.evidence {
  margin-top: 6px;
  padding: 7px;
  border-radius: 5px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: Consolas, monospace;
  font-size: 8.5px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.evidence-table {
  margin-top: 6px;
  border: 1px solid #d7dee8;
  border-radius: 6px;
  overflow: hidden;
}
.evidence-table th {
  width: 30%;
  background: #f8fafc;
  color: #334155;
  font-family: Consolas, monospace;
  font-size: 8.5px;
}
.evidence-table td {
  font-family: Consolas, monospace;
  font-size: 8.5px;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.remediation {
  margin-top: 6px;
  padding: 7px;
  border-left: 3px solid #16a34a;
  border-radius: 0 5px 5px 0;
  background: #f0fdf4;
}
.small { color: #64748b; font-size: 9px; }
.steps { margin: 6px 0 0 16px; padding: 0; }
.steps li { margin-bottom: 3px; }
.footer {
  position: fixed;
  right: 14mm;
  bottom: 5mm;
  display: flex;
  align-items: center;
  gap: 8px;
  color: #64748b;
  font-size: 8px;
  background: rgba(255, 255, 255, 0.94);
  padding: 2px 0 0 6px;
}
.footer img { width: 54px; height: auto; object-fit: contain; }
</style>
</head>
<body>
<main>
  <header class="topbar">
    <div class="brand">
      {% if brand_logo_path %}<img src="{{ brand_logo_path }}" alt="ARES">{% endif %}
      <div class="brand-title"><span>A</span>RES</div>
    </div>
    <div class="meta">
      <strong>Authorized Red-Team Report</strong><br>
      Generated {{ generated_at }}<br>
      Confidential - Authorized use only
    </div>
  </header>

  <h1>{{ campaign.name }}</h1>
  <div class="subtitle">{{ campaign.client }} - {{ campaign.operator }} - {{ campaign.noise_profile.value|upper }}</div>

  <section class="grid">
    <div class="card"><span class="label">Campaign</span><span class="value">{{ campaign.name }}</span></div>
    <div class="card"><span class="label">Client</span><span class="value">{{ campaign.client }}</span></div>
    <div class="card"><span class="label">Confirmed</span><span class="value">{{ total_findings }}</span></div>
    <div class="card"><span class="label">Filtered FP</span><span class="value">{{ fp_filtered }}</span></div>
  </section>

  <section class="risk-band">
    <div class="risk-score">{{ "%.1f"|format(risk_score) }}</div>
    <div>
      <h3>Overall Risk Posture: <span class="risk-label">{{ risk_label }}</span></h3>
      <p class="small">Composite score derived from confirmed findings, CVSS enrichment, severity, and campaign context.</p>
    </div>
  </section>

  <h2>Executive Summary</h2>
  <div class="exec">{{ exec_summary }}</div>

  <h2>Engagement Overview</h2>
  <table>
    <tbody>
      <tr><th>Noise Profile</th><td>{{ campaign.noise_profile.value }}</td></tr>
      <tr><th>Targets Declared</th><td>{{ report_scope.target_count }}</td></tr>
      <tr><th>Scope Entries</th><td>{{ report_scope.scope_count }}</td></tr>
      <tr><th>Authorization</th><td>{{ report_scope.authorization_note }}</td></tr>
    </tbody>
  </table>

  <h2>Scope and Authorization</h2>
  <table>
    <thead><tr><th>Targets</th><th>Scope CIDRs</th></tr></thead>
    <tbody>
      <tr>
        <td>{% if report_scope.targets %}{{ report_scope.targets|join(', ') }}{% else %}No explicit targets declared{% endif %}</td>
        <td>{% if report_scope.scope_entries %}{{ report_scope.scope_entries|join(', ') }}{% else %}No CIDR scope entries declared{% endif %}</td>
      </tr>
    </tbody>
  </table>

  <h2>Methodology</h2>
  <ol class="steps">
    {% for step in methodology %}<li>{{ step }}</li>{% endfor %}
  </ol>

  <h2>Key Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Module</th><th>MITRE</th></tr></thead>
    <tbody>
      {% for f in key_findings %}
      <tr>
        <td><span class="sev {{ f.severity.value }}">{{ f.severity.value.upper() }}</span></td>
        <td>{{ f.title }}</td>
        <td>{{ f.module_id }}</td>
        <td>{% if f.mitre_technique %}<span class="pill">{{ f.mitre_technique }}</span>{% else %}N/A{% endif %}</td>
      </tr>
      {% endfor %}
      {% if not key_findings %}<tr><td colspan="4" class="small">No confirmed findings were recorded.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Severity Breakdown</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th><th>Remediation SLA</th></tr></thead>
    <tbody>
      {% for sev, count in summary.items() %}
      <tr><td><span class="sev {{ sev }}">{{ sev.upper() }}</span></td><td>{{ count }}</td><td>{{ sla[sev] }} days</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>MITRE ATT&CK Coverage</h2>
  <table>
    <thead><tr><th>Tactic</th><th>Techniques Demonstrated</th></tr></thead>
    <tbody>
      {% for tactic, techs in mitre_map.items() %}
      <tr>
        <td><strong>{{ tactic }}</strong></td>
        <td>{% for t in techs %}<span class="pill">{{ t.technique }}</span> {% endfor %}</td>
      </tr>
      {% endfor %}
      {% if not mitre_map %}<tr><td colspan="2" class="small">No MITRE-mapped findings yet.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Attack Narrative</h2>
  {% if attack_path %}
  <ol class="steps">{% for step in attack_path %}<li>{{ step }}</li>{% endfor %}</ol>
  {% else %}
  <p class="small">No graph-derived attack path was supplied for this report.</p>
  {% endif %}

  <h2>Attack Timeline</h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Finding</th><th>Module</th></tr></thead>
    <tbody>
      {% for f in timeline %}
      <tr>
        <td>{{ f.discovered_at.strftime('%Y-%m-%d %H:%M UTC') }}</td>
        <td><span class="sev {{ f.severity.value }}">{{ f.severity.value.upper() }}</span></td>
        <td>{{ f.title }}</td>
        <td>{{ f.module_id }}</td>
      </tr>
      {% endfor %}
      {% if not timeline %}<tr><td colspan="4" class="small">No confirmed findings yet.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Detailed Observations</h2>
  {% for f in findings %}
  <article class="finding">
    <div class="finding-head">
      <div>
        <h3>{{ f.title }}</h3>
        <div class="small">
          Module: {{ f.module_id }} - Host: {{ f.host or 'N/A' }}
          {% if f.mitre_technique %} - MITRE: <span class="pill">{{ f.mitre_technique }}</span>{% endif %}
        </div>
      </div>
      <span class="sev {{ f.severity.value }}">{{ f.severity.value.upper() }}</span>
    </div>
    <p>{{ f.description }}</p>
    {% if f.evidence %}
    <table class="evidence-table">
      <tbody>
        {% for row in f.evidence|evidence_rows %}
        <tr><th>{{ row.key }}</th><td>{{ row.value }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}
    {% if f.remediation %}<div class="remediation"><strong>Remediation:</strong> {{ f.remediation }}</div>{% endif %}
    <div class="small">SLA: {{ sla[f.severity.value] }} days - Confidence: {{ "%.0f"|format(f.confidence*100) }}%</div>
  </article>
  {% endfor %}
  {% if not findings %}<p class="small">No detailed findings are available for this report.</p>{% endif %}

  <h2>Remediation Roadmap</h2>
  <table>
    <thead><tr><th>Priority</th><th>Count</th><th>SLA</th><th>Examples</th></tr></thead>
    <tbody>
      {% for item in remediation_roadmap %}
      <tr>
        <td><span class="sev {{ item.severity }}">{{ item.severity.upper() }}</span></td>
        <td>{{ item.count }}</td>
        <td>{{ item.sla_days }} days</td>
        <td>{{ item.titles|join(', ') }}</td>
      </tr>
      {% endfor %}
      {% if not remediation_roadmap %}<tr><td colspan="4" class="small">No remediation items were generated.</td></tr>{% endif %}
    </tbody>
  </table>

  <h2>Appendix</h2>
  <table>
    <tbody>
      <tr><th>Report Engine</th><td>ARES reporting module</td></tr>
      <tr><th>Compliance Mapping</th><td>{% if compliance %}{{ compliance.keys()|list|join(', ') }}{% else %}No compliance mappings generated{% endif %}</td></tr>
      <tr><th>Usage Notice</th><td>This report is intended for authorized security testing, lab use, and defensive validation only.</td></tr>
    </tbody>
  </table>

  <div class="footer">
    <span>Confidential - Authorized use only</span>
    {% if brand_logo_path %}<img src="{{ brand_logo_path }}" alt="ARES">{% endif %}
  </div>
</main>
</body>
</html>"""

_HTML_TEMPLATE = _PROFESSIONAL_REPORT_TEMPLATE
_PDF_TEMPLATE = _PROFESSIONAL_REPORT_TEMPLATE


class ReportDependencyError(RuntimeError):
    """Raised when an optional report backend is unavailable."""


class ReportGenerator:
    FORMATS = ("json", "html", "markdown", "pdf")
    _FMT_ALIASES = {"md": "markdown"}

    def __init__(
        self,
        output_dir: str = "~/.ares/reports",
        *,
        include_sensitive_evidence: bool = False,
        strict_pdf_browser: bool | None = None,
    ) -> None:
        self.output_dir = Path(output_dir).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.include_sensitive_evidence = include_sensitive_evidence
        if strict_pdf_browser is None:
            strict_pdf_browser = os.environ.get("ARES_PDF_BROWSER_STRICT", "").lower() in {
                "1",
                "true",
                "yes",
            }
        self.strict_pdf_browser = strict_pdf_browser
        self._last_pdf_browser_error = ""

    def generate(
        self,
        campaign: Campaign,
        fmt: str = "html",
        graph_json: dict[str, Any] | None = None,
    ) -> Path:
        fmt = self._FMT_ALIASES.get(fmt, fmt)
        if fmt not in self.FORMATS:
            raise ValueError(f"Unknown format '{fmt}'. Choose: {self.FORMATS}")
        return getattr(self, f"_gen_{fmt}")(campaign, graph_json)

    def generate_all(
        self, campaign: Campaign, graph_json: dict[str, Any] | None = None
    ) -> dict[str, Path]:
        results: dict[str, Path] = {}
        for fmt in self.FORMATS:
            try:
                path = self.generate(campaign, fmt, graph_json)
                results[fmt] = path
                # Also expose under short alias
                if fmt == "markdown":
                    results["md"] = path
            except AssertionError:
                raise
            except Exception as e:
                logger.warning("report_format_failed", fmt=fmt, error=str(e))
        return results

    def generate_pdf_smoke(self) -> Path:
        """Render a tiny PDF through the same backends used by dashboard export."""
        smoke_path = self.output_dir / "ares_pdf_smoke.pdf"
        smoke_path.unlink(missing_ok=True)
        backend_error = ""
        try:
            from weasyprint import HTML as WP

            WP(string=_PDF_SMOKE_HTML, base_url=str(self.output_dir.resolve())).write_pdf(
                str(smoke_path)
            )
            if self._pdf_artifact_ready(smoke_path):
                return smoke_path
            backend_error = (
                f"WeasyPrint did not create a valid PDF artifact at {smoke_path}."
            )
        except (ImportError, OSError) as exc:
            backend_error = self._pdf_backend_failure_detail(exc)
            logger.warning("pdf_smoke_backend_unavailable", error=backend_error)

        if self._write_pdf_with_browser(_PDF_SMOKE_HTML, smoke_path):
            return smoke_path
        detail = self._last_pdf_browser_error or (
            "No local Chromium-compatible PDF browser was available."
        )
        raise ReportDependencyError(f"{backend_error} {detail}".strip())

    # ── JSON ──────────────────────────────────────────────────────────────

    def _gen_json(self, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
        ctx = build_report_context(campaign, graph_json)
        ctx["include_sensitive_evidence"] = self.include_sensitive_evidence
        findings = ctx["findings"]

        from ares.__version__ import __version__ as _ares_ver

        data: dict[str, Any] = {
            "meta": {
                "ares_version": _ares_ver,
                "schema_version": 1,
                "generated_at": ctx["generated_at"],
            },
            "campaign": {
                "id": campaign.id,
                "name": campaign.name,
                "client": campaign.client,
                "operator": campaign.operator,
                "noise_profile": campaign.noise_profile.value,
                "targets": campaign.targets,
                "scope": [s.model_dump() for s in campaign.scope],
                "created_at": campaign.created_at.isoformat(),
            },
            "summary": {
                "risk_score": ctx["risk_score"],
                "total_confirmed": ctx["total_findings"],
                "false_positives": ctx["fp_filtered"],
                "by_severity": ctx["summary"],
                "by_mitre_tactic": {k: len(v) for k, v in ctx["mitre_map"].items()},
                "by_module": self._by_module(findings),
                "remediation_sla": REMEDIATION_SLA,
            },
            "executive_summary": ctx["exec_summary"],
            "engagement_overview": ctx["report_scope"],
            "methodology": ctx["methodology"],
            "key_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "module_id": f.module_id,
                    "mitre_technique": f.mitre_technique,
                }
                for f in ctx["key_findings"]
            ],
            "remediation_roadmap": ctx["remediation_roadmap"],
            "mitre_coverage": ctx["mitre_map"],
            "attack_timeline": [
                {
                    "time": f.discovered_at.isoformat(),
                    "title": f.title,
                    "severity": f.severity.value,
                    "module": f.module_id,
                    "mitre": f.mitre_technique,
                }
                for f in ctx["timeline"]
            ],
            "attack_path": ctx["attack_path"],
            "attack_graph": graph_json or {},
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "confidence": round(f.confidence, 3),
                    "mitre_technique": f.mitre_technique,
                    "mitre_tactic": f.mitre_tactic,
                    "evidence": _redact_sensitive_evidence(
                        f.evidence,
                        include_sensitive_evidence=self.include_sensitive_evidence,
                    ),
                    "remediation": f.remediation,
                    "remediation_sla_days": REMEDIATION_SLA.get(f.severity.value, 365),
                    "module_id": f.module_id,
                    "host": f.host,
                    "discovered_at": f.discovered_at.isoformat(),
                }
                for f in findings
            ],
        }

        out = self._out(campaign, "json")
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("report_generated", fmt="json", path=str(out))
        return out

    # ── HTML ──────────────────────────────────────────────────────────────

    def _render_html(
        self,
        campaign: Campaign,
        graph_json: dict[str, Any] | None,
        template: str,
    ) -> str:
        env = Environment(loader=BaseLoader(), autoescape=True)
        env.filters["tojson"] = lambda v: json.dumps(v, indent=2, default=str)
        env.filters["evidence_rows"] = lambda v: _evidence_rows(
            v,
            include_sensitive_evidence=self.include_sensitive_evidence,
        )
        return env.from_string(template).render(
            **build_report_context(campaign, graph_json)
        )

    def _gen_html(self, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
        html = self._render_html(campaign, graph_json, _HTML_TEMPLATE)
        out = self._out(campaign, "html")
        out.write_text(html, encoding="utf-8")
        logger.info("report_generated", fmt="html", path=str(out))
        return out

    # ── Markdown ──────────────────────────────────────────────────────────

    def _gen_markdown(
        self, campaign: Campaign, graph_json: dict[str, Any] | None
    ) -> Path:
        ctx = build_report_context(campaign, graph_json)
        ctx["include_sensitive_evidence"] = self.include_sensitive_evidence
        lines = _render_markdown_report(campaign, ctx)
        out = self._out(campaign, "md")
        out.write_text("\n".join(lines), encoding="utf-8")
        logger.info("report_generated", fmt="markdown", path=str(out))
        return out

        lines: list[str] = [
            f"# ARES Report — {campaign.name}\n",
            f"> **Client:** {campaign.client} · **Operator:** {campaign.operator} · **Generated:** {ctx['generated_at']}",
            f"\n**Risk Score:** `{ctx['risk_score']:.1f}` · **Confirmed:** `{ctx['total_findings']}`\n",
            "---\n",
            "## Executive Summary\n",
            ctx["exec_summary"] + "\n",
            "---\n",
            "## Severity Summary\n",
            "| Severity | Count | SLA (days) |",
            "|----------|-------|------------|",
        ]
        for sev, count in ctx["summary"].items():
            lines.append(
                f"| {sev.upper()} | {count} | {REMEDIATION_SLA.get(sev, 365)} |"
            )

        lines += [
            "\n---\n",
            "## MITRE ATT&CK Coverage\n",
            "| Tactic | Techniques |",
            "|--------|------------|",
        ]
        for tactic, techs in ctx["mitre_map"].items():
            techs_str = ", ".join(f'`{t["technique"]}`' for t in techs)
            lines.append(f"| {tactic} | {techs_str} |")

        if ctx["attack_path"]:
            lines += ["\n---\n", "## Attack Path\n"]
            for step in ctx["attack_path"]:
                lines.append(step)

        lines += ["\n---\n", "## Attack Timeline\n"]
        for f in ctx["timeline"]:
            ts = f.discovered_at.strftime("%Y-%m-%d %H:%M")
            lines.append(
                f"- `{ts}` **[{f.severity.upper()}]** {f.title} `{f.mitre_technique or ''}`"
            )

        lines += ["\n---\n", "## Findings\n"]
        for f in ctx["findings"]:
            lines += [
                f"### [{f.severity.upper()}] {f.title}",
                f"**Module:** `{f.module_id}` · **Confidence:** `{f.confidence*100:.0f}%`"
                + (f" · **MITRE:** `{f.mitre_technique}`" if f.mitre_technique else ""),
                f"\n{f.description}\n",
                (
                    f"> 🛡 **Remediation (SLA: {REMEDIATION_SLA.get(f.severity.value, 365)}d):** {f.remediation}"
                    if f.remediation
                    else ""
                ),
                "\n---\n",
            ]

        out = self._out(campaign, "md")
        out.write_text("\n".join(lines), encoding="utf-8")
        logger.info("report_generated", fmt="markdown", path=str(out))
        return out

    # ── PDF ───────────────────────────────────────────────────────────────

    def _gen_pdf(self, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
        html = self._render_html(campaign, graph_json, _PDF_TEMPLATE)
        pdf_path = self._out(campaign, "pdf")
        try:
            from weasyprint import HTML as WP

            WP(string=html, base_url=str(self.output_dir.resolve())).write_pdf(
                str(pdf_path)
            )
        except (ImportError, OSError) as exc:
            backend_detail = self._pdf_backend_failure_detail(exc)
            logger.warning("pdf_backend_unavailable", error=backend_detail)
            if self._write_pdf_with_browser(html, pdf_path):
                logger.info("report_generated", fmt="pdf", path=str(pdf_path))
                return pdf_path
            detail = self._last_pdf_browser_error
            if detail:
                raise ReportDependencyError(f"{backend_detail} {detail}") from exc
            raise ReportDependencyError(
                "PDF generation requires the optional WeasyPrint backend or a "
                "local Chromium-compatible browser. Install the PDF extra/native "
                "runtime, set ARES_PDF_BROWSER, or generate HTML, JSON, or "
                "Markdown instead."
            ) from exc
        if not self._pdf_artifact_ready(pdf_path):
            raise ReportDependencyError(
                f"PDF backend did not create a downloadable artifact at {pdf_path}"
            )
        logger.info("report_generated", fmt="pdf", path=str(pdf_path))
        return pdf_path

    # ── Helpers ───────────────────────────────────────────────────────────

    def _write_pdf_with_browser(self, html: str, pdf_path: Path) -> bool:
        """Use a local Chromium-compatible browser when WeasyPrint is unavailable."""
        self._last_pdf_browser_error = ""
        errors: list[str] = []
        for browser in self._pdf_browser_candidates():
            strict_current = self._is_strict_configured_pdf_browser(browser)
            work_path: Path | None = None
            try:
                work_path, profile_dir, html_path = self._create_pdf_browser_workspace()
                html_path.write_text(html, encoding="utf-8")
            except OSError as exc:
                message = (
                    f"PDF browser profile directory was not writable for {browser}: "
                    f"{exc}. Output path was {pdf_path.resolve()}. Set "
                    "ARES_PDF_BROWSER to a working Chromium/Edge/Chrome executable "
                    "or install ARES with the PDF extra/native WeasyPrint dependencies."
                )
                errors.append(message)
                self._last_pdf_browser_error = "\n".join(errors)
                logger.warning(
                    "pdf_browser_profile_unusable",
                    browser=str(browser),
                    error=str(exc),
                )
                if work_path is not None:
                    shutil.rmtree(work_path, ignore_errors=True)
                if strict_current:
                    break
                continue

            skip_reason = self._pdf_browser_skip_reason(browser)
            if skip_reason:
                message = (
                    f"PDF browser fallback skipped {browser}: {skip_reason}. "
                    f"User data dir was {profile_dir}. Output path was "
                    f"{pdf_path.resolve()}. Set ARES_PDF_BROWSER to a working "
                    "Chromium/Edge/Chrome executable or install ARES with the "
                    "PDF extra/native WeasyPrint dependencies."
                )
                errors.append(message)
                self._last_pdf_browser_error = "\n".join(errors)
                logger.warning(
                    "pdf_browser_skipped",
                    browser=str(browser),
                    user_data_dir=str(profile_dir),
                    reason=skip_reason,
                )
                if work_path is not None:
                    shutil.rmtree(work_path, ignore_errors=True)
                if strict_current:
                    break
                continue

            cmd = [
                str(browser),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-crash-reporter",
                "--disable-features=TranslateUI",
                "--print-to-pdf-no-header",
                "--no-pdf-header-footer",
                f"--user-data-dir={str(profile_dir.resolve())}",
                f"--print-to-pdf={str(pdf_path.resolve())}",
                html_path.resolve().as_uri(),
            ]
            try:
                completed = self._run_pdf_browser(cmd)
                if completed.returncode == 0 and self._pdf_artifact_ready(pdf_path):
                    logger.info("pdf_browser_fallback_used", browser=str(browser))
                    return True
                message = (
                    f"PDF browser fallback exited with return code "
                    f"{completed.returncode} using {browser}, but no downloadable "
                    f"PDF was created at {pdf_path.resolve()}. User data dir was "
                    f"{profile_dir}. HTML input was {html_path}. Command was: "
                    f"{' '.join(cmd)}. Set ARES_PDF_BROWSER to a working "
                    "Chromium/Edge/Chrome executable or install ARES with the "
                    "PDF extra/native WeasyPrint dependencies."
                )
                errors.append(message)
                self._last_pdf_browser_error = "\n".join(errors)
                logger.warning(
                    "pdf_browser_failed",
                    browser=str(browser),
                    user_data_dir=str(profile_dir),
                    html_input=str(html_path),
                    output_path=str(pdf_path.resolve()),
                    returncode=completed.returncode,
                    stderr=completed.stderr[-500:],
                )
            except subprocess.TimeoutExpired as exc:
                message = (
                    f"PDF browser fallback timed out after "
                    f"{BROWSER_PDF_TIMEOUT_SECONDS}s using {browser}. "
                    f"User data dir was {profile_dir}. HTML input was {html_path}. "
                    f"Output path was {pdf_path.resolve()}. Set ARES_PDF_BROWSER "
                    "to a working Chromium/Edge/Chrome executable or install "
                    "ARES with the PDF extra/native WeasyPrint dependencies."
                )
                errors.append(message)
                self._last_pdf_browser_error = "\n".join(errors)
                logger.warning(
                    "pdf_browser_failed",
                    browser=str(browser),
                    error=str(exc),
                    timeout_s=BROWSER_PDF_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                message = (
                    f"PDF browser fallback failed using {browser}: {exc}. "
                    f"User data dir was {profile_dir}. HTML input was {html_path}. "
                    f"Output path was {pdf_path.resolve()}. Set ARES_PDF_BROWSER "
                    "to a working Chromium/Edge/Chrome executable or install "
                    "ARES with the PDF extra/native WeasyPrint dependencies."
                )
                errors.append(message)
                self._last_pdf_browser_error = "\n".join(errors)
                logger.warning(
                    "pdf_browser_failed", browser=str(browser), error=str(exc)
                )
            finally:
                if work_path is not None:
                    shutil.rmtree(work_path, ignore_errors=True)
            if strict_current:
                break
        if not self._last_pdf_browser_error:
            self._last_pdf_browser_error = (
                "PDF generation requires the optional WeasyPrint backend or a "
                "local Chromium-compatible browser. Install the PDF extra/native "
                "runtime, set ARES_PDF_BROWSER, or generate HTML, JSON, or "
                "Markdown instead."
            )
        return False

    def _run_pdf_browser(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            text=True,
            timeout=BROWSER_PDF_TIMEOUT_SECONDS,
        )

    def _is_strict_configured_pdf_browser(self, browser: Path) -> bool:
        if not self.strict_pdf_browser:
            return False
        configured = os.environ.get("ARES_PDF_BROWSER")
        if not configured:
            return False
        try:
            return browser.resolve() == Path(configured).expanduser().resolve()
        except OSError:
            return False

    def _pdf_browser_skip_reason(self, browser: Path) -> str:
        if (
            self._is_windows_host()
            and browser.name.lower() == "msedge.exe"
            and self._windows_session_is_elevated()
        ):
            return WINDOWS_EDGE_ELEVATED_PDF_MESSAGE
        return ""

    @staticmethod
    def _pdf_backend_failure_detail(exc: BaseException) -> str:
        message = str(exc) or repr(exc)
        lowered = message.lower()
        native_markers = ("libgobject", "pango", "gtk", "gdk", "cairo")
        if ReportGenerator._is_windows_host() and any(
            marker in lowered for marker in native_markers
        ):
            return f"{WINDOWS_WEASYPRINT_NATIVE_HINT} Original error: {message}"
        return (
            "WeasyPrint PDF backend is unavailable. Install the PDF extra/native "
            f"runtime or use browser fallback. Original error: {exc.__class__.__name__}: {message}"
        )

    @staticmethod
    def _is_windows_host() -> bool:
        return os.name == "nt"

    @staticmethod
    def _windows_session_is_elevated() -> bool:
        if not ReportGenerator._is_windows_host():
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _create_pdf_browser_workspace(self) -> tuple[Path, Path, Path]:
        """Create a browser workspace with a probed writable profile directory."""
        last_error: OSError | None = None
        for root in self._pdf_browser_workspace_roots():
            work_path: Path | None = None
            cleanup_work_path = False
            try:
                root.mkdir(parents=True, exist_ok=True)
                self._probe_writable_dir(root)
                work_path = Path(
                    tempfile.mkdtemp(prefix="ares-pdf-browser-", dir=str(root))
                )
                profile_dir = work_path / "profile"
                profile_dir.mkdir(parents=True, exist_ok=True)
                self._probe_writable_dir(profile_dir)
                return work_path, profile_dir, work_path / "report.html"
            except OSError as exc:
                last_error = exc
                cleanup_work_path = True
                logger.warning(
                    "pdf_browser_workspace_unusable",
                    root=str(root),
                    error=str(exc),
                )
                continue
            finally:
                if cleanup_work_path and work_path is not None:
                    shutil.rmtree(work_path, ignore_errors=True)
        raise OSError(
            f"No writable PDF browser profile directory was available: {last_error}"
        )

    def _pdf_browser_workspace_roots(self) -> list[Path]:
        primary = Path.home() / ".ares" / "runtime" / "pdf-browser"
        fallback = Path(tempfile.gettempdir()) / "ares" / "pdf-browser"
        roots = [primary]
        if fallback != primary:
            roots.append(fallback)
        return roots

    @staticmethod
    def _probe_writable_dir(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".ares-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)

    @staticmethod
    def _pdf_artifact_ready(pdf_path: Path) -> bool:
        deadline = time.monotonic() + PDF_ARTIFACT_WAIT_SECONDS
        while time.monotonic() <= deadline:
            try:
                if (
                    pdf_path.exists()
                    and pdf_path.stat().st_size > 0
                    and pdf_path.read_bytes()[:5] == b"%PDF-"
                ):
                    return True
            except OSError:
                pass
            time.sleep(0.15)
        return False

    @staticmethod
    def _pdf_browser_candidates() -> list[Path]:
        configured = os.environ.get("ARES_PDF_BROWSER")
        raw: list[Path] = []
        if configured:
            raw.append(Path(configured).expanduser())
        if ReportGenerator._is_windows_host():
            raw.extend(ReportGenerator._windows_browser_default_paths())
            for name in ("msedge", "chrome", "chromium"):
                found = shutil.which(name)
                if found:
                    raw.append(Path(found))
        else:
            for name in (
                "chrome",
                "chromium",
                "google-chrome",
                "chromium-browser",
                "msedge",
            ):
                found = shutil.which(name)
                if found:
                    raw.append(Path(found))

        candidates: list[Path] = []
        seen: set[str] = set()
        for path in raw:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            key = str(resolved).lower()
            if key not in seen and resolved.is_file():
                seen.add(key)
                candidates.append(resolved)
        return candidates

    @staticmethod
    def _windows_browser_default_paths() -> list[Path]:
        return [
            Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        ]

    def _out(self, campaign: Campaign, ext: str) -> Path:
        import re as _re

        slug = _re.sub(r"[^\w\-]", "_", campaign.name)[:64].strip("_") or "campaign"
        campaign_id = (
            _re.sub(r"[^\w\-]", "_", campaign.id)[:64].strip("_") or "campaign"
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        return self.output_dir / f"{campaign_id}_{slug}_{ts}.{ext}"

    @staticmethod
    def _by_module(findings: list[Any]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.module_id] = counts.get(f.module_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))
