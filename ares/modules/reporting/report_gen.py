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


class ReportGenerator:
    FORMATS = ("json", "html", "markdown", "pdf")
    _FMT_ALIASES = {"md": "markdown"}

    def __init__(self, output_dir: str = "~/.ares/reports") -> None:
        self.output_dir = Path(output_dir).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)

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
            except Exception as e:
                logger.warning("report_format_failed", fmt=fmt, error=str(e))
        return results

    # ── JSON ──────────────────────────────────────────────────────────────

    def _gen_json(self, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
        ctx = build_report_context(campaign, graph_json)
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
                    "evidence": f.evidence,
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

    def _gen_html(self, campaign: Campaign, graph_json: dict[str, Any] | None) -> Path:
        env = Environment(loader=BaseLoader(), autoescape=True)
        env.filters["tojson"] = lambda v: json.dumps(v, indent=2, default=str)
        html = env.from_string(_HTML_TEMPLATE).render(
            **build_report_context(campaign, graph_json)
        )
        out = self._out(campaign, "html")
        out.write_text(html, encoding="utf-8")
        logger.info("report_generated", fmt="html", path=str(out))
        return out

    # ── Markdown ──────────────────────────────────────────────────────────

    def _gen_markdown(
        self, campaign: Campaign, graph_json: dict[str, Any] | None
    ) -> Path:
        ctx = build_report_context(campaign, graph_json)
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
        html_path = self._gen_html(campaign, graph_json)
        pdf_path = html_path.with_suffix(".pdf")
        try:
            from weasyprint import HTML as WP

            WP(filename=str(html_path)).write_pdf(str(pdf_path))
        except ImportError:
            logger.warning("weasyprint_not_installed", fallback="returning html path")
            return html_path
        logger.info("report_generated", fmt="pdf", path=str(pdf_path))
        return pdf_path

    # ── Helpers ───────────────────────────────────────────────────────────

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
