"""
ARES Web Dashboard
Single-file FastAPI app serving an operator dashboard.

Routes:
  GET /             → dashboard HTML (single-page app)
  GET /api/status   → engine health
  GET /api/campaigns                → list campaigns
  GET /api/campaigns/{id}/findings  → findings (filterable)
  GET /api/campaigns/{id}/hosts     → discovered hosts
  GET /api/campaigns/{id}/summary   → risk score + stats
  GET /api/workers                  → distributed worker status
  WS  /ws/live                      → real-time finding stream
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ares.core.logger import get_logger
from ares.__version__ import __version__ as _ares_version

# ── Dashboard auth dependency ─────────────────────────────────────────────────
# Dashboard is a sub-application separate from the main FastAPI app.
# It validates the same JWT / API-key tokens as the main API.
_bearer_scheme = HTTPBearer(auto_error=False)


async def _require_dashboard_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """
    Validate JWT or API key. Raises 401 if missing/invalid.
    Accepts: Authorization: Bearer <token>  OR  X-API-Key: <key>
    Deliberately minimal — dashboard is read-only, any authenticated user is allowed.
    """
    from ares.core.config import get_settings
    from ares.core.security import decode_access_token
    from ares.db.database import AresDatabase

    settings = get_settings()

    # Check bearer JWT first
    if credentials and credentials.credentials:
        payload = decode_access_token(credentials.credentials, settings.secret_key_value,
                                       settings.ares_jwt_algorithm)
        if payload:
            # Honour token revocation list
            jti = payload.get("jti")
            if jti:
                try:
                    async with await AresDatabase.create(
                        settings.ares_database_url, settings.encryption_key_value
                    ) as _db:
                        if await _db.is_access_token_revoked(jti):
                            raise HTTPException(status_code=401, detail="Token revoked")
                except HTTPException:
                    raise
                except Exception:
                    pass  # DB unavailable — still accept if token signature valid
            return

    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        try:
            async with await AresDatabase.create(
                settings.ares_database_url, settings.encryption_key_value
            ) as _db:
                user = await _db.verify_api_key(api_key)
            if user:
                return
        except Exception:
            pass

    raise HTTPException(status_code=401, detail="Authentication required")

logger = get_logger("ares.dashboard")

dashboard_app = FastAPI(title="ARES Dashboard", docs_url=None, redoc_url=None)

# WebSocket connections for live streaming
live_connections: list[WebSocket] = []  # public — exported for testing
_live_connections = live_connections  # private alias for internal use


# ── Dashboard HTML ────────────────────────────────────────────────────────────

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARES Dashboard</title>
<style>
:root{--red:#e94560;--dark:#0a0f1e;--card:#111827;--border:#1f2937;--text:#e2e8f0;--muted:#6b7280;--green:#10b981;--yellow:#f59e0b;--blue:#3b82f6}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--dark);color:var(--text);min-height:100vh}
.header{background:var(--card);border-bottom:1px solid var(--border);padding:1rem 1.5rem;display:flex;align-items:center;gap:1rem}
.header h1{color:var(--red);font-size:1.4rem;font-weight:800}
.header .subtitle{color:var(--muted);font-size:.85rem}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.nav{background:var(--card);border-bottom:1px solid var(--border);display:flex;gap:0}
.nav-btn{padding:.75rem 1.25rem;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;font-size:.9rem;background:none;border-top:none;border-left:none;border-right:none;transition:.15s}
.nav-btn:hover{color:var(--text)}
.nav-btn.active{color:var(--red);border-bottom-color:var(--red)}
.layout{display:flex;height:calc(100vh - 97px)}
.sidebar{width:260px;background:var(--card);border-right:1px solid var(--border);overflow-y:auto;padding:1rem}
.sidebar h3{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem}
.campaign-item{padding:.6rem .75rem;border-radius:6px;cursor:pointer;margin-bottom:.25rem;font-size:.88rem;border:1px solid transparent;transition:.1s}
.campaign-item:hover{background:#1f2937}
.campaign-item.active{background:#1e3a5f;border-color:var(--blue)}
.campaign-item .cname{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.campaign-item .cmeta{color:var(--muted);font-size:.78rem;margin-top:.2rem}
.main{flex:1;overflow-y:auto;padding:1.5rem}
.stat-row{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;min-width:130px;flex:1}
.stat-card .val{font-size:2rem;font-weight:800;line-height:1}
.stat-card .label{color:var(--muted);font-size:.8rem;margin-top:.25rem}
.critical .val{color:#ef4444}
.high .val{color:#f97316}
.medium .val{color:#f59e0b}
.low .val{color:#10b981}
.score .val{color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{text-align:left;padding:.6rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
td{padding:.65rem .75rem;border-bottom:1px solid #0d1117}
tr:hover td{background:#111827}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600}
.badge.critical{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
.badge.high{background:#431407;color:#fb923c;border:1px solid #7c2d12}
.badge.medium{background:#422006;color:#fbbf24;border:1px solid #78350f}
.badge.low{background:#052e16;color:#4ade80;border:1px solid #14532d}
.badge.info{background:#0c1a3a;color:#60a5fa;border:1px solid #1e3a5f}
.conf{font-size:.78rem;color:var(--muted)}
.mitre{font-family:monospace;font-size:.78rem;color:#7dd3fc;background:#0c1a3a;padding:.1rem .4rem;border-radius:3px}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--red);display:inline-block;animation:pulse 1s infinite;margin-right:.35rem}
.panel-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}
.panel-header h2{font-size:1rem;font-weight:600}
.filter-bar{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
.filter-btn{padding:.3rem .75rem;border-radius:20px;border:1px solid var(--border);background:none;color:var(--muted);cursor:pointer;font-size:.8rem;transition:.1s}
.filter-btn:hover,.filter-btn.active{background:var(--red);color:#fff;border-color:var(--red)}
.host-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:.75rem}
.host-card .ip{font-family:monospace;font-weight:700;color:var(--blue)}
.host-card .dc-badge{background:#1e3a5f;color:#93c5fd;padding:.1rem .4rem;border-radius:3px;font-size:.75rem;margin-left:.5rem}
.empty{color:var(--muted);text-align:center;padding:3rem;font-size:.9rem}
.worker-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:.75rem;display:flex;justify-content:space-between;align-items:center}
.alive{color:var(--green)}
.dead{color:#ef4444}
#live-feed{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;height:300px;overflow-y:auto;font-family:monospace;font-size:.8rem}
.live-entry{padding:.25rem 0;border-bottom:1px solid #0d1117;animation:fadeIn .3s}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
select,input{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:.35rem .6rem;font-size:.85rem}
</style>
</head>
<body>

<div class="header">
  <span class="status-dot" id="status-dot"></span>
  <h1>🔴 ARES</h1>
  <span class="subtitle">Automated Red team Engagement System</span>
  <span style="margin-left:auto;color:var(--muted);font-size:.8rem" id="clock"></span>
</div>

<div class="nav">
  <button class="nav-btn active" onclick="switchTab('findings')">Findings</button>
  <button class="nav-btn" onclick="switchTab('hosts')">Hosts</button>
  <button class="nav-btn" onclick="switchTab('live')">Live Feed</button>
  <button class="nav-btn" onclick="switchTab('workers')">Workers</button>
</div>

<div class="layout">
  <!-- Sidebar: campaign list -->
  <div class="sidebar">
    <h3>Campaigns</h3>
    <div id="campaign-list"><div class="empty">Loading...</div></div>
  </div>

  <!-- Main content -->
  <div class="main">

    <!-- Stats row -->
    <div class="stat-row" id="stats-row">
      <div class="stat-card score"><div class="val" id="stat-risk">—</div><div class="label">Risk Score</div></div>
      <div class="stat-card critical"><div class="val" id="stat-critical">—</div><div class="label">Critical</div></div>
      <div class="stat-card high"><div class="val" id="stat-high">—</div><div class="label">High</div></div>
      <div class="stat-card medium"><div class="val" id="stat-medium">—</div><div class="label">Medium</div></div>
      <div class="stat-card low"><div class="val" id="stat-low">—</div><div class="label">Low</div></div>
      <div class="stat-card"><div class="val" id="stat-hosts" style="color:var(--blue)">—</div><div class="label">Hosts</div></div>
      <div class="stat-card"><div class="val" id="stat-creds" style="color:var(--yellow)">—</div><div class="label">Credentials</div></div>
    </div>

    <!-- Findings tab -->
    <div id="tab-findings">
      <div class="panel-header">
        <h2>Confirmed Findings</h2>
        <div class="filter-bar">
          <button class="filter-btn active" onclick="filterFindings('all',this)">All</button>
          <button class="filter-btn" onclick="filterFindings('critical',this)">Critical</button>
          <button class="filter-btn" onclick="filterFindings('high',this)">High</button>
          <button class="filter-btn" onclick="filterFindings('medium',this)">Medium</button>
          <button class="filter-btn" onclick="filterFindings('low',this)">Low</button>
        </div>
      </div>
      <table>
        <thead><tr>
          <th>Severity</th><th>Title</th><th>MITRE</th><th>Module</th><th>Confidence</th><th>Host</th>
        </tr></thead>
        <tbody id="findings-table"><tr><td colspan="6" class="empty">Select a campaign</td></tr></tbody>
      </table>
    </div>

    <!-- Hosts tab -->
    <div id="tab-hosts" style="display:none">
      <div class="panel-header"><h2>Discovered Hosts</h2></div>
      <div id="hosts-list"><div class="empty">Select a campaign</div></div>
    </div>

    <!-- Live feed tab -->
    <div id="tab-live" style="display:none">
      <div class="panel-header">
        <h2><span class="live-dot"></span>Live Finding Stream</h2>
        <button class="filter-btn" onclick="clearLiveFeed()">Clear</button>
      </div>
      <div id="live-feed"><div style="color:var(--muted)">Connecting to live feed...</div></div>
    </div>

    <!-- Workers tab -->
    <div id="tab-workers" style="display:none">
      <div class="panel-header"><h2>Distributed Workers</h2></div>
      <div id="workers-list"><div class="empty">Loading...</div></div>
    </div>

  </div>
</div>

<script>
const API = '';
let currentCampaign = null;
let allFindings = [];
let ws = null;

// ── Clock ─────────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
}, 1000);

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(tab) {
  ['findings','hosts','live','workers'].forEach(t => {
    document.getElementById('tab-' + t).style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('.nav-btn').forEach((btn, i) => {
    btn.classList.toggle('active', ['findings','hosts','live','workers'][i] === tab);
  });
  if (tab === 'live') connectLiveFeed();
  if (tab === 'workers') loadWorkers();
}

// ── Load campaigns ────────────────────────────────────────────────────────
async function loadCampaigns() {
  try {
    const r = await fetch(API + '/api/campaigns');
    const campaigns = await r.json();
    const list = document.getElementById('campaign-list');

    if (!campaigns.length) { list.innerHTML = '<div class="empty">No campaigns yet</div>'; return; }

    list.innerHTML = campaigns.map((c, i) => `
      <div class="campaign-item" data-campaign-index="${i}" data-campaign-id="${escHtml(c.id)}">
        <div class="cname">${escHtml(c.name)}</div>
        <div class="cmeta">${escHtml(c.client)} · ${escHtml(c.noise_profile)} · ${escHtml(c.status)}</div>
      </div>
    `).join('');
    list.querySelectorAll('.campaign-item').forEach(item => {
      const index = Number(item.dataset.campaignIndex);
      item.addEventListener('click', () => selectCampaign(campaigns[index].id, item));
    });

    if (campaigns.length > 0) selectCampaign(campaigns[0].id, list.querySelector('.campaign-item'));
  } catch(e) {
    document.getElementById('campaign-list').innerHTML = '<div class="empty" style="color:#ef4444">API offline</div>';
    document.getElementById('status-dot').style.background = '#ef4444';
  }
}

// ── Select campaign ───────────────────────────────────────────────────────
async function selectCampaign(id, el) {
  currentCampaign = id;
  document.querySelectorAll('.campaign-item').forEach(e => e.classList.remove('active'));
  if (el) el.classList.add('active');
  await Promise.all([loadSummary(id), loadFindings(id), loadHosts(id)]);
}

// ── Summary ───────────────────────────────────────────────────────────────
async function loadSummary(id) {
  try {
    const r = await fetch(API + `/api/campaigns/${id}/summary`);
    const d = await r.json();
    const f = d.findings || {};
    document.getElementById('stat-risk').textContent     = (d.risk_score || 0).toFixed(1);
    document.getElementById('stat-critical').textContent = f.critical || 0;
    document.getElementById('stat-high').textContent     = f.high || 0;
    document.getElementById('stat-medium').textContent   = f.medium || 0;
    document.getElementById('stat-low').textContent      = f.low || 0;
    document.getElementById('stat-hosts').textContent    = d.host_count || 0;
    document.getElementById('stat-creds').textContent    = d.credential_count || 0;
  } catch(e) {}
}

// ── Findings ──────────────────────────────────────────────────────────────
async function loadFindings(id) {
  try {
    const r = await fetch(API + `/api/campaigns/${id}/findings`);
    allFindings = await r.json();
    renderFindings(allFindings);
  } catch(e) {}
}

function renderFindings(findings) {
  const tbody = document.getElementById('findings-table');
  if (!findings.length) { tbody.innerHTML = '<tr><td colspan="6" class="empty">No confirmed findings</td></tr>'; return; }
  tbody.innerHTML = findings.map(f => `
    <tr>
      <td><span class="badge ${escCssToken(f.severity)}">${escHtml(String(f.severity || 'info').toUpperCase())}</span></td>
      <td>${escHtml(f.title)}</td>
      <td>${f.mitre_technique ? `<span class="mitre">${escHtml(f.mitre_technique)}</span>` : '<span style="color:var(--muted)">—</span>'}</td>
      <td style="font-family:monospace;font-size:.78rem">${escHtml(f.module_id || '')}</td>
      <td class="conf">${Math.round((f.confidence||1)*100)}%</td>
      <td style="font-family:monospace;font-size:.78rem">${escHtml(f.host||'—')}</td>
    </tr>
  `).join('');
}

function filterFindings(severity, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const filtered = severity === 'all' ? allFindings : allFindings.filter(f => f.severity === severity);
  renderFindings(filtered);
}

// ── Hosts ─────────────────────────────────────────────────────────────────
async function loadHosts(id) {
  try {
    const r = await fetch(API + `/api/campaigns/${id}/hosts`);
    const hosts = await r.json();
    const el = document.getElementById('hosts-list');
    if (!hosts.length) { el.innerHTML = '<div class="empty">No hosts discovered</div>'; return; }
    el.innerHTML = hosts.map(h => `
      <div class="host-card">
        <div>
          <span class="ip">${escHtml(h.ip_address)}</span>
          ${h.is_dc ? '<span class="dc-badge">DC</span>' : ''}
          ${h.hostname ? ` <span style="color:var(--muted);font-size:.85rem">(${escHtml(h.hostname)})</span>` : ''}
        </div>
        <div style="margin-top:.4rem;font-size:.82rem;color:var(--muted)">
          ${escHtml(h.os || 'Unknown OS')}${h.os_version ? ' ' + escHtml(h.os_version) : ''}
          ${h.domain ? ` · ${escHtml(h.domain)}` : ''}
        </div>
        ${h.open_ports_json && h.open_ports_json !== '[]' ?
          `<div style="margin-top:.3rem;font-size:.78rem;color:var(--muted)">Ports: ${JSON.parse(h.open_ports_json).map(escHtml).join(', ')}</div>` : ''}
      </div>
    `).join('');
  } catch(e) {}
}

// ── Live WebSocket feed ───────────────────────────────────────────────────
function connectLiveFeed() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  ws.onopen  = () => { appendLive('🟢 Connected to live feed'); };
  ws.onclose = () => { appendLive('🔴 Disconnected — reconnecting in 5s...'); setTimeout(connectLiveFeed, 5000); };
  ws.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      const sev = d.severity || 'info';
      appendLive(`[${d.timestamp?.slice(11,19)||'now'}] [${sev.toUpperCase()}] ${d.title||d.event||e.data}`, sev);
    } catch { appendLive(e.data); }
  };
}

function appendLive(msg, sev) {
  const feed = document.getElementById('live-feed');
  const colors = {critical:'#f87171',high:'#fb923c',medium:'#fbbf24',low:'#4ade80',info:'#60a5fa'};
  const div = document.createElement('div');
  div.className = 'live-entry';
  div.style.color = colors[sev] || 'var(--text)';
  div.textContent = msg;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function clearLiveFeed() {
  document.getElementById('live-feed').innerHTML = '';
}

// ── Workers ───────────────────────────────────────────────────────────────
async function loadWorkers() {
  try {
    const r = await fetch(API + '/api/workers');
    const data = await r.json();
    const el = document.getElementById('workers-list');
    if (!data.workers?.length) { el.innerHTML = '<div class="empty">No workers registered</div>'; return; }
    el.innerHTML = data.workers.map(w => `
      <div class="worker-card">
        <div>
          <div><span class="${w.alive ? 'alive' : 'dead'}">${w.alive ? '●' : '○'}</span>
               <strong style="margin-left:.4rem">${escHtml(w.hostname)}</strong>
               <span style="color:var(--muted);font-size:.8rem;margin-left:.5rem">${escHtml(String(w.id || '').slice(0,8))}</span></div>
          <div style="font-size:.8rem;color:var(--muted);margin-top:.2rem">
            Capabilities: ${(w.capabilities || []).map(escHtml).join(', ')||'all'} · Last heartbeat: ${escHtml(w.last_beat)}s ago
          </div>
        </div>
        <div style="text-align:right;font-size:.85rem">
          <div>Active: <strong>${escHtml(w.active_tasks)}</strong></div>
          <div style="color:var(--green)">Done: ${escHtml(w.completed)}</div>
          <div style="color:#ef4444">Failed: ${escHtml(w.failed)}</div>
        </div>
      </div>
    `).join('');
    document.querySelector('#tab-workers .panel-header h2').textContent =
      `Distributed Workers (${data.workers.filter(w=>w.alive).length} alive)`;
  } catch(e) {}
}

// ── Utils ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function escCssToken(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'info';
}

// ── Boot ──────────────────────────────────────────────────────────────────
loadCampaigns();
setInterval(() => { if (currentCampaign) { loadSummary(currentCampaign); loadFindings(currentCampaign); } }, 30000);
setInterval(loadCampaigns, 60000);
</script>
</body>
</html>"""


# ── API routes ────────────────────────────────────────────────────────────────

@dashboard_app.get("/", response_class=HTMLResponse)
async def dashboard_root() -> str:
    return _DASHBOARD_HTML


@dashboard_app.get("/api/status")
async def api_status(_auth: None = Depends(_require_dashboard_auth)) -> dict[str, Any]:
    return {"status": "online", "version": _ares_version}


def _get_db() -> "AresDatabase":
    """
    Return the shared AresDatabase from dashboard_app.state.
    Set at startup via: dashboard_app.state.db = <AresDatabase instance>
    Falls back to creating a fresh connection if state not set (standalone mode).
    """
    db = getattr(dashboard_app.state, "db", None)
    if db is not None:
        return db
    # Standalone fallback — create per-request (not ideal, but safe)
    from ares.core.config import get_settings
    from ares.db.database import AresDatabase as _DB
    s = get_settings()
    return _DB(s.db_path, s.encryption_key_value)


@dashboard_app.get("/api/campaigns")
async def api_campaigns(_auth: None = Depends(_require_dashboard_auth)) -> list[dict[str, Any]]:
    try:
        db = _get_db()
        if getattr(dashboard_app.state, "db", None) is not None:
            rows, _ = await db.list_campaigns()
            return rows
        async with db:
            rows, _ = await db.list_campaigns()
            return rows
    except Exception as e:
        logger.warning("dashboard_api_error", error=str(e)[:200])
        raise HTTPException(status_code=500, detail="Internal server error")


@dashboard_app.get("/api/campaigns/{campaign_id}/findings")
async def api_findings(campaign_id: str, severity: str | None = None,
                       _auth: None = Depends(_require_dashboard_auth)) -> list[dict[str, Any]]:
    try:
        db = _get_db()
        if getattr(dashboard_app.state, "db", None) is not None:
            rows, _ = await db.list_findings(campaign_id, severity=severity,
                                             validated=True, false_positive=False)
            return rows
        async with db:
            rows, _ = await db.list_findings(campaign_id, severity=severity,
                                             validated=True, false_positive=False)
            return rows
    except Exception as e:
        logger.warning("dashboard_api_error", error=str(e)[:200])
        raise HTTPException(status_code=500, detail="Internal server error")


@dashboard_app.get("/api/campaigns/{campaign_id}/hosts")
async def api_hosts(campaign_id: str,
                    _auth: None = Depends(_require_dashboard_auth)) -> list[dict[str, Any]]:
    try:
        db = _get_db()
        if getattr(dashboard_app.state, "db", None) is not None:
            return await db.get_hosts(campaign_id)
        async with db:
            return await db.get_hosts(campaign_id)
    except Exception as e:
        logger.warning("dashboard_api_error", error=str(e)[:200])
        raise HTTPException(status_code=500, detail="Internal server error")


@dashboard_app.get("/api/campaigns/{campaign_id}/summary")
async def api_summary(campaign_id: str,
                      _auth: None = Depends(_require_dashboard_auth)) -> dict[str, Any]:
    try:
        db = _get_db()
        use_shared = getattr(dashboard_app.state, "db", None) is not None

        async def _fetch(db: "AresDatabase") -> dict[str, Any]:
            summary  = await db.campaign_summary(campaign_id)
            findings, _ = await db.list_findings(campaign_id,
                                                  validated=True, false_positive=False)
            risk = sum(
                {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
                    f["severity"], 1) * f.get("confidence", 1.0)
                for f in findings
            )
            summary["risk_score"] = round(risk, 1)
            sev_counts: dict[str, int] = {k: 0 for k in
                                           ("critical", "high", "medium", "low", "info")}
            for f in findings:
                sev = f.get("severity", "info")
                if sev in sev_counts:
                    sev_counts[sev] += 1
            summary["findings"] = sev_counts
            return summary

        if use_shared:
            return await _fetch(db)
        async with db:
            return await _fetch(db)
    except Exception as e:
        logger.warning("dashboard_api_error", error=str(e)[:200])
        raise HTTPException(status_code=500, detail="Internal server error")


@dashboard_app.get("/api/workers")
async def api_workers(_auth: None = Depends(_require_dashboard_auth)) -> dict[str, Any]:
    # Returns empty if distributed controller not running
    return {"workers": [], "queue": {"pending": 0, "active": 0, "done": 0, "failed": 0}}


@dashboard_app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket) -> None:
    # Auth via query param token (WebSocket cannot send Authorization header before connect)
    from ares.core.config import get_settings
    from ares.core.security import decode_access_token
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    settings = get_settings()
    payload = decode_access_token(token, settings.secret_key_value, settings.ares_jwt_algorithm)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return
    await websocket.accept()
    _live_connections.append(websocket)
    logger.info("dashboard_ws_connect", total=len(_live_connections))
    try:
        while True:
            await websocket.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        pass
    except (RuntimeError, ConnectionError):
        pass
    finally:
        # Always clean up — regardless of which exception disconnected the client
        if websocket in _live_connections:
            _live_connections.remove(websocket)
        logger.info("dashboard_ws_disconnect", total=len(_live_connections))


async def broadcast_finding(finding_dict: dict[str, Any]) -> None:
    """Call this from the engine when a finding is confirmed — pushes to all dashboard clients."""
    import json
    dead: list[WebSocket] = []
    for ws in list(_live_connections):  # snapshot — prevent concurrent modification
        try:
            await ws.send_text(json.dumps(finding_dict, default=str))
        except (RuntimeError, ConnectionError):
            dead.append(ws)
    for ws in dead:
        _live_connections.remove(ws)
