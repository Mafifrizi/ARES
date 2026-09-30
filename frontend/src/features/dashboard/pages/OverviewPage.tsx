import {
  Crosshair,
  Layers,
  Plus,
  Radio,
  ShieldCheck,
  Target,
  Terminal,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { MonthlyFindingStats } from "../../../api/types";
import {
  useDashboardUi,
} from "../dashboardUiState";
import {
  CampaignTable,
  Page,
  SparklineBars,
  TelemetrySnapshot,
  formatMetric,
  formatRate,
  formatReportTime,
  metricNumber,
  metricNumberOrNull,
} from "../dashboardComponents";

export function OverviewPage() {
  const navigate = useNavigate();
  const { campaigns: campaignList, campaignsLoading, selectedCampaignId, setSelectedCampaignId } = useDashboardUi();
  const telemetry = useQuery({
    queryKey: ["telemetry", selectedCampaignId],
    queryFn: () => api.telemetry(selectedCampaignId || undefined)
  });
  const monthlyStats = useQuery({
    queryKey: ["monthlyStats", selectedCampaignId],
    queryFn: () => api.monthlyStats(selectedCampaignId || undefined)
  });
  const snapshot = telemetry.data as TelemetrySnapshot | undefined;
  const monthlyData = monthlyStats.data as MonthlyFindingStats | undefined;

  const selectedCampaign = selectedCampaignId
    ? campaignList.find((campaign) => campaign.id === selectedCampaignId)
    : undefined;

  const nonDeletedCampaigns = (selectedCampaign ? [selectedCampaign] : campaignList).filter(
    (campaign) => String(campaign.status ?? "").toLowerCase() !== "deleted"
  );
  const runningCampaigns = nonDeletedCampaigns.filter((campaign) =>
    ["running", "active", "executing"].includes(String(campaign.status ?? "").toLowerCase())
  );
  const trackedCount = nonDeletedCampaigns.length;
  const runningCount = runningCampaigns.length;

  const findings = typeof monthlyData?.confirmed_findings === "number"
    ? monthlyData.confirmed_findings
    : typeof snapshot?.findings === "number"
    ? snapshot.findings
    : 0;
  const monthlyTotal = typeof monthlyData?.total === "number" ? monthlyData.total : 0;
  const monthlySeries = normalizeMonthlySeries(monthlyData?.period, monthlyData?.series);

  // Dynamic header status subtitle (strictly distinguish running execution vs in-scope campaigns)
  let overviewSubtitle: string;
  if (selectedCampaign) {
    const scopeStr = selectedCampaign.scope_cidrs?.length ? selectedCampaign.scope_cidrs.join(", ") : "Single target";
    overviewSubtitle = `Active Scope: ${selectedCampaign.name} (${selectedCampaign.id.slice(0, 8)}) · CIDRs: ${scopeStr} · Telemetry Scoped`;
  } else if (trackedCount === 0) {
    overviewSubtitle = "Enclave standby · No campaigns in scope · Ready for campaign deployment";
  } else if (runningCount > 0) {
    overviewSubtitle = `${runningCount} active execution${runningCount === 1 ? "" : "s"} · ${trackedCount} in scope · Enclave telemetry streaming`;
  } else {
    overviewSubtitle = `${trackedCount} campaign${trackedCount === 1 ? "" : "s"} in scope · Telemetry pipeline standby · Fail-closed policy enforced`;
  }

  // Fresh install empty-state (Task 5 / CampaignSync test requirement)
  if (!campaignsLoading && trackedCount === 0) {
    return (
      <Page title="Overview" subtitle={overviewSubtitle}>
        <div className="dashboard-empty-hero">
          <div className="fresh-hero-icon-wrap">
            <Target size={32} className="text-cyan-400" />
          </div>
          <h2>No Campaigns Initialized</h2>
          <p>
            Initialize an authorized red-team engagement to define target boundaries,
            configure CIDR scopes, and execute automated validation modules.
          </p>
          <div className="fresh-hero-actions">
            <button
              className="btn btn-primary flex items-center gap-2 px-4 py-2 text-sm font-semibold"
              onClick={() => {
                navigate("/campaigns?tab=List");
              }}
              type="button"
            >
              <Plus size={16} />
              <span>Create First Campaign</span>
            </button>
            <button
              className="btn flex items-center gap-2 px-4 py-2 text-sm"
              onClick={() => navigate("/modules")}
              type="button"
            >
              <Layers size={15} />
              <span>Browse Module Catalog</span>
            </button>
          </div>
        </div>

        <div className="fresh-readiness-panel">
          <div className="telemetry-strip flex items-center justify-between text-xs text-zinc-400">
            <div className="flex items-center gap-5">
              <span><strong className="text-zinc-200">Runtime:</strong> Ready</span>
              <span><strong className="text-zinc-200">Worker Pool:</strong> {metricNumber(snapshot?.workers, "active")} active</span>
              <span><strong className="text-zinc-200">Task Queue:</strong> {metricNumber(snapshot?.queue, "depth")} queued</span>
            </div>
            <span className="text-zinc-500 font-mono text-[11px]">Awaiting first engagement initialization</span>
          </div>
        </div>
      </Page>
    );
  }

  // Tactical operational metrics extraction
  const totalRuns = metricNumber(snapshot?.modules, "total");
  const successRuns = metricNumber(snapshot?.modules, "success");
  const failedRuns = metricNumber(snapshot?.modules, "failed");
  const errorRate = metricNumber(snapshot?.modules, "error_rate");
  const p95 = metricNumberOrNull(snapshot?.latency_ms, "p95");
  const queueDepth = metricNumber(snapshot?.queue, "depth");
  const activeWorkers = metricNumber(snapshot?.workers, "active");
  const hostsDiscovered = metricNumber(snapshot?.hosts, "discovered");
  const hostsOwned = metricNumberOrNull(snapshot?.hosts, "owned");
  const isIngestionActive = Boolean(snapshot && snapshot.timestamp);

  const quickActions = (
    <div className="overview-quick-actions">
      <button
        type="button"
        className="btn btn-primary text-xs flex items-center gap-1.5"
        onClick={() => {
          navigate("/campaigns?tab=List");
        }}
        title="Initialize an authorized engagement"
      >
        <Plus size={14} />
        <span>New Campaign</span>
      </button>
      <button
        type="button"
        className="btn text-xs flex items-center gap-1.5"
        onClick={() => navigate("/modules")}
        title="Browse validation module catalog"
      >
        <Layers size={14} />
        <span>Module Catalog</span>
      </button>
      <button
        type="button"
        className="btn text-xs flex items-center gap-1.5"
        onClick={() => navigate("/live")}
        title="Open real-time event telemetry stream"
      >
        <Radio size={14} />
        <span>Live Stream</span>
      </button>
    </div>
  );

  return (
    <Page title="Overview" subtitle={overviewSubtitle} actions={quickActions}>
      <div className="overview-shell">
        {/* Tier 1: Executive Telemetry HUD */}
        <div className="hud-bento-grid">
          {/* Card 1: Active Engagements */}
          <div className="hud-bezel-card">
            <div className="hud-bezel-inner">
              <div className="hud-card-header">
                <span className="hud-card-title">Active Engagements</span>
              </div>
              <div className="hud-card-value">
                {trackedCount}
              </div>
              <div className="hud-card-footer">
                <span className="hud-context-text">
                  {runningCount > 0
                    ? `${runningCount} active execution${runningCount > 1 ? "s" : ""}`
                    : trackedCount > 0
                    ? "Staged readiness"
                    : "Standby"}
                </span>
              </div>
            </div>
          </div>

          {/* Card 2: Validated Findings */}
          <div className="hud-bezel-card">
            <div className="hud-bezel-inner">
              <div className="hud-card-header">
                <span className="hud-card-title">Validated Findings</span>
              </div>
              <div className="hud-card-value">
                {formatMetric(findings)}
              </div>
              <div className="hud-card-footer">
                <span className="hud-context-text">
                  {findings > 0 ? "Confirmed security vulnerabilities" : "No vulnerabilities detected"}
                </span>
              </div>
            </div>
          </div>

          {/* Card 3: Attack Surface */}
          <div className="hud-bezel-card">
            <div className="hud-bezel-inner">
              <div className="hud-card-header">
                <span className="hud-card-title">Attack Surface</span>
              </div>
              <div className="hud-card-value">
                {hostsDiscovered > 0 ? hostsDiscovered : "0"} <span className="text-xs font-normal text-zinc-400 font-sans">hosts</span>
              </div>
              <div className="hud-card-footer">
                <span className="hud-context-text">
                  {hostsOwned !== null && hostsOwned > 0
                    ? `${hostsOwned} compromise targets`
                    : "Perimeter mapped"}
                </span>
              </div>
            </div>
          </div>

          {/* Card 4: Engine Health */}
          <div className="hud-bezel-card">
            <div className="hud-bezel-inner">
              <div className="hud-card-header">
                <span className="hud-card-title">Engine Health</span>
              </div>
              <div className="hud-card-value">
                {p95 !== null ? `${formatMetric(p95)} ms` : isIngestionActive ? "Nominal" : "Standby"}
              </div>
              <div className="hud-card-footer">
                <span className="hud-context-text">
                  {activeWorkers} workers online · {queueDepth} queued
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tier 2: Operational Telemetry (Clean 50/50 Balanced Grid) */}
        <div className="workstation-split">
          {/* Panel 1: Execution & Queue Telemetry */}
          <div className="overview-content-card">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  Execution Telemetry
                </span>
                <span className="font-mono text-[11px] text-zinc-500">
                  {snapshot?.timestamp ? formatReportTime(snapshot.timestamp) : "Standby"}
                </span>
              </div>

              <div className="pulse-stat-grid mt-3">
                <div className="pulse-stat-cell">
                  <div className="pulse-stat-label">Task Queue</div>
                  <div className="pulse-stat-value">
                    {queueDepth} <span className="text-xs font-normal text-zinc-400 font-sans">queued</span>
                  </div>
                </div>
                <div className="pulse-stat-cell">
                  <div className="pulse-stat-label">Module Runs</div>
                  <div className="pulse-stat-value">
                    {totalRuns} <span className="text-xs font-normal text-zinc-400 font-sans">({successRuns} ok)</span>
                  </div>
                </div>
                <div className="pulse-stat-cell">
                  <div className="pulse-stat-label">Failure Rate</div>
                  <div className={`pulse-stat-value ${failedRuns > 0 ? "text-rose-400" : "text-zinc-200"}`}>
                    {formatRate(errorRate)}
                  </div>
                </div>
                <div className="pulse-stat-cell">
                  <div className="pulse-stat-label">Worker Pool</div>
                  <div className="pulse-stat-value text-emerald-400">
                    {activeWorkers} <span className="text-xs font-normal text-zinc-400 font-sans">active</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 pt-2 border-t border-zinc-800/60">
              <button
                type="button"
                className="btn btn-compact text-xs flex items-center gap-1.5"
                onClick={() => navigate("/modules")}
                title="Browse validation module catalog"
              >
                <Terminal size={13} />
                <span>Run Modules</span>
              </button>
              <button
                type="button"
                className="btn btn-compact text-xs flex items-center gap-1.5"
                onClick={() => navigate("/graph")}
                title="Open attack relationship graph"
              >
                <Crosshair size={13} />
                <span>Attack Graph</span>
              </button>
              <button
                type="button"
                className="btn btn-compact text-xs flex items-center gap-1.5 ml-auto"
                onClick={() => navigate("/reports")}
                title="View compliance and engagement reports"
              >
                <ShieldCheck size={13} />
                <span>Reports</span>
              </button>
            </div>
          </div>

          {/* Panel 2: Activity Pulse & Signals */}
          <div className="overview-content-card">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  Activity Pulse
                </span>
                <span className="font-mono text-[11px] text-zinc-300">
                  {monthlyTotal} signals total
                </span>
              </div>
              <div className="mt-3">
                {monthlySeries.some((value) => value.count > 0) ? (
                  <SparklineBars values={monthlySeries} />
                ) : (
                  <div className="h-24 flex items-center justify-center text-xs text-zinc-400 bg-zinc-950/40 rounded border border-dashed border-zinc-800">
                    Awaiting operational signal telemetry
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-zinc-400 pt-2 border-t border-zinc-800/60 font-mono text-[11px]">
              <span>Telemetry: {isIngestionActive ? "Ingestion Active" : "Standby"}</span>
              <span>{hostsDiscovered} hosts mapped</span>
            </div>
          </div>
        </div>

        {/* Tier 3: Campaign Inventory Matrix */}
        <CampaignTable
          campaigns={selectedCampaign ? [selectedCampaign] : campaignList}
          scopedCampaignId={selectedCampaignId}
          onClearScope={() => setSelectedCampaignId("")}
          onSelectCampaign={(id) => setSelectedCampaignId(id)}
        />
      </div>
    </Page>
  );
}

function normalizeMonthlySeries(
  period: string | undefined,
  series: MonthlyFindingStats["series"] | undefined
): MonthlyFindingStats["series"] {
  if (!period || !/^\d{4}-\d{2}$/.test(period)) return [];
  const [yearText, monthText] = period.split("-");
  const year = Number(yearText);
  const month = Number(monthText);
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) return [];

  const counts = new Map<string, number>();
  for (const item of series ?? []) {
    const count = Number(item.count);
    if (item.date && Number.isFinite(count)) counts.set(item.date, Math.max(0, count));
  }

  const daysInMonth = new Date(year, month, 0).getDate();
  return Array.from({ length: daysInMonth }, (_, index) => {
    const date = `${period}-${String(index + 1).padStart(2, "0")}`;
    return { date, count: counts.get(date) ?? 0 };
  });
}



export default OverviewPage;
