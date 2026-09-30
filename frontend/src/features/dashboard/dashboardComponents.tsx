import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Eye,
  EyeOff,
  FileText,
  Info,
  Key,
  Loader2,
  MinusCircle,
  Radio,
  ShieldCheck,
  Target,
  Terminal,
  X,
} from "lucide-react";
import {
  ChangeEvent,
  FormEvent,
  KeyboardEvent,
  ReactNode,
  useCallback,
  useState,
} from "react";
import {
  ApiError,
} from "../../api/client";
import type {
  Campaign,
  Finding,
  ModuleMeta,
  MonthlyFindingStats,
  ParamField,
} from "../../api/types";
import { StructuredJsonViewer } from "../../components/common/StructuredJsonViewer";

export interface PersistedResult {
  key: string;
  payload: unknown;
  isError?: boolean;
}

export interface ModuleRunRecord {
  campaignId: string;
  moduleId: string;
  payload: unknown;
  isError?: boolean;
}

export interface GeneratedApiKey {
  id?: string;
  key: string;
  note?: string;
  prefix?: string;
}

export type ApiKeyCopyStatus = "idle" | "copied" | "manual";

export const REQUIRED_FIELD_MESSAGE = "This field is required.";

export type ValidatableElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
export type TelemetryMetricMap = Record<string, boolean | number | string | null | undefined>;
export interface TelemetrySnapshot {
  modules?: TelemetryMetricMap;
  queue?: TelemetryMetricMap;
  workers?: TelemetryMetricMap;
  latency_ms?: TelemetryMetricMap;
  throughput?: TelemetryMetricMap;
  findings?: number;
  credentials?: number;
  hosts?: TelemetryMetricMap;
  campaign_id?: string;
  timestamp?: number;
  [key: string]: unknown;
}

export interface TemplatePlanStage {
  name?: string;
  modules?: string[];
  params?: Record<string, unknown>;
}

export interface TemplatePlanResponse {
  template?: string;
  description?: string;
  plan?: {
    stages?: TemplatePlanStage[];
  };
  global_params?: Record<string, unknown>;
  note?: string;
}

export const pageMeta: Record<string, { eyebrow: string; description: string }> = {
  Overview: {
    eyebrow: "Dashboard",
    description: "Health, telemetry, campaigns, and activity."
  },
  Campaigns: {
    eyebrow: "Operations",
    description: "Scopes, status, findings, and comparisons."
  },
  Modules: {
    eyebrow: "Operations",
    description: "Catalog, OPSEC, and authorized runs."
  },
  Reports: {
    eyebrow: "Operations",
    description: "Evidence packages and artifacts."
  },
  Graph: {
    eyebrow: "Intelligence",
    description: "Entities, relationships, and attack paths."
  },
  Templates: {
    eyebrow: "Intelligence",
    description: "Reusable campaign plans."
  },
  Strategy: {
    eyebrow: "Intelligence",
    description: "Authorized objective planning."
  },
  Security: {
    eyebrow: "Control",
    description: "Account, API keys, audit, and users."
  },
  "EDR/OPSEC": {
    eyebrow: "Control",
    description: "Detection outcomes and OPSEC feedback."
  },
  "Live Events": {
    eyebrow: "Control",
    description: "Campaign events as they arrive."
  }
};

export function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function setRequiredMessage<T extends ValidatableElement>(event: FormEvent<T>) {
  event.currentTarget.setCustomValidity(REQUIRED_FIELD_MESSAGE);
}

export function clearValidationMessage<T extends ValidatableElement>(event: ChangeEvent<T>) {
  event.currentTarget.setCustomValidity("");
}

export function Page({
  title,
  subtitle,
  actions,
  tabs,
  activeTab,
  onTabChange,
  children
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  tabs?: string[];
  activeTab?: string;
  onTabChange?: (tab: string) => void;
  children: ReactNode;
}) {
  const [fallbackTab, setFallbackTab] = useState(tabs?.[0] ?? "");
  const meta = pageMeta[title] ?? {
    eyebrow: "ARES",
    description: "Security dashboard workspace."
  };
  const selectedTab = activeTab ?? fallbackTab;
  const setTab = useCallback((tab: string) => {
    if (onTabChange) {
      onTabChange(tab);
    } else {
      setFallbackTab(tab);
    }
  }, [onTabChange]);

  function handleTabKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (!tabs || tabs.length === 0 || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      return;
    }
    event.preventDefault();
    const currentIndex = Math.max(0, tabs.indexOf(selectedTab));
    if (event.key === "Home") {
      setTab(tabs[0]);
      return;
    }
    if (event.key === "End") {
      setTab(tabs[tabs.length - 1]);
      return;
    }
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const nextIndex = (currentIndex + offset + tabs.length) % tabs.length;
    setTab(tabs[nextIndex]);
  }

  return (
    <div className="page">
      <section className="page-header">
        <div className="page-heading">
          <div>
            <p className="page-eyebrow">{meta.eyebrow}</p>
            <h1>{title}</h1>
            <p className="page-subtitle">{subtitle ?? meta.description}</p>
          </div>
        </div>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </section>
      {tabs ? (
        <div className="page-tabs" aria-label={`${title} sections`} onKeyDown={handleTabKeyDown} role="tablist">
          {tabs.map((tab) => (
            <button
              aria-selected={tab === selectedTab}
              className={tab === selectedTab ? "active" : ""}
              key={tab}
              onClick={() => setTab(tab)}
              role="tab"
              tabIndex={tab === selectedTab ? 0 : -1}
              type="button"
            >
              {tab}
            </button>
          ))}
        </div>
      ) : null}
      <div className="page-content">{children}</div>
    </div>
  );
}

export function SectionHeader({
  title,
  eyebrow,
  description,
  action
}: {
  title: string;
  eyebrow?: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="section-header">
      <div>
        {eyebrow ? <p className="section-eyebrow">{eyebrow}</p> : null}
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="section-action">{action}</div> : null}
    </div>
  );
}

export function MiniStat({ title, value, detail, icon }: { title: string; value: string; detail?: string; icon?: ReactNode }) {
  return (
    <div className="mini-stat">
      <div>
        <span>{title}</span>
        <strong>{value}</strong>
        {detail ? <small>{detail}</small> : null}
      </div>
      {icon ? <div className="mini-stat-icon">{icon}</div> : null}
    </div>
  );
}

export function HighlightRow({
  label,
  value,
  detail,
  tone = "neutral"
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "low" | "medium" | "high" | "neutral";
}) {
  return (
    <div className="highlight-row">
      <div>
        <strong>{label}</strong>
        <span>{detail}</span>
      </div>
      <span className={`highlight-value highlight-${tone}`}>{value}</span>
    </div>
  );
}

export function SparklineBars({ values }: { values: MonthlyFindingStats["series"] }) {
  const max = Math.max(...values.map((value) => value.count), 1);
  const labelDays = new Set([1, 7, 14, 21, 28, values.length]);
  return (
    <>
      <div className="sparkline" aria-hidden="true">
        {values.map((value) => (
          <span
            key={value.date}
            title={`${formatMonthlyDate(value.date)} - ${value.count} ${value.count === 1 ? "security signal" : "security signals"}`}
            style={{ height: value.count > 0 ? `${Math.max(6, (value.count / max) * 100)}%` : "0%" }}
          />
        ))}
      </div>
      <div className="sparkline-axis" aria-hidden="true">
        {values.map((value) => {
          const day = Number(value.date.slice(-2));
          return <span key={value.date}>{labelDays.has(day) ? formatMonthlyDate(value.date) : null}</span>;
        })}
      </div>
    </>
  );
}

export function formatMonthlyDate(date: string): string {
  const [year, month, day] = date.split("-").map(Number);
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" }).format(
    new Date(Date.UTC(year, month - 1, day))
  );
}

export function metricNumber(map: TelemetryMetricMap | undefined, key: string): number {
  return metricNumberOrNull(map, key) ?? 0;
}

export function metricNumberOrNull(map: TelemetryMetricMap | undefined, key: string): number | null {
  const value = map?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

export function formatMetric(value: number, suffix = ""): string {
  if (!Number.isFinite(value)) return `0${suffix}`;
  if (Number.isInteger(value)) return `${value}${suffix}`;
  return `${value.toFixed(1)}${suffix}`;
}

export function formatRate(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "not enough data";
  }
  const normalized = value <= 1 ? value * 100 : value;
  return `${Math.round(normalized)}%`;
}

export function formatTimestamp(value: number | undefined): string {
  if (!value) return "No runtime sample yet";
  const ms = value > 1e11 ? value : value * 1000;
  return new Date(ms).toLocaleString();
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
}

export function formatReportDate(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  const timestamp = value > 10_000_000_000 ? value : value * 1000;
  return new Date(timestamp).toLocaleString();
}

export function formatReportTime(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  const timestamp = value > 10_000_000_000 ? value : value * 1000;
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function TelemetryPanel({ snapshot, loading, confirmedFindings }: { snapshot?: TelemetrySnapshot; loading: boolean; confirmedFindings: number }) {
  const total = metricNumber(snapshot?.modules, "total");
  const success = metricNumber(snapshot?.modules, "success");
  const failed = metricNumber(snapshot?.modules, "failed");
  const findings = confirmedFindings;
  const successRate = total > 0 ? Math.round((success / total) * 100) : null;
  const errorRate = total > 0 ? Math.min(100, Math.round(metricNumber(snapshot?.modules, "error_rate") * 100)) : null;
  const p95 = metricNumberOrNull(snapshot?.latency_ms, "p95");
  const queueDepth = metricNumber(snapshot?.queue, "depth");
  const activeWorkers = metricNumber(snapshot?.workers, "active");
  const unhealthyWorkers = metricNumber(snapshot?.workers, "unhealthy");
  const hostsDiscovered = metricNumber(snapshot?.hosts, "discovered");
  const hostsOwned = metricNumberOrNull(snapshot?.hosts, "owned");
  const tasksPerMin = metricNumberOrNull(snapshot?.throughput, "tasks_per_min");
  const workerTotal = activeWorkers + unhealthyWorkers;
  const workerCapacity = workerTotal > 0 ? Math.round((activeWorkers / workerTotal) * 100) : null;
  const hostsAvailable = snapshot?.hosts?.available === true;
  const hostOwnership = hostsAvailable && hostsDiscovered > 0 && hostsOwned !== null
    ? Math.round((hostsOwned / hostsDiscovered) * 100)
    : null;
  const throughputValue = tasksPerMin === null ? "n/a" : `${formatMetric(tasksPerMin)}/min`;
  const latencyDetail = p95 === null ? "no run timing data" : `${formatMetric(p95, " ms")} p95`;

  const isIngestionActive = Boolean(snapshot && snapshot.timestamp);
  const ingestionDotClass = loading ? "pending" : isIngestionActive ? "active" : "pending";
  const ingestionText = loading ? "Connecting..." : isIngestionActive ? "Ingestion Active" : "Awaiting Data";

  return (
    <section className="panel telemetry-panel">
      <SectionHeader
        title="Telemetry Report"
        description={loading ? "Waiting for metrics." : `Last sample: ${formatTimestamp(snapshot?.timestamp)}`}
        action={
          <div className="telemetry-live-status" title="Real-time telemetry ingestion pipeline">
            <span className={`status-indicator-dot ${ingestionDotClass}`} />
            <span className="status-indicator-text">{ingestionText}</span>
            {snapshot?.timestamp ? (
              <span className="status-indicator-time font-mono">{formatReportTime(snapshot.timestamp)}</span>
            ) : null}
          </div>
        }
      />

      <div className="telemetry-chart" aria-label="Runtime telemetry chart">
        <TelemetryBar label="Success rate" value={successRate} />
        <TelemetryBar label="Error rate" value={errorRate} tone="danger" />
        <TelemetryBar label="Worker capacity" value={workerCapacity} />
        <TelemetryBar label="Host ownership" value={hostOwnership} tone={hostsOwned !== null && hostsOwned > 0 ? "danger" : "ok"} />
      </div>

      <div className="mini-stat-grid mt-4">
        <MiniStat title="Module runs" value={formatMetric(total)} detail={`${success} success / ${failed} failed`} />
        <MiniStat title="Findings" value={formatMetric(findings)} />
        <MiniStat title="Queue" value={formatMetric(queueDepth)} detail={`${activeWorkers} active workers`} />
        <MiniStat title="Throughput" value={throughputValue} detail={latencyDetail} />
      </div>

      <div className="telemetry-footer">
        <span>Scope: {snapshot?.campaign_id ? `campaign ${snapshot.campaign_id}` : "global"}</span>
        <span>{hostsAvailable ? `${hostsDiscovered} discovered / ${hostsOwned ?? 0} owned hosts` : "Host ownership unavailable"}</span>
        <span>{workerTotal === 0 ? "no worker sample" : unhealthyWorkers === 0 ? "workers healthy" : `${unhealthyWorkers} unhealthy workers`}</span>
      </div>

      <details className="advanced-details">
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer mb-2">Telemetry Engine Payload</summary>
        <StructuredJsonViewer data={snapshot ?? {}} title="Telemetry Engine Snapshot" maxHeightClass="max-h-64" />
      </details>
    </section>
  );
}

export function TelemetryBar({ label, value, tone = "ok" }: { label: string; value: number | null; tone?: "ok" | "danger" }) {
  const isNa = value === null;
  const isZero = value === 0;
  const clamped = isNa ? 0 : Math.max(0, Math.min(100, value));
  const trackClass = `telemetry-bar-track ${isNa ? "is-na" : isZero ? "is-zero" : ""}`;
  const valueLabel = isNa ? "n/a" : `${clamped}%`;
  const valueClass = isNa ? "is-na font-mono" : isZero ? "is-zero font-mono" : "font-mono";

  return (
    <div className="telemetry-bar" title={isNa ? "No data yet" : isZero ? "0% (measured baseline)" : `${label}: ${clamped}%`}>
      <span>{label}</span>
      <div className={trackClass}>
        <div className={tone === "danger" ? "telemetry-bar-fill danger" : "telemetry-bar-fill"} style={{ width: `${clamped}%` }} />
      </div>
      <strong className={valueClass}>{valueLabel}</strong>
    </div>
  );
}

export function CvssScoreCard({ data }: { data?: Record<string, unknown> }) {
  if (!data) return null;
  const score = data.base_score ?? data.score ?? data.overall;
  const severity = String(data.severity ?? (typeof score === "number" && score >= 9 ? "critical" : typeof score === "number" && score >= 7 ? "high" : typeof score === "number" && score >= 4 ? "medium" : "low")).toLowerCase();
  const vector = data.vector_string ?? data.vector;
  return (
    <section className="panel p-4 cvss-card">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Risk Assessment</div>
          <h3 className="text-base font-semibold text-white">CVSS Metrics</h3>
        </div>
        <span className={`${opsecBadge(severity)} font-semibold uppercase text-xs px-2.5 py-1`}>
          {severity}
        </span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
        <div className="bg-[#18181c] border border-[#27272a] rounded-lg p-3">
          <div className="text-[11px] text-zinc-400">Base Score</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{score !== undefined ? String(score) : "N/A"}</div>
        </div>
        <div className="bg-[#18181c] border border-[#27272a] rounded-lg p-3 sm:col-span-2">
          <div className="text-[11px] text-zinc-400">Vector String</div>
          <div className="text-xs font-mono text-zinc-300 mt-1.5 break-all">{vector ? String(vector) : "Vector string not calculated"}</div>
        </div>
      </div>
      <details className="advanced-details">
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer mb-2">Inspect Raw CVSS Payload</summary>
        <StructuredJsonViewer data={data} title="CVSS Risk Metrics" maxHeightClass="max-h-64" />
      </details>
    </section>
  );
}

export function CampaignDiffCard({ data }: { data?: Record<string, unknown> }) {
  if (!data) return null;
  return (
    <section className="panel p-4 diff-card">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Delta Analysis</div>
          <h3 className="text-base font-semibold text-white">Campaign Comparison</h3>
        </div>
        <span className="badge badge-low text-xs">Compared</span>
      </div>
      <details className="advanced-details" open>
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer mb-2">Detailed Delta Metrics</summary>
        <StructuredJsonViewer data={data} title="Campaign Delta Metrics" maxHeightClass="max-h-72" />
      </details>
    </section>
  );
}

export function DataPanel({
  title,
  data,
  onClear
}: {
  title: string;
  data: unknown;
  onClear?: () => void;
}) {
  if (!data) {
    return null;
  }
  const isError = data instanceof Error || data instanceof ApiError;
  if (isError) {
    const errorMsg = data instanceof ApiError ? String(data.detail) : data instanceof Error ? data.message : "The request failed.";
    return (
      <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-300 flex items-start justify-between gap-3 mb-3">
        <div className="flex items-start gap-2.5">
          <AlertTriangle size={16} className="text-rose-400 shrink-0 mt-0.5" />
          <div>
            <strong className="font-semibold text-rose-200 block mb-0.5">{title}</strong>
            <span className="leading-relaxed">{errorMsg}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {onClear && (
            <button
              className="btn btn-compact text-[11px] py-0.5 px-2 flex items-center gap-1 text-rose-300 hover:text-white border-rose-500/30 hover:bg-rose-500/20"
              onClick={onClear}
              type="button"
              title="Dismiss error"
            >
              <X size={12} />
              <span>Dismiss</span>
            </button>
          )}
          <span className="badge badge-high shrink-0 text-[10px] uppercase font-mono">Error</span>
        </div>
      </div>
    );
  }

  return (
    <section className="panel detail-panel mb-3">
      <div className="flex items-center justify-between mb-2">
        <strong className="text-xs font-semibold text-zinc-200">{title}</strong>
        {onClear && (
          <button
            className="btn btn-compact text-[11px] py-0.5 px-2 flex items-center gap-1 text-zinc-400 hover:text-rose-400 hover:border-rose-900/50"
            onClick={onClear}
            type="button"
            title="Clear payload preview"
          >
            <X size={12} />
            <span>Clear</span>
          </button>
        )}
      </div>
      <StructuredJsonViewer data={data} title={`${title} Telemetry`} maxHeightClass="max-h-96" defaultExpandedDepth={1} />
    </section>
  );
}

export function getTailoredFindingDetails(finding: Finding) {
  const title = String(finding.title ?? "").toUpperCase();
  const desc = String(finding.description ?? "");
  const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
  const rawPort = evidence.port ?? desc.match(/port\s+(\d+)/i)?.[1];
  const port = rawPort ? Number(rawPort) : null;
  const isKerberos = title.includes("KERBEROS") || port === 88;
  const isLdaps = title.includes("LDAPS") || port === 636;
  const isLdap = !isLdaps && (title.includes("LDAP") || port === 389);
  const isSmb = title.includes("SMB") || port === 445;
  const isWinrm = title.includes("WINRM") || port === 5985 || port === 5986;
  const isDns = title.includes("DNS") || port === 53;
  const isRpc = title.includes("RPC") || port === 135;
  const isMssql = title.includes("MSSQL") || port === 1433;
  const isRdp = title.includes("RDP") || port === 3389;
  const isDocker = title.includes("DOCKER") || port === 2375;
  const isRedis = title.includes("REDIS") || port === 6379;
  const isAttackSurface = title.includes("ATTACK SURFACE");

  let serviceTag = typeof evidence.role === "string" && evidence.role ? evidence.role : "";
  let serviceCategory = typeof evidence.service === "string" && evidence.service ? String(evidence.service).toUpperCase() : "";
  let tailoredRemediation = String(finding.remediation ?? "");

  if (isKerberos) {
    serviceTag = serviceTag || "PORT 88 / KERBEROS KDC / TIER-0 DC";
    serviceCategory = serviceCategory || "Active Directory Authentication";
    tailoredRemediation = tailoredRemediation || "Enforce AES-256 Kerberos encryption (disable RC4-HMAC), audit service accounts for SPNs to mitigate Kerberoasting, and monitor Event ID 4769 for abnormal TGS requests.";
  } else if (isLdaps) {
    serviceTag = serviceTag || "PORT 636 / LDAPS SECURE / TIER-0 DC";
    serviceCategory = serviceCategory || "Encrypted Directory Service";
    tailoredRemediation = tailoredRemediation || "Enforce strong TLS cipher suites, validate CA trust chains, and ensure LDAP channel binding is strictly enforced (LdapEnforceChannelBinding=2).";
  } else if (isLdap) {
    serviceTag = serviceTag || "PORT 389 / LDAP DIRECTORY";
    serviceCategory = serviceCategory || "Active Directory Service";
    tailoredRemediation = tailoredRemediation || "Require LDAP signing (LDAPServerIntegrity=2) and upgrade clients to LDAPS (port 636) to prevent NTLM relay and credential harvesting.";
  } else if (isSmb) {
    serviceTag = serviceTag || "PORT 445 / SMB SERVICE";
    serviceCategory = serviceCategory || "Core Windows File Sharing & Remote Admin";
    tailoredRemediation = tailoredRemediation || "Require SMB signing (RequireSecuritySignature=1), disable legacy SMBv1, and restrict port 445 inbound access to management subnets.";
  } else if (isWinrm) {
    serviceTag = serviceTag || `PORT ${port || 5985} / WINRM REMOTE MGMT`;
    serviceCategory = serviceCategory || "Windows Remote Management (PowerShell Remoting)";
    tailoredRemediation = tailoredRemediation || "Disable WinRM plaintext HTTP listeners, transition management traffic to WinRM HTTPS (port 5986), and enforce GPO firewall restrictions.";
  } else if (isMssql) {
    serviceTag = serviceTag || "PORT 1433 / MSSQL DATABASE";
    serviceCategory = serviceCategory || "Enterprise Relational Database";
    tailoredRemediation = tailoredRemediation || "Disable 'sa' account, enforce Windows Authentication only, and keep xp_cmdshell disabled in configuration.";
  } else if (isRdp) {
    serviceTag = serviceTag || "PORT 3389 / RDP REMOTE DESKTOP";
    serviceCategory = serviceCategory || "Interactive Terminal Services";
    tailoredRemediation = tailoredRemediation || "Enforce Network Level Authentication (NLA) and restrict RDP access to management VPN jump hosts.";
  } else if (isDocker) {
    serviceTag = serviceTag || "PORT 2375 / DOCKER DAEMON API";
    serviceCategory = serviceCategory || "Unauthenticated Container Engine";
    tailoredRemediation = tailoredRemediation || "Disable unauthenticated TCP socket; bind to local Unix socket or require mutual TLS authentication on port 2376.";
  } else if (isRedis) {
    serviceTag = serviceTag || "PORT 6379 / REDIS MEMORY STORE";
    serviceCategory = serviceCategory || "In-Memory Cache & Key-Value Store";
    tailoredRemediation = tailoredRemediation || "Enable requirepass authentication and bind Redis listener strictly to 127.0.0.1.";
  } else if (isDns) {
    serviceTag = serviceTag || "PORT 53 / MICROSOFT DNS";
    serviceCategory = serviceCategory || "Domain Name Resolution";
    tailoredRemediation = tailoredRemediation || "Restrict DNS zone transfers (AXFR) to designated secondary nameservers only, and enable DNSSEC validation.";
  } else if (isRpc) {
    serviceTag = serviceTag || "PORT 135 / MSRPC ENDPOINT";
    serviceCategory = serviceCategory || "RPC Endpoint Mapper";
    tailoredRemediation = tailoredRemediation || "Restrict RPC endpoint mapper via host-based firewall to prevent unauthenticated RPC enumeration and coercions.";
  } else if (isAttackSurface) {
    serviceTag = "HOST ATTACK SURFACE SUMMARY";
    serviceCategory = "Exposed Network Services";
    tailoredRemediation = tailoredRemediation || "Audit all listening ports against the enterprise baseline and enforce host-based micro-segmentation with Windows Defender Firewall.";
  }

  const rawConf = typeof finding.confidence === "number" ? finding.confidence : 1.0;
  const isHighConf = rawConf >= 0.85 || finding.validated === true;
  const confidenceText = rawConf >= 0.95
    ? "100% Confirmed"
    : formatRate(rawConf);

  const nextModules = Array.isArray(evidence.next_modules)
    ? (evidence.next_modules as string[])
    : isKerberos
    ? ["ad.asreproast", "ad.kerberoast", "ad.enum_spn"]
    : isLdaps
    ? ["ad.enum_users", "ad.adcs", "ad.ghost_forge"]
    : isLdap
    ? ["ad.enum_users", "ad.enum_spn", "ad.enum_acl"]
    : isSmb
    ? ["ad.coerce", "windows.secretsdump"]
    : isWinrm
    ? ["lateral.winrm"]
    : [];

  return {
    port,
    serviceTag,
    serviceCategory,
    tailoredRemediation,
    isHighConf,
    confidenceText,
    nextModules
  };
}

export function DiscoveredPerimeterCard({
  rawOutput,
  onSelectModule,
  findingsCount = 0
}: {
  rawOutput?: Record<string, unknown>;
  onSelectModule?: (moduleId: string, params?: Record<string, unknown>) => void;
  findingsCount?: number;
}) {
  const [copiedLootIdx, setCopiedLootIdx] = useState<number | null>(null);
  const [showLoot, setShowLoot] = useState(false);
  if (!rawOutput) return null;

  const target = String(rawOutput.target ?? rawOutput.host ?? "");
  const openPorts = Array.isArray(rawOutput.open_ports) ? (rawOutput.open_ports as (number | string)[]) : [];
  const serviceMap = (rawOutput.service_map ?? {}) as Record<string, string>;
  const serviceVersions = (rawOutput.service_versions ?? {}) as Record<string, Record<string, unknown> | string>;
  const loot = Array.isArray(rawOutput.loot) ? (rawOutput.loot as Record<string, unknown>[]) : [];
  const scanMs = typeof rawOutput.scan_ms === "number" ? rawOutput.scan_ms : null;
  const totalScanned = typeof rawOutput.total_scanned === "number" ? rawOutput.total_scanned : null;

  const hasPerimeter = openPorts.length > 0 || Object.keys(serviceVersions).length > 0;
  if (!hasPerimeter && loot.length === 0) return null;

  return (
    <div className="space-y-2 mt-3">
      {/* 1. Defensive Telemetry & Purple Loot (Collapsible Progressive Disclosure) */}
      {loot.length > 0 && (
        <div className="border border-zinc-800 bg-zinc-950/80 rounded-sm overflow-hidden text-xs">
          <button
            type="button"
            onClick={() => setShowLoot((prev) => !prev)}
            className="w-full p-2.5 px-3 flex items-center justify-between hover:bg-zinc-900/60 transition-colors text-left font-sans"
          >
            <div className="flex items-center gap-2">
              <ShieldCheck size={14} className="text-emerald-400 shrink-0" />
              <span className="font-semibold text-zinc-200 text-xs">
                Synthesized Detection Rules ({loot.length})
              </span>
              <span className="text-[10px] px-1.5 py-0.2 bg-zinc-900 border border-zinc-800 text-zinc-400 rounded font-mono">
                KQL & Sigma
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-zinc-400">
              <span className="text-[11px]">{showLoot ? "Hide Rules" : "Show Rules"}</span>
              <ChevronDown size={14} className={`transform transition-transform duration-200 ${showLoot ? "rotate-180" : ""}`} />
            </div>
          </button>

          {showLoot && (
            <div className="p-3 border-t border-zinc-800/80 space-y-2.5 bg-zinc-950/50 font-mono">
              {loot.map((item, idx) => {
                const name = String(item.name ?? `Artifact #${idx + 1}`);
                const lootType = String(item.loot_type ?? "rule");
                const content = item.content as Record<string, unknown> | undefined;
                const ruleText = typeof content?.kql === "string"
                  ? content.kql
                  : typeof content?.sigma === "string"
                  ? content.sigma
                  : typeof item.content === "string"
                  ? item.content
                  : JSON.stringify(item.content ?? item, null, 2);

                const handleCopyRule = () => {
                  void navigator.clipboard.writeText(ruleText);
                  setCopiedLootIdx(idx);
                  setTimeout(() => setCopiedLootIdx(null), 1500);
                };

                return (
                  <div key={idx} className="p-2.5 rounded-sm border border-zinc-800 bg-zinc-900/60 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 truncate">
                        <Terminal size={12} className="text-zinc-400 shrink-0" />
                        <strong className="text-zinc-200 text-xs truncate">{name}</strong>
                        <span className="badge text-[10px] py-0 px-1.5 uppercase">{lootType}</span>
                      </div>
                      <button
                        type="button"
                        onClick={handleCopyRule}
                        className="btn btn-compact text-[10px] py-0.5 px-2 flex items-center gap-1 shrink-0"
                        title="Copy detection rule query"
                      >
                        {copiedLootIdx === idx ? (
                          <>
                            <CheckCircle2 size={11} className="text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy size={11} />
                            <span>Copy Rule</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="text-[11px] font-mono text-zinc-300 bg-zinc-950 p-2 rounded-sm overflow-x-auto max-h-36 border border-zinc-800/60 leading-relaxed select-all">
                      {ruleText}
                    </pre>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* 2. Perimeter Inventory Bar (Clean, non-redundant when findings are present) */}
      {hasPerimeter && findingsCount > 0 && (
        <div className="border border-zinc-800 bg-zinc-950/80 rounded-sm p-2.5 px-3 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <div className="flex items-center gap-2">
            <Radio size={13} className="text-emerald-400 shrink-0" />
            <span className="font-semibold text-zinc-300 text-[11px]">
              Surface Inventory:
            </span>
            {target && (
              <span className="text-zinc-400">
                Host <strong className="text-zinc-100">{target}</strong>
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 text-zinc-400 text-[11px]">
            {totalScanned !== null && <span>Scanned: {totalScanned} ports</span>}
            {scanMs !== null && <span>Latency: {scanMs}ms</span>}
            <div className="flex items-center gap-1.5">
              {openPorts.map((port) => (
                <span key={String(port)} className="px-1.5 py-0.5 rounded-sm bg-zinc-900 border border-zinc-700/80 text-emerald-400 font-semibold text-[10px]">
                  {String(port)}/TCP ({serviceMap[String(port)] ?? "active"})
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. Discovered Services Grid (Rendered only if no findings exist, avoiding duplicate cards) */}
      {hasPerimeter && findingsCount === 0 && (
        <div className="border border-zinc-800 bg-zinc-950/80 rounded-sm p-3 space-y-2.5 font-mono text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/60 pb-2">
            <div className="flex items-center gap-2">
              <Radio size={14} className="text-emerald-400 shrink-0" />
              <span className="font-semibold text-zinc-200 text-xs">
                Discovered Target Services
              </span>
              {target && (
                <span className="text-zinc-400 bg-zinc-900 px-2 py-0.5 border border-zinc-800 rounded-sm text-[11px]">
                  Host: <strong className="text-zinc-100">{target}</strong>
                </span>
              )}
            </div>
            <div className="flex items-center gap-3 text-[11px] text-zinc-400">
              {totalScanned !== null && <span>Scanned: {totalScanned} ports</span>}
              {scanMs !== null && <span>Latency: {scanMs}ms</span>}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {openPorts.map((port) => {
              const portStr = String(port);
              const service = serviceMap[portStr] ?? "unknown";
              const versionInfo = serviceVersions[portStr];
              const banner = typeof versionInfo === "object" && versionInfo !== null
                ? String(versionInfo.banner ?? versionInfo.version ?? "")
                : typeof versionInfo === "string" ? versionInfo : "";

              return (
                <div
                  key={portStr}
                  className="p-2.5 rounded-sm border border-zinc-800 bg-zinc-900/60 hover:border-zinc-700 space-y-1.5 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-zinc-100 bg-zinc-950 px-2 py-0.5 border border-zinc-800 rounded-sm">
                      PORT {portStr}/TCP
                    </span>
                    <span className="text-[10px] text-emerald-400 uppercase font-semibold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                      OPEN ({service})
                    </span>
                  </div>

                  {banner && (
                    <div className="text-[10px] text-zinc-400 truncate bg-zinc-950/70 p-1 rounded-sm border border-zinc-800/40">
                      <span className="text-zinc-500 font-semibold">Banner: </span>
                      <span className="text-zinc-300 font-mono">{banner}</span>
                    </div>
                  )}

                  {onSelectModule && (
                    <div className="pt-1 flex items-center gap-1 flex-wrap">
                      {portStr === "22" && (
                        <>
                          <button
                            type="button"
                            onClick={() => onSelectModule("network.service_detect", { target, ports: "22" })}
                            className="text-[10px] px-2 py-0.5 rounded-sm border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-colors"
                          >
                            Fingerprint SSH
                          </button>
                          <button
                            type="button"
                            onClick={() => onSelectModule("lateral.ssh_pivot", { target, port: 22 })}
                            className="text-[10px] px-2 py-0.5 rounded-sm border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-colors"
                          >
                            SSH Pivot
                          </button>
                          <button
                            type="button"
                            onClick={() => onSelectModule("linux.privesc", { target })}
                            className="text-[10px] px-2 py-0.5 rounded-sm border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-colors"
                          >
                            Privesc Audit
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export function maskSecret(val: string): string {
  if (!val) return "••••";
  if (val.length <= 4) return "••••";
  if (val.length <= 8) return val.slice(0, 2) + "••••" + val.slice(-1);
  return val.slice(0, 3) + "••••••••" + val.slice(-3);
}

export function getPatternBadgeClass(pattern: string): string {
  const p = pattern.toLowerCase();
  if (p.includes("aws") || p.includes("cloud")) {
    return "bg-amber-950/40 text-amber-300 border-amber-800/60";
  }
  if (p.includes("conn") || p.includes("sql") || p.includes("db")) {
    return "bg-cyan-950/40 text-cyan-300 border-cyan-800/60";
  }
  if (p.includes("cert") || p.includes("private") || p.includes("rsa")) {
    return "bg-emerald-950/40 text-emerald-300 border-emerald-800/60";
  }
  if (p.includes("pass") || p.includes("pwd") || p.includes("shadow")) {
    return "bg-rose-950/40 text-rose-300 border-rose-800/60";
  }
  if (p.includes("key") || p.includes("token") || p.includes("api")) {
    return "bg-purple-950/40 text-purple-300 border-purple-800/60";
  }
  return "bg-zinc-900 text-zinc-300 border-zinc-700/80";
}

export interface DiscoveredSecretHit {
  file?: string;
  line?: number;
  pattern?: string;
  snippet?: string;
  extracted_secret?: string;
  secret_value?: string;
  entropy?: number;
  confidence?: number;
  is_placeholder?: boolean;
  [key: string]: unknown;
}

export function DiscoveredSecretsEvidenceViewer({
  hits,
  title = "Discovered Secrets & Hardcoded Credentials"
}: {
  hits: DiscoveredSecretHit[];
  title?: string;
}) {
  const [isExpanded, setIsExpanded] = useState(hits.length <= 6);
  const [revealedIdxs, setRevealedIdxs] = useState<Record<number, boolean>>({});
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [copiedFileIdx, setCopiedFileIdx] = useState<number | null>(null);
  const [revealAll, setRevealAll] = useState(false);

  if (!hits || hits.length === 0) return null;

  const toggleReveal = (idx: number) => {
    setRevealedIdxs((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const handleToggleRevealAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    const next = !revealAll;
    setRevealAll(next);
    const updated: Record<number, boolean> = {};
    hits.forEach((_, i) => {
      updated[i] = next;
    });
    setRevealedIdxs(updated);
  };

  const copySecret = (text: string, idx: number) => {
    void navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  const copyFile = (path: string, idx: number) => {
    void navigator.clipboard.writeText(path);
    setCopiedFileIdx(idx);
    setTimeout(() => setCopiedFileIdx(null), 1500);
  };

  return (
    <div className="mt-2.5 rounded-sm border border-zinc-800/90 bg-zinc-950/90 overflow-hidden font-mono text-xs">
      {/* Header */}
      <div
        role="button"
        tabIndex={0}
        onClick={() => setIsExpanded((prev) => !prev)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setIsExpanded((prev) => !prev);
          }
        }}
        className="w-full p-2.5 px-3 flex items-center justify-between hover:bg-zinc-900/60 transition-colors text-left cursor-pointer select-none"
      >
        <div className="flex items-center gap-2 flex-wrap">
          <Key size={13} className="text-amber-400 shrink-0" />
          <strong className="text-zinc-200 text-xs font-sans tracking-tight">
            {title} ({hits.length})
          </strong>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-amber-950/50 border border-amber-800/60 text-amber-300 font-semibold">
            LOOT EXTRACTED
          </span>
          {hits.some((h) => h.is_placeholder) && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
              SAMPLE / TEST IDENTIFIED
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            type="button"
            onClick={handleToggleRevealAll}
            className="text-[11px] font-mono px-2 py-0.5 rounded border border-zinc-700 bg-zinc-900 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800 transition-colors flex items-center gap-1 shrink-0"
            title={revealAll ? "Mask all discovered secret values" : "Reveal all discovered secret values"}
          >
            {revealAll ? <EyeOff size={11} className="text-zinc-400" /> : <Eye size={11} className="text-zinc-400" />}
            <span>{revealAll ? "Mask All" : "Reveal All"}</span>
          </button>
          <div className="flex items-center gap-1 text-zinc-400 text-xs">
            <span className="text-[11px] font-sans">{isExpanded ? "Hide Details" : "Show Details"}</span>
            <ChevronDown size={14} className={`transform transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`} />
          </div>
        </div>
      </div>

      {/* Expanded Table */}
      {isExpanded && (
        <div className="border-t border-zinc-800/80 overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-zinc-900/80 border-b border-zinc-800/70 text-[10px] uppercase text-zinc-400 tracking-wider">
                <th className="py-2 px-3 font-medium">Source File & Line</th>
                <th className="py-2 px-3 font-medium">Pattern</th>
                <th className="py-2 px-3 font-medium">Discovered Credential / Value</th>
                <th className="py-2 px-3 font-medium">Shannon Entropy</th>
                <th className="py-2 px-3 font-medium">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {hits.map((hit, idx) => {
                const isRevealed = Boolean(revealedIdxs[idx]);
                const secretVal = String(hit.secret_value || hit.extracted_secret || hit.snippet || "");
                const displayVal = isRevealed ? secretVal : maskSecret(secretVal);
                const entropyVal = typeof hit.entropy === "number" ? hit.entropy : null;
                const confVal = typeof hit.confidence === "number" ? hit.confidence : null;
                const patternName = String(hit.pattern ?? "credential");
                const filePath = String(hit.file ?? "");
                const lineNo = hit.line;

                return (
                  <tr key={idx} className="hover:bg-zinc-900/40 transition-colors">
                    {/* File Path & Line */}
                    <td className="py-2.5 px-3 max-w-[240px]">
                      <div className="flex items-center gap-1.5 truncate" title={filePath}>
                        <FileText size={12} className="text-zinc-500 shrink-0" />
                        <span className="text-zinc-200 truncate text-[11px] font-mono">
                          {filePath.split(/\\|\//).slice(-2).join("/") || filePath}
                        </span>
                        {lineNo !== undefined && (
                          <span className="text-[10px] text-amber-400 bg-zinc-900 px-1 py-0.2 border border-zinc-800 rounded shrink-0">
                            :{lineNo}
                          </span>
                        )}
                        <button
                          type="button"
                          onClick={() => copyFile(filePath, idx)}
                          className="text-zinc-500 hover:text-zinc-300 p-0.5 rounded transition-colors shrink-0"
                          title="Copy file path"
                        >
                          {copiedFileIdx === idx ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>

                    {/* Pattern Badge */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-medium ${getPatternBadgeClass(patternName)}`}>
                        {patternName.replace(/_/g, " ")}
                      </span>
                    </td>

                    {/* Secret Value & Show/Hide + Copy */}
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5 max-w-sm">
                        <div
                          className="bg-zinc-900/90 border border-zinc-800/80 rounded px-2 py-1 font-mono text-[11px] text-zinc-100 truncate select-all flex-1 tracking-wider"
                          title={isRevealed ? secretVal : "Value masked. Click Eye icon to reveal."}
                        >
                          {displayVal}
                        </div>
                        <button
                          type="button"
                          onClick={() => toggleReveal(idx)}
                          className="p-1 rounded bg-zinc-900 border border-zinc-700/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors shrink-0"
                          title={isRevealed ? "Mask secret" : "Reveal full secret value"}
                        >
                          {isRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                        </button>
                        <button
                          type="button"
                          onClick={() => copySecret(secretVal, idx)}
                          className="p-1 rounded bg-zinc-900 border border-zinc-700/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors shrink-0"
                          title="Copy secret value"
                        >
                          {copiedIdx === idx ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                        </button>
                      </div>
                      {hit.snippet && hit.snippet !== hit.extracted_secret && isRevealed && (
                        <div className="mt-1 text-[10px] font-mono text-zinc-500 bg-zinc-950/70 p-1 rounded border border-zinc-900 truncate" title={hit.snippet}>
                          Context: <code className="text-zinc-400">{hit.snippet}</code>
                        </div>
                      )}
                    </td>

                    {/* Shannon Entropy */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {entropyVal !== null ? (
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`font-semibold ${
                              entropyVal >= 3.5
                                ? "text-emerald-400"
                                : entropyVal >= 2.5
                                ? "text-amber-400"
                                : "text-zinc-500"
                            }`}
                          >
                            {entropyVal.toFixed(2)}
                          </span>
                          <span className="text-[10px] text-zinc-500">bits</span>
                          <span
                            className="text-[9px] px-1 py-0.2 rounded uppercase border text-zinc-400 border-zinc-800"
                            title={
                              entropyVal >= 3.5
                                ? "High entropy (Likely true random credential/key)"
                                : entropyVal >= 2.5
                                ? "Moderate entropy (Standard passphrase)"
                                : "Low entropy (Dictionary word or placeholder)"
                            }
                          >
                            {entropyVal >= 3.5 ? "HIGH" : entropyVal >= 2.5 ? "MED" : "LOW"}
                          </span>
                        </div>
                      ) : (
                        <span className="text-zinc-600">n/a</span>
                      )}
                    </td>

                    {/* Confidence & Placeholder Pill */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {confVal !== null ? (
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[10px] font-medium font-mono ${
                              confVal >= 0.85
                                ? "text-emerald-300 bg-emerald-950/50 border-emerald-800/60"
                                : confVal >= 0.60
                                ? "text-amber-300 bg-amber-950/50 border-amber-800/60"
                                : "text-rose-300 bg-rose-950/50 border-rose-800/60"
                            }`}
                          >
                            {confVal >= 0.95 ? "100% Confirmed" : `${Math.round(confVal * 100)}%`}
                          </span>
                        ) : (
                          <span className="text-zinc-500 text-[10px]">Standard</span>
                        )}

                        {hit.is_placeholder && (
                          <span
                            className="text-[9px] px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-700 text-zinc-400 uppercase tracking-tight"
                            title="Identified as test sample or mock placeholder"
                          >
                            Placeholder
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function DiscoveredHashesEvidenceViewer({
  hashes,
  title = "Discovered Hashes & Account Secrets"
}: {
  hashes: Record<string, unknown>[];
  title?: string;
}) {
  const [isExpanded, setIsExpanded] = useState(hashes.length <= 6);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  if (!hashes || hashes.length === 0) return null;

  const copyHash = (hash: string, idx: number) => {
    void navigator.clipboard.writeText(hash);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  return (
    <div className="mt-2 rounded-sm border border-zinc-800/90 bg-zinc-950/90 overflow-hidden font-mono text-xs">
      <button
        type="button"
        onClick={() => setIsExpanded((p) => !p)}
        className="w-full p-2.5 px-3 flex items-center justify-between hover:bg-zinc-900/60 transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          <Key size={13} className="text-purple-400 shrink-0" />
          <strong className="text-zinc-200 text-xs font-sans tracking-tight">
            {title} ({hashes.length})
          </strong>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-purple-950/50 border border-purple-800/60 text-purple-300 font-semibold">
            HASH REPOSITORY
          </span>
        </div>
        <div className="flex items-center gap-1 text-zinc-400 text-xs">
          <span className="text-[11px] font-sans">{isExpanded ? "Hide" : "Show"}</span>
          <ChevronDown size={14} className={`transform transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`} />
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-zinc-800/80 overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-zinc-900/80 border-b border-zinc-800/70 text-[10px] uppercase text-zinc-400 tracking-wider">
                <th className="py-2 px-3">Principal / Account</th>
                <th className="py-2 px-3">Type</th>
                <th className="py-2 px-3">Extracted Hash</th>
                <th className="py-2 px-3">Privilege</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {hashes.map((item, idx) => {
                const user = String(item.username || item.account || item.user || "unknown");
                const hash = String(item.hash || item.ntlm_hash || item.value || "");
                const type = String(item.hash_type || item.type || "crypt");
                const isAdmin = Boolean(item.is_admin || item.is_domain_admin || item.privilege === "Domain Admin");

                return (
                  <tr key={idx} className="hover:bg-zinc-900/40">
                    <td className="py-2 px-3 font-semibold text-zinc-200">{user}</td>
                    <td className="py-2 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 uppercase">
                        {type}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1.5 max-w-md">
                        <code className="text-zinc-300 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800 truncate text-[11px] select-all flex-1">
                          {hash}
                        </code>
                        <button
                          type="button"
                          onClick={() => copyHash(hash, idx)}
                          className="p-1 rounded bg-zinc-900 border border-zinc-700/80 text-zinc-400 hover:text-zinc-200"
                          title="Copy hash"
                        >
                          {copiedIdx === idx ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {isAdmin ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950/50 border border-rose-800/60 text-rose-300 font-semibold">
                          Domain Admin
                        </span>
                      ) : (
                        <span className="text-zinc-500 text-[10px]">Standard User</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function DiscoveredTicketsEvidenceViewer({
  tickets,
  title = "Discovered Kerberos Tickets & TGTs"
}: {
  tickets: Record<string, unknown>[];
  title?: string;
}) {
  const [isExpanded, setIsExpanded] = useState(tickets.length <= 6);

  if (!tickets || tickets.length === 0) return null;

  return (
    <div className="mt-2 rounded-sm border border-zinc-800/90 bg-zinc-950/90 overflow-hidden font-mono text-xs">
      <button
        type="button"
        onClick={() => setIsExpanded((p) => !p)}
        className="w-full p-2.5 px-3 flex items-center justify-between hover:bg-zinc-900/60 transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          <Key size={13} className="text-cyan-400 shrink-0" />
          <strong className="text-zinc-200 text-xs font-sans tracking-tight">
            {title} ({tickets.length})
          </strong>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-cyan-950/50 border border-cyan-800/60 text-cyan-300 font-semibold">
            KERBEROS CREDENTIAL CACHE
          </span>
        </div>
        <div className="flex items-center gap-1 text-zinc-400 text-xs">
          <span className="text-[11px] font-sans">{isExpanded ? "Hide" : "Show"}</span>
          <ChevronDown size={14} className={`transform transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`} />
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-zinc-800/80 overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-zinc-900/80 border-b border-zinc-800/70 text-[10px] uppercase text-zinc-400 tracking-wider">
                <th className="py-2 px-3">Client Principal</th>
                <th className="py-2 px-3">Service Principal</th>
                <th className="py-2 px-3">Expiry</th>
                <th className="py-2 px-3">Cache Path / Origin</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {tickets.map((t, idx) => {
                const client = String(t.client || t.client_principal || "n/a");
                const server = String(t.server || t.service_principal || "krbtgt");
                const expiry = String(t.endtime || t.expiry || t.expires || "valid");
                const path = String(t.path || t.ccache_path || t.source || "/tmp/krb5cc_*");

                return (
                  <tr key={idx} className="hover:bg-zinc-900/40">
                    <td className="py-2 px-3 font-semibold text-zinc-200">{client}</td>
                    <td className="py-2 px-3 text-zinc-300">{server}</td>
                    <td className="py-2 px-3 text-zinc-400 text-[11px]">{expiry}</td>
                    <td className="py-2 px-3 text-zinc-500 font-mono text-[11px]">{path}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ModuleRunSummary({
  result,
  error,
  onSelectModule
}: {
  result?: Record<string, unknown>;
  error?: unknown;
  onSelectModule?: (moduleId: string, params?: Record<string, unknown>) => void;
}) {
  if (!result && !error) {
    return null;
  }
  if (error) {
    return (
      <div className="border border-rose-900/60 bg-rose-950/20 p-3.5 rounded mt-4 font-mono text-xs text-rose-300" role="alert">
        <div className="flex items-center gap-2 font-semibold text-rose-400 mb-1">
          <AlertTriangle size={15} />
          <span>[EXECUTION_FAILED]</span>
        </div>
        <p>{error instanceof ApiError ? String(error.detail) : error instanceof Error ? error.message : "Module run failed."}</p>
      </div>
    );
  }

  const findings = Array.isArray(result?.findings) ? result.findings as Finding[] : [];
  const validationCount = Array.isArray(result?.validation_results) ? result.validation_results.length : 0;
  const duration = typeof result?.duration_ms === "number" ? formatMetric(result.duration_ms, " ms") : "n/a";
  const status = String(result?.status ?? "unknown");
  const moduleId = String(result?.module_id ?? "module");
  const rawOutput = (result?.raw_output ?? result?.raw) as Record<string, unknown> | undefined;
  const rawError = typeof rawOutput?.error === "string" ? rawOutput.error : "";
  const rawHint = typeof rawOutput?.hint === "string" ? rawOutput.hint : "";
  const auditProv = rawOutput?._audit_provenance as Record<string, unknown> | undefined;
  const provenanceHash = typeof auditProv?.provenance_hash === "string" ? auditProv.provenance_hash : "";

  const runError = typeof result?.error === "string" ? result.error : "";
  const outcome = String(result?.outcome ?? "");
  const outcomeMessage = String(result?.outcome_message ?? "");
  const displayOutcome = outcome || status;
  const dryRun = result?.dry_run === true || status.startsWith("dry_run_");
  const warnings = Array.isArray(result?.warnings) ? result.warnings.map(String) : [];
  const nextSteps = Array.isArray(result?.operator_next_steps) ? result.operator_next_steps.map(String) : [];
  const hasOutcomeError = ["operator_error", "dependency_error", "network_error", "unsupported", "module_error", "failed", "timeout"].includes(displayOutcome);
  const openPorts = Array.isArray(rawOutput?.open_ports) ? (rawOutput.open_ports as (number | string)[]) : [];
  const hasPerimeter = openPorts.length > 0 || Object.keys((rawOutput?.service_versions ?? {}) as object).length > 0;
  const filteredFindings = (result?.filtered_findings as { count?: number; reasons?: Record<string, number> } | undefined) ?? {};
  const filteredCount = typeof filteredFindings.count === "number" ? filteredFindings.count : 0;
  const filteredReasons = filteredFindings.reasons && typeof filteredFindings.reasons === "object" ? filteredFindings.reasons : {};
  let topReasonLabel = "below reporting threshold";
  const reasonEntries = Object.entries(filteredReasons).sort((a, b) => b[1] - a[1]);
  if (reasonEntries.length > 0) {
    const topKey = reasonEntries[0][0];
    if (topKey === "below_confidence_threshold") {
      topReasonLabel = "below reporting threshold";
    } else if (topKey === "no_evidence") {
      topReasonLabel = "no evidence";
    } else if (topKey === "validator_rejected") {
      topReasonLabel = "validator rejected";
    } else {
      topReasonLabel = topKey.replace(/_/g, " ");
    }
  }
  const emptyText = dryRun
    ? "No live execution was performed."
    : rawError
      ? `Module halted with status '${rawError}'. See execution notice above.`
      : hasPerimeter
        ? `Target perimeter active: ${openPorts.length} port(s) identified. Review reconnaissance telemetry below.`
        : outcome === "completed_no_findings"
          ? "No confirmed findings. The module completed without observing an exploitable condition."
          : runError
            ? "No findings recorded because execution failed."
            : "No findings returned.";

  return (
    <section className="mt-4 space-y-3 font-sans">
      {/* Tactical Telemetry Strip (Replacing bulky cards & notice clutter) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-zinc-800/80 border border-zinc-800 rounded-sm overflow-hidden text-xs font-mono">
        <div className="bg-zinc-950 p-2.5">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">MODULE / OPERATION</span>
          <span className="font-semibold text-zinc-200">{moduleId}</span>
        </div>
        <div className="bg-zinc-950 p-2.5">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">EXECUTION OUTCOME</span>
          <span className={hasOutcomeError ? "text-rose-400 font-semibold" : "text-emerald-400 font-semibold"}>
            {displayOutcome}
          </span>
        </div>
        <div className="bg-zinc-950 p-2.5">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">OBSERVATIONS / AUDIT</span>
          <span className="font-semibold text-zinc-100">
            {findings.length} findings <span className="text-zinc-500 text-[11px]">({validationCount} verified)</span>
          </span>
        </div>
        <div className="bg-zinc-950 p-2.5">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">DURATION</span>
          <span className="font-semibold text-zinc-300">{duration}</span>
        </div>
      </div>

      {provenanceHash && (
        <div className="px-3 py-1.5 rounded-sm border border-zinc-800/80 bg-zinc-950/80 flex items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-zinc-400 truncate">
            <ShieldCheck size={13} className="text-emerald-400 shrink-0" />
            <span className="text-zinc-500 font-semibold">AUDIT PROVENANCE:</span>
            <code className="text-zinc-300 truncate text-[11px] select-all">{provenanceHash}</code>
          </div>
          <span className="text-[10px] text-emerald-400/90 uppercase tracking-wider shrink-0 font-semibold">[IMMUTABLE RECORD]</span>
        </div>
      )}

      {rawError && (
        <div className="p-3 rounded-sm border border-amber-900/50 bg-amber-950/20 text-xs font-mono text-amber-300 flex items-start gap-2" role="alert">
          <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-400" />
          <div>
            <span className="font-semibold">[EXECUTION NOTICE: {rawError.replace(/_/g, " ").toUpperCase()}]</span>
            {rawHint && <p className="mt-0.5 text-zinc-400">{rawHint}</p>}
          </div>
        </div>
      )}

      {(outcomeMessage || runError) && !rawError && hasOutcomeError && (
        <div className="p-3 rounded-sm border border-rose-900/60 bg-rose-950/20 text-xs font-mono text-rose-300 flex items-center gap-2" role="alert">
          <AlertTriangle size={14} className="shrink-0 text-rose-400" />
          <span>{outcomeMessage || runError}</span>
        </div>
      )}

      {warnings.length > 0 && (
        <div className="p-3 rounded-sm border border-zinc-800 bg-zinc-950/60 text-xs font-mono text-zinc-400">
          <span className="text-zinc-300 uppercase tracking-wider font-semibold block mb-1">
            [{dryRun ? "SIMULATION NOTES" : "OPERATION NOTES"}]
          </span>
          <ul className="list-disc pl-4 space-y-0.5">
            {warnings.map((warning) => <li key={warning}>{warning}</li>)}
          </ul>
        </div>
      )}

      {nextSteps.length > 0 && (
        <div className="p-3 rounded-sm border border-zinc-800 bg-zinc-950/60 text-xs font-mono text-zinc-400">
          <span className="text-zinc-300 uppercase tracking-wider font-semibold block mb-1">
            [OPERATOR NEXT STEPS]
          </span>
          <ul className="list-disc pl-4 space-y-0.5">
            {nextSteps.map((step) => <li key={step}>{step}</li>)}
          </ul>
        </div>
      )}

      {/* Discovered Target Perimeter Matrix & Purple Team Loot */}
      <DiscoveredPerimeterCard rawOutput={rawOutput} onSelectModule={onSelectModule} findingsCount={findings.length} />

      {/* Findings Telemetry Stream (High-Density Tactical Matrix) */}
      {findings.length > 0 ? (
        <div className="space-y-2 mt-2">
          {findings.map((finding, index) => {
            const details = getTailoredFindingDetails(finding);
            const normSev = String(finding.severity ?? "info").toLowerCase();
            const borderAccent =
              normSev.includes("high") || normSev.includes("crit")
                ? "border-l-rose-500"
                : normSev.includes("med")
                ? "border-l-amber-500"
                : "border-l-zinc-700";

            const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
            const rawSecretHits = (
              Array.isArray(evidence.hits)
                ? evidence.hits
                : Array.isArray(evidence.discovered_secrets)
                ? evidence.discovered_secrets
                : Array.isArray(rawOutput?.discovered_secrets) &&
                  (finding.module_id === "exfil.secrets_scan" ||
                    String(finding.title ?? "").toLowerCase().includes("secrets"))
                ? rawOutput.discovered_secrets
                : []
            ) as DiscoveredSecretHit[];

            const hashes = Array.isArray(evidence.hashes) ? (evidence.hashes as Record<string, unknown>[]) : [];
            const tickets = Array.isArray(evidence.tickets) ? (evidence.tickets as Record<string, unknown>[]) : [];

            return (
              <div
                className={`border border-zinc-800/80 border-l-[3px] ${borderAccent} bg-zinc-950/70 hover:bg-zinc-900/40 hover:border-zinc-700 transition-colors p-3.5 space-y-2.5 rounded-sm`}
                key={finding.id ?? index}
              >
                {/* Header Row: Endpoint Port, Mitre, Host, Severity & Confidence */}
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono pb-2 border-b border-zinc-800/50">
                  <div className="flex items-center gap-2 flex-wrap">
                    {details.port ? (
                      <span className="font-bold text-zinc-100 bg-zinc-900 px-2 py-0.5 border border-zinc-800 rounded-sm">
                        PORT {details.port}/TCP
                      </span>
                    ) : details.serviceTag ? (
                      <span className="font-bold text-zinc-100 bg-zinc-900 px-2 py-0.5 border border-zinc-800 rounded-sm">
                        {details.serviceTag}
                      </span>
                    ) : null}
                    {details.serviceCategory && (
                      <span className="text-[11px] text-zinc-400 font-sans">
                        {details.serviceCategory}
                      </span>
                    )}
                    {finding.host && (
                      <span className="text-[11px] text-zinc-500">
                        TARGET: <strong className="text-zinc-300 font-mono">{finding.host}</strong>
                      </span>
                    )}
                    {finding.mitre_technique && (
                      <span className="text-[10px] text-zinc-500 border border-zinc-800 px-1.5 py-0.5 rounded-sm">
                        {finding.mitre_technique}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <span className={details.isHighConf ? "text-emerald-400 font-mono text-[11px] flex items-center gap-1 font-medium" : "text-zinc-400 font-mono text-[11px]"}>
                      {details.isHighConf && <CheckCircle2 size={12} className="text-emerald-400" />}
                      {details.confidenceText}
                    </span>
                    <span className={opsecBadge(finding.severity)}>
                      {finding.severity ? String(finding.severity).toUpperCase() : "INFO"}
                    </span>
                  </div>
                </div>

                {/* Finding Title & Concise Narrative */}
                <div>
                  <h3 className="font-sans font-semibold text-sm text-zinc-100 tracking-tight">
                    {finding.title ?? `Observation #${index + 1}`}
                  </h3>
                  <p className="mt-1 text-xs text-zinc-400 leading-relaxed font-sans whitespace-pre-line">
                    {String(finding.description ?? "")}
                  </p>
                </div>

                {/* Discovered Secrets Evidence (Hardcoded Credentials, Keys & Tokens) */}
                {rawSecretHits.length > 0 && (
                  <DiscoveredSecretsEvidenceViewer hits={rawSecretHits} />
                )}

                {/* Discovered Hashes Evidence Repository */}
                {hashes.length > 0 && (
                  <DiscoveredHashesEvidenceViewer hashes={hashes} />
                )}

                {/* Discovered Kerberos Tickets Evidence Repository */}
                {tickets.length > 0 && (
                  <DiscoveredTicketsEvidenceViewer tickets={tickets} />
                )}

                {/* Technical Remediation */}
                {details.tailoredRemediation && (
                  <div className="pt-2 border-t border-zinc-800/50 text-xs font-mono text-zinc-400 flex items-start gap-2">
                    <span className="text-zinc-500 shrink-0 text-[10px] uppercase font-semibold">[MITIGATION]</span>
                    <span className="font-sans text-xs text-zinc-300 leading-relaxed">
                      {details.tailoredRemediation}
                    </span>
                  </div>
                )}

                {/* Next Actions */}
                {details.nextModules.length > 0 && onSelectModule && (
                  <div className="pt-2 border-t border-zinc-800/50 flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider shrink-0">
                      Next Actions:
                    </span>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {details.nextModules.map((nextMod) => (
                        <button
                          key={nextMod}
                          type="button"
                          onClick={() => onSelectModule(nextMod, { target: finding.host })}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm border border-zinc-700/80 bg-zinc-900/90 hover:border-zinc-500 hover:bg-zinc-800 text-zinc-200 font-mono text-[11px] transition-colors"
                          title={`Arm and execute ${nextMod} on ${finding.host}`}
                        >
                          <Terminal size={11} className="text-zinc-400" />
                          <span>Execute: <strong className="text-zinc-100">{nextMod}</strong></span>
                          <ArrowRight size={11} className="text-zinc-400" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState text={emptyText} />
      )}

      {filteredCount > 0 && (
        <div
          data-testid="filtered-findings-notice"
          className="flex items-center gap-2 px-3 py-2 rounded-sm border border-zinc-800 bg-zinc-900/60 text-xs font-mono text-zinc-400 mt-2"
        >
          <Info size={13} className="text-zinc-500 shrink-0" />
          <span>
            {filteredCount} finding{filteredCount === 1 ? "" : "s"} filtered as low-confidence ({topReasonLabel})
          </span>
        </div>
      )}
    </section>
  );
}

export function TemplatePlanSummary({ plan }: { plan?: TemplatePlanResponse }) {
  const stages = plan?.plan?.stages ?? [];
  if (!plan || stages.length === 0) {
    return null;
  }
  const moduleCount = stages.reduce((total, stage) => total + (stage.modules?.length ?? 0), 0);
  return (
    <section className="inline-summary mt-4">
      <SectionHeader
        title={plan.template ?? "Generated Plan"}
        description={plan.description}
        action={(
          <div className="flex flex-wrap gap-2">
            <span className="badge">{stages.length} stages</span>
            <span className="badge">{moduleCount} modules</span>
          </div>
        )}
      />
      <div className="compact-list">
        {stages.map((stage, index) => (
          <div className="compact-row" key={`${stage.name ?? "stage"}-${index}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-bold">{index + 1}. {stage.name ?? "stage"}</span>
              <span className="text-xs font-semibold text-zinc-400">{stage.modules?.length ?? 0} modules</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {(stage.modules ?? []).map((moduleId) => <span className="badge" key={moduleId}>{moduleId}</span>)}
            </div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-sm text-zinc-400">Ready for campaign dry-run structure.</p>
    </section>
  );
}

export function CampaignScopeSummary({ campaign, loading }: { campaign?: Campaign; loading?: boolean }) {
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  if (loading) {
    return (
      <div className="detail-summary mt-3">
        <div className="loading-row">
          <Loader2 className="spin" size={16} /> Loading campaign...
        </div>
      </div>
    );
  }
  if (!campaign) {
    return <EmptyState text="Select a campaign to review scope and findings." />;
  }
  const targets = campaignTargets(campaign);
  const scope = campaignScopeEntries(campaign);
  const excluded = campaignExcludedHosts(campaign);

  const copyScope = () => {
    void navigator.clipboard.writeText(JSON.stringify(campaign, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="detail-summary mt-3">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight">{campaign.name}</h3>
          <p className="text-xs text-zinc-400 mt-0.5">{campaign.client ?? "No client"} &middot; <span className="text-emerald-400 uppercase font-mono text-[11px]">{campaign.status ?? "created"}</span></p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={copyScope}
            className="btn btn-compact text-[11px] py-1 px-2.5 flex items-center gap-1.5"
            title="Copy campaign JSON"
          >
            {copied ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Copy size={12} />}
            <span>{copied ? "Copied" : "Copy Scope"}</span>
          </button>
          <span className="badge font-mono text-[11px]">{campaign.operator ?? "operator"}</span>
        </div>
      </div>
      <div className="mini-stat-grid">
        <MiniStat title="Targets" value={String(targets.length)} detail={targets.slice(0, 3).join(", ") || "none declared"} />
        <MiniStat title="Scope CIDRs" value={String(scope.length)} detail={scope.slice(0, 3).join(", ") || "none declared"} />
        <MiniStat title="Excluded Hosts" value={String(excluded.length)} detail={excluded.length > 0 ? excluded.slice(0, 2).join(", ") : "none"} />
        <MiniStat title="Noise Profile" value={String(campaign.noise_profile ?? "stealth")} detail="OPSEC guardrail" />
      </div>

      <div className="mt-4 space-y-3">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">Authorized IP Ranges &amp; CIDRs</span>
            <span className="badge font-mono text-[10px]">{scope.length} range{scope.length === 1 ? "" : "s"}</span>
          </div>
          {scope.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {scope.map((cidr) => (
                <span
                  key={cidr}
                  className="badge badge-info font-mono text-xs px-2.5 py-1 flex items-center gap-1.5"
                >
                  <Radio size={11} className="text-cyan-400" />
                  <span>{cidr}</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-500 italic">No network CIDRs declared for this campaign.</p>
          )}
        </div>

        {targets.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">Target Hosts</span>
              <span className="badge font-mono text-[10px]">{targets.length} host{targets.length === 1 ? "" : "s"}</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {targets.map((tgt) => (
                <span
                  key={tgt}
                  className="badge font-mono text-xs px-2 py-0.5 flex items-center gap-1 text-zinc-200"
                >
                  <Target size={11} className="text-emerald-400" />
                  <span>{tgt}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">Excluded Hosts / Out-of-Scope</span>
            <span className="badge font-mono text-[10px]">{excluded.length} excluded</span>
          </div>
          {excluded.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {excluded.map((host) => (
                <span
                  key={host}
                  className="badge badge-high font-mono text-xs px-2.5 py-1 flex items-center gap-1.5 border-rose-500/30 bg-rose-950/20 text-rose-300"
                >
                  <MinusCircle size={12} className="text-rose-400" />
                  <span>{host}</span>
                </span>
              ))}
            </div>
          ) : (
            <div className="text-xs text-zinc-500 italic flex items-center gap-1.5">
              <ShieldCheck size={13} className="text-zinc-600" />
              <span>None declared (all addresses within defined CIDRs are active scope)</span>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-zinc-800/80">
        <button
          type="button"
          onClick={() => setShowRaw(!showRaw)}
          className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
        >
          <FileText size={12} />
          <span>{showRaw ? "Hide Raw Scope JSON" : "View Raw Scope JSON"}</span>
          <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
        </button>
        {showRaw && (
          <div className="mt-2">
            <StructuredJsonViewer data={campaign} title="Campaign Scope & Target Configuration" maxHeightClass="max-h-72" />
          </div>
        )}
      </div>
    </div>
  );
}

export function CampaignPicker({
  campaigns,
  value,
  onChange,
  id,
  hasError,
  className
}: {
  campaigns: Campaign[];
  value: string;
  onChange: (id: string) => void;
  id?: string;
  hasError?: boolean;
  className?: string;
}) {
  const safeValue = value && campaigns.some((c) => c.id === value) ? value : "";
  return (
    <select
      id={id}
      className={`field ${hasError ? "border-rose-500/70 focus:border-rose-500" : ""} ${className ?? ""}`.trim()}
      value={safeValue}
      onChange={(event) => onChange(event.target.value)}
    >
      <option value="">Select campaign</option>
      {campaigns.map((campaign) => (
        <option key={campaign.id} value={campaign.id}>
          {campaign.name || campaign.id}
        </option>
      ))}
    </select>
  );
}

export function StatusBadge({ status }: { status?: string }) {
  const normalized = String(status ?? "").toLowerCase();
  const isOk = ["active", "running", "ready", "restored", "complete", "completed"].some((item) => normalized.includes(item));
  const isWarn = ["paused", "pending", "draft", "created"].some((item) => normalized.includes(item));
  const isDanger = ["failed", "deleted", "blocked", "error"].some((item) => normalized.includes(item));
  const toneClass = isOk ? "badge badge-low" : isDanger ? "badge badge-high" : isWarn ? "badge badge-medium" : "badge";
  const dotColor = isOk ? "bg-emerald-400" : isDanger ? "bg-rose-400" : isWarn ? "bg-amber-400" : "bg-zinc-400";
  return (
    <span className={toneClass}>
      <span className={`inline-block h-1.5 w-1.5 rounded-full ${dotColor}`} />
      <span>{status ?? "created"}</span>
    </span>
  );
}

export function NoiseProfileBadge({ noise }: { noise?: string }) {
  const normalized = String(noise ?? "stealth").toLowerCase();
  const isNoisy = normalized.includes("noisy") || normalized.includes("critical") || normalized.includes("high");
  const isEvasive = normalized.includes("evasive") || normalized.includes("medium");
  const isStealth = normalized.includes("stealth") || normalized.includes("low");
  const badgeClass = isNoisy ? "badge badge-high" : isEvasive ? "badge badge-medium" : isStealth ? "badge badge-low" : "badge";
  return (
    <span className={`${badgeClass} font-mono text-[11px] uppercase tracking-wider`}>
      {noise ?? "stealth"}
    </span>
  );
}

export function CampaignTable({
  campaigns,
  scopedCampaignId,
  onClearScope,
  onSelectCampaign
}: {
  campaigns: Campaign[];
  scopedCampaignId?: string;
  onClearScope?: () => void;
  onSelectCampaign?: (id: string) => void;
}) {
  return (
    <section className="panel table-panel">
      <SectionHeader
        title={scopedCampaignId ? "Scoped Campaign Activity" : "Campaign Activity"}
        action={
          <div className="flex items-center gap-2">
            {scopedCampaignId && onClearScope ? (
              <button
                type="button"
                onClick={onClearScope}
                className="btn btn-compact text-xs font-mono"
                title="Reset scope filter to display all campaigns"
              >
                Show All Campaigns
              </button>
            ) : null}
            <span className="badge">{campaigns.length} record{campaigns.length === 1 ? "" : "s"}</span>
          </div>
        }
      />
      {campaigns.length > 0 ? (
        <div className="table-scroll">
          <table className="table">
            <thead><tr><th>#</th><th>Name</th><th>Client</th><th>Status</th><th>Noise</th><th>Operator</th></tr></thead>
            <tbody>
              {campaigns.map((campaign, index) => (
                <tr
                  key={campaign.id}
                  className={`campaign-table-row ${campaign.id === scopedCampaignId ? "is-selected" : ""} ${onSelectCampaign ? "cursor-pointer" : ""}`}
                  onClick={() => onSelectCampaign?.(campaign.id)}
                  title={onSelectCampaign ? `Filter dashboard to ${campaign.name}` : undefined}
                >
                  <td className="muted-cell">#{String(index + 1).padStart(2, "0")}</td>
                  <td>
                    <div className="font-semibold text-zinc-100 text-sm tracking-tight">{campaign.name}</div>
                    <div className="mt-1 flex items-center gap-1.5 text-xs">
                      <span className="font-mono text-[11px] text-zinc-400 bg-zinc-900/90 px-1.5 py-0.5 rounded border border-zinc-800/80">
                        {campaign.id.slice(0, 12)}
                      </span>
                    </div>
                  </td>
                  <td className="text-zinc-300 text-sm">{campaign.client || "Internal"}</td>
                  <td><StatusBadge status={campaign.status} /></td>
                  <td><NoiseProfileBadge noise={campaign.noise_profile} /></td>
                  <td className="text-zinc-400 text-sm font-mono">{campaign.operator || "operator"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState text="No campaigns yet. Create one from the Campaigns page to unlock modules, reports, and graph views." />
      )}
    </section>
  );
}

export function FindingsTable({ findings }: { findings: any[] }) {
  return (
    <section className="panel table-panel">
      <SectionHeader
        title="Findings"
        action={<span className="badge">{findings.length} records</span>}
      />
      {findings.length > 0 ? (
        <div className="table-scroll">
          <table className="table">
            <thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>MITRE</th><th>Host</th></tr></thead>
            <tbody>
              {findings.map((finding, index) => (
                <tr key={finding.id ?? index}>
                  <td><span className={opsecBadge(finding.severity)}>{finding.severity ?? "info"}</span></td>
                  <td className="font-semibold text-zinc-100 text-sm">{finding.title ?? `Finding ${index + 1}`}</td>
                  <td className="text-zinc-300 font-mono text-xs">{finding.module_id ?? "n/a"}</td>
                  <td className="text-zinc-300 font-mono text-xs">{finding.mitre_technique ?? "n/a"}</td>
                  <td className="text-zinc-400 text-sm">{finding.host ?? "n/a"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState text="No findings recorded for this campaign." />
      )}
    </section>
  );
}

export function LiveEventCard({
  event,
  index,
  campaigns
}: {
  event: unknown;
  index: number;
  campaigns?: Campaign[];
}) {
  const record = event && typeof event === "object" && !Array.isArray(event) ? event as Record<string, unknown> : null;
  const type = String(record?.type ?? record?.event ?? record?.name ?? `event.${index + 1}`);
  const message = String(record?.message ?? record?.status ?? record?.detail ?? "Campaign event received.");
  const campaign = typeof record?.campaign_id === "string" ? record.campaign_id : "";
  const matchedCampaign = campaigns?.find((c) => c.id === campaign);
  const campaignLabel = matchedCampaign?.name ? matchedCampaign.name : (campaign ? `Campaign ${campaign.slice(0, 8)}` : "");
  const moduleId = typeof record?.module_id === "string" ? record.module_id : "";
  const created = typeof record?.timestamp === "number"
    ? formatTimestamp(record.timestamp)
    : typeof record?.created_at === "string"
      ? formatDateTime(record.created_at)
      : "";

  return (
    <article className="event-card">
      <div className="event-marker" aria-hidden="true" />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <strong>{type}</strong>
          {campaignLabel ? <span className="badge">{campaignLabel}</span> : null}
          {moduleId ? <span className="badge">{moduleId}</span> : null}
        </div>
        <p>{message}</p>
        {created ? <small>{created}</small> : null}
        <details className="advanced-details compact mt-2">
          <summary className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 cursor-pointer">Telemetry Details</summary>
          <div className="mt-1.5">
            <StructuredJsonViewer
              data={serializeError(event)}
              title="Event Telemetry"
              defaultExpandedDepth={1}
              maxHeightClass="max-h-56"
              showSummaryStrip={false}
            />
          </div>
        </details>
      </div>
    </article>
  );
}

export function ParamForm({
  schema,
  values,
  onChange,
  requiredOverrides
}: {
  schema: ModuleMeta["param_schema"];
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
  requiredOverrides?: Record<string, boolean>;
}) {
  const entries = Object.entries(schema ?? {});
  if (entries.length === 0) {
    return <EmptyState text="No parameters" />;
  }
  return (
    <div className="grid gap-3">
      {entries.map(([name, field]) => {
        const required = requiredOverrides?.[name] ?? field.required;
        const inputField = required === field.required ? field : { ...field, required };
        const description = fieldDescription(name, field);
        const isBool = field.type === "boolean";

        const inputId = `param_${name}`;
        if (isBool) {
          return (
            <div className="flex items-center gap-2.5 py-1 text-xs text-zinc-300" key={name}>
              <input
                id={inputId}
                name={inputId}
                type="checkbox"
                checked={Boolean(values[name] ?? field.default)}
                onChange={(event) => {
                  onChange({ ...values, [name]: event.target.checked });
                }}
              />
              <label htmlFor={inputId} className="font-mono text-xs text-zinc-200 cursor-pointer select-none">
                {name}
              </label>
              {!required && <span className="text-[10px] font-mono text-zinc-500">(optional)</span>}
              {description && <span className="text-[11px] text-zinc-500">({description})</span>}
            </div>
          );
        }

        return (
          <div className="block" key={name}>
            <div className="flex items-center justify-between gap-2 mb-1">
              <label htmlFor={inputId} className="font-mono text-xs text-zinc-300 cursor-pointer select-none">
                {name}
                {required && <span className="text-rose-500 font-sans ml-1">*</span>}
              </label>
              {!required && <span className="text-[10px] font-mono text-zinc-500">optional</span>}
            </div>
            <ParamInput
              id={inputId}
              name={name}
              field={inputField}
              value={values[name]}
              onChange={(value) => {
                const next = { ...values };
                if (!required && isEmptyParamValue(value)) {
                  delete next[name];
                } else {
                  next[name] = value;
                }
                onChange(next);
              }}
            />
            {description && (
              <span className="mt-1 block text-[11px] text-zinc-500 leading-snug">
                {description}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function ParamInput({
  id,
  name,
  field,
  value,
  onChange
}: {
  id?: string;
  name: string;
  field: ParamField;
  value: unknown;
  onChange: (value: unknown) => void;
}) {
  const inputId = id ?? `param_${name}`;
  if (field.type === "boolean") {
    return (
      <input
        id={inputId}
        name={inputId}
        className="ml-2 cursor-pointer"
        type="checkbox"
        checked={Boolean(value)}
        required={field.required}
        onChange={(event) => onChange(event.target.checked)}
      />
    );
  }
  if (field.type === "array") {
    return (
      <textarea
        id={inputId}
        name={inputId}
        className="field mt-1 min-h-20"
        value={Array.isArray(value) ? value.join(", ") : String(value ?? "")}
        placeholder={paramPlaceholder(name, field)}
        required={field.required}
        autoComplete="off"
        spellCheck={false}
        onInvalid={setRequiredMessage}
        onChange={(event) => {
          clearValidationMessage(event);
          onChange(parseArrayParam(event.target.value, field));
        }}
      />
    );
  }
  const type = field.secret ? "password" : field.type === "integer" || field.type === "number" ? "number" : "text";
  return (
    <input
      id={inputId}
      name={inputId}
      className="field mt-1"
      type={type}
      value={String(value ?? "")}
      min={field.min}
      max={field.max}
      placeholder={paramPlaceholder(name, field)}
      required={field.required}
      autoComplete={field.secret ? "new-password" : "off"}
      autoCorrect="off"
      autoCapitalize="off"
      spellCheck={false}
      data-lpignore="true"
      data-form-type="other"
      onInvalid={setRequiredMessage}
      onChange={(event) => {
        clearValidationMessage(event);
        if (type === "number") {
          onChange(event.target.value === "" ? undefined : Number(event.target.value));
          return;
        }
        onChange(event.target.value === "" ? undefined : event.target.value);
      }}
    />
  );
}

export function fieldDefaultHint(field: ParamField): string {
  if (field.secret || field.default === undefined) {
    return "";
  }
  const value = formatDefaultValue(field.default);
  return value ? `Default: ${value}` : "";
}

export function paramPlaceholder(name: string, field: ParamField): string {
  if (!field.secret) {
    const value = formatDefaultValue(field.default);
    if (value) {
      return value;
    }
  }
  const lower = name.toLowerCase();
  if (lower === "target_user" && field.description === "Required target user or SPN; run ad.enum_spn first") {
    return "svc-sql or MSSQLSvc/sql01.lab.local:1433";
  }
  if (lower.includes("target")) {
    return "127.0.0.1";
  }
  if (lower.includes("port")) {
    return "80, 443, 8080, 8443, 8888";
  }
  if (lower.includes("domain")) {
    return "corp.local";
  }
  return field.required ? "" : "Leave blank to use the module default";
}

export function fieldDescription(name: string, field: ParamField): string | undefined {
  if (name === "target_user" && field.description === "Required target user or SPN; run ad.enum_spn first") {
    return "Required target user or SPN; run ad.enum_spn first.";
  }
  if (name === "timeout") {
    return (field.description ? `${field.description}. ` : "") + "Recommendation: use 2.5s - 3.0s for virtual lab / VM targets.";
  }
  if (name === "ports" && (!field.description || field.description.includes("Port spec"))) {
    return "Comma-separated ports (e.g. 88, 389, 445) or presets (top1000). Required for service detection.";
  }
  return field.description;
}

export function formatDefaultValue(value: unknown): string {
  if (value === undefined || value === null || value === "") {
    return "";
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

export function ScreenMessage({ title, body }: { title: string; body: string }) {
  return (
    <div className="grid min-h-screen place-items-center bg-zinc-950 p-4 text-zinc-100">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6 text-center shadow-sm">
        <h1 className="text-lg font-semibold tracking-tight text-zinc-100">{title}</h1>
        <p className="mt-1 text-xs text-zinc-400">{body}</p>
      </div>
    </div>
  );
}

export function EmptyState({ text }: { text: string }) {
  return <div className="empty-state">{text}</div>;
}

export function strategyBackendHint(backend: string): string {
  if (backend === "openai") {
    return "OpenAI planning requires OPENAI_API_KEY in the ARES server environment. Security-page API keys do not count as LLM provider keys.";
  }
  if (backend === "local") {
    return "Local planning uses Ollama from the ARES server host, usually http://localhost:11434. No cloud LLM key is required.";
  }
  return "Claude planning requires ANTHROPIC_API_KEY in the ARES server environment. Security-page API keys only authenticate callers to ARES.";
}

export function moduleRunHint(
  campaignId: string,
  module: ModuleMeta | undefined,
  campaign: Campaign | undefined,
  sensitive: boolean,
  confirmed: boolean,
  dryRun: boolean
): string {
  if (!campaignId) {
    return "Select a campaign before running a module.";
  }
  if (!module) {
    return "Select a module from the catalog.";
  }
  if (!campaign) {
    return "Campaign details are still loading.";
  }
  if (sensitive && !confirmed) {
    return "Confirm authorization before running high-noise or sensitive modules.";
  }
  if (!dryRun && "target" in (module.param_schema ?? {}) && campaignScopeEntries(campaign).length === 0) {
    return "Live target modules require campaign scope CIDRs. Add a scope such as 127.0.0.1/32 before running.";
  }
  return "";
}

export function splitLines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function findInvalidScopeEntries(value: string): string[] {
  return splitLines(value).filter((entry) => !looksLikeScopeEntry(entry));
}

export function looksLikeScopeEntry(entry: string): boolean {
  if (entry.includes(":")) {
    return true;
  }
  const [address, prefix] = entry.split("/");
  if (!isIpv4Address(address)) {
    return false;
  }
  if (prefix === undefined) {
    return true;
  }
  if (!/^\d{1,2}$/.test(prefix)) {
    return false;
  }
  const value = Number(prefix);
  return value >= 0 && value <= 32;
}

export function parseArrayParam(value: string, field: ParamField): unknown[] | undefined {
  const entries = splitLines(value);
  if (entries.length === 0) {
    return undefined;
  }
  const itemType = field.items?.type ?? "string";
  if (itemType === "integer" || itemType === "number") {
    const numericEntries = entries.map((entry) => Number(entry));
    return numericEntries.every((entry) => Number.isFinite(entry)) ? numericEntries : entries;
  }
  return entries;
}

export function isEmptyParamValue(value: unknown): boolean {
  return value === undefined || value === "" || (Array.isArray(value) && value.length === 0);
}

export function moduleScopeWarning(
  module: ModuleMeta | undefined,
  campaign: Campaign | undefined,
  values: Record<string, unknown>,
  dryRun: boolean
): string {
  if (!module || !campaign || dryRun || !("target" in (module.param_schema ?? {}))) {
    return "";
  }
  const target = typeof values.target === "string" ? values.target.trim() : "";
  if (!target) {
    return "";
  }
  const scope = campaignScopeEntries(campaign);
  if (scope.length === 0) {
    return "Selected campaign has no scope CIDRs. Add a scoped campaign such as 127.0.0.1/32 before running target modules.";
  }
  if (isIpv4Address(target) && scope.every(looksLikeScopeEntry) && !scope.some((entry) => ipv4InScope(target, entry))) {
    return `Target ${target} is outside the selected campaign scope (${scope.join(", ")}).`;
  }
  return "";
}

export function campaignScopeEntries(campaign: Campaign): string[] {
  if (Array.isArray(campaign.scope_cidrs)) {
    return campaign.scope_cidrs.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
  }
  const rawScope = campaign.scope;
  if (Array.isArray(rawScope)) {
    return rawScope
      .map((entry) => {
        if (typeof entry === "string") {
          return entry;
        }
        if (entry && typeof entry === "object" && "cidr" in entry && typeof entry.cidr === "string") {
          return entry.cidr;
        }
        return "";
      })
      .filter(Boolean);
  }
  if (typeof campaign.scope_json === "string" && campaign.scope_json.trim()) {
    try {
      const parsed = JSON.parse(campaign.scope_json) as unknown;
      if (Array.isArray(parsed)) {
        return parsed
          .map((entry) => {
            if (typeof entry === "string") {
              return entry;
            }
            if (entry && typeof entry === "object" && "cidr" in entry && typeof entry.cidr === "string") {
              return entry.cidr;
            }
            return "";
          })
          .filter(Boolean);
      }
    } catch {
      return [];
    }
  }
  return [];
}

export function campaignTargets(campaign: Campaign): string[] {
  if (Array.isArray(campaign.targets)) {
    return campaign.targets.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
  }
  if (typeof campaign.targets_json === "string" && campaign.targets_json.trim()) {
    try {
      const parsed = JSON.parse(campaign.targets_json) as unknown;
      if (Array.isArray(parsed)) {
        return parsed.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
      }
    } catch {
      return [];
    }
  }
  return [];
}

export function campaignExcludedHosts(campaign: Campaign): string[] {
  const explicit = campaign as { excluded_hosts?: unknown; excluded?: unknown };
  if (Array.isArray(explicit.excluded_hosts)) {
    return explicit.excluded_hosts.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
  }
  if (Array.isArray(explicit.excluded)) {
    return explicit.excluded.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
  }
  if (typeof campaign.scope_json === "string" && campaign.scope_json.trim()) {
    try {
      const parsed = JSON.parse(campaign.scope_json) as Record<string, unknown>;
      if (parsed && Array.isArray(parsed.excluded_hosts)) {
        return parsed.excluded_hosts.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
      }
      if (parsed && Array.isArray(parsed.excluded)) {
        return parsed.excluded.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "");
      }
    } catch {
      return [];
    }
  }
  return [];
}

export function ipv4InScope(ip: string, cidr: string): boolean {
  const [network, prefixText = "32"] = cidr.split("/");
  if (!isIpv4Address(network) || !/^\d{1,2}$/.test(prefixText)) {
    return false;
  }
  const prefix = Number(prefixText);
  if (prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToNumber(ip) & mask) === (ipv4ToNumber(network) & mask);
}

export function ipv4ToNumber(ip: string): number {
  return ip.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

export function isIpv4Address(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

export function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

export function safeJson(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

export function isJsonObject(value: string): boolean {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Boolean(parsed && typeof parsed === "object" && !Array.isArray(parsed));
  } catch {
    return false;
  }
}

export function isSensitiveModule(module?: ModuleMeta): boolean {
  if (!module) {
    return false;
  }
  const text = `${module.id} ${module.category ?? ""} ${module.opsec_level ?? ""}`.toLowerCase();
  return (
    text.includes("high_noise") ||
    text.includes("credential") ||
    text.includes("persistence") ||
    text.includes("edr") ||
    text.includes("dcsync")
  );
}

export function statusBadge(status?: string): string {
  const normalized = String(status ?? "").toLowerCase();
  if (["active", "running", "ready", "restored", "complete", "completed"].some((item) => normalized.includes(item))) {
    return "badge badge-low";
  }
  if (["failed", "deleted", "blocked", "error"].some((item) => normalized.includes(item))) {
    return "badge badge-high";
  }
  if (["paused", "pending", "draft", "created"].some((item) => normalized.includes(item))) {
    return "badge badge-medium";
  }
  return "badge";
}

export function opsecBadge(level?: string): string {
  const normalized = String(level ?? "").toLowerCase().trim();
  if (!normalized || normalized === "n/a" || normalized === "none" || normalized === "unknown") {
    return "badge";
  }
  if (normalized.includes("high") || normalized.includes("critical") || normalized.includes("alarm")) {
    return "badge badge-high";
  }
  if (normalized.includes("medium") || normalized.includes("moderate") || normalized.includes("warn")) {
    return "badge badge-medium";
  }
  if (normalized.includes("low") || normalized.includes("safe") || normalized.includes("info") || normalized.includes("stealth") || normalized.includes("minimal")) {
    return "badge badge-low";
  }
  return "badge";
}

export function serializeError(value: unknown): unknown {
  if (value instanceof ApiError) {
    const idempotencyKey = "idempotencyKey" in value
      && typeof value.idempotencyKey === "string"
      ? value.idempotencyKey
      : undefined;
    return {
      name: value.name,
      status: value.status,
      detail: value.detail,
      ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {})
    };
  }
  if (value instanceof Error) {
    const idempotencyKey = "idempotencyKey" in value
      && typeof value.idempotencyKey === "string"
      ? value.idempotencyKey
      : undefined;
    return {
      name: value.name,
      message: value.message,
      ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {})
    };
  }
  return value;
}

export function readableError(value: unknown, fallback: string): string {
  if (value instanceof ApiError) {
    if (typeof value.detail === "string") {
      return value.detail;
    }
    return value.message || fallback;
  }
  if (value instanceof Error) {
    return value.message || fallback;
  }
  if (typeof value === "string") {
    return value;
  }
  return fallback;
}

export function pdfFailureHint(value: unknown): string {
  if (!value) return "";
  const serialized = serializeError(value);
  const text = typeof serialized === "string"
    ? serialized
    : JSON.stringify(serialized);
  const normalized = text.toLowerCase();
  if (normalized.includes("elevated windows") || normalized.includes("administrator powershell")) {
    return "PDF export is blocked from this elevated Windows session. Run PowerShell normally, or set ARES_PDF_BROWSER to a working non-Edge browser.";
  }
  if (
    normalized.includes("gtk")
    || normalized.includes("pango")
    || normalized.includes("libgobject")
  ) {
    return "WeasyPrint needs native GTK/Pango libraries on Windows. Use the browser fallback from normal PowerShell or install those native libraries.";
  }
  if (normalized.includes("no downloadable pdf") || normalized.includes("pdf smoke")) {
    return "PDF export did not create a valid artifact. Run ares doctor --pdf-smoke to verify the local PDF backend and browser fallback.";
  }
  return "";
}
