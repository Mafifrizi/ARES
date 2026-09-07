import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronDown,
  Copy,
  Info,
  Layers,
  Loader2,
  Menu,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X
} from "lucide-react";
import {
  ChangeEvent,
  FormEvent,
  KeyboardEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import { NavLink, Navigate, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  api,
  buildModuleRunPayload,
  campaignEventsPath,
  captureSession,
  isSessionCurrent
} from "../../api/client";
import type { ApiKeyMeta, Campaign, ExecutionChain, FeasibilityReportData, FeasibilityResponse, Finding, ModuleMeta, MonthlyFindingStats, ParamField, ReportItem } from "../../api/types";
import { useAuth } from "../auth/authContext";
import { DashboardUiProvider } from "./dashboardUi";
import {
  type DashboardUiState,
  useDashboardSessionWriter,
  useDashboardUi,
  useSessionState
} from "./dashboardUiState";

interface ModuleRunRecord {
  campaignId: string;
  moduleId: string;
  payload: unknown;
  isError?: boolean;
}

interface PersistedResult {
  key: string;
  payload: unknown;
  isError?: boolean;
}

interface GeneratedApiKey {
  id?: string;
  key: string;
  note?: string;
  prefix?: string;
}

type ApiKeyCopyStatus = "idle" | "copied" | "manual";

interface SearchResult {
  id: string;
  label: string;
  detail: string;
  route: string;
  onSelect?: () => void;
}

interface DashboardNotification {
  id: string;
  title: string;
  detail: string;
  tone: "info" | "warn" | "danger";
}

const REQUIRED_FIELD_MESSAGE = "This field is required.";

type ValidatableElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
type TelemetryMetricMap = Record<string, boolean | number | string | null | undefined>;
interface TelemetrySnapshot {
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

interface TemplatePlanStage {
  name?: string;
  modules?: string[];
  params?: Record<string, unknown>;
}

interface TemplatePlanResponse {
  template?: string;
  description?: string;
  plan?: {
    stages?: TemplatePlanStage[];
  };
  global_params?: Record<string, unknown>;
  note?: string;
}

function setRequiredMessage<T extends ValidatableElement>(event: FormEvent<T>) {
  event.currentTarget.setCustomValidity(REQUIRED_FIELD_MESSAGE);
}

function clearValidationMessage<T extends ValidatableElement>(event: ChangeEvent<T>) {
  event.currentTarget.setCustomValidity("");
}

const navItems = [
  { to: "/", label: "Overview", code: "OVR" },
  { to: "/campaigns", label: "Campaigns", code: "CMP" },
  { to: "/modules", label: "Modules", code: "MOD" },
  { to: "/reports", label: "Reports", code: "REP" },
  { to: "/graph", label: "Graph", code: "GRP" },
  { to: "/templates", label: "Templates", code: "TPL" },
  { to: "/strategy", label: "Strategy", code: "STR" },
  { to: "/security", label: "Security", code: "SEC" },
  { to: "/edr", label: "EDR/OPSEC", code: "EDR" },
  { to: "/live", label: "Live", code: "LIV" }
];

const navGroups = [
  { label: "Core", items: navItems.slice(0, 1) },
  { label: "Operations", items: navItems.slice(1, 4) },
  { label: "Intelligence", items: navItems.slice(4, 7) },
  { label: "Control", items: navItems.slice(7) }
];

const pageMeta: Record<string, { eyebrow: string; description: string }> = {
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

const brandMarkPath = "/dashboard/brand/ares-mark.png";

interface CampaignEventSocketOptions {
  campaignId: string;
  enabled: boolean;
  onDisconnected: () => void;
  onEvent: (event: unknown) => void;
}

function useCampaignEventSocket({
  campaignId,
  enabled,
  onDisconnected,
  onEvent
}: CampaignEventSocketOptions): void {
  const socketRef = useRef<WebSocket | null>(null);
  const generationRef = useRef(0);
  const onDisconnectedRef = useRef(onDisconnected);
  const onEventRef = useRef(onEvent);
  onDisconnectedRef.current = onDisconnected;
  onEventRef.current = onEvent;

  useEffect(() => {
    generationRef.current += 1;
    const connectionGeneration = generationRef.current;
    let disposed = false;
    let ownedSocket: WebSocket | null = null;

    if (!enabled || !campaignId) {
      return;
    }

    const session = captureSession();
    if (!session.accessToken) {
      onDisconnectedRef.current();
      return;
    }

    void (async () => {
      try {
        const response = await api.websocketTicket(campaignId);
        const responseIsCanonical =
          response.expires_in === 30
          && /^[A-Za-z0-9_-]{43}$/.test(response.ticket);
        if (!responseIsCanonical) {
          throw new Error("Invalid WebSocket ticket response");
        }
        if (
          disposed
          || generationRef.current !== connectionGeneration
          || !isSessionCurrent(session)
        ) {
          return;
        }

        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const socket = new WebSocket(
          `${protocol}//${window.location.host}${campaignEventsPath(campaignId, response.ticket)}`
        );
        ownedSocket = socket;
        socketRef.current = socket;
        socket.onmessage = (event) => {
          try {
            onEventRef.current(JSON.parse(event.data));
          } catch {
            onEventRef.current(event.data);
          }
        };
        socket.onclose = () => {
          if (socketRef.current === socket) {
            socketRef.current = null;
            onDisconnectedRef.current();
          }
        };
      } catch {
        if (
          !disposed
          && generationRef.current === connectionGeneration
          && isSessionCurrent(session)
        ) {
          onDisconnectedRef.current();
        }
      }
    })();

    return () => {
      disposed = true;
      generationRef.current += 1;
      if (ownedSocket) {
        ownedSocket.onclose = null;
        ownedSocket.close();
        if (socketRef.current === ownedSocket) {
          socketRef.current = null;
        }
      }
    };
  }, [campaignId, enabled]);
}

export function CampaignEventSocketController(
  options: CampaignEventSocketOptions
): null {
  useCampaignEventSocket(options);
  return null;
}

function formatRole(role?: string): string {
  const labels: Record<string, string> = {
    team_lead: "Team Lead",
    operator: "Operator",
    recon: "Recon",
    reporter: "Reporter"
  };
  if (!role) {
    return "";
  }
  return labels[role] ?? role.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function DashboardShell({ children }: { children: ReactNode }) {
  const { user, loading, logout, logoutAll } = useAuth();
  const navigate = useNavigate();
  const writeDashboardSession = useDashboardSessionWriter();
  const [selectedCampaignId, setSelectedCampaignId] = useSessionState("ares.dashboard.selectedCampaignId", "");
  const [liveCampaignId, setLiveCampaignId] = useSessionState("ares.dashboard.live.campaignId", "");
  const [liveEvents, setLiveEvents] = useSessionState<unknown[]>("ares.dashboard.live.events", []);
  const [liveConnected, setLiveConnected] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [operatorMenuOpen, setOperatorMenuOpen] = useState(false);
  const [telemetryOpen, setTelemetryOpen] = useState(false);
  const [readNotificationIds, setReadNotificationIds] = useState<string[]>([]);
  const [deletedNotificationIds, setDeletedNotificationIds] = useState<string[]>([]);
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const telemetry = useQuery({ queryKey: ["telemetry"], queryFn: api.telemetry });
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const modules = useQuery({ queryKey: ["modules"], queryFn: api.modules });
  const templates = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const reports = useQuery({
    queryKey: ["reports", selectedCampaignId],
    queryFn: () => api.reports(selectedCampaignId),
    enabled: Boolean(selectedCampaignId)
  });
  const telemetrySnapshot = telemetry.data as TelemetrySnapshot | undefined;

  const queryClient = useQueryClient();
  const deleteCampaignMutation = useMutation({
    mutationFn: (id: string) => api.deleteCampaign(id),
    onSuccess: async (_, id) => {
      queryClient.setQueryData<Campaign[]>(["campaigns"], (old) =>
        old ? old.filter((c) => c.id !== id) : []
      );
      queryClient.removeQueries({ queryKey: ["campaign", id] });
      queryClient.removeQueries({ queryKey: ["findings", id] });
      queryClient.removeQueries({ queryKey: ["cvss", id] });
      queryClient.removeQueries({ queryKey: ["reports", id] });

      if (selectedCampaignId === id) {
        setSelectedCampaignId("");
      }
      if (liveCampaignId === id) {
        setLiveCampaignId("");
        setLiveConnected(false);
      }

      await queryClient.invalidateQueries({ queryKey: ["telemetry"], refetchType: "all" });
      await queryClient.invalidateQueries({ queryKey: ["monthlyStats"], refetchType: "all" });
      await queryClient.invalidateQueries({ queryKey: ["campaigns"], refetchType: "all" });
    }
  });

  const deleteCampaign = useCallback(
    async (id: string): Promise<boolean> => {
      try {
        await deleteCampaignMutation.mutateAsync(id);
        return true;
      } catch {
        return false;
      }
    },
    [deleteCampaignMutation]
  );

  useEffect(() => {
    if (selectedCampaignId && campaigns.isSuccess) {
      const exists = (campaigns.data ?? []).some((c) => c.id === selectedCampaignId);
      if (!exists) {
        setSelectedCampaignId("");
      }
    }
  }, [selectedCampaignId, campaigns.data, campaigns.isSuccess, setSelectedCampaignId]);

  useEffect(() => {
    if (liveCampaignId && campaigns.isSuccess) {
      const exists = (campaigns.data ?? []).some((c) => c.id === liveCampaignId);
      if (!exists) {
        setLiveCampaignId("");
        setLiveConnected(false);
      }
    }
  }, [liveCampaignId, campaigns.data, campaigns.isSuccess, setLiveCampaignId, setLiveConnected]);

  useCampaignEventSocket({
    campaignId: liveCampaignId,
    enabled: liveConnected,
    onDisconnected: () => setLiveConnected(false),
    onEvent: (event) => setLiveEvents((items) => [event, ...items].slice(0, 100))
  });

  const campaignList = campaigns.data ?? [];

  const dashboardUi = useMemo<DashboardUiState>(
    () => ({
      selectedCampaignId,
      setSelectedCampaignId,
      liveCampaignId,
      setLiveCampaignId,
      liveConnected,
      setLiveConnected,
      liveEvents,
      clearLiveEvents: () => setLiveEvents([]),
      campaigns: campaignList,
      campaignsLoading: campaigns.isLoading,
      campaignsError: campaigns.error,
      deleteCampaign,
      refetchCampaigns: () => queryClient.invalidateQueries({ queryKey: ["campaigns"], refetchType: "all" })
    }),
    [
      campaignList,
      campaigns.error,
      campaigns.isLoading,
      deleteCampaign,
      liveCampaignId,
      liveConnected,
      liveEvents,
      queryClient,
      selectedCampaignId,
      setLiveCampaignId,
      setLiveConnected,
      setLiveEvents,
      setSelectedCampaignId
    ]
  );
  const searchResults = useMemo<SearchResult[]>(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return [];
    const results: SearchResult[] = [];
    const addIfMatch = (result: SearchResult, haystack: string) => {
      if (haystack.toLowerCase().includes(term)) {
        results.push(result);
      }
    };

    navItems.forEach((item) => {
      addIfMatch(
        {
          id: `page:${item.to}`,
          label: item.label,
          detail: `Open ${item.to === "/" ? "Overview" : item.to}`,
          route: item.to
        },
        `${item.label} ${item.to}`
      );
    });

    (campaigns.data ?? []).forEach((campaign) => {
      addIfMatch(
        {
          id: `campaign:${campaign.id}`,
          label: campaign.name || campaign.id,
          detail: `Campaign ${campaign.id.slice(0, 12)}`,
          route: "/campaigns",
          onSelect: () => {
            setSelectedCampaignId(campaign.id);
            writeDashboardSession("ares.dashboard.campaigns.tab", "Scope");
          }
        },
        `${campaign.name ?? ""} ${campaign.id} ${campaign.client ?? ""} ${campaign.status ?? ""}`
      );
    });

    (modules.data ?? []).forEach((module) => {
      addIfMatch(
        {
          id: `module:${module.id}`,
          label: module.id,
          detail: module.description || "Module",
          route: "/modules",
          onSelect: () => {
            writeDashboardSession("ares.dashboard.modules.selectedId", module.id);
            writeDashboardSession("ares.dashboard.modules.tab", "Run Panel");
          }
        },
        `${module.id} ${module.name ?? ""} ${module.description ?? ""} ${module.category ?? ""} ${module.mitre ?? ""}`
      );
    });

    const reportItems = reports.data?.reports ?? [];
    reportItems.forEach((report) => {
      addIfMatch(
        {
          id: `report:${report.filename}`,
          label: report.filename,
          detail: `${report.format || "report"} artifact`,
          route: "/reports",
          onSelect: () => {
            writeDashboardSession("ares.dashboard.reports.tab", "Library");
          }
        },
        `${report.filename} ${report.format ?? ""}`
      );
    });

    const templateItems = Array.isArray(templates.data) ? templates.data as Array<Record<string, unknown>> : [];
    templateItems.forEach((template, index) => {
      const templateName = String(template.name ?? template.id ?? index);
      addIfMatch(
        {
          id: `template:${templateName}`,
          label: templateName,
          detail: String(template.description ?? "Campaign template"),
          route: "/templates",
          onSelect: () => {
            writeDashboardSession("ares.dashboard.templates.name", templateName);
            writeDashboardSession("ares.dashboard.templates.tab", "Plan Builder");
          }
        },
        `${templateName} ${String(template.description ?? "")}`
      );
    });

    return results.slice(0, 8);
  }, [
    campaigns.data,
    modules.data,
    reports.data,
    searchTerm,
    setSelectedCampaignId,
    templates.data,
    writeDashboardSession
  ]);

  const notifications = useMemo<DashboardNotification[]>(() => {
    const items: DashboardNotification[] = [];
    const snapshot = telemetry.data as TelemetrySnapshot | undefined;
    const healthSnapshot = health.data as Record<string, unknown> | undefined;
    const healthStatus = String(healthSnapshot?.status ?? "").toLowerCase();

    if (health.isError) {
      items.push({ id: "health:error", title: "Backend health check failed", detail: "ARES API health is not reachable.", tone: "danger" });
    } else if (health.isSuccess && healthStatus && !["ok", "healthy", "online"].includes(healthStatus)) {
      items.push({ id: `health:status:${healthStatus}`, title: "Backend status needs attention", detail: String(healthSnapshot?.status), tone: "warn" });
    }
    if (telemetry.isError) {
      items.push({ id: "telemetry:error", title: "Telemetry unavailable", detail: "Runtime telemetry could not be loaded.", tone: "warn" });
    }
    if (campaigns.isError) {
      items.push({ id: "campaigns:error", title: "Campaign list unavailable", detail: "Campaign data could not be loaded.", tone: "warn" });
    }
    if (modules.isError) {
      items.push({ id: "modules:error", title: "Module catalog unavailable", detail: "Module metadata could not be loaded.", tone: "warn" });
    }
    if (reports.isError && selectedCampaignId) {
      items.push({ id: `reports:error:${selectedCampaignId}`, title: "Report library unavailable", detail: "Selected campaign reports could not be loaded.", tone: "warn" });
    }

    const failedRuns = metricNumber(snapshot?.modules, "failed");
    const errorRate = metricNumber(snapshot?.modules, "error_rate");
    const unhealthyWorkers = metricNumber(snapshot?.workers, "unhealthy");
    const queueDepth = metricNumber(snapshot?.queue, "depth");
    if (failedRuns > 0) {
      items.push({ id: `telemetry:failed-runs:${failedRuns}`, title: "Failed module runs", detail: `${failedRuns} failed module run(s) reported by telemetry.`, tone: "warn" });
    }
    if (errorRate > 0) {
      items.push({ id: `telemetry:error-rate:${errorRate}`, title: "Runtime error rate above zero", detail: `${formatRate(errorRate)} module error rate.`, tone: "warn" });
    }
    if (unhealthyWorkers > 0) {
      items.push({ id: `telemetry:workers:${unhealthyWorkers}`, title: "Unhealthy worker detected", detail: `${unhealthyWorkers} worker(s) unhealthy.`, tone: "danger" });
    }
    if (queueDepth > 0) {
      items.push({ id: `telemetry:queue:${queueDepth}`, title: "Queue has pending work", detail: `${queueDepth} queued task(s).`, tone: "info" });
    }
    return items;
  }, [campaigns.isError, health.data, health.isError, health.isSuccess, modules.isError, reports.isError, selectedCampaignId, telemetry.data, telemetry.isError]);

  const activeNotificationKey = useMemo(() => notifications.map((item) => item.id).join("|"), [notifications]);
  const visibleNotifications = useMemo(
    () => notifications.filter((item) => !deletedNotificationIds.includes(item.id)),
    [deletedNotificationIds, notifications]
  );
  const unreadNotificationCount = visibleNotifications.filter((item) => !readNotificationIds.includes(item.id)).length;

  useEffect(() => {
    const activeIds = activeNotificationKey ? activeNotificationKey.split("|") : [];
    setReadNotificationIds((current) => current.filter((id) => activeIds.includes(id)));
    setDeletedNotificationIds((current) => current.filter((id) => activeIds.includes(id)));
  }, [activeNotificationKey]);

  function markVisibleNotificationsRead(): void {
    const visibleIds = visibleNotifications.map((item) => item.id);
    if (visibleIds.length === 0) return;
    setReadNotificationIds((current) => unique([...current, ...visibleIds]));
  }

  function toggleNotifications(): void {
    const nextOpen = !notificationsOpen;
    if (nextOpen) {
      markVisibleNotificationsRead();
    }
    setNotificationsOpen(nextOpen);
  }

  function deleteNotification(id: string): void {
    setDeletedNotificationIds((current) => unique([...current, id]));
    setReadNotificationIds((current) => unique([...current, id]));
  }

  function clearNotifications(): void {
    const visibleIds = visibleNotifications.map((item) => item.id);
    setDeletedNotificationIds((current) => unique([...current, ...visibleIds]));
    setReadNotificationIds((current) => unique([...current, ...visibleIds]));
  }

  function selectSearchResult(result: SearchResult): void {
    result.onSelect?.();
    navigate(result.route);
    setSearchTerm("");
    setSearchOpen(false);
  }

  if (loading) {
    return <ScreenMessage title="ARES" body="Loading session" />;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return (
    <DashboardUiProvider value={dashboardUi}>
      <div className={sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"}>
        <aside className="sidebar">
          <div className="sidebar-brand">
            <img className="sidebar-mark" src={brandMarkPath} alt="" aria-hidden="true" />
            <div className="min-w-0">
              <div className="sidebar-title">ARES</div>
              <div className="sidebar-subtitle">Automated Red Team Engagement System</div>
            </div>
          </div>
          <nav className="sidebar-nav" aria-label="Dashboard navigation">
            {navGroups.map((group) => (
              <div className="nav-group" key={group.label}>
                <div className="nav-group-label">{group.label}</div>
                <div className="grid gap-1">
                  {group.items.map((item) => {
                    const count = item.to === "/campaigns" ? (campaigns.data ?? []).length : item.to === "/modules" ? (modules.data ?? []).length : null;
                    return (
                      <NavLink key={item.to} to={item.to} end={item.to === "/"} className="nav-link" title={sidebarCollapsed ? item.label : undefined}>
                        <span className="nav-code font-mono">{item.code}</span>
                        <span className="nav-label">{item.label}</span>
                        {count !== null && count > 0 && !sidebarCollapsed ? (
                          <span className="nav-count-badge font-mono">{count}</span>
                        ) : null}
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
        </aside>
        <main className="main-shell">
          <header className="topbar">
            <div className="topbar-left">
              <button
                className="icon-button"
                aria-label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
                aria-pressed={sidebarCollapsed}
                onClick={() => setSidebarCollapsed((value) => !value)}
                type="button"
              >
                <Menu size={16} />
              </button>

              <div className="topbar-scope-wrap" title="Active campaign engagement scope">
                <select
                  className="topbar-scope-select"
                  aria-label="Active campaign scope"
                  value={selectedCampaignId && campaignList.some((c) => c.id === selectedCampaignId) ? selectedCampaignId : ""}
                  onChange={(e) => {
                    setSelectedCampaignId(e.target.value);
                    if (e.target.value) {
                      writeDashboardSession("ares.dashboard.campaigns.tab", "Scope");
                    }
                  }}
                >
                  <option value="">Scope: Global / All</option>
                  {campaignList.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name || c.id.slice(0, 12)}
                    </option>
                  ))}
                </select>
              </div>

              <div className="topbar-search-wrap">
                <label className="topbar-search" aria-label="Dashboard search">
                  <Search size={15} />
                  <input
                    aria-label="Search dashboard"
                    onBlur={() => window.setTimeout(() => setSearchOpen(false), 140)}
                    onChange={(event) => {
                      setSearchTerm(event.target.value);
                      setSearchOpen(true);
                    }}
                    onFocus={() => setSearchOpen(true)}
                    onKeyDown={(event) => {
                      if (event.key === "Escape") {
                        setSearchOpen(false);
                      }
                      if (event.key === "Enter" && searchResults.length > 0) {
                        event.preventDefault();
                        selectSearchResult(searchResults[0]);
                      }
                    }}
                    placeholder="Search campaigns, modules, reports"
                    value={searchTerm}
                  />
                  <span className="search-kbd-badge">/</span>
                </label>
                {searchOpen && (
                  <div className="search-results" role="listbox">
                    {searchTerm.trim() ? (
                      searchResults.length > 0 ? (
                        searchResults.map((result) => (
                          <button key={result.id} onMouseDown={(event) => event.preventDefault()} onClick={() => selectSearchResult(result)} type="button">
                            <strong>{result.label}</strong>
                            <span>{result.detail}</span>
                          </button>
                        ))
                      ) : (
                        <div className="search-empty">No matches found</div>
                      )
                    ) : (
                      <div className="search-empty">Type to search dashboard</div>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="topbar-right">
              {/* Telemetry Operational Status */}
              <div className="relative">
                {(() => {
                  const healthSnapshot = health.data as Record<string, unknown> | undefined;
                  const healthStatus = String(healthSnapshot?.status ?? "").toLowerCase();
                  const isHealthOk = health.isSuccess && healthStatus === "ok";
                  const isHealthDegraded = health.isSuccess && healthStatus === "degraded";
                  const isHealthOffline = health.isError;
                  const isHealthConnecting = health.isLoading;

                  let topbarDotClass = "online";
                  let topbarText = "Operational";

                  if (isHealthOffline) {
                    topbarDotClass = "danger";
                    topbarText = "Offline";
                  } else if (isHealthConnecting) {
                    topbarDotClass = "warning";
                    topbarText = "Connecting";
                  } else if (isHealthDegraded || telemetry.isError) {
                    topbarDotClass = "warning";
                    topbarText = isHealthDegraded ? "Degraded" : "Telemetry Lag";
                  } else if (isHealthOk) {
                    topbarDotClass = "online";
                    topbarText = "Operational";
                  }

                  return (
                    <button
                      className="topbar-status-btn"
                      type="button"
                      aria-label="System operational status"
                      aria-expanded={telemetryOpen}
                      onClick={() => setTelemetryOpen((v) => !v)}
                      title={`System operational health: ${topbarText} (API: ${healthStatus || "pending"})`}
                    >
                      <span className={`status-dot ${topbarDotClass}`} />
                      <span className="status-title">{topbarText}</span>
                      <span className="status-pill-count font-mono">
                        {telemetrySnapshot ? `${metricNumber(telemetrySnapshot.modules, "total")} runs` : healthSnapshot?.version ? `v${healthSnapshot.version}` : "v6.0"}
                      </span>
                    </button>
                  );
                })()}

                {telemetryOpen && (
                  <aside className="telemetry-popover" aria-label="Enclave telemetry quick view">
                    <div className="telemetry-popover-header">
                      <div className="flex items-center gap-2">
                        <span className={`status-dot ${health.isSuccess && !telemetry.isError ? "online" : "warning"}`} />
                        <strong>Enclave Subsystem Health</strong>
                      </div>
                      <button className="icon-button icon-button-small" onClick={() => setTelemetryOpen(false)} aria-label="Close telemetry view" type="button">
                        <X size={13} />
                      </button>
                    </div>
                    <div className="telemetry-popover-grid">
                      <div className="popover-stat">
                        <span>API Backend</span>
                        <strong>{health.isSuccess ? String((health.data as Record<string, unknown> | undefined)?.status ?? "ok").toUpperCase() : health.isError ? "OFFLINE" : "CHECKING"}</strong>
                      </div>
                      <div className="popover-stat">
                        <span>Worker Pool</span>
                        <strong>{metricNumber(telemetrySnapshot?.workers, "active")} active</strong>
                      </div>
                      <div className="popover-stat">
                        <span>Task Queue</span>
                        <strong>{metricNumber(telemetrySnapshot?.queue, "depth")} queued</strong>
                      </div>
                      <div className="popover-stat">
                        <span>Live Ingest</span>
                        <div className="mt-0.5 flex items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 rounded-full ${telemetry.isSuccess ? "bg-emerald-400" : "bg-zinc-500"}`} />
                          <strong className="!mt-0 text-zinc-100">{telemetry.isSuccess ? "Active" : "Standby"}</strong>
                        </div>
                      </div>
                    </div>
                  </aside>
                )}
              </div>

              {/* Notifications */}
              <button
                className="icon-button has-badge"
                aria-expanded={notificationsOpen}
                aria-label="Notifications"
                onClick={toggleNotifications}
                type="button"
              >
                <Bell size={15} />
                {unreadNotificationCount > 0 ? <span>{unreadNotificationCount}</span> : null}
              </button>
              {notificationsOpen && (
                <aside className="notification-drawer" aria-label="Notifications">
                  <SectionHeader
                    title="Notifications"
                    action={visibleNotifications.length > 0 ? (
                      <button className="btn btn-compact" onClick={clearNotifications} type="button">
                        Clear all
                      </button>
                    ) : <span className="badge">0</span>}
                  />
                  {visibleNotifications.length > 0 ? (
                    <div className="notification-list">
                      {visibleNotifications.map((item) => (
                        <div className={`notification-item notification-${item.tone}`} key={item.id}>
                          <div className="notification-item-header">
                            <strong>{item.title}</strong>
                            <button className="icon-button icon-button-small" aria-label={`Dismiss ${item.title}`} onClick={() => deleteNotification(item.id)} type="button">
                              <Trash2 size={13} />
                            </button>
                          </div>
                          <p>{item.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState text="No notifications." />
                  )}
                </aside>
              )}

              {/* Consolidated Operator Menu */}
              <div className="operator-menu-wrap">
                <button
                  className="operator-trigger"
                  type="button"
                  aria-expanded={operatorMenuOpen}
                  onClick={() => setOperatorMenuOpen((v) => !v)}
                  aria-label="Operator clearance menu"
                >
                  <span className="operator-avatar">{user.username.slice(0, 1).toUpperCase()}</span>
                  <div className="operator-info">
                    <strong>{user.username}</strong>
                    <small>{formatRole(user.role)}</small>
                  </div>
                  <ChevronDown size={13} className={`chevron-indicator ${operatorMenuOpen ? "open" : ""}`} />
                </button>

                {operatorMenuOpen && (
                  <div className="operator-dropdown" role="menu">
                    <div className="operator-dropdown-header">
                      <div className="operator-dropdown-title">Operator Clearance</div>
                      <div className="operator-dropdown-badge">{formatRole(user.role)}</div>
                      <div className="operator-dropdown-sub">Signed in as {user.username}</div>
                    </div>
                    <div className="operator-dropdown-actions">
                      <button
                        className="operator-action-item"
                        role="menuitem"
                        onClick={() => {
                          setOperatorMenuOpen(false);
                          void logout();
                        }}
                        type="button"
                      >
                        <span>Logout</span>
                      </button>
                      <button
                        className="operator-action-item danger"
                        role="menuitem"
                        onClick={() => {
                          setOperatorMenuOpen(false);
                          void logoutAll();
                        }}
                        type="button"
                      >
                        <span>Logout all devices</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </header>
          <div className="content-shell">{children}</div>
        </main>
      </div>
    </DashboardUiProvider>
  );
}

export function OverviewPage() {
  const navigate = useNavigate();
  const writeDashboardSession = useDashboardSessionWriter();
  const { campaigns: campaignList, campaignsLoading } = useDashboardUi();
  const telemetry = useQuery({ queryKey: ["telemetry"], queryFn: api.telemetry });
  const monthlyStats = useQuery({ queryKey: ["monthlyStats"], queryFn: api.monthlyStats });
  const snapshot = telemetry.data as TelemetrySnapshot | undefined;
  const monthlyData = monthlyStats.data as MonthlyFindingStats | undefined;
  const nonDeletedCampaigns = campaignList.filter(
    (campaign) => String(campaign.status ?? "").toLowerCase() !== "deleted"
  );
  const runningCampaigns = nonDeletedCampaigns.filter((campaign) =>
    ["running", "active", "executing"].includes(String(campaign.status ?? "").toLowerCase())
  );
  const trackedCount = nonDeletedCampaigns.length;
  const runningCount = runningCampaigns.length;

  const findings = typeof monthlyData?.confirmed_findings === "number" ? monthlyData.confirmed_findings : 0;
  const monthlyTotal = typeof monthlyData?.total === "number" ? monthlyData.total : 0;
  const monthlySeries = normalizeMonthlySeries(monthlyData?.period, monthlyData?.series);

  // Dynamic header status subtitle (strictly distinguish running execution vs in-scope campaigns)
  let overviewSubtitle: string;
  if (trackedCount === 0) {
    overviewSubtitle = "Enclave standby · No campaigns in scope · Ready for campaign deployment";
  } else if (runningCount > 0) {
    overviewSubtitle = `${runningCount} active execution${runningCount === 1 ? "" : "s"} · ${trackedCount} in scope · Enclave telemetry streaming`;
  } else {
    overviewSubtitle = `${trackedCount} campaign${trackedCount === 1 ? "" : "s"} in scope · Telemetry pipeline standby · Fail-closed policy enforced`;
  }

  // Fresh install empty-state (Task 5)
  if (!campaignsLoading && trackedCount === 0) {
    return (
      <Page title="Overview" subtitle={overviewSubtitle}>
        <div className="dashboard-empty-hero">
          <div className="fresh-hero-icon-wrap">
            <ShieldAlert size={32} className="text-rose-500" />
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
                writeDashboardSession("ares.dashboard.campaigns.tab", "List");
                navigate("/campaigns");
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

  // Tactical operational highlights (Task 2 & 3)
  const failedRuns = metricNumber(snapshot?.modules, "failed");
  const errorRate = metricNumber(snapshot?.modules, "error_rate");
  const hostsDiscovered = metricNumber(snapshot?.hosts, "discovered");
  const hostsOwned = metricNumberOrNull(snapshot?.hosts, "owned");

  return (
    <Page title="Overview" subtitle={overviewSubtitle}>
      <div className="dashboard-grid">
        <TelemetryPanel snapshot={snapshot} loading={telemetry.isLoading} confirmedFindings={findings} />
        <div className="side-stack">
          <section className="panel-subtle">
            <SectionHeader title="Highlights" />
            <div className="highlight-list">
              {runningCount > 0 ? (
                <HighlightRow
                  label="Engagement Posture"
                  value={`${runningCount} Running`}
                  tone="low"
                  detail={`${runningCount} engagement${runningCount === 1 ? "" : "s"} actively executing validation modules`}
                />
              ) : trackedCount > 0 ? (
                <HighlightRow
                  label="Engagement Posture"
                  value="Staged"
                  tone="neutral"
                  detail={
                    trackedCount === 1
                      ? "1 campaign in scope — awaiting execution run"
                      : `${trackedCount} campaigns in scope — awaiting execution run`
                  }
                />
              ) : (
                <HighlightRow
                  label="Engagement Posture"
                  value="Standby"
                  tone="neutral"
                  detail="No active engagements"
                />
              )}

              {failedRuns > 0 ? (
                <HighlightRow
                  label="Execution Health"
                  value={`${failedRuns} Failed`}
                  tone="high"
                  detail={`${formatRate(errorRate)} module failure rate detected`}
                />
              ) : snapshot ? (
                <HighlightRow
                  label="Execution Health"
                  value="Nominal"
                  tone="low"
                  detail="Zero module execution errors recorded"
                />
              ) : (
                <HighlightRow
                  label="Execution Health"
                  value="Standby"
                  tone="neutral"
                  detail="Awaiting telemetry sample ingestion"
                />
              )}

              {hostsDiscovered > 0 ? (
                <HighlightRow
                  label="Attack Surface"
                  value={`${hostsDiscovered} Mapped`}
                  tone={hostsOwned && hostsOwned > 0 ? "high" : "low"}
                  detail={hostsOwned && hostsOwned > 0 ? `${hostsOwned} targets owned` : "Perimeter discovered, 0 targets owned"}
                />
              ) : (
                <HighlightRow
                  label="Attack Surface"
                  value="Unmapped"
                  tone="neutral"
                  detail="Run recon modules to map attack surface"
                />
              )}
            </div>
          </section>

          <section className="panel-subtle">
            <SectionHeader title="Monthly Statistics" />
            <div className="monthly-stat">
              <span>{formatMetric(monthlyTotal)}</span>
              <small>{monthlyData?.label ?? "Security signals this cycle"}</small>
            </div>
            {monthlyStats.isPending ? <p className="text-sm text-zinc-400">Loading monthly activity...</p> : null}
            {monthlyStats.isError ? <p className="text-sm text-zinc-400">Monthly activity unavailable.</p> : null}
            {!monthlyStats.isPending && !monthlyStats.isError && monthlyTotal === 0 ? (
              <p className="text-sm text-zinc-400">No monthly activity yet</p>
            ) : null}
            {!monthlyStats.isPending && !monthlyStats.isError && monthlyTotal > 0 && monthlySeries.some((value) => value.count > 0) ? (
              <SparklineBars values={monthlySeries} />
            ) : null}
          </section>
        </div>
      </div>
      <CampaignTable campaigns={campaignList} />
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

export function CampaignsPage() {
  const queryClient = useQueryClient();
  const {
    selectedCampaignId: selected,
    setSelectedCampaignId: setSelected,
    campaigns: campaignList,
    deleteCampaign,
    refetchCampaigns
  } = useDashboardUi();
  const [name, setName] = useSessionState("ares.dashboard.campaigns.create.name", "");
  const [client, setClient] = useSessionState("ares.dashboard.campaigns.create.client", "Internal");
  const [targets, setTargets] = useSessionState("ares.dashboard.campaigns.create.targets", "");
  const [scope, setScope] = useSessionState("ares.dashboard.campaigns.create.scope", "");
  const [noiseProfile, setNoiseProfile] = useSessionState("ares.dashboard.campaigns.create.noiseProfile", "stealth");
  const [createWarning, setCreateWarning] = useState("");
  const [otherId, setOtherId] = useSessionState("ares.dashboard.campaigns.compareId", "");
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.campaigns.tab", "List");
  const [deleteError, setDeleteError] = useState<unknown>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const detail = useQuery({
    queryKey: ["campaign", selected],
    queryFn: () => api.campaign(selected),
    enabled: Boolean(selected)
  });
  const findings = useQuery({
    queryKey: ["findings", selected],
    queryFn: () => api.findings(selected),
    enabled: Boolean(selected)
  });
  const cvss = useQuery({
    queryKey: ["cvss", selected],
    queryFn: () => api.cvss(selected),
    enabled: Boolean(selected)
  });
  const diff = useQuery({
    queryKey: ["diff", selected, otherId],
    queryFn: () => api.diffCampaign(selected, otherId),
    enabled: Boolean(selected && otherId)
  });
  const create = useMutation({
    mutationFn: () =>
      api.createCampaign({
        name: name.trim(),
        client: client.trim(),
        targets: splitLines(targets),
        scope_cidrs: splitLines(scope),
        noise_profile: noiseProfile
      }),
    onSuccess: (campaign) => {
      setSelected(campaign.id);
      setName("");
      setTargets("");
      setScope("");
      setNoiseProfile("stealth");
      setCreateWarning("");
      setActiveTab("Scope");
      queryClient.setQueryData<Campaign[]>(["campaigns"], (old) => [campaign, ...(old ?? [])]);
      void queryClient.invalidateQueries({ queryKey: ["campaigns"], refetchType: "all" });
    }
  });
  const restore = useMutation({ mutationFn: () => api.restoreVault(selected) });
  const run = useMutation({
    mutationFn: () => api.runCampaign(selected, { plan: { stages: [] }, global_params: {}, dry_run: true })
  });

  const handleDelete = async (targetId: string) => {
    if (!targetId) return;
    if (!window.confirm("Delete this campaign and its stored findings, hosts, credentials, and loot?")) {
      return;
    }
    setIsDeleting(true);
    setDeleteError(null);
    try {
      const ok = await deleteCampaign(targetId);
      if (ok) {
        setSelected("");
        setOtherId("");
        setActiveTab("List");
      } else {
        setDeleteError("Failed to delete campaign");
      }
    } catch (err) {
      setDeleteError(err);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Page
      title="Campaigns"
      actions={<span className="status-pill">{campaignList.length} campaigns</span>}
      tabs={["List", "Scope", "Findings"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "List" && (
        <>
          <section className="panel p-4">
            <SectionHeader title="Create Campaign" />
            <form className="grid gap-3" onSubmit={(e) => {
              e.preventDefault();
              if (!e.currentTarget.reportValidity()) return;
              const invalidScopeEntries = findInvalidScopeEntries(scope);
              if (invalidScopeEntries.length > 0) {
                setCreateWarning(`Scope CIDRs must be valid IPv4 CIDR/IP entries. Invalid: ${invalidScopeEntries.slice(0, 3).join(", ")}. Example: 10.0.0.0/24`);
                return;
              }
              setCreateWarning("");
              create.mutate();
            }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <input className="field" required placeholder="Name" value={name} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setName(e.target.value); }} />
                <input className="field" required placeholder="Client" value={client} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setClient(e.target.value); }} />
              </div>
              <select className="field" value={noiseProfile} onChange={(e) => { setCreateWarning(""); setNoiseProfile(e.target.value); }}>
                <option value="stealth">Stealth</option>
                <option value="normal">Normal</option>
                <option value="aggressive">Aggressive</option>
              </select>
              <textarea className="field min-h-20" required placeholder="Targets" value={targets} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setTargets(e.target.value); }} />
              <textarea className="field min-h-20" required placeholder="Scope CIDRs" value={scope} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setScope(e.target.value); }} />
              {createWarning && <p className="notice notice-danger">{createWarning}</p>}
              <button className="btn btn-primary" disabled={create.isPending} type="submit">
                Create Campaign
              </button>
            </form>
            <DataPanel title="Create Error" data={create.error} />
          </section>
          <CampaignTable campaigns={campaignList} />
        </>
      )}
      {activeTab === "Scope" && (
        <>
          <section className="panel p-4">
            <SectionHeader title="Campaign Detail" />
            <div>
              <label htmlFor="scope-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
                Target Campaign
              </label>
              <CampaignPicker id="scope-campaign-select" campaigns={campaignList} value={selected} onChange={setSelected} />
            </div>
            <CampaignScopeSummary campaign={detail.data ?? campaignList.find((item) => item.id === selected)} loading={detail.isFetching} />
            <div className="mt-3 flex flex-wrap gap-2">
              <button className="btn" disabled={!selected} onClick={() => restore.mutate()}>
                Restore Vault
              </button>
              <button className="btn" disabled={!selected} onClick={() => run.mutate()}>
                Dry Run Plan
              </button>
              <button
                className="btn btn-danger"
                disabled={!selected || isDeleting}
                onClick={() => handleDelete(selected)}
              >
                {isDeleting ? "Deleting…" : "Delete"}
              </button>
              <input className="field max-w-xs" placeholder="Compare campaign ID" value={otherId} onChange={(e) => setOtherId(e.target.value)} />
            </div>
          </section>
          <DataPanel title="Delete Error" data={deleteError} />
          <DataPanel title="Campaign Detail Error" data={detail.error} />
          <DataPanel title="CVSS Error" data={cvss.error} />
          <DataPanel title="Campaign Diff Error" data={diff.error} />
          {cvss.data && <CvssScoreCard data={cvss.data} />}
          {diff.data && <CampaignDiffCard data={diff.data} />}
        </>
      )}
      {activeTab === "Findings" && (
        <section className="grid gap-4">
          <section className="panel p-4">
            <SectionHeader title="Campaign Findings" />
            <div>
              <label htmlFor="findings-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
                Target Campaign
              </label>
              <CampaignPicker id="findings-campaign-select" campaigns={campaignList} value={selected} onChange={setSelected} />
            </div>
            {!selected ? <EmptyState text="Select a campaign to review findings." /> : null}
          </section>
          {selected ? <DataPanel title="Findings Error" data={findings.error} /> : null}
          {selected ? <FindingsTable findings={findings.data ?? []} /> : null}
        </section>
      )}
    </Page>
  );
}

function ExecutionChainsPanel({
  chains,
  moduleIds,
  onSelectModule
}: {
  chains: ExecutionChain[];
  moduleIds: Set<string>;
  onSelectModule: (moduleId: string) => void;
}) {
  if (chains.length === 0) {
    return <EmptyState text="No execution chains are available." />;
  }
  return (
    <section className="grid gap-3">
      {chains.map((chain) => (
        <article className="panel p-4" key={chain.id}>
          <SectionHeader
            title={chain.title}
            eyebrow={chain.category}
            description={chain.description}
            action={<span className="badge">{chain.stages.length} stages</span>}
          />
          <div className="grid gap-3">
            {chain.stages.map((stage) => (
              <div className="compact-row" key={`${chain.id}-${stage.order}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="badge">Step {stage.order}</span>
                    <strong>{stage.title}</strong>
                    {stage.final_goal && <span className="badge badge-low">Final goal</span>}
                  </div>
                  <span className="text-xs font-medium text-zinc-400">
                    {stage.uses_previous_output ? "Uses prior output" : "Starts from campaign inputs"}
                  </span>
                </div>
                <p className="mt-2 text-sm text-zinc-300">{stage.purpose}</p>
                {stage.module_ids.length > 0 && (
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <strong className="text-sm">Run</strong>
                    {stage.module_ids.map((moduleId) => (
                      <button
                        className="btn btn-compact"
                        disabled={!moduleIds.has(moduleId)}
                        key={moduleId}
                        onClick={() => onSelectModule(moduleId)}
                        title={moduleIds.has(moduleId) ? `Open ${moduleId} in the run panel` : "Module is not available in the current catalog"}
                        type="button"
                      >
                        {moduleId}
                      </button>
                    ))}
                  </div>
                )}
                <div className="mt-3 grid gap-1 text-xs text-zinc-400">
                  <span><strong>Inputs:</strong> {stage.required_inputs.join(", ") || "none"}</span>
                  <span><strong>Produces:</strong> {stage.produces.join("; ") || "none"}</span>
                  <span><strong>Next:</strong> {stage.next_action}</span>
                </div>
              </div>
            ))}
          </div>
        </article>
      ))}
    </section>
  );
}

export function ModulesPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const queryClient = useQueryClient();
  const modules = useQuery({ queryKey: ["modules"], queryFn: api.modules });
  const executionChains = useQuery({ queryKey: ["executionChains"], queryFn: api.executionChains });
  const [selectedId, setSelectedId] = useSessionState("ares.dashboard.modules.selectedId", "");
  const [search, setSearch] = useSessionState("ares.dashboard.modules.search", "");
  const [category, setCategory] = useSessionState("ares.dashboard.modules.category", "");
  const [opsec, setOpsec] = useSessionState("ares.dashboard.modules.opsec", "");
  const [dryRun, setDryRun] = useSessionState("ares.dashboard.modules.dryRun", true);
  const [confirmed, setConfirmed] = useSessionState("ares.dashboard.modules.confirmed", false);
  const [params, setParams] = useSessionState<Record<string, unknown>>("ares.dashboard.modules.params", {});
  const [lastRunRecord, setLastRunRecord] = useSessionState<ModuleRunRecord | null>("ares.dashboard.modules.lastRun", null);
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.modules.tab", "Catalog");
  const previousSelectedId = useRef(selectedId);
  const campaignDetail = useQuery({
    queryKey: ["campaign", campaignId],
    queryFn: () => api.campaign(campaignId),
    enabled: Boolean(campaignId)
  });
  const run = useMutation({
    mutationFn: () => api.runModule(selectedId, buildModuleRunPayload(campaignId, params, dryRun)),
    onSuccess: (payload) => {
      setLastRunRecord({ campaignId, moduleId: selectedId, payload });
      setActiveTab("Results");
      if (!dryRun) {
        void queryClient.invalidateQueries({ queryKey: ["telemetry"] });
        void queryClient.invalidateQueries({ queryKey: ["monthlyStats"] });
      }
    },
    onError: (error) => {
      setLastRunRecord({ campaignId, moduleId: selectedId, payload: serializeError(error), isError: true });
      setActiveTab("Results");
      if (!dryRun) {
        void queryClient.invalidateQueries({ queryKey: ["telemetry"] });
        void queryClient.invalidateQueries({ queryKey: ["monthlyStats"] });
      }
    }
  });
  const list = useMemo(() => modules.data ?? [], [modules.data]);
  const moduleIds = useMemo(() => new Set(list.map((item) => item.id)), [list]);
  const relatedChainsByModule = useMemo(() => {
    const related = new Map<string, string[]>();
    for (const chain of executionChains.data ?? []) {
      for (const stage of chain.stages) {
        for (const moduleId of stage.module_ids) {
          const current = related.get(moduleId) ?? [];
          if (!current.includes(chain.title)) {
            current.push(chain.title);
          }
          related.set(moduleId, current);
        }
      }
    }
    return related;
  }, [executionChains.data]);
  const selected = list.find((item) => item.id === selectedId);
  const selectedCampaign = campaignDetail.data ?? campaignList.find((item) => item.id === campaignId);
  const scopeWarning = moduleScopeWarning(selected, selectedCampaign, params, dryRun);
  const categories = unique(list.map((item) => item.category || ""));
  const visible = list.filter((item) => {
    const haystack = `${item.id} ${item.name ?? ""} ${item.description ?? ""} ${item.mitre ?? ""}`.toLowerCase();
    return (
      (!search || haystack.includes(search.toLowerCase())) &&
      (!category || item.category === category) &&
      (!opsec || item.opsec_level === opsec)
    );
  });
  const sensitive = isSensitiveModule(selected);
  const feasibility = useQuery({
    queryKey: ["moduleFeasibility", selectedId, campaignId, params],
    queryFn: () =>
      api.moduleFeasibility(selectedId, {
        campaign_id: campaignId,
        params,
        target: typeof params.target === "string" ? params.target : undefined
      }),
    enabled: Boolean(selectedId && campaignId),
    staleTime: 10_000
  });
  const feasibilityReport = feasibility.data?.report;
  const isFeasibilityBlocked = Boolean(feasibilityReport && !feasibilityReport.feasible);
  const requiresConfirmation = sensitive || isFeasibilityBlocked;
  const dryRunSupported = selected?.dry_run_supported !== false;
  const kerberoastTargetMissing = selected?.id === "ad.kerberoast" && !String(params.target_user ?? "").trim();
  const [attemptedRun, setAttemptedRun] = useState(false);
  const executionConditionBlocked = (!requiresConfirmation || confirmed) && !run.isPending && (!dryRun || dryRunSupported) && !Boolean(scopeWarning) && !kerberoastTargetMissing;
  const canRun = Boolean(campaignId && selectedId) && executionConditionBlocked;
  const runBlocked = !canRun;
  const runHint = moduleRunHint(campaignId, selected, selectedCampaign, sensitive, confirmed, dryRun);
  const persistedRun = lastRunRecord?.campaignId === campaignId && lastRunRecord.moduleId === selectedId ? lastRunRecord : null;
  const runResult = (run.data ?? (!persistedRun?.isError ? persistedRun?.payload : undefined)) as Record<string, unknown> | undefined;
  const runError = run.error ?? (persistedRun?.isError ? persistedRun.payload : undefined);

  useEffect(() => {
    if (previousSelectedId.current === selectedId) {
      return;
    }
    previousSelectedId.current = selectedId;
    setParams({});
    setConfirmed(false);
    setDryRun(true);
  }, [selectedId, setConfirmed, setDryRun, setParams]);

  return (
    <Page
      title="Modules"
      actions={<span className="status-pill">{visible.length} shown</span>}
      tabs={["Catalog", "Execution Chains", "Run Panel", "Results"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Catalog" && (
        <section className="panel p-4">
          <SectionHeader title="Module Catalog" />
          <div className="mb-3 grid gap-2 sm:grid-cols-3">
            <label className="field-with-icon sm:col-span-3">
              <Search size={15} />
              <input placeholder="Search modules, MITRE, descriptions" value={search} onChange={(e) => setSearch(e.target.value)} />
            </label>
            <select className="field" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">Category</option>
              {categories.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <select className="field" value={opsec} onChange={(e) => setOpsec(e.target.value)}>
              <option value="">OPSEC</option>
              {unique(list.map((item) => item.opsec_level || "")).map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </div>
          <div className="grid max-h-[640px] gap-2 overflow-auto">
            {visible.map((item) => (
              <button
                className={`catalog-card ${selectedId === item.id ? "active" : ""}`}
                key={item.id}
                onClick={() => {
                  setSelectedId(item.id);
                  setActiveTab("Run Panel");
                }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-bold">{item.id}</div>
                    <div className="text-sm text-zinc-400">{item.description}</div>
                  </div>
                  <span className={opsecBadge(item.opsec_level)}>{item.opsec_level || "n/a"}</span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(item.mitre_list ?? []).slice(0, 4).map((technique) => <span className="badge" key={technique}>{technique}</span>)}
                  {(relatedChainsByModule.get(item.id) ?? []).slice(0, 2).map((chainTitle) => (
                    <span className="badge" key={chainTitle}>Chain: {chainTitle}</span>
                  ))}
                </div>
              </button>
            ))}
            {visible.length === 0 && (
              <EmptyState text="No modules match the current search and filters." />
            )}
          </div>
          <DataPanel title="Module Catalog Error" data={modules.error} />
        </section>
      )}
      {activeTab === "Execution Chains" && (
        <>
          {executionChains.isPending && <EmptyState text="Loading execution chains..." />}
          {executionChains.error && <DataPanel title="Execution Chain Error" data={executionChains.error} />}
          {!executionChains.isPending && !executionChains.error && (
            <ExecutionChainsPanel
              chains={executionChains.data ?? []}
              moduleIds={moduleIds}
              onSelectModule={(moduleId) => {
                setSelectedId(moduleId);
                setActiveTab("Run Panel");
              }}
            />
          )}
        </>
      )}
      {activeTab === "Run Panel" && (
        <section className="panel p-4">
          <SectionHeader
            title="Run Panel"
            eyebrow={selected ? selected.id : "Select module"}
            action={selected ? <span className={opsecBadge(selected.opsec_level)}>{selected.opsec_level || "n/a"}</span> : null}
          />
          {selected?.description && <p className="text-sm text-zinc-300">{selected.description}</p>}
          {selected && (selected.capability_flags?.length || selected.supported_modes?.length) ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {(selected.capability_flags ?? []).map((flag) => <span className="badge" key={flag}>{flag}</span>)}
              {(selected.supported_modes ?? []).map((mode) => <span className="badge" key={mode}>mode: {mode}</span>)}
            </div>
          ) : null}
          {selected?.dependency_notes?.length ? (
            <p className="mt-2 text-xs text-zinc-400 flex items-center gap-1.5">
              <Info size={13} className="text-zinc-500 shrink-0" />
              <span className="text-zinc-400 font-medium">Dependencies:</span> {selected.dependency_notes.join("; ")}
            </p>
          ) : null}
          {selected && !dryRunSupported && (
            <p className="mt-1 text-xs text-amber-400/80 flex items-center gap-1.5">
              <Info size={13} className="text-amber-400 shrink-0" />
              <span>Dry-run preview is unavailable for this module.</span>
            </p>
          )}
          <div className="mt-3">
            <label htmlFor="module-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
              Target Campaign
            </label>
            <CampaignPicker
              id="module-campaign-select"
              campaigns={campaignList}
              value={campaignId}
              hasError={attemptedRun && !campaignId}
              onChange={(id) => {
                setCampaignId(id);
                if (id) {
                  setAttemptedRun(false);
                }
              }}
            />
            {attemptedRun && !campaignId && (
              <p className="mt-1.5 flex items-center gap-1.5 text-xs text-rose-400" role="alert">
                <AlertTriangle size={13} className="shrink-0 text-rose-400" />
                Select a scoped campaign before executing this module.
              </p>
            )}
          </div>
          {campaignId && campaignDetail.isFetching && (
            <div className="notice mt-3">
              <Loader2 className="spin" size={16} /> Loading campaign scope...
            </div>
          )}
          <DataPanel title="Campaign Scope Error" data={campaignDetail.error} />
          {selected ? (
            <form
              aria-busy={run.isPending}
              className="mt-4 grid gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (!campaignId) {
                  setAttemptedRun(true);
                  return;
                }
                if (!executionConditionBlocked) {
                  return;
                }
                setAttemptedRun(false);
                run.mutate();
              }}
            >
              <ParamForm
                schema={selected.param_schema}
                values={params}
                onChange={setParams}
                requiredOverrides={selected.id === "ad.kerberoast" ? { target_user: true } : undefined}
              />
              {feasibility.isFetching && !feasibilityReport && (
                <div className="notice text-xs">
                  <Loader2 className="spin shrink-0" size={14} /> Assessing target defensive posture...
                </div>
              )}
              {feasibilityReport && (
                <div
                  className={`defense-feasibility-card ${
                    !feasibilityReport.feasible || feasibilityReport.risk_level === "critical_alarm"
                      ? "danger"
                      : feasibilityReport.score >= 0.8
                      ? "optimal"
                      : ""
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      {!feasibilityReport.feasible || feasibilityReport.risk_level === "critical_alarm" ? (
                        <ShieldAlert size={18} className="text-rose-400 shrink-0" />
                      ) : feasibilityReport.risk_level === "high_noise" ? (
                        <AlertTriangle size={18} className="text-amber-400 shrink-0" />
                      ) : (
                        <ShieldCheck size={18} className="text-emerald-400 shrink-0" />
                      )}
                      <div>
                        <div className="font-semibold text-sm flex items-center gap-2 flex-wrap">
                          <span>Pre-Flight Defense Feasibility</span>
                          <span
                            className={
                              !feasibilityReport.feasible
                                ? "badge badge-high"
                                : feasibilityReport.score >= 0.8
                                ? "badge badge-low"
                                : "badge badge-medium"
                            }
                          >
                            {Math.round(feasibilityReport.score * 100)}% Feasible
                          </span>
                          <span
                            className={
                              feasibilityReport.risk_level === "critical_alarm" || feasibilityReport.risk_level === "high_noise"
                                ? "badge badge-high"
                                : feasibilityReport.risk_level === "medium"
                                ? "badge badge-medium"
                                : "badge badge-low"
                            }
                          >
                            Risk: {feasibilityReport.risk_level.replace(/_/g, " ").toUpperCase()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {feasibilityReport.blockers.length > 0 && (
                    <div className="mt-2.5 p-2 rounded bg-rose-950/40 border border-rose-800/40 text-rose-300 text-xs space-y-1">
                      <div className="font-medium text-rose-200 flex items-center gap-1.5">
                        <AlertTriangle size={14} className="shrink-0" />
                        <span>Defensive Telemetry & Policy Blockers:</span>
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-zinc-300">
                        {feasibilityReport.blockers.map((blocker, idx) => (
                          <li key={idx}>{blocker}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {Object.keys(feasibilityReport.opsec_tuning || {}).length > 0 && (
                    <div className="mt-2 text-xs text-zinc-400 space-y-1 bg-zinc-900/60 p-2 rounded border border-zinc-800">
                      <span className="font-medium text-zinc-300">OPSEC Tuning Guidance:</span>
                      {Object.entries(feasibilityReport.opsec_tuning).map(([k, v]) => (
                        <div key={k} className="text-zinc-400">
                          <span className="text-amber-400 font-mono text-[11px]">{k}:</span> {String(v)}
                        </div>
                      ))}
                    </div>
                  )}

                  {feasibilityReport.recommended_alternatives.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-zinc-800">
                      <div className="text-xs font-semibold text-zinc-200 mb-1.5 flex items-center gap-1.5">
                        <ShieldCheck size={14} className="text-amber-400" />
                        <span>Recommended Defense Evasion Alternatives:</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {feasibilityReport.recommended_alternatives.map((altId) => (
                          <button
                            key={altId}
                            type="button"
                            className="btn btn-secondary flex items-center gap-1.5 text-xs py-1 px-2.5 border border-amber-500/40 hover:border-amber-400 text-amber-200 hover:bg-amber-950/30 transition-colors"
                            onClick={() => {
                              setSelectedId(altId);
                            }}
                            title={`Switch module to ${altId}`}
                          >
                            <span>Switch to <strong>{altId}</strong> →</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {runHint && runHint !== "Select a campaign before running a module." && (
                <p className="notice">
                  {runHint}
                </p>
              )}
              {scopeWarning && (
                <p className="notice notice-danger">
                  {scopeWarning}
                </p>
              )}
              <label className="toggle-row">
                <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                {dryRunSupported ? "Dry run" : "Dry run unavailable"}
              </label>
              {requiresConfirmation && (
                <label className="notice notice-danger">
                  <input className="mr-2" type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  {isFeasibilityBlocked
                    ? "Override pre-flight defense blocker and confirm authorized execution"
                    : "Confirm authorized high-noise or sensitive execution"}
                </label>
              )}
              <button
                className="btn btn-primary"
                type="submit"
                disabled={!selectedId || run.isPending || (campaignId ? !executionConditionBlocked : false)}
              >
                {run.isPending ? (
                  <>
                    <Loader2 className="spin" size={16} /> Running...
                  </>
                ) : (
                  "Execute Module"
                )}
              </button>
              {run.isPending && (
                <div className="notice notice-danger" role="status" aria-live="polite">
                  <Loader2 className="spin shrink-0" size={18} />
                  Module execution in progress. Keep this page open while ARES validates the target and collects results.
                </div>
              )}
            </form>
          ) : (
            <EmptyState text="Select a module" />
          )}
        </section>
      )}
      {activeTab === "Results" && (
        <section className="panel p-4">
          <SectionHeader
            title="Run Results"
            eyebrow={selected ? selected.id : undefined}
            action={persistedRun ? <span className={persistedRun.isError ? "badge badge-high" : "badge badge-low"}>{persistedRun.isError ? "error" : "latest"}</span> : null}
          />
          {runResult || runError ? (
            <>
              <ModuleRunSummary result={runResult} error={runError} />
              <DataPanel title={runError ? "Run Error" : "Run Result"} data={runError ?? runResult} />
            </>
          ) : (
            <EmptyState text="Run a selected module to see results here." />
          )}
        </section>
      )}
    </Page>
  );
}

export function ReportsPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const [format, setFormat] = useSessionState("ares.dashboard.reports.format", "html");
  const [warning, setWarning] = useState("");
  const [libraryError, setLibraryError] = useState("");
  const [lastGenerateResult, setLastGenerateResult] = useSessionState<PersistedResult | null>("ares.dashboard.reports.lastGenerate", null);
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.reports.tab", "Generate");
  const queryClient = useQueryClient();
  const reports = useQuery({
    queryKey: ["reports", campaignId],
    queryFn: () => api.reports(campaignId),
    enabled: Boolean(campaignId)
  });
  const reportItems = reports.data?.reports ?? [];
  const reportResultKey = `${campaignId}:${format}`;
  const generate = useMutation({
    mutationFn: () => api.generateReport(campaignId, format),
    onSuccess: (payload) => {
      setLastGenerateResult({ key: reportResultKey, payload });
      setActiveTab("Library");
      void queryClient.invalidateQueries({ queryKey: ["reports", campaignId] });
    },
    onError: (error) => {
      setLastGenerateResult({ key: reportResultKey, payload: serializeError(error), isError: true });
      setActiveTab("Generate");
    }
  });
  const persistedGenerateResult = lastGenerateResult?.key === reportResultKey ? lastGenerateResult : null;
  const generateIssue = generate.error ?? (persistedGenerateResult?.isError ? persistedGenerateResult.payload : undefined);
  const pdfIssueHint = format === "pdf" ? pdfFailureHint(generateIssue) : "";
  const download = useMutation({
    mutationFn: async (item: ReportItem) => {
      const blob = await api.downloadReport(campaignId, item.filename);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = item.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });
  const deleteReport = useMutation({
    mutationFn: (item: ReportItem) => api.deleteReport(campaignId, item.filename),
    onSuccess: (_payload, item) => {
      queryClient.setQueryData<{ campaign_id: string; reports: ReportItem[] }>(
        ["reports", campaignId],
        (current) => current
          ? {
              ...current,
              reports: current.reports.filter((report) => report.filename !== item.filename)
            }
          : current
      );
      setLibraryError("");
      const activePayload = (generate.data ?? lastGenerateResult?.payload) as { filename?: string } | undefined;
      if (activePayload?.filename === item.filename) {
        generate.reset();
        setLastGenerateResult(null);
      }
    },
    onError: (error) => {
      setLibraryError(readableError(error, "Report could not be deleted."));
    }
  });
  const clearReports = useMutation({
    mutationFn: () => api.clearReports(campaignId),
    onSuccess: () => {
      queryClient.setQueryData<{ campaign_id: string; reports: ReportItem[] }>(
        ["reports", campaignId],
        (current) => current ? { ...current, reports: [] } : current
      );
      setLibraryError("");
      generate.reset();
      setLastGenerateResult(null);
    },
    onError: (error) => {
      setLibraryError(readableError(error, "Report library could not be cleared."));
    }
  });

  // Auto-clear stale generate result if the report file was deleted from library
  useEffect(() => {
    if (reports.isSuccess && (generate.data || lastGenerateResult?.payload)) {
      const activePayload = (generate.data ?? lastGenerateResult?.payload) as { filename?: string } | undefined;
      const activeFilename = activePayload?.filename;
      if (activeFilename && !reportItems.some((r) => r.filename === activeFilename)) {
        generate.reset();
        setLastGenerateResult(null);
      }
    }
  }, [reports.isSuccess, reportItems, generate.data, lastGenerateResult]);

  const deleteDisabled = deleteReport.isPending || clearReports.isPending;
  return (
    <Page
      title="Reports"
      actions={<span className="status-pill">{reports.data?.reports?.length ?? 0} artifacts</span>}
      tabs={["Generate", "Library"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Generate" && (
      <section className="panel p-4">
        <SectionHeader
          title="Generate Report"
          description="Export findings, scope, and remediation."
        />
        <div className="grid gap-3 sm:grid-cols-3 items-end">
          <div>
            <label htmlFor="report-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
              Target Campaign
            </label>
            <CampaignPicker
              id="report-campaign-select"
              campaigns={campaignList}
              value={campaignId}
              hasError={Boolean(warning && !campaignId)}
              onChange={(id) => {
                setCampaignId(id);
                setWarning("");
              }}
            />
            {warning && !campaignId && (
              <p className="mt-1.5 flex items-center gap-1.5 text-xs text-rose-400" role="alert">
                <AlertTriangle size={13} className="shrink-0 text-rose-400" />
                {warning}
              </p>
            )}
          </div>
          <div>
            <label htmlFor="report-format-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
              Export Format
            </label>
            <select
              id="report-format-select"
              className="field"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
            >
              <option value="html">HTML Document</option>
              <option value="pdf">PDF Document</option>
              <option value="markdown">Markdown</option>
              <option value="json">JSON Export</option>
            </select>
          </div>
          <div>
            <button
              className="btn btn-primary w-full"
              disabled={generate.isPending}
              onClick={() => {
                if (!campaignId) {
                  setWarning("Select a scoped campaign before generating a report.");
                  return;
                }
                setWarning("");
                generate.mutate();
              }}
            >
              {generate.isPending ? (
                <>
                  <Loader2 className="spin" size={16} /> Generating...
                </>
              ) : (
                "Generate Report"
              )}
            </button>
          </div>
        </div>
        {warning && campaignId && <p className="notice notice-danger mt-3">{warning}</p>}
        {pdfIssueHint && (
          <p className="notice notice-danger mt-3">
            <AlertTriangle size={16} />
            {pdfIssueHint}
          </p>
        )}
        <DataPanel
          title={generateIssue ? "Generate Error" : "Generate Result"}
          data={generate.error ?? generate.data ?? persistedGenerateResult?.payload}
          onClear={() => {
            generate.reset();
            setLastGenerateResult(null);
          }}
        />
      </section>
      )}
      {activeTab === "Library" && (
      <section className="panel table-panel">
        <SectionHeader
          title="Report Library"
          action={campaignId && reportItems.length > 0 ? (
            <button
              className="btn btn-danger"
              disabled={deleteDisabled}
              onClick={() => {
                if (!window.confirm(`Delete all ${reportItems.length} report artifacts for this campaign? This cannot be undone.`)) {
                  return;
                }
                setLibraryError("");
                clearReports.mutate();
              }}
            >
              {clearReports.isPending ? (
                <Loader2 className="spin" size={15} />
              ) : null}
              Delete all
            </button>
          ) : null}
        />
        <div className="table-scroll">
          <table className="table">
            <thead><tr><th>Filename</th><th>Format</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead>
            <tbody>
              {reportItems.map((item) => (
                <tr key={item.filename}>
                  <td className="font-medium text-zinc-100 font-mono text-sm">{item.filename}</td>
                  <td><span className="badge">{item.format}</span></td>
                  <td>{formatBytes(item.size_bytes)}</td>
                  <td>{formatReportDate(item.modified_at)}</td>
                  <td>
                    <button className="btn" disabled={download.isPending || deleteDisabled} onClick={() => download.mutate(item)}>
                      Download
                    </button>
                    <button
                      className="btn btn-danger"
                      disabled={deleteDisabled}
                      onClick={() => {
                        if (!window.confirm(`Delete report artifact "${item.filename}"? This cannot be undone.`)) {
                          return;
                        }
                        setLibraryError("");
                        deleteReport.mutate(item);
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {libraryError && (
          <p className="notice notice-danger mt-3">
            <AlertTriangle size={16} />
            {libraryError}
          </p>
        )}
        <DataPanel title="Report Library Error" data={reports.error} />
        {campaignId && reportItems.length === 0 && (
          <EmptyState text="No reports generated for this campaign yet." />
        )}
        {!campaignId && <EmptyState text="Select a campaign to list reports." />}
        <DataPanel title="Download Result" data={download.error} />
      </section>
      )}
    </Page>
  );
}

export function TemplatesPage() {
  const templates = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const [name, setName] = useSessionState("ares.dashboard.templates.name", "");
  const [params, setParams] = useSessionState("ares.dashboard.templates.params", "{}");
  const [warning, setWarning] = useState("");
  const [lastPlanResult, setLastPlanResult] = useSessionState<PersistedResult | null>("ares.dashboard.templates.lastPlan", null);
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.templates.tab", "Templates");
  const templatePlanKey = `${name.trim()}:${params}`;
  const plan = useMutation({
    mutationFn: () => api.templatePlan(name, safeJson(params)),
    onSuccess: (payload) => setLastPlanResult({ key: templatePlanKey, payload }),
    onError: (error) => setLastPlanResult({ key: templatePlanKey, payload: serializeError(error), isError: true })
  });
  const selected = (templates.data ?? []).find((item) => item.name === name);
  const persistedPlanResult = lastPlanResult?.key === templatePlanKey ? lastPlanResult : null;
  const generated = (plan.data ?? (!persistedPlanResult?.isError ? persistedPlanResult?.payload : undefined)) as TemplatePlanResponse | undefined;
  const paramsValid = isJsonObject(params);
  return (
    <Page
      title="Templates"
      actions={<span className="status-pill">{templates.data?.length ?? 0} templates</span>}
      tabs={["Templates", "Plan Builder"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      <DataPanel title="Template Error" data={templates.error} />
      {activeTab === "Templates" && (
        <section className="panel p-4">
          <SectionHeader
            title="Campaign Templates"
            description="Pick a template and generate a plan."
          />
          <div className="grid gap-2">
            {(templates.data ?? []).map((item, index) => {
              const templateName = String(item.name ?? item.id ?? index);
              return (
                <button
                  className={`template-card ${name === templateName ? "active" : ""}`}
                  key={templateName}
                  onClick={() => {
                    setName(templateName);
                    setWarning("");
                    setLastPlanResult(null);
                    plan.reset();
                    setActiveTab("Plan Builder");
                  }}
                >
                  <span className="font-bold">{templateName}</span>
                  <small>{item.description ?? "Campaign execution template"}</small>
                  <span className="mt-2 flex flex-wrap gap-2">
                    <span className="badge">{item.stages ?? 0} stages</span>
                    <span className="badge">{item.modules ?? 0} modules</span>
                  </span>
                </button>
              );
            })}
          </div>
        </section>
      )}
      {activeTab === "Plan Builder" && (
        <section className="panel p-4">
          <SectionHeader title="Plan Builder" action={name ? <span className="badge">{name}</span> : null} />
          <input className="field" placeholder="Template name" value={name} onChange={(e) => {
            setName(e.target.value);
            setWarning("");
            setLastPlanResult(null);
          }} />
          {selected ? (
            <div className="preview-card mt-3">
              <div className="font-bold">{selected.name}</div>
              <p className="mt-1 text-sm text-zinc-300">{selected.description}</p>
              <div className="mt-2 flex flex-wrap gap-2">
                <span className="badge">{selected.stages ?? 0} stages</span>
                <span className="badge">{selected.modules ?? 0} modules</span>
              </div>
            </div>
          ) : (
            <EmptyState text="Select a template from the left panel." />
          )}
          <label className="mt-3 block text-sm font-semibold">
            Global parameters
            <textarea
              className="field mt-1 min-h-32"
              value={params}
              placeholder={'{"target":"127.0.0.1","domain":"corp.local","dc":"10.0.0.5"}'}
              onChange={(e) => {
                setParams(e.target.value);
                setWarning("");
              }}
            />
          </label>
          <p className="mt-1 text-xs text-zinc-400">JSON object. Leave {"{}"} for defaults.</p>
          {(warning || !paramsValid) && (
            <p className="notice notice-danger mt-2">
              {warning || "Global parameters must be a valid JSON object."}
            </p>
          )}
          <button
            className="btn btn-primary mt-3"
            disabled={!name || plan.isPending || !paramsValid}
            onClick={() => {
              if (!name.trim()) {
                setWarning("Template name is required.");
                return;
              }
              if (!paramsValid) {
                setWarning("Global parameters must be a valid JSON object.");
                return;
              }
              setWarning("");
              plan.mutate();
            }}
          >
            {plan.isPending ? (
              <>
                <Loader2 className="spin" size={16} /> Generating...
              </>
            ) : (
              "Generate Plan"
            )}
          </button>
          <TemplatePlanSummary plan={generated} />
          <DataPanel
            title={(plan.error ?? (persistedPlanResult?.isError ? persistedPlanResult.payload : undefined)) ? "Plan Error" : "Plan Details"}
            data={plan.error ?? plan.data ?? persistedPlanResult?.payload}
          />
        </section>
      )}
    </Page>
  );
}

export function StrategyPage() {
  const { user } = useAuth();
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const active = useQuery({ queryKey: ["strategy-active"], queryFn: api.activeStrategy });
  const [goal, setGoal] = useSessionState("ares.dashboard.strategy.goal", "domain_admin");
  const [llmBackend, setLlmBackend] = useSessionState("ares.dashboard.strategy.llmBackend", "claude");
  const [authorizations, setAuthorizations] = useSessionState("ares.dashboard.strategy.authorizations", "");
  const [lastEngageResult, setLastEngageResult] = useSessionState<PersistedResult | null>("ares.dashboard.strategy.lastEngage", null);
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.strategy.tab", "Objective");
  const [attemptedSubmit, setAttemptedSubmit] = useState(false);
  const strategyResultKey = `${campaignId}:${goal}:${llmBackend}:${authorizations}`;
  const engage = useMutation({
    mutationFn: () =>
      api.engageStrategy({
        campaign_id: campaignId,
        goal,
        llm_backend: llmBackend,
        max_rounds: 5,
        authorizations: splitLines(authorizations)
      }),
    onSuccess: (payload) => {
      setLastEngageResult({ key: strategyResultKey, payload });
      setActiveTab("Result");
    },
    onError: (error) => {
      setLastEngageResult({ key: strategyResultKey, payload: serializeError(error), isError: true });
      setActiveTab("Result");
    }
  });
  const persistedEngageResult = lastEngageResult?.key === strategyResultKey ? lastEngageResult : null;
  const allowed = user?.role === "team_lead" || user?.role === "operator";

  const llmBackends = (active.data?.llm_backends as Record<string, boolean> | undefined);
  const isEngineUnconfigured = llmBackends ? llmBackends[llmBackend] === false : false;

  const handleEngage = () => {
    if (!campaignId) {
      setAttemptedSubmit(true);
      return;
    }
    setAttemptedSubmit(false);
    engage.mutate();
  };

  return (
    <Page
      title="Strategy"
      actions={<span className={allowed ? "status-pill status-low" : "status-pill status-high"}>{allowed ? "Authorized" : "Restricted"}</span>}
      tabs={["Objective", "Active", "Result"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Objective" && (
        <section className="panel p-4">
          <SectionHeader title="Objective Builder" />
          <div className="space-y-4">
            <div>
              <label htmlFor="strategy-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
                Target Campaign
              </label>
              <CampaignPicker
                id="strategy-campaign-select"
                campaigns={campaignList}
                value={campaignId}
                hasError={attemptedSubmit && !campaignId}
                onChange={(id) => {
                  setCampaignId(id);
                  if (id) {
                    setAttemptedSubmit(false);
                  }
                }}
              />
              {attemptedSubmit && !campaignId && (
                <p className="mt-1.5 flex items-center gap-1.5 text-xs text-rose-400" role="alert">
                  <AlertTriangle size={13} className="shrink-0 text-rose-400" />
                  Select a scoped campaign before starting Strategy.
                </p>
              )}
            </div>

            <div>
              <label htmlFor="strategy-goal-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
                Strategic Objective
              </label>
              <select
                id="strategy-goal-select"
                className="field"
                value={goal}
                onChange={(e) => setGoal(e.target.value)}
              >
                <option value="domain_admin">Domain Admin (Active Directory)</option>
                <option value="enterprise_admin">Enterprise Admin (Forest Root)</option>
                <option value="cloud_admin">Cloud Admin (Identity Provider)</option>
                <option value="data_exfil">Data Exfiltration</option>
                <option value="persistence">Persistence & Foothold</option>
                <option value="full_compromise">Full Infrastructure Compromise</option>
              </select>
            </div>

            <div>
              <label htmlFor="strategy-engine-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
                AI Planning Engine
              </label>
              <select
                id="strategy-engine-select"
                className="field"
                value={llmBackend}
                onChange={(e) => setLlmBackend(e.target.value)}
              >
                <option value="claude">Claude (Anthropic)</option>
                <option value="openai">OpenAI (GPT-4o)</option>
                <option value="local">Local (Ollama)</option>
              </select>
              {isEngineUnconfigured && (
                <p className="mt-1.5 flex items-center gap-1.5 text-xs text-amber-400/90">
                  <Info size={13} className="shrink-0 text-amber-400" />
                  {llmBackend === "claude"
                    ? "Anthropic API key is not configured in the server environment. Configure it on the server or select another engine."
                    : llmBackend === "openai"
                      ? "OpenAI API key is not configured in the server environment. Configure it on the server or select another engine."
                      : "Local Ollama service is not reachable at http://127.0.0.1:11434. Start Ollama or verify server connection."}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="strategy-authorizations" className="block text-xs font-medium text-zinc-300 mb-1.5">
                Explicit Authorizations
              </label>
              <textarea
                id="strategy-authorizations"
                className="field min-h-24"
                placeholder="Authorization notes or specific module constraints, one per line"
                value={authorizations}
                onChange={(e) => setAuthorizations(e.target.value)}
              />
            </div>
          </div>

          {!allowed && (
            <p className="notice notice-danger mt-3">
              Strategy engagement requires operator or team lead role.
            </p>
          )}

          <button
            className="btn btn-primary mt-4"
            disabled={!allowed || engage.isPending}
            onClick={handleEngage}
          >
            {engage.isPending ? (
              <>
                <Loader2 className="spin" size={16} /> Engaging...
              </>
            ) : (
              "Engage Scope"
            )}
          </button>
        </section>
      )}
      {activeTab === "Active" && (
        <section className="grid gap-4">
          <section className="panel p-4">
            <SectionHeader title="Planning Snapshot" />
            <div className="mini-stat-grid">
              <MiniStat title="Goal" value={goal} />
              <MiniStat title="Backend" value={llmBackend} />
              <MiniStat title="Authorization" value={allowed ? "ready" : "restricted"} />
            </div>
          </section>
          {active.error ? <DataPanel title="Active Strategy Error" data={active.error} /> : active.data ? <DataPanel title="Active" data={active.data} /> : <EmptyState text="No active strategy state is available yet." />}
        </section>
      )}
      {activeTab === "Result" && (
        <section className="panel p-4">
          <SectionHeader title="Engagement Result" />
          {(engage.data ?? engage.error ?? persistedEngageResult?.payload) ? (
            <DataPanel
              title={(engage.error ?? (persistedEngageResult?.isError ? persistedEngageResult.payload : undefined)) ? "Engagement Error" : "Engagement Result"}
              data={engage.data ?? engage.error ?? persistedEngageResult?.payload}
            />
          ) : (
            <EmptyState text="Engage a strategy objective to see results here." />
          )}
        </section>
      )}
    </Page>
  );
}

function apiKeyVisibleIdentifier(key: ApiKeyMeta): string {
  const prefix = typeof key.key_prefix === "string" && key.key_prefix
    ? key.key_prefix
    : typeof key.prefix === "string" && key.prefix
      ? key.prefix
      : "";
  return prefix ? `Prefix: ${prefix}` : `ID: ${key.id.slice(0, 12)}`;
}

function apiKeyOwnerLabel(key: ApiKeyMeta): string {
  const owner = key.owner ?? key.owner_username ?? key.username ?? key.role;
  return typeof owner === "string" && owner.trim() ? owner : "";
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function SecurityPage() {
  const { user } = useAuth();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.apiKeys });
  const audit = useQuery({ queryKey: ["security-audit"], queryFn: api.securityAudit, enabled: user?.role === "team_lead" });
  const users = useQuery({ queryKey: ["security-users"], queryFn: api.users, enabled: user?.role === "team_lead" });
  const queryClient = useQueryClient();
  const secretKeyInputRef = useRef<HTMLInputElement | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [keyName, setKeyName] = useState("");
  const [scopes, setScopes] = useState("read");
  const [creatingApiKey, setCreatingApiKey] = useState(false);
  const [generatedApiKey, setGeneratedApiKey] = useState<GeneratedApiKey | null>(null);
  const [apiKeyError, setApiKeyError] = useState<unknown>(null);
  const [copyStatus, setCopyStatus] = useState<ApiKeyCopyStatus>("idle");
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.security.tab", "Account");
  const change = useMutation({
    mutationFn: () => api.changePassword({ current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
    }
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteApiKey(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    }
  });

  useEffect(() => {
    if (generatedApiKey) {
      secretKeyInputRef.current?.focus();
    }
  }, [generatedApiKey]);

  async function handleCreateApiKey(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    setApiKeyError(null);
    setGeneratedApiKey(null);
    setCopyStatus("idle");
    setCreatingApiKey(true);
    try {
      const response = await api.createApiKey({ name: keyName, scopes });
      if (!response.key) {
        throw new Error("API key created, but the secret was not returned by the API.");
      }
      setGeneratedApiKey({
        id: response.id,
        key: response.key,
        note: response.note,
        prefix: response.prefix ?? response.key_prefix
      });
      setKeyName("");
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (error) {
      setApiKeyError(error);
    } finally {
      setCreatingApiKey(false);
    }
  }

  async function copyGeneratedKey(): Promise<void> {
    if (!generatedApiKey?.key) return;

    let copied = false;
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(generatedApiKey.key);
        copied = true;
      } catch {
        copied = false;
      }
    }

    if (!copied && secretKeyInputRef.current) {
      secretKeyInputRef.current.focus();
      secretKeyInputRef.current.select();
      try {
        copied = document.execCommand("copy");
      } catch {
        copied = false;
      }
    }

    setCopyStatus(copied ? "copied" : "manual");
  }

  function closeGeneratedKeyModal(): void {
    setGeneratedApiKey(null);
    setCopyStatus("idle");
  }

  return (
    <Page
      title="Security"
      actions={<span className="status-pill">{formatRole(user?.role)}</span>}
      tabs={["Account", "API Keys", "Audit"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Account" && (
        <section className="panel p-4">
          <SectionHeader title="Account" />
          <div className="profile-row mb-3">
            <span className="profile-avatar-light">{user?.username?.slice(0, 1).toUpperCase() ?? "A"}</span>
            <div>
              <div className="font-semibold text-zinc-100">{user?.username}</div>
              <div className="text-xs text-zinc-400">{formatRole(user?.role)}</div>
            </div>
          </div>
          <form className="grid gap-2" onSubmit={(event) => {
            event.preventDefault();
            if (!event.currentTarget.reportValidity()) return;
            change.mutate();
          }}>
            <input className="field" required type="password" placeholder="Current password" value={currentPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCurrentPassword(e.target.value); }} />
            <input className="field" required minLength={12} type="password" placeholder="New password" value={newPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setNewPassword(e.target.value); }} />
            <button className="btn" disabled={change.isPending} type="submit">
              {change.isPending && <Loader2 className="spin" size={16} />}
              Change Password
            </button>
          </form>
          <DataPanel title="Password Result" data={change.data ?? change.error} />
        </section>
      )}
      {activeTab === "API Keys" && (
        <section className="panel p-4">
          <SectionHeader
            title="API Keys"
            action={<span className="badge">{keys.data?.length ?? 0} active</span>}
            description="Metadata only; new secrets are shown once."
          />
          <form className="mb-3 grid gap-2 sm:grid-cols-[1fr_120px_auto]" onSubmit={(event) => void handleCreateApiKey(event)}>
            <input className="field" required placeholder="Name" value={keyName} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setKeyName(e.target.value); }} />
            <select className="field" value={scopes} onChange={(e) => setScopes(e.target.value)}>
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn" disabled={creatingApiKey} type="submit">
              {creatingApiKey && <Loader2 className="spin" size={16} />}
              Create
            </button>
          </form>
          {(keys.data ?? []).map((key) => (
            <div className="key-row" key={key.id}>
              <div className="min-w-0">
                <div className="font-semibold text-zinc-100">{key.name ?? "Unnamed API key"}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs font-semibold text-zinc-400">
                  <span className="font-mono">{apiKeyVisibleIdentifier(key)}</span>
                  {key.scopes ? <span className="badge">Scope: {key.scopes}</span> : null}
                  {apiKeyOwnerLabel(key) ? <span>Owner: {apiKeyOwnerLabel(key)}</span> : null}
                </div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-zinc-400">
                  {key.created_at ? <span>Created: {formatDateTime(key.created_at)}</span> : null}
                  {key.expires_at ? <span>Expires: {formatDateTime(key.expires_at)}</span> : <span>No expiry</span>}
                </div>
              </div>
              <button className="btn btn-danger" disabled={remove.isPending} onClick={() => remove.mutate(key.id)}>Delete</button>
            </div>
          ))}
          {(keys.data ?? []).length === 0 && <EmptyState text="No API keys yet." />}
          <DataPanel title="API Key Error" data={apiKeyError ?? remove.error ?? keys.error} />
        </section>
      )}
      {activeTab === "Audit" && (
        <section className="grid gap-4">
          {user?.role === "team_lead" ? (
            <>
              {audit.error ? <DataPanel title="Security Audit Error" data={audit.error} /> : audit.data ? <DataPanel title="Security Audit" data={audit.data} /> : <EmptyState text="No security audit data loaded yet." />}
              {users.error ? <DataPanel title="Users Error" data={users.error} /> : users.data ? <DataPanel title="Users" data={users.data} /> : <EmptyState text="No user records loaded yet." />}
            </>
          ) : (
            <EmptyState text="Audit data is available to team leads." />
          )}
        </section>
      )}
      {generatedApiKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
          <section
            aria-labelledby="api-key-dialog-title"
            aria-modal="true"
            className="panel w-full max-w-2xl p-5 shadow-2xl"
            role="dialog"
          >
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-zinc-100" id="api-key-dialog-title">Save your key</h2>
                <p className="mt-1 text-sm text-zinc-400">Copy this secret key now and store it somewhere safe.</p>
              </div>
              {generatedApiKey.prefix ? <span className="badge font-mono">{generatedApiKey.prefix}</span> : null}
            </div>
            <p className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm font-semibold text-amber-200">
              This secret key is shown only once. After you close this dialog, ARES will not show the full key again.
            </p>
            <label className="block text-sm font-semibold text-zinc-300">
              Secret key
              <div className="mt-2 grid gap-2 sm:grid-cols-[1fr_auto]">
                <input
                  aria-label="Generated API key secret"
                  className="field font-mono text-sm"
                  onFocus={(event) => event.currentTarget.select()}
                  readOnly
                  ref={secretKeyInputRef}
                  value={generatedApiKey.key}
                />
                <button className="btn" onClick={() => void copyGeneratedKey()} type="button">
                  {copyStatus === "copied" ? <CheckCircle2 size={16} /> : <Copy size={16} />}
                  {copyStatus === "copied" ? "Copied" : "Copy"}
                </button>
              </div>
            </label>
            {copyStatus === "manual" && (
              <p className="mt-2 rounded-md border border-zinc-700 bg-zinc-900 p-3 text-sm text-zinc-300">
                Clipboard access was blocked. The key field is selected; press Ctrl+C to copy it manually.
              </p>
            )}
            {generatedApiKey.note ? <p className="mt-3 text-sm text-zinc-400">{generatedApiKey.note}</p> : null}
            <div className="mt-5 flex justify-end">
              <button className="btn btn-primary" onClick={closeGeneratedKeyModal} type="button">Done</button>
            </div>
          </section>
        </div>
      )}
    </Page>
  );
}

export function EdrPage() {
  const stats = useQuery({ queryKey: ["edr-stats"], queryFn: api.edrStats });
  const [techniqueId, setTechniqueId] = useSessionState("ares.dashboard.edr.techniqueId", "");
  const [vendor, setVendor] = useSessionState("ares.dashboard.edr.vendor", "");
  const [version, setVersion] = useSessionState("ares.dashboard.edr.version", "");
  const [success, setSuccess] = useSessionState("ares.dashboard.edr.success", false);
  const [notes, setNotes] = useSessionState("ares.dashboard.edr.notes", "");
  const [lastReportResult, setLastReportResult] = useSessionState<PersistedResult | null>("ares.dashboard.edr.lastReport", null);
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.edr.tab", "Knowledge Base");
  const edrReportKey = `${techniqueId.trim()}:${vendor.trim()}:${version.trim()}:${success}:${notes.trim()}`;
  const report = useMutation({
    mutationFn: () =>
      api.reportBypass({
        technique_id: techniqueId.trim(),
        edr_vendor: vendor.trim(),
        edr_version: version.trim(),
        success,
        notes: notes.trim()
      }),
    onSuccess: (payload) => setLastReportResult({ key: edrReportKey, payload }),
    onError: (error) => setLastReportResult({ key: edrReportKey, payload: serializeError(error), isError: true })
  });
  const persistedReportResult = lastReportResult?.key === edrReportKey ? lastReportResult : null;
  return (
    <Page
      title="EDR/OPSEC"
      actions={<span className={success ? "status-pill status-low" : "status-pill status-medium"}>{success ? "Successful" : "Blocked / detected"}</span>}
      tabs={["Knowledge Base", "Report Outcome"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Knowledge Base" && (
      <>
      <section className="panel p-4">
        <SectionHeader
          title="Bypass Knowledge Base"
          description="Track outcomes by technique and vendor."
        />
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="telemetry-strip">
            <span>Technique</span>
            <strong>{String(stats.data?.technique_id ?? "all")}</strong>
          </div>
          <div className="telemetry-strip">
            <span>Vendor</span>
            <strong>{String(stats.data?.edr_vendor ?? "all")}</strong>
          </div>
          <div className="telemetry-strip">
            <span>Current rate</span>
            <strong>{formatRate(stats.data?.success_rate)}</strong>
          </div>
        </div>
        <p className="mt-3 text-sm text-zinc-400">{String(stats.data?.message ?? "No historical sample loaded yet.")}</p>
      </section>
      <DataPanel title="Stats Details" data={stats.data} />
      <DataPanel title="Stats Error" data={stats.error} />
      </>
      )}
      {activeTab === "Report Outcome" && (
      <>
      <section className="panel p-4">
        <SectionHeader title="Report Outcome" />
        <form className="grid gap-3" onSubmit={(event) => {
          event.preventDefault();
          if (!event.currentTarget.reportValidity()) return;
          report.mutate();
        }}>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block text-sm font-semibold">
              Technique ID <span className="text-red-700">*</span>
              <input className="field mt-1" required placeholder="edr.bypass_adaptive / amsi-patch-reflection" value={techniqueId} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setTechniqueId(e.target.value); }} />
            </label>
            <label className="block text-sm font-semibold">
              EDR vendor <span className="text-red-700">*</span>
              <input className="field mt-1" required placeholder="crowdstrike, defender_atp, sentinelone" value={vendor} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setVendor(e.target.value); }} />
            </label>
            <label className="block text-sm font-semibold">
              EDR version
              <input className="field mt-1" placeholder="optional" value={version} onChange={(e) => setVersion(e.target.value)} />
            </label>
            <label className="block text-sm font-semibold">
              Outcome
              <select className="field mt-1" value={success ? "success" : "blocked"} onChange={(e) => setSuccess(e.target.value === "success")}>
                <option value="blocked">Blocked / detected</option>
                <option value="success">Successful</option>
              </select>
            </label>
          </div>
          <label className="block text-sm font-semibold">
            Notes
            <textarea className="field mt-1 min-h-24" placeholder="Signal observed, lab context, or detection notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          </label>
          <button className="btn btn-primary" disabled={report.isPending} type="submit">
            {report.isPending ? (
              <>
                <Loader2 className="spin" size={16} /> Saving...
              </>
            ) : (
              "Report Outcome"
            )}
          </button>
        </form>
      </section>
      <DataPanel
        title={(report.error ?? (persistedReportResult?.isError ? persistedReportResult.payload : undefined)) ? "Outcome Error" : "Outcome Result"}
        data={report.data ?? report.error ?? persistedReportResult?.payload}
      />
      </>
      )}
    </Page>
  );
}

export function LivePage() {
  const {
    selectedCampaignId,
    setSelectedCampaignId,
    liveCampaignId,
    setLiveCampaignId,
    liveConnected,
    setLiveConnected,
    liveEvents,
    clearLiveEvents,
    campaigns: campaignList
  } = useDashboardUi();
  const campaignId = liveCampaignId || selectedCampaignId;
  const [activeTab, setActiveTab] = useSessionState("ares.dashboard.live.tab", "Stream");
  const streamEvents = liveEvents.slice(0, 10);

  return (
    <Page
      title="Live Events"
      actions={<span className={liveConnected ? "status-pill status-low" : "status-pill"}>{liveConnected ? "Listening" : "Offline"}</span>}
      tabs={["Stream", "Buffer"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Stream" && (
      <>
      <div className="panel p-4">
        <SectionHeader
          title="Campaign Event Stream"
          action={<span className="badge">{liveEvents.length} buffered</span>}
          description="Watch selected campaign events."
        />
        <CampaignPicker
          campaigns={campaignList}
          value={campaignId}
          onChange={(id) => {
            setLiveCampaignId(id);
            setSelectedCampaignId(id);
          }}
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button className="btn btn-primary" disabled={!campaignId || liveConnected} onClick={() => {
            if (!liveCampaignId && campaignId) {
              setLiveCampaignId(campaignId);
            }
            setLiveConnected(true);
          }}>
            {liveConnected ? "Connected" : "Connect Stream"}
          </button>
          {liveConnected && (
            <button className="btn" onClick={() => setLiveConnected(false)}>
              Disconnect
            </button>
          )}
          <span className={liveConnected ? "badge badge-low" : "badge"}>{liveConnected ? "listening" : "offline"}</span>
        </div>
      </div>
      <section className="panel p-4">
        <SectionHeader title="Current Stream" action={<span className="badge">{streamEvents.length} newest</span>} />
        {streamEvents.length > 0 ? (
          <div className="grid gap-2">
            {streamEvents.map((event, index) => (
              <LiveEventCard event={event} index={index} key={index} />
            ))}
          </div>
        ) : (
          <EmptyState text={liveConnected ? "Connected. Waiting for events." : "Select a campaign and connect."} />
        )}
      </section>
      </>
      )}
      {activeTab === "Buffer" && (
        <section className="panel p-4">
          <SectionHeader
            title="Buffered Events"
            action={liveEvents.length > 0 ? <button className="btn" onClick={clearLiveEvents}>Clear Events</button> : <span className="badge">0 retained</span>}
          />
          {liveEvents.length > 0 ? (
            <div className="grid gap-2">
              {liveEvents.map((event, index) => (
                <LiveEventCard event={event} index={index} key={index} />
              ))}
            </div>
          ) : (
            <EmptyState text="No events retained in the buffer." />
          )}
        </section>
      )}
    </Page>
  );
}

function Page({
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
  const setTab = onTabChange ?? setFallbackTab;

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

function SectionHeader({
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

function MiniStat({ title, value, detail, icon }: { title: string; value: string; detail?: string; icon?: ReactNode }) {
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

function HighlightRow({
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

function SparklineBars({ values }: { values: MonthlyFindingStats["series"] }) {
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

function formatMonthlyDate(date: string): string {
  const [year, month, day] = date.split("-").map(Number);
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" }).format(
    new Date(Date.UTC(year, month - 1, day))
  );
}

function metricNumber(map: TelemetryMetricMap | undefined, key: string): number {
  return metricNumberOrNull(map, key) ?? 0;
}

function metricNumberOrNull(map: TelemetryMetricMap | undefined, key: string): number | null {
  const value = map?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function formatMetric(value: number, suffix = ""): string {
  if (!Number.isFinite(value)) return `0${suffix}`;
  if (Number.isInteger(value)) return `${value}${suffix}`;
  return `${value.toFixed(1)}${suffix}`;
}

function formatRate(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "not enough data";
  }
  const normalized = value <= 1 ? value * 100 : value;
  return `${Math.round(normalized)}%`;
}

function formatTimestamp(value: number | undefined): string {
  if (!value) return "No runtime sample yet";
  return new Date(value * 1000).toLocaleString();
}

function formatBytes(value: number): string {
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

function formatReportDate(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  const timestamp = value > 10_000_000_000 ? value : value * 1000;
  return new Date(timestamp).toLocaleString();
}

function formatReportTime(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  const timestamp = value > 10_000_000_000 ? value : value * 1000;
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function TelemetryPanel({ snapshot, loading, confirmedFindings }: { snapshot?: TelemetrySnapshot; loading: boolean; confirmedFindings: number }) {
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
        <summary>Details</summary>
        <pre className="json-box">{JSON.stringify(snapshot ?? {}, null, 2)}</pre>
      </details>
    </section>
  );
}

function TelemetryBar({ label, value, tone = "ok" }: { label: string; value: number | null; tone?: "ok" | "danger" }) {
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

function CvssScoreCard({ data }: { data?: Record<string, unknown> }) {
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
        <span className={`badge status-${severity} font-semibold uppercase text-xs px-2.5 py-1`}>
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
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer">Inspect Raw CVSS Payload</summary>
        <pre className="json-box mt-2 text-xs font-mono">{JSON.stringify(data, null, 2)}</pre>
      </details>
    </section>
  );
}

function CampaignDiffCard({ data }: { data?: Record<string, unknown> }) {
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
        <pre className="json-box text-xs font-mono">{JSON.stringify(data, null, 2)}</pre>
      </details>
    </section>
  );
}

function DataPanel({
  title,
  data,
  onClear
}: {
  title: string;
  data: unknown;
  onClear?: () => void;
}) {
  const [copied, setCopied] = useState(false);
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

  const jsonText = JSON.stringify(serializeError(data), null, 2);
  const handleCopy = () => {
    void navigator.clipboard.writeText(jsonText);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <section className="panel detail-panel mb-3">
      <div className="flex items-center justify-between mb-2">
        <strong className="text-xs font-semibold text-zinc-200">{title}</strong>
        <div className="flex items-center gap-2">
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
          <button
            className="btn btn-compact text-[11px] py-0.5 px-2 flex items-center gap-1.5"
            onClick={handleCopy}
            type="button"
            title="Copy payload to clipboard"
          >
            {copied ? <CheckCircle2 size={12} className="text-emerald-400" /> : <Copy size={12} />}
            <span>{copied ? "Copied" : "Copy Payload"}</span>
          </button>
          <span className="badge text-[10px] uppercase font-mono">Payload</span>
        </div>
      </div>
      <details className="advanced-details">
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer">Inspect Payload Details</summary>
        <pre className="json-box mt-2 text-xs font-mono">{jsonText}</pre>
      </details>
    </section>
  );
}

function ModuleRunSummary({ result, error }: { result?: Record<string, unknown>; error?: unknown }) {
  if (!result && !error) {
    return null;
  }
  if (error) {
    return (
      <section className="inline-summary mt-4">
        <SectionHeader title="Execution Summary" action={<span className="badge badge-high">failed</span>} />
        <p className="notice notice-danger">
          <AlertTriangle size={16} />
          {error instanceof ApiError ? String(error.detail) : error instanceof Error ? error.message : "Module run failed."}
        </p>
      </section>
    );
  }

  const findings = Array.isArray(result?.findings) ? result.findings as Finding[] : [];
  const validationCount = Array.isArray(result?.validation_results) ? result.validation_results.length : 0;
  const duration = typeof result?.duration_ms === "number" ? formatMetric(result.duration_ms, " ms") : "n/a";
  const status = String(result?.status ?? "unknown");
  const moduleId = String(result?.module_id ?? "module");
  const runError = typeof result?.error === "string" ? result.error : "";
  const outcome = String(result?.outcome ?? "");
  const outcomeMessage = String(result?.outcome_message ?? "");
  const displayOutcome = outcome || status;
  const dryRun = result?.dry_run === true || status.startsWith("dry_run_");
  const warnings = Array.isArray(result?.warnings) ? result.warnings.map(String) : [];
  const nextSteps = Array.isArray(result?.operator_next_steps) ? result.operator_next_steps.map(String) : [];
  const hasOutcomeError = ["operator_error", "dependency_error", "network_error", "unsupported", "module_error", "failed", "timeout"].includes(displayOutcome);
  const emptyText = dryRun
    ? "No live execution was performed."
    : outcome === "completed_no_findings"
      ? "No confirmed findings. The module completed without observing an exploitable condition."
      : runError
        ? "No findings recorded because execution failed."
        : "No findings returned.";

  return (
    <section className="inline-summary mt-4">
      <SectionHeader
        title="Execution Summary"
        action={(
          <div className="flex flex-wrap gap-2">
            <span className="badge">{moduleId}</span>
            <span className={hasOutcomeError ? "badge badge-high" : displayOutcome === "confirmed_findings" || displayOutcome === "completed_no_findings" || displayOutcome === "dry_run_ok" || displayOutcome === "done" ? "badge badge-low" : "badge badge-medium"}>{displayOutcome}</span>
            <span className="badge">{duration}</span>
          </div>
        )}
      />
      {(outcomeMessage || runError) && (
        <p className={`notice mb-3 ${hasOutcomeError || runError ? "notice-danger" : ""}`}>
          {hasOutcomeError || runError ? <AlertTriangle size={16} /> : null}
          {outcomeMessage || runError}
        </p>
      )}
      {warnings.length > 0 && (
        <div className="notice mb-3">
          <strong>{dryRun ? "Dry-run notes" : "Notes"}</strong>
          <ul className="mt-1 list-disc pl-5">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
        </div>
      )}
      {nextSteps.length > 0 && (
        <div className="notice mb-3">
          <strong>Next steps</strong>
          <ul className="mt-1 list-disc pl-5">{nextSteps.map((step) => <li key={step}>{step}</li>)}</ul>
        </div>
      )}
      <div className="mini-stat-grid mb-3">
        <MiniStat title="Findings" value={String(findings.length)} detail="returned observations" />
        <MiniStat title="Validation" value={String(validationCount)} detail="post-run checks" />
        <MiniStat title="Duration" value={duration} detail="server execution" />
      </div>
      {findings.length > 0 ? (
        <div className="compact-list">
          {findings.map((finding, index) => (
            <div className="compact-row" key={finding.id ?? index}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div className="font-bold">{finding.title ?? `Finding ${index + 1}`}</div>
                  <div className="mt-1 text-sm text-zinc-400">{String(finding.description ?? "")}</div>
                </div>
                <span className={opsecBadge(finding.severity)}>{finding.severity ?? "info"}</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {finding.host && <span className="badge">Host: {finding.host}</span>}
                {finding.mitre_technique && <span className="badge">{finding.mitre_technique}</span>}
                {typeof finding.confidence === "number" && <span className="badge">Confidence: {formatRate(finding.confidence)}</span>}
              </div>
              {finding.remediation ? (
                <p className="mt-2 text-sm text-zinc-300">
                  <strong>Remediation:</strong> {String(finding.remediation)}
                </p>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState text={emptyText} />
      )}
    </section>
  );
}

function TemplatePlanSummary({ plan }: { plan?: TemplatePlanResponse }) {
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

function CampaignScopeSummary({ campaign, loading }: { campaign?: Campaign; loading?: boolean }) {
  const [copied, setCopied] = useState(false);
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
        <MiniStat title="Noise Profile" value={String(campaign.noise_profile ?? "stealth")} detail="OPSEC guardrail" />
        <MiniStat title="Campaign ID" value={campaign.id.slice(0, 8)} detail="API/report key" />
      </div>
      <details className="advanced-details mt-3">
        <summary className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer">Inspect Raw Scope Parameters</summary>
        <pre className="json-box mt-2 text-xs font-mono">{JSON.stringify(campaign, null, 2)}</pre>
      </details>
    </div>
  );
}

function CampaignPicker({
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

function StatusBadge({ status }: { status?: string }) {
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

function NoiseProfileBadge({ noise }: { noise?: string }) {
  const normalized = String(noise ?? "stealth").toLowerCase();
  const isNoisy = normalized.includes("noisy") || normalized.includes("critical");
  const isEvasive = normalized.includes("evasive") || normalized.includes("medium");
  const badgeClass = isNoisy ? "badge badge-high" : isEvasive ? "badge badge-medium" : "badge";
  return (
    <span className={`${badgeClass} font-mono text-[11px] uppercase tracking-wider`}>
      {noise ?? "stealth"}
    </span>
  );
}

function CampaignTable({ campaigns }: { campaigns: Campaign[] }) {
  return (
    <section className="panel table-panel">
      <SectionHeader
        title="Campaign Activity"
        action={<span className="badge">{campaigns.length} records</span>}
      />
      {campaigns.length > 0 ? (
        <div className="table-scroll">
          <table className="table">
            <thead><tr><th>#</th><th>Name</th><th>Client</th><th>Status</th><th>Noise</th><th>Operator</th></tr></thead>
            <tbody>
              {campaigns.map((campaign, index) => (
                <tr key={campaign.id}>
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

function FindingsTable({ findings }: { findings: any[] }) {
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

function LiveEventCard({ event, index }: { event: unknown; index: number }) {
  const record = event && typeof event === "object" && !Array.isArray(event) ? event as Record<string, unknown> : null;
  const type = String(record?.type ?? record?.event ?? record?.name ?? `event.${index + 1}`);
  const message = String(record?.message ?? record?.status ?? record?.detail ?? "Campaign event received.");
  const campaign = typeof record?.campaign_id === "string" ? record.campaign_id : "";
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
          {campaign ? <span className="badge">Campaign {campaign.slice(0, 8)}</span> : null}
          {moduleId ? <span className="badge">{moduleId}</span> : null}
        </div>
        <p>{message}</p>
        {created ? <small>{created}</small> : null}
        <details className="advanced-details compact">
          <summary>Details</summary>
          <pre className="json-box">{JSON.stringify(serializeError(event), null, 2)}</pre>
        </details>
      </div>
    </article>
  );
}

function ParamForm({
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
        return (
          <label className="block text-sm font-semibold" key={name}>
            <span className="flex items-center gap-2">
              <span>
                {name}
                {required && <span className="text-red-700"> *</span>}
              </span>
              {!required && <span className="badge">optional</span>}
            </span>
            <ParamInput
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
            {description && <span className="mt-1 block text-xs text-zinc-400">{description}</span>}
            {fieldDefaultHint(field) && (
              <span className="mt-1 block text-xs font-medium text-zinc-400">{fieldDefaultHint(field)}</span>
            )}
          </label>
        );
      })}
    </div>
  );
}

function ParamInput({
  name,
  field,
  value,
  onChange
}: {
  name: string;
  field: ParamField;
  value: unknown;
  onChange: (value: unknown) => void;
}) {
  if (field.type === "boolean") {
    return (
      <input
        className="ml-2"
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
        className="field mt-1 min-h-20"
        value={Array.isArray(value) ? value.join(", ") : String(value ?? "")}
        placeholder={paramPlaceholder(name, field)}
        required={field.required}
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
      className="field mt-1"
      type={type}
      value={String(value ?? "")}
      min={field.min}
      max={field.max}
      placeholder={paramPlaceholder(name, field)}
      required={field.required}
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

function fieldDefaultHint(field: ParamField): string {
  if (field.secret || field.default === undefined) {
    return "";
  }
  const value = formatDefaultValue(field.default);
  return value ? `Default: ${value}` : "";
}

function paramPlaceholder(name: string, field: ParamField): string {
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

function fieldDescription(name: string, field: ParamField): string | undefined {
  if (name === "target_user" && field.description === "Required target user or SPN; run ad.enum_spn first") {
    return "Required target user or SPN; run ad.enum_spn first.";
  }
  return field.description;
}

function formatDefaultValue(value: unknown): string {
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

function ScreenMessage({ title, body }: { title: string; body: string }) {
  return (
    <div className="grid min-h-screen place-items-center bg-zinc-950 p-4 text-zinc-100">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6 text-center shadow-sm">
        <h1 className="text-lg font-semibold tracking-tight text-zinc-100">{title}</h1>
        <p className="mt-1 text-xs text-zinc-400">{body}</p>
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="empty-state">{text}</div>;
}

function strategyBackendHint(backend: string): string {
  if (backend === "openai") {
    return "OpenAI planning requires OPENAI_API_KEY in the ARES server environment. Security-page API keys do not count as LLM provider keys.";
  }
  if (backend === "local") {
    return "Local planning uses Ollama from the ARES server host, usually http://localhost:11434. No cloud LLM key is required.";
  }
  return "Claude planning requires ANTHROPIC_API_KEY in the ARES server environment. Security-page API keys only authenticate callers to ARES.";
}

function moduleRunHint(
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

function splitLines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function findInvalidScopeEntries(value: string): string[] {
  return splitLines(value).filter((entry) => !looksLikeScopeEntry(entry));
}

function looksLikeScopeEntry(entry: string): boolean {
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

function parseArrayParam(value: string, field: ParamField): unknown[] | undefined {
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

function isEmptyParamValue(value: unknown): boolean {
  return value === undefined || value === "" || (Array.isArray(value) && value.length === 0);
}

function moduleScopeWarning(
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

function campaignScopeEntries(campaign: Campaign): string[] {
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

function campaignTargets(campaign: Campaign): string[] {
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

function ipv4InScope(ip: string, cidr: string): boolean {
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

function ipv4ToNumber(ip: string): number {
  return ip.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

function isIpv4Address(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function safeJson(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function isJsonObject(value: string): boolean {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Boolean(parsed && typeof parsed === "object" && !Array.isArray(parsed));
  } catch {
    return false;
  }
}

function isSensitiveModule(module?: ModuleMeta): boolean {
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

function statusBadge(status?: string): string {
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

function opsecBadge(level?: string): string {
  const normalized = String(level ?? "").toLowerCase();
  if (normalized.includes("high") || normalized.includes("critical")) {
    return "badge badge-high";
  }
  if (normalized.includes("medium") || normalized.includes("moderate")) {
    return "badge badge-medium";
  }
  return "badge badge-low";
}

function serializeError(value: unknown): unknown {
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

function readableError(value: unknown, fallback: string): string {
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

function pdfFailureHint(value: unknown): string {
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
