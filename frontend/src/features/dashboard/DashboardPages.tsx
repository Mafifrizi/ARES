import {
  Bell,
  ChevronDown,
  Menu,
  Search,
  Trash2,
  X,
} from "lucide-react";
import {
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { NavLink, Navigate, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  campaignEventsPath,
  captureSession,
  isSessionCurrent,
} from "../../api/client";
import type { Campaign, LiveWebSocketEvent } from "../../api/types";
import { useAuth } from "../auth/authContext";
import {
  EmptyState,
  ScreenMessage,
  SectionHeader,
  type TelemetrySnapshot,
  formatRate,
  metricNumber,
  unique,
} from "./dashboardComponents";

import { DashboardUiProvider } from "./dashboardUi";
import {
  type DashboardUiState,
  useDashboardSessionWriter,
  useSessionState,
} from "./dashboardUiState";

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

const NOTIFICATIONS_DELETED_KEY = "ares.dashboard.notifications.deleted";
const NOTIFICATIONS_READ_KEY = "ares.dashboard.notifications.read";

function getStoredNotificationIds(key: string, username?: string): string[] {
  try {
    const userKey = username ? `${key}.${username}` : key;
    const raw = window.localStorage.getItem(userKey) || window.localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function setStoredNotificationIds(key: string, username: string | undefined, ids: string[]): void {
  try {
    const serialized = JSON.stringify(ids);
    if (username) {
      window.localStorage.setItem(`${key}.${username}`, serialized);
    }
    window.localStorage.setItem(key, serialized);
  } catch {
    // Storage sandbox fallback
  }
}

export function DashboardShell({ children }: { children: ReactNode }) {
  const { user, loading, logout, logoutAll } = useAuth();
  const username = user?.username;
  const navigate = useNavigate();
  const writeDashboardSession = useDashboardSessionWriter();
  const [selectedCampaignId, setSelectedCampaignId] = useSessionState("ares.dashboard.selectedCampaignId", "");
  const [liveCampaignId, setLiveCampaignId] = useSessionState("ares.dashboard.live.campaignId", "");
  const [liveEvents, setLiveEvents] = useSessionState<unknown[]>("ares.dashboard.live.events", []);
  const [liveConnected, setLiveConnected] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [operatorMenuOpen, setOperatorMenuOpen] = useState(false);
  const [telemetryOpen, setTelemetryOpen] = useState(false);
  const [readNotificationIds, setReadNotificationIds] = useState<string[]>(() =>
    getStoredNotificationIds(NOTIFICATIONS_READ_KEY, username)
  );
  const [deletedNotificationIds, setDeletedNotificationIds] = useState<string[]>(() =>
    getStoredNotificationIds(NOTIFICATIONS_DELETED_KEY, username)
  );

  useEffect(() => {
    function handleKeyDown(e: globalThis.KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase() || "";
      const isEditable =
        tag === "input" ||
        tag === "textarea" ||
        tag === "select" ||
        Boolean(target?.isContentEditable) ||
        target?.getAttribute?.("contenteditable") === "true" ||
        Boolean(target?.closest?.("[contenteditable='true']"));

      if (e.key === "/" && !isEditable && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    if (username) {
      const storedDeleted = getStoredNotificationIds(NOTIFICATIONS_DELETED_KEY, username);
      if (storedDeleted.length > 0) {
        setDeletedNotificationIds((current) => unique([...current, ...storedDeleted]));
      }
      const storedRead = getStoredNotificationIds(NOTIFICATIONS_READ_KEY, username);
      if (storedRead.length > 0) {
        setReadNotificationIds((current) => unique([...current, ...storedRead]));
      }
    }
  }, [username]);

  useEffect(() => {
    if (!notificationsOpen && !operatorMenuOpen && !telemetryOpen) {
      return;
    }
    function handleDocumentClick(e: MouseEvent) {
      const target = e.target as HTMLElement | null;
      if (!target) return;
      if (
        !target.closest(".operator-menu-wrap") &&
        !target.closest(".telemetry-popover") &&
        !target.closest(".topbar-status-btn") &&
        !target.closest(".notification-drawer") &&
        !target.closest(".icon-button.has-badge")
      ) {
        setNotificationsOpen(false);
        setOperatorMenuOpen(false);
        setTelemetryOpen(false);
      }
    }
    document.addEventListener("mousedown", handleDocumentClick);
    return () => document.removeEventListener("mousedown", handleDocumentClick);
  }, [notificationsOpen, operatorMenuOpen, telemetryOpen]);
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const telemetry = useQuery({
    queryKey: ["telemetry", selectedCampaignId],
    queryFn: () => api.telemetry(selectedCampaignId || undefined)
  });
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
      setLiveEvents((items) => items.filter((item) => (item as LiveWebSocketEvent)?.campaign_id !== id));

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
    onEvent: (event) => setLiveEvents((items) => {
      const liveEvt = (typeof event === "object" && event !== null ? event : {}) as LiveWebSocketEvent;
      const normalized = typeof event === "object" && event !== null
        ? {
            ...(event as Record<string, unknown>),
            campaign_id: liveEvt.campaign_id || liveCampaignId,
            timestamp: typeof liveEvt.timestamp === "number" ? liveEvt.timestamp : Date.now()
          }
        : { raw: event, campaign_id: liveCampaignId, timestamp: Date.now() };
      return [normalized, ...items].slice(0, 100);
    })
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
      pushLiveEvent: (event: unknown) => setLiveEvents((items) => {
        const liveEvt = (typeof event === "object" && event !== null ? event : {}) as LiveWebSocketEvent;
        const normalized = typeof event === "object" && event !== null
          ? {
              ...(event as Record<string, unknown>),
              campaign_id: liveEvt.campaign_id || liveCampaignId || selectedCampaignId || "",
              timestamp: typeof liveEvt.timestamp === "number" ? liveEvt.timestamp : Date.now()
            }
          : { raw: event, campaign_id: liveCampaignId || selectedCampaignId || "", timestamp: Date.now() };
        return [normalized, ...items].slice(0, 100);
      }),
      clearLiveEvents: (targetCampaignId?: string) => {
        if (targetCampaignId) {
          setLiveEvents((items) => items.filter((item) => (item as LiveWebSocketEvent)?.campaign_id !== targetCampaignId));
        } else {
          setLiveEvents([]);
        }
      },
      campaigns: campaignList,
      campaignsLoading: campaigns.isLoading,
      campaignsError: campaigns.error,
      deleteCampaign,
      isDeletingCampaign: deleteCampaignMutation.isPending,
      refetchCampaigns: () => queryClient.invalidateQueries({ queryKey: ["campaigns"], refetchType: "all" })
    }),
    [
      campaignList,
      campaigns.error,
      campaigns.isLoading,
      deleteCampaign,
      deleteCampaignMutation.isPending,
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
          route: "/campaigns?tab=Scope",
          onSelect: () => {
            setSelectedCampaignId(campaign.id);
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
          route: `/modules?tab=Run+Panel&module=${encodeURIComponent(module.id)}`,
          onSelect: () => {
            writeDashboardSession("ares.dashboard.modules.selectedId", module.id);
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
          route: "/reports?tab=Library",
          onSelect: () => {}
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
          route: "/templates?tab=Plan+Builder",
          onSelect: () => {
            writeDashboardSession("ares.dashboard.templates.name", templateName);
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
      items.push({
        id: "telemetry:failed-runs",
        title: "Failed module runs",
        detail: `${failedRuns} failed module run(s) reported by telemetry.`,
        tone: "warn"
      });
    }
    if (errorRate > 0) {
      items.push({
        id: "telemetry:error-rate",
        title: "Runtime error rate above zero",
        detail: `${formatRate(errorRate)} module error rate.`,
        tone: "warn"
      });
    }
    if (unhealthyWorkers > 0) {
      items.push({
        id: "telemetry:workers",
        title: "Unhealthy worker detected",
        detail: `${unhealthyWorkers} worker(s) unhealthy.`,
        tone: "danger"
      });
    }
    if (queueDepth > 0) {
      items.push({
        id: "telemetry:queue",
        title: "Queue has pending work",
        detail: `${queueDepth} queued task(s).`,
        tone: "info"
      });
    }
    return items;
  }, [campaigns.isError, health.data, health.isError, health.isSuccess, modules.isError, reports.isError, selectedCampaignId, telemetry.data, telemetry.isError]);

  const isNotificationDeleted = useCallback(
    (id: string): boolean => {
      return (
        deletedNotificationIds.includes(id) ||
        deletedNotificationIds.some(
          (deletedId) => deletedId.startsWith(`${id}:`) || id.startsWith(`${deletedId}:`)
        )
      );
    },
    [deletedNotificationIds]
  );

  const isNotificationRead = useCallback(
    (id: string): boolean => {
      return (
        readNotificationIds.includes(id) ||
        readNotificationIds.some(
          (readId) => readId.startsWith(`${id}:`) || id.startsWith(`${readId}:`)
        )
      );
    },
    [readNotificationIds]
  );

  const visibleNotifications = useMemo(
    () => notifications.filter((item) => !isNotificationDeleted(item.id)),
    [isNotificationDeleted, notifications]
  );
  const unreadNotificationCount = visibleNotifications.filter(
    (item) => !isNotificationRead(item.id)
  ).length;

  function markVisibleNotificationsRead(): void {
    const visibleIds = visibleNotifications.map((item) => item.id);
    if (visibleIds.length === 0) return;
    setReadNotificationIds((current) => {
      const next = unique([...current, ...visibleIds]).slice(-200);
      setStoredNotificationIds(NOTIFICATIONS_READ_KEY, username, next);
      return next;
    });
  }

  function toggleNotifications(): void {
    const nextOpen = !notificationsOpen;
    if (nextOpen) {
      markVisibleNotificationsRead();
    }
    setNotificationsOpen(nextOpen);
  }

  function deleteNotification(id: string): void {
    setDeletedNotificationIds((current) => {
      const next = unique([...current, id]).slice(-200);
      setStoredNotificationIds(NOTIFICATIONS_DELETED_KEY, username, next);
      return next;
    });
    setReadNotificationIds((current) => {
      const next = unique([...current, id]).slice(-200);
      setStoredNotificationIds(NOTIFICATIONS_READ_KEY, username, next);
      return next;
    });
  }

  function clearNotifications(): void {
    const visibleIds = visibleNotifications.map((item) => item.id);
    setDeletedNotificationIds((current) => {
      const next = unique([...current, ...visibleIds]).slice(-200);
      setStoredNotificationIds(NOTIFICATIONS_DELETED_KEY, username, next);
      return next;
    });
    setReadNotificationIds((current) => {
      const next = unique([...current, ...visibleIds]).slice(-200);
      setStoredNotificationIds(NOTIFICATIONS_READ_KEY, username, next);
      return next;
    });
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
                    ref={searchInputRef}
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
                        (event.target as HTMLInputElement).blur();
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



// ============================================================================
// MODULAR RE-EXPORTS (AUD-006 & AUD-008)
// 100% backward-compatible façade re-exporting modular pages & components.
// ============================================================================

export * from "./dashboardComponents";

export { OverviewPage } from "./pages/OverviewPage";
export { CampaignsPage } from "./pages/CampaignsPage";
export { ModulesPage } from "./pages/ModulesPage";
export { ReportsPage } from "./pages/ReportsPage";
export { TemplatesPage } from "./pages/TemplatesPage";
export { StrategyPage } from "./pages/StrategyPage";
export { SecurityPage } from "./pages/SecurityPage";
export { EdrPage } from "./pages/EdrPage";
export { LivePage } from "./pages/LivePage";
