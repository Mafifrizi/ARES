import {
  Activity,
  BarChart3,
  Boxes,
  FileText,
  GitGraph,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Loader2,
  LogOut,
  Play,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserCog,
  Workflow
} from "lucide-react";
import {
  ChangeEvent,
  createContext,
  Dispatch,
  FormEvent,
  ReactNode,
  SetStateAction,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  api,
  buildModuleRunPayload,
  campaignEventsPath,
  getAccessToken,
  getRefreshToken,
  login as loginRequest,
  logout as logoutRequest
} from "./api/client";
import type { Campaign, Finding, ModuleMeta, ParamField, ReportItem, UserProfile } from "./api/types";

interface AuthState {
  user: UserProfile | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("AuthContext missing");
  }
  return value;
}

interface DashboardUiState {
  selectedCampaignId: string;
  setSelectedCampaignId: Dispatch<SetStateAction<string>>;
  liveCampaignId: string;
  setLiveCampaignId: Dispatch<SetStateAction<string>>;
  liveConnected: boolean;
  setLiveConnected: Dispatch<SetStateAction<boolean>>;
  liveEvents: unknown[];
  clearLiveEvents: () => void;
}

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

const DashboardUiContext = createContext<DashboardUiState | null>(null);

function useDashboardUi(): DashboardUiState {
  const value = useContext(DashboardUiContext);
  if (!value) {
    throw new Error("DashboardUiContext missing");
  }
  return value;
}

function readSessionState<T>(key: string, initialValue: T): T {
  try {
    const stored = window.sessionStorage.getItem(key);
    return stored ? JSON.parse(stored) as T : initialValue;
  } catch {
    return initialValue;
  }
}

function useSessionState<T>(key: string, initialValue: T): readonly [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readSessionState(key, initialValue));

  useEffect(() => {
    try {
      const serialized = JSON.stringify(value);
      if (serialized === undefined) {
        window.sessionStorage.removeItem(key);
      } else {
        window.sessionStorage.setItem(key, serialized);
      }
    } catch {
      // Session persistence is a UX aid; storage failures should never block the dashboard.
    }
  }, [key, value]);

  return [value, setValue] as const;
}

const REQUIRED_FIELD_MESSAGE = "This field is required.";

type ValidatableElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
type TelemetryMetricMap = Record<string, number | string | undefined>;
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

function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(Boolean(getRefreshToken()));
  const queryClient = useQueryClient();

  useEffect(() => {
    let active = true;
    if (!getRefreshToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then((profile) => {
        if (active) {
          setUser(profile);
        }
      })
      .catch(() => {
        if (active) {
          setUser(null);
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      login: async (username, password) => {
        await loginRequest(username, password);
        const profile = await api.me();
        setUser(profile);
      },
      logout: async () => {
        await logoutRequest();
        setUser(null);
        queryClient.clear();
      }
    }),
    [loading, queryClient, user]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

const navItems = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/campaigns", label: "Campaigns", icon: ListChecks },
  { to: "/modules", label: "Modules", icon: Boxes },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/graph", label: "Graph", icon: GitGraph },
  { to: "/templates", label: "Templates", icon: Workflow },
  { to: "/strategy", label: "Strategy", icon: ShieldCheck },
  { to: "/security", label: "Security", icon: UserCog },
  { to: "/edr", label: "EDR/OPSEC", icon: ShieldAlert },
  { to: "/live", label: "Live", icon: Radio }
];

const brandLogoPath = "/dashboard/brand/ares-logo.png";
const brandMarkPath = "/dashboard/brand/ares-mark.png";

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

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/*" element={<ProtectedShell />} />
      </Routes>
    </AuthProvider>
  );
}

function ProtectedShell() {
  const { user, loading, logout } = useAuth();
  const [selectedCampaignId, setSelectedCampaignId] = useSessionState("ares.dashboard.selectedCampaignId", "");
  const [liveCampaignId, setLiveCampaignId] = useSessionState("ares.dashboard.live.campaignId", "");
  const [liveEvents, setLiveEvents] = useSessionState<unknown[]>("ares.dashboard.live.events", []);
  const [liveConnected, setLiveConnected] = useState(false);
  const liveSocketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const accessToken = getAccessToken();
    if (!liveConnected || !liveCampaignId || !accessToken) {
      if (liveSocketRef.current) {
        liveSocketRef.current.close();
        liveSocketRef.current = null;
      }
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}${campaignEventsPath(liveCampaignId, accessToken)}`);
    liveSocketRef.current = socket;
    socket.onmessage = (event) => {
      try {
        setLiveEvents((items) => [JSON.parse(event.data), ...items].slice(0, 100));
      } catch {
        setLiveEvents((items) => [event.data, ...items].slice(0, 100));
      }
    };
    socket.onclose = () => {
      if (liveSocketRef.current === socket) {
        liveSocketRef.current = null;
        setLiveConnected(false);
      }
    };

    return () => {
      socket.onclose = null;
      socket.close();
      if (liveSocketRef.current === socket) {
        liveSocketRef.current = null;
      }
    };
  }, [liveCampaignId, liveConnected, setLiveEvents]);

  const dashboardUi = useMemo<DashboardUiState>(
    () => ({
      selectedCampaignId,
      setSelectedCampaignId,
      liveCampaignId,
      setLiveCampaignId,
      liveConnected,
      setLiveConnected,
      liveEvents,
      clearLiveEvents: () => setLiveEvents([])
    }),
    [
      liveCampaignId,
      liveConnected,
      liveEvents,
      selectedCampaignId,
      setLiveCampaignId,
      setLiveConnected,
      setLiveEvents,
      setSelectedCampaignId
    ]
  );

  if (loading) {
    return <ScreenMessage title="ARES" body="Loading session" />;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return (
    <DashboardUiContext.Provider value={dashboardUi}>
      <div className="app-shell grid min-h-screen grid-cols-1 lg:grid-cols-[240px_1fr]">
        <aside className="sidebar p-4">
          <div className="mb-6 flex items-center gap-3">
            <img className="h-11 w-11 shrink-0 object-contain" src={brandMarkPath} alt="" aria-hidden="true" />
            <div>
              <div className="text-base font-bold">ARES</div>
              <div className="text-xs text-slate-300">{user.username} &middot; {formatRole(user.role)}</div>
            </div>
          </div>
          <nav className="grid gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink key={item.to} to={item.to} end={item.to === "/"} className="nav-link">
                  <Icon size={17} />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </aside>
        <main className="min-w-0 p-4 lg:p-6">
          <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-bold text-slate-950">Operator Dashboard</h1>
              <p className="text-sm text-slate-600">{user.username}</p>
            </div>
            <button className="btn" onClick={() => void logout()}>
              <LogOut size={16} /> Logout
            </button>
          </header>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/campaigns" element={<CampaignsPage />} />
            <Route path="/modules" element={<ModulesPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="/templates" element={<TemplatesPage />} />
            <Route path="/strategy" element={<StrategyPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/edr" element={<EdrPage />} />
            <Route path="/live" element={<LivePage />} />
          </Routes>
        </main>
      </div>
    </DashboardUiContext.Provider>
  );
}

function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { login, user } = useAuth();
  const navigate = useNavigate();

  if (user) {
    return <Navigate to="/" replace />;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await login(username, password);
      navigate("/");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Login failed");
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
      <form className="panel w-full max-w-sm p-5" onSubmit={(event) => void submit(event)}>
        <div className="mb-5 text-center">
          <img className="mx-auto mb-4 h-28 w-auto max-w-full object-contain" src={brandLogoPath} alt="ARES" />
          <h1 className="text-xl font-bold">ARES Dashboard</h1>
          <p className="text-sm text-slate-600">Authorized access</p>
        </div>
        <label className="mb-3 block text-sm font-semibold">
          Username
          <input className="field mt-1" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="mb-4 block text-sm font-semibold">
          Password
          <input
            className="field mt-1"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <div className="mb-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800">{error}</div>}
        <button className="btn btn-primary w-full" type="submit">
          <KeyRound size={16} /> Login
        </button>
      </form>
    </div>
  );
}

function OverviewPage() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const telemetry = useQuery({ queryKey: ["telemetry"], queryFn: api.telemetry });
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const snapshot = telemetry.data as TelemetrySnapshot | undefined;
  return (
    <Page title="Overview">
      <div className="grid gap-4 md:grid-cols-3">
        <Stat title="Health" value={String(health.data?.status ?? "unknown")} icon={<Activity size={18} />} />
        <Stat title="Campaigns" value={String(campaigns.data?.length ?? 0)} icon={<ListChecks size={18} />} />
        <Stat title="Telemetry" value={telemetry.isSuccess ? "online" : "pending"} icon={<BarChart3 size={18} />} />
      </div>
      <TelemetryPanel snapshot={snapshot} loading={telemetry.isLoading} />
      <CampaignTable campaigns={campaigns.data ?? []} />
    </Page>
  );
}

function CampaignsPage() {
  const queryClient = useQueryClient();
  const { selectedCampaignId: selected, setSelectedCampaignId: setSelected } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [name, setName] = useSessionState("ares.dashboard.campaigns.create.name", "");
  const [client, setClient] = useSessionState("ares.dashboard.campaigns.create.client", "Internal");
  const [targets, setTargets] = useSessionState("ares.dashboard.campaigns.create.targets", "");
  const [scope, setScope] = useSessionState("ares.dashboard.campaigns.create.scope", "");
  const [createWarning, setCreateWarning] = useState("");
  const [otherId, setOtherId] = useSessionState("ares.dashboard.campaigns.compareId", "");
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
        scope_cidrs: splitLines(scope)
      }),
    onSuccess: (campaign) => {
      setSelected(campaign.id);
      setName("");
      setTargets("");
      setScope("");
      setCreateWarning("");
      void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
    }
  });
  const restore = useMutation({ mutationFn: () => api.restoreVault(selected) });
  const run = useMutation({
    mutationFn: () => api.runCampaign(selected, { plan: { stages: [] }, global_params: {}, dry_run: true })
  });
  const remove = useMutation({
    mutationFn: () => api.deleteCampaign(selected),
    onSuccess: () => {
      const deleted = selected;
      setSelected("");
      setOtherId("");
      void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      void queryClient.removeQueries({ queryKey: ["campaign", deleted] });
      void queryClient.removeQueries({ queryKey: ["findings", deleted] });
      void queryClient.removeQueries({ queryKey: ["cvss", deleted] });
      void queryClient.removeQueries({ queryKey: ["reports", deleted] });
    }
  });

  return (
    <Page title="Campaigns">
      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <section className="panel p-4">
          <h2 className="mb-3 text-base font-bold">Create Campaign</h2>
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
            <input className="field" required placeholder="Name" value={name} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setName(e.target.value); }} />
            <input className="field" required placeholder="Client" value={client} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setClient(e.target.value); }} />
            <textarea className="field min-h-24" required placeholder="Targets" value={targets} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setTargets(e.target.value); }} />
            <textarea className="field min-h-24" required placeholder="Scope CIDRs" value={scope} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCreateWarning(""); setScope(e.target.value); }} />
            {createWarning && <p className="text-sm font-semibold text-red-700">{createWarning}</p>}
            <button className="btn btn-primary" disabled={create.isPending} type="submit">
              <ListChecks size={16} /> Create
            </button>
          </form>
          <DataPanel title="Create Error" data={create.error} />
        </section>
        <section className="grid gap-4">
          <CampaignPicker campaigns={campaigns.data ?? []} value={selected} onChange={setSelected} />
          <CampaignScopeSummary campaign={detail.data ?? campaigns.data?.find((item) => item.id === selected)} loading={detail.isFetching} />
          <div className="flex flex-wrap gap-2">
            <button className="btn" disabled={!selected} onClick={() => restore.mutate()}>
              <ShieldCheck size={16} /> Restore Vault
            </button>
            <button className="btn" disabled={!selected} onClick={() => run.mutate()}>
              <Play size={16} /> Dry Run Plan
            </button>
            <button
              className="btn btn-danger"
              disabled={!selected || remove.isPending}
              onClick={() => {
                if (window.confirm("Delete this campaign and its stored findings, hosts, credentials, and loot?")) {
                  remove.mutate();
                }
              }}
            >
              <Trash2 size={16} /> Delete
            </button>
            <input className="field max-w-xs" placeholder="Compare campaign ID" value={otherId} onChange={(e) => setOtherId(e.target.value)} />
          </div>
          <DataPanel title="Delete Error" data={remove.error} />
          <DataPanel title="Campaign Detail" data={detail.data} />
          <DataPanel title="CVSS Summary" data={cvss.data} />
          <DataPanel title="Diff" data={diff.data} />
          <FindingsTable findings={findings.data ?? []} />
        </section>
      </div>
    </Page>
  );
}

function ModulesPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const modules = useQuery({ queryKey: ["modules"], queryFn: api.modules });
  const [selectedId, setSelectedId] = useSessionState("ares.dashboard.modules.selectedId", "");
  const [search, setSearch] = useSessionState("ares.dashboard.modules.search", "");
  const [category, setCategory] = useSessionState("ares.dashboard.modules.category", "");
  const [opsec, setOpsec] = useSessionState("ares.dashboard.modules.opsec", "");
  const [dryRun, setDryRun] = useSessionState("ares.dashboard.modules.dryRun", true);
  const [confirmed, setConfirmed] = useSessionState("ares.dashboard.modules.confirmed", false);
  const [params, setParams] = useSessionState<Record<string, unknown>>("ares.dashboard.modules.params", {});
  const [lastRunRecord, setLastRunRecord] = useSessionState<ModuleRunRecord | null>("ares.dashboard.modules.lastRun", null);
  const previousSelectedId = useRef(selectedId);
  const campaignDetail = useQuery({
    queryKey: ["campaign", campaignId],
    queryFn: () => api.campaign(campaignId),
    enabled: Boolean(campaignId)
  });
  const run = useMutation({
    mutationFn: () => api.runModule(selectedId, buildModuleRunPayload(campaignId, params, dryRun)),
    onSuccess: (payload) => setLastRunRecord({ campaignId, moduleId: selectedId, payload }),
    onError: (error) => setLastRunRecord({ campaignId, moduleId: selectedId, payload: serializeError(error), isError: true })
  });
  const list = modules.data ?? [];
  const selected = list.find((item) => item.id === selectedId);
  const selectedCampaign = campaignDetail.data ?? (campaigns.data ?? []).find((item) => item.id === campaignId);
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
  const canRun = Boolean(campaignId && selectedId) && (!sensitive || confirmed) && !run.isPending;
  const runBlocked = !canRun || Boolean(scopeWarning);
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
    <Page title="Modules">
      <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <section className="panel p-4">
          <div className="mb-3 grid gap-2 sm:grid-cols-3">
            <input className="field sm:col-span-3" placeholder="Search" value={search} onChange={(e) => setSearch(e.target.value)} />
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
                className={`panel p-3 text-left ${selectedId === item.id ? "ring-2 ring-red-700" : ""}`}
                key={item.id}
                onClick={() => setSelectedId(item.id)}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-bold">{item.id}</div>
                    <div className="text-sm text-slate-600">{item.description}</div>
                  </div>
                  <span className={opsecBadge(item.opsec_level)}>{item.opsec_level || "n/a"}</span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(item.mitre_list ?? []).slice(0, 4).map((technique) => <span className="badge" key={technique}>{technique}</span>)}
                </div>
              </button>
            ))}
            {visible.length === 0 && (
              <EmptyState text="No modules match the current search and filters." />
            )}
          </div>
        </section>
        <section className="panel p-4">
          <h2 className="mb-3 text-base font-bold">Run Module</h2>
          <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={setCampaignId} />
          {campaignId && campaignDetail.isFetching && (
            <div className="mt-3 flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold text-slate-700">
              <Loader2 className="spin" size={16} /> Loading campaign scope...
            </div>
          )}
          {selected ? (
            <form
              aria-busy={run.isPending}
              className="mt-4 grid gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (runBlocked) {
                  return;
                }
                run.mutate();
              }}
            >
              <ParamForm schema={selected.param_schema} values={params} onChange={setParams} />
              {runHint && (
                <p className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold text-slate-700">
                  {runHint}
                </p>
              )}
              {scopeWarning && (
                <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-800">
                  {scopeWarning}
                </p>
              )}
              <label className="flex items-center gap-2 text-sm font-semibold">
                <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                Dry run
              </label>
              {sensitive && (
                <label className="rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-900">
                  <input className="mr-2" type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  Confirm authorized high-noise or sensitive execution
                </label>
              )}
              <button className="btn btn-primary" type="submit" disabled={runBlocked}>
                {run.isPending ? (
                  <>
                    <Loader2 className="spin" size={16} /> Running...
                  </>
                ) : (
                  <>
                    <Play size={16} /> Run
                  </>
                )}
              </button>
              {run.isPending && (
                <div className="flex items-center gap-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-900" role="status" aria-live="polite">
                  <Loader2 className="spin shrink-0" size={18} />
                  Module execution in progress. Keep this page open while ARES validates the target and collects results.
                </div>
              )}
            </form>
          ) : (
            <EmptyState text="Select a module" />
          )}
          <ModuleRunSummary result={runResult} error={runError} />
          <DataPanel title={runError ? "Run Error" : "Raw Run Result"} data={runError ?? runResult} />
        </section>
      </div>
    </Page>
  );
}

function ReportsPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [format, setFormat] = useSessionState("ares.dashboard.reports.format", "html");
  const [warning, setWarning] = useState("");
  const [lastGenerateResult, setLastGenerateResult] = useSessionState<PersistedResult | null>("ares.dashboard.reports.lastGenerate", null);
  const queryClient = useQueryClient();
  const reports = useQuery({
    queryKey: ["reports", campaignId],
    queryFn: () => api.reports(campaignId),
    enabled: Boolean(campaignId)
  });
  const reportResultKey = `${campaignId}:${format}`;
  const generate = useMutation({
    mutationFn: () => api.generateReport(campaignId, format),
    onSuccess: (payload) => {
      setLastGenerateResult({ key: reportResultKey, payload });
      void queryClient.invalidateQueries({ queryKey: ["reports", campaignId] });
    },
    onError: (error) => setLastGenerateResult({ key: reportResultKey, payload: serializeError(error), isError: true })
  });
  const persistedGenerateResult = lastGenerateResult?.key === reportResultKey ? lastGenerateResult : null;
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
  return (
    <Page title="Reports">
      <div className="panel p-4">
        <h2 className="mb-2 text-base font-bold">Generate Report</h2>
        <p className="mb-3 text-sm text-slate-600">
          Choose a campaign and export the current findings, scope, and remediation notes. PDF is for sharing, HTML is for browser review, JSON/Markdown are for downstream workflows.
        </p>
        <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={(id) => { setCampaignId(id); setWarning(""); }} />
        <div className="mt-3 flex flex-wrap gap-2">
          <select className="field max-w-40" value={format} onChange={(e) => setFormat(e.target.value)}>
            {["html", "pdf", "markdown", "json"].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <button className="btn btn-primary" disabled={generate.isPending} onClick={() => {
            if (!campaignId) {
              setWarning("Campaign is required.");
              return;
            }
            setWarning("");
            generate.mutate();
          }}>
            {generate.isPending ? (
              <>
                <Loader2 className="spin" size={16} /> Generating...
              </>
            ) : (
              <>
                <FileText size={16} /> Generate
              </>
            )}
          </button>
        </div>
        {warning && <p className="mt-2 text-sm font-semibold text-red-700">{warning}</p>}
        <DataPanel
          title={(generate.error ?? (persistedGenerateResult?.isError ? persistedGenerateResult.payload : undefined)) ? "Generate Error" : "Generate Result"}
          data={generate.error ?? generate.data ?? persistedGenerateResult?.payload}
        />
      </div>
      <section className="panel mt-4 overflow-auto p-4">
        <table className="table">
          <thead><tr><th>Filename</th><th>Format</th><th>Size</th><th></th></tr></thead>
          <tbody>
            {(reports.data?.reports ?? []).map((item) => (
              <tr key={item.filename}>
                <td>{item.filename}</td>
                <td>{item.format}</td>
                <td>{item.size_bytes}</td>
                <td>
                  <button className="btn" disabled={download.isPending} onClick={() => download.mutate(item)}>Download</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {campaignId && (reports.data?.reports ?? []).length === 0 && (
          <EmptyState text="No reports generated for this campaign yet." />
        )}
        {!campaignId && <EmptyState text="Select a campaign to list generated reports." />}
        <DataPanel title="Download Result" data={download.error} />
      </section>
    </Page>
  );
}

function GraphPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [jsonPath, setJsonPath] = useSessionState("ares.dashboard.graph.jsonPath", "");
  const [warning, setWarning] = useState("");
  const [lastIngestResult, setLastIngestResult] = useSessionState<PersistedResult | null>("ares.dashboard.graph.lastIngest", null);
  const graph = useQuery({ queryKey: ["graph", campaignId], queryFn: () => api.graph(campaignId), enabled: Boolean(campaignId) });
  const paths = useQuery({ queryKey: ["attack-paths", campaignId], queryFn: () => api.attackPaths(campaignId), enabled: Boolean(campaignId) });
  const ingestResultKey = `${campaignId}:${jsonPath.trim()}`;
  const ingest = useMutation({
    mutationFn: () => api.ingestBloodhound(campaignId, jsonPath),
    onSuccess: (payload) => setLastIngestResult({ key: ingestResultKey, payload }),
    onError: (error) => setLastIngestResult({ key: ingestResultKey, payload: serializeError(error), isError: true })
  });
  const persistedIngestResult = lastIngestResult?.key === ingestResultKey ? lastIngestResult : null;
  const nodes = Array.isArray(graph.data?.nodes) ? graph.data.nodes : [];
  const links = Array.isArray(graph.data?.links) ? graph.data.links : [];
  return (
    <Page title="Graph">
      <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={(id) => { setCampaignId(id); setWarning(""); }} />
      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_360px]">
        <section className="panel min-h-[360px] p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-bold">Attack Graph</h2>
              <p className="text-sm text-slate-600">Hosts, identities, and BloodHound relationships linked to the selected campaign.</p>
            </div>
            <div className="flex gap-2">
              <span className="badge">{nodes.length} nodes</span>
              <span className="badge">{links.length} links</span>
            </div>
          </div>
          {nodes.length > 0 ? (
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {nodes.slice(0, 24).map((node: any, index) => (
                <div className="rounded-md border border-slate-300 bg-slate-50 p-3" key={node.id ?? index}>
                  <div className="font-bold">{node.label ?? node.id ?? `Node ${index + 1}`}</div>
                  <div className="text-sm text-slate-600">{node.type ?? "artifact"}</div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState text={campaignId ? "No graph nodes yet. Run modules that discover hosts or ingest BloodHound JSON." : "Select a campaign to load graph data."} />
          )}
        </section>
        <section className="panel p-4">
          <h2 className="mb-2 text-base font-bold">BloodHound Ingest</h2>
          <p className="mb-3 text-sm text-slate-600">
            Paste a server-local JSON file or directory path produced by BloodHound/SharpHound. ARES imports it into the selected campaign graph.
          </p>
          <form className="grid gap-2" onSubmit={(e) => {
            e.preventDefault();
            if (!campaignId) {
              setWarning("Campaign is required.");
              return;
            }
            if (!jsonPath.trim()) {
              setWarning("BloodHound JSON path is required.");
              return;
            }
            setWarning("");
            ingest.mutate();
          }}>
            <input className="field" required placeholder="C:\\labs\\bloodhound\\results.json" value={jsonPath} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setJsonPath(e.target.value); setWarning(""); }} />
            <button className="btn" disabled={ingest.isPending} type="submit">
              {ingest.isPending ? (
                <>
                  <Loader2 className="spin" size={16} /> Ingesting...
                </>
              ) : (
                <>
                  <GitGraph size={16} /> Ingest
                </>
              )}
            </button>
          </form>
          {warning && <p className="mt-2 text-sm font-semibold text-red-700">{warning}</p>}
          <DataPanel title="Attack Paths" data={paths.data} />
          <DataPanel
            title={(ingest.error ?? (persistedIngestResult?.isError ? persistedIngestResult.payload : undefined)) ? "Ingest Error" : "Ingest Result"}
            data={ingest.data ?? ingest.error ?? persistedIngestResult?.payload}
          />
        </section>
      </div>
    </Page>
  );
}

function TemplatesPage() {
  const templates = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const [name, setName] = useSessionState("ares.dashboard.templates.name", "");
  const [params, setParams] = useSessionState("ares.dashboard.templates.params", "{}");
  const [warning, setWarning] = useState("");
  const [lastPlanResult, setLastPlanResult] = useSessionState<PersistedResult | null>("ares.dashboard.templates.lastPlan", null);
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
    <Page title="Templates">
      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <section className="panel p-4">
          <h2 className="mb-2 text-base font-bold">Campaign Templates</h2>
          <p className="mb-3 text-sm text-slate-600">
            Pick a built-in engagement shape, add optional global values, then generate a run plan for a campaign dry-run.
          </p>
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
        <section className="panel p-4">
          <h2 className="mb-2 text-base font-bold">Plan Builder</h2>
          <input className="field" placeholder="Template name" value={name} onChange={(e) => {
            setName(e.target.value);
            setWarning("");
            setLastPlanResult(null);
          }} />
          {selected ? (
            <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3">
              <div className="font-bold">{selected.name}</div>
              <p className="mt-1 text-sm text-slate-600">{selected.description}</p>
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
          <p className="mt-1 text-xs text-slate-600">
            Optional JSON object. Leave as {"{}"} when the template should use module defaults or campaign-level values.
          </p>
          {(warning || !paramsValid) && (
            <p className="mt-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-800">
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
              <>
                <Workflow size={16} /> Generate Plan
              </>
            )}
          </button>
          <TemplatePlanSummary plan={generated} />
          <DataPanel
            title={(plan.error ?? (persistedPlanResult?.isError ? persistedPlanResult.payload : undefined)) ? "Plan Error" : "Plan Details"}
            data={plan.error ?? plan.data ?? persistedPlanResult?.payload}
          />
        </section>
      </div>
    </Page>
  );
}

function StrategyPage() {
  const { user } = useAuth();
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const active = useQuery({ queryKey: ["strategy-active"], queryFn: api.activeStrategy });
  const [goal, setGoal] = useSessionState("ares.dashboard.strategy.goal", "domain_admin");
  const [llmBackend, setLlmBackend] = useSessionState("ares.dashboard.strategy.llmBackend", "claude");
  const [authorizations, setAuthorizations] = useSessionState("ares.dashboard.strategy.authorizations", "");
  const [lastEngageResult, setLastEngageResult] = useSessionState<PersistedResult | null>("ares.dashboard.strategy.lastEngage", null);
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
    onSuccess: (payload) => setLastEngageResult({ key: strategyResultKey, payload }),
    onError: (error) => setLastEngageResult({ key: strategyResultKey, payload: serializeError(error), isError: true })
  });
  const persistedEngageResult = lastEngageResult?.key === strategyResultKey ? lastEngageResult : null;
  const allowed = user?.role === "team_lead" || user?.role === "operator";
  return (
    <Page title="Strategy">
      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <section className="panel p-4">
          <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={setCampaignId} />
          <select className="field mt-3" value={goal} onChange={(e) => setGoal(e.target.value)}>
            {["domain_admin", "enterprise_admin", "cloud_admin", "data_exfil", "persistence", "full_compromise"].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select className="field mt-3" value={llmBackend} onChange={(e) => setLlmBackend(e.target.value)}>
            <option value="claude">Claude / ANTHROPIC_API_KEY</option>
            <option value="openai">OpenAI / OPENAI_API_KEY</option>
            <option value="local">Local Ollama</option>
          </select>
          <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
            {strategyBackendHint(llmBackend)}
          </p>
          <textarea
            className="field mt-3 min-h-28"
            placeholder="Authorization notes, one per line"
            value={authorizations}
            onChange={(e) => setAuthorizations(e.target.value)}
          />
          {!allowed && (
            <p className="mt-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-800">
              Strategy engagement requires operator or team lead role.
            </p>
          )}
          {!campaignId && (
            <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold text-slate-700">
              Select a scoped campaign before starting Strategy.
            </p>
          )}
          <button className="btn btn-primary mt-3" disabled={!allowed || !campaignId || engage.isPending} onClick={() => engage.mutate()}>
            {engage.isPending ? (
              <>
                <Loader2 className="spin" size={16} /> Engaging...
              </>
            ) : (
              <>
                <ShieldCheck size={16} /> Engage
              </>
            )}
          </button>
        </section>
        <section>
          <DataPanel title="Active" data={active.data} />
          <DataPanel
            title={(engage.error ?? (persistedEngageResult?.isError ? persistedEngageResult.payload : undefined)) ? "Engagement Error" : "Engagement Result"}
            data={engage.data ?? engage.error ?? persistedEngageResult?.payload}
          />
        </section>
      </div>
    </Page>
  );
}

function SecurityPage() {
  const { user } = useAuth();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.apiKeys });
  const audit = useQuery({ queryKey: ["security-audit"], queryFn: api.securityAudit, enabled: user?.role === "team_lead" });
  const users = useQuery({ queryKey: ["security-users"], queryFn: api.users, enabled: user?.role === "team_lead" });
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [keyName, setKeyName] = useState("");
  const [scopes, setScopes] = useState("read");
  const change = useMutation({
    mutationFn: () => api.changePassword({ current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
    }
  });
  const create = useMutation({
    mutationFn: () => api.createApiKey({ name: keyName, scopes }),
    onSuccess: () => {
      setKeyName("");
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    }
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteApiKey(id),
    onSuccess: () => {
      create.reset();
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    }
  });
  return (
    <Page title="Security">
      <div className="grid gap-4 xl:grid-cols-2">
        <section className="panel p-4">
          <h2 className="mb-3 font-bold">Account</h2>
          <div className="mb-3 text-sm">{user?.username} &middot; {formatRole(user?.role)}</div>
          <form className="grid gap-2" onSubmit={(event) => {
            event.preventDefault();
            if (!event.currentTarget.reportValidity()) return;
            change.mutate();
          }}>
            <input className="field" required type="password" placeholder="Current password" value={currentPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCurrentPassword(e.target.value); }} />
            <input className="field" required minLength={12} type="password" placeholder="New password" value={newPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setNewPassword(e.target.value); }} />
            <button className="btn" disabled={change.isPending} type="submit">
              {change.isPending ? <Loader2 className="spin" size={16} /> : <KeyRound size={16} />}
              Change Password
            </button>
          </form>
          <DataPanel title="Password Result" data={change.data ?? change.error} />
        </section>
        <section className="panel p-4">
          <h2 className="mb-3 font-bold">API Keys</h2>
          <p className="mb-3 text-sm text-slate-600">
            Use ARES API keys for scripts, integrations, or CI jobs that call ARES. They are not LLM provider keys for Strategy.
          </p>
          <form className="mb-3 grid gap-2 sm:grid-cols-[1fr_120px_auto]" onSubmit={(event) => {
            event.preventDefault();
            if (!event.currentTarget.reportValidity()) return;
            create.mutate();
          }}>
            <input className="field" required placeholder="Name" value={keyName} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setKeyName(e.target.value); }} />
            <select className="field" value={scopes} onChange={(e) => setScopes(e.target.value)}>
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn" disabled={create.isPending} type="submit">
              {create.isPending ? <Loader2 className="spin" size={16} /> : <KeyRound size={16} />}
              Create
            </button>
          </form>
          {(keys.data ?? []).map((key) => (
            <div className="mb-2 flex items-center justify-between rounded-md border border-slate-200 p-2" key={key.id}>
              <span>{key.name ?? key.prefix ?? key.id}</span>
              <button className="btn btn-danger" disabled={remove.isPending} onClick={() => remove.mutate(key.id)}>Delete</button>
            </div>
          ))}
          {(keys.data ?? []).length === 0 && <EmptyState text="No API keys have been created yet." />}
          <DataPanel title="New Key" data={create.data} />
          <DataPanel title="API Key Error" data={create.error ?? remove.error} />
        </section>
      </div>
      <DataPanel title="Security Audit" data={audit.data} />
      <DataPanel title="Users" data={users.data} />
    </Page>
  );
}

function EdrPage() {
  const stats = useQuery({ queryKey: ["edr-stats"], queryFn: api.edrStats });
  const [techniqueId, setTechniqueId] = useSessionState("ares.dashboard.edr.techniqueId", "");
  const [vendor, setVendor] = useSessionState("ares.dashboard.edr.vendor", "");
  const [version, setVersion] = useSessionState("ares.dashboard.edr.version", "");
  const [success, setSuccess] = useSessionState("ares.dashboard.edr.success", false);
  const [notes, setNotes] = useSessionState("ares.dashboard.edr.notes", "");
  const [lastReportResult, setLastReportResult] = useSessionState<PersistedResult | null>("ares.dashboard.edr.lastReport", null);
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
    <Page title="EDR/OPSEC">
      <section className="panel p-4">
        <h2 className="mb-2 text-base font-bold">Bypass Knowledge Base</h2>
        <p className="text-sm text-slate-600">
          Record whether an approved technique was blocked or successful so future Strategy runs can avoid weak options.
        </p>
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
        <p className="mt-3 text-sm text-slate-600">{String(stats.data?.message ?? "No historical sample loaded yet.")}</p>
      </section>
      <section className="panel p-4">
        <h2 className="mb-3 text-base font-bold">Report Outcome</h2>
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
              <>
                <ShieldAlert size={16} /> Report Outcome
              </>
            )}
          </button>
        </form>
      </section>
      <DataPanel
        title={(report.error ?? (persistedReportResult?.isError ? persistedReportResult.payload : undefined)) ? "Outcome Error" : "Outcome Result"}
        data={report.data ?? report.error ?? persistedReportResult?.payload}
      />
      <DataPanel title="Raw Stats" data={stats.data} />
    </Page>
  );
}

function LivePage() {
  const {
    selectedCampaignId,
    setSelectedCampaignId,
    liveCampaignId,
    setLiveCampaignId,
    liveConnected,
    setLiveConnected,
    liveEvents,
    clearLiveEvents
  } = useDashboardUi();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const campaignId = liveCampaignId || selectedCampaignId;

  return (
    <Page title="Live Events">
      <div className="panel p-4">
        <h2 className="mb-2 text-base font-bold">Campaign Event Stream</h2>
        <p className="mb-3 text-sm text-slate-600">
          Connect to a campaign to watch module runs, findings, and audit events as they are emitted.
        </p>
        <CampaignPicker
          campaigns={campaigns.data ?? []}
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
            <Radio size={16} /> {liveConnected ? "Connected" : "Connect"}
          </button>
          {liveConnected && (
            <button className="btn" onClick={() => setLiveConnected(false)}>
              Disconnect
            </button>
          )}
          {liveEvents.length > 0 && (
            <button className="btn" onClick={clearLiveEvents}>
              Clear Events
            </button>
          )}
          <span className={liveConnected ? "badge badge-low" : "badge"}>{liveConnected ? "listening" : "offline"}</span>
        </div>
      </div>
      <section className="panel p-4">
        <h3 className="mb-2 font-bold">Event Stream</h3>
        {liveEvents.length > 0 ? (
          <div className="grid gap-2">
            {liveEvents.map((event, index) => (
              <pre className="json-box max-h-48" key={index}>{JSON.stringify(event, null, 2)}</pre>
            ))}
          </div>
        ) : (
          <EmptyState text={liveConnected ? "Connected. Waiting for campaign events." : "Select a campaign and connect to start listening."} />
        )}
      </section>
    </Page>
  );
}

function Page({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h2 className="mb-4 text-xl font-bold text-slate-950">{title}</h2>
      <div className="grid gap-4">{children}</div>
    </div>
  );
}

function Stat({ title, value, icon }: { title: string; value: string; icon: ReactNode }) {
  return (
    <div className="stat flex items-center justify-between p-4">
      <div>
        <div className="text-sm font-semibold text-slate-600">{title}</div>
        <div className="mt-1 text-2xl font-bold">{value}</div>
      </div>
      <div className="text-red-700">{icon}</div>
    </div>
  );
}

function metricNumber(map: TelemetryMetricMap | undefined, key: string): number {
  const value = map?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
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

function TelemetryPanel({ snapshot, loading }: { snapshot?: TelemetrySnapshot; loading: boolean }) {
  const total = metricNumber(snapshot?.modules, "total");
  const success = metricNumber(snapshot?.modules, "success");
  const failed = metricNumber(snapshot?.modules, "failed");
  const findings = typeof snapshot?.findings === "number" ? snapshot.findings : 0;
  const successRate = total > 0 ? Math.round((success / total) * 100) : 0;
  const errorRate = metricNumber(snapshot?.modules, "error_rate");
  const p95 = metricNumber(snapshot?.latency_ms, "p95");
  const queueDepth = metricNumber(snapshot?.queue, "depth");
  const activeWorkers = metricNumber(snapshot?.workers, "active");
  const unhealthyWorkers = metricNumber(snapshot?.workers, "unhealthy");
  const hostsDiscovered = metricNumber(snapshot?.hosts, "discovered");
  const hostsOwned = metricNumber(snapshot?.hosts, "owned");
  const tasksPerMin = metricNumber(snapshot?.throughput, "tasks_per_min");

  return (
    <section className="panel p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-slate-800">Telemetry Snapshot</h3>
          <p className="text-sm text-slate-500">
            {loading ? "Waiting for runtime metrics" : `Last sample: ${formatTimestamp(snapshot?.timestamp)}`}
          </p>
        </div>
        <span className="badge badge-low">{snapshot ? "online" : "pending"}</span>
      </div>

      <div className="telemetry-grid">
        <TelemetryMetric label="Module runs" value={formatMetric(total)} detail={`${success} success / ${failed} failed`} />
        <TelemetryMetric label="Findings" value={formatMetric(findings)} detail="confirmed runtime observations" />
        <TelemetryMetric label="Queue depth" value={formatMetric(queueDepth)} detail={`${activeWorkers} active workers`} />
        <TelemetryMetric label="Hosts" value={`${hostsDiscovered} / ${hostsOwned}`} detail="discovered / owned" />
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <TelemetryBar label="Success rate" value={successRate} />
        <TelemetryBar label="Error rate" value={Math.min(100, Math.round(errorRate * 100))} tone="danger" />
        <div className="telemetry-strip">
          <span>P95 latency</span>
          <strong>{formatMetric(p95, " ms")}</strong>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <div className="telemetry-strip">
          <span>Throughput</span>
          <strong>{formatMetric(tasksPerMin)} tasks/min</strong>
        </div>
        <div className="telemetry-strip">
          <span>Worker health</span>
          <strong>{unhealthyWorkers === 0 ? "healthy" : `${unhealthyWorkers} unhealthy`}</strong>
        </div>
        <div className="telemetry-strip">
          <span>Scope</span>
          <strong>{snapshot?.campaign_id ? `campaign ${snapshot.campaign_id}` : "global"}</strong>
        </div>
      </div>

      <details className="mt-4">
        <summary className="cursor-pointer text-sm font-semibold text-slate-600">Raw telemetry data</summary>
        <pre className="json-box mt-2">{JSON.stringify(snapshot ?? {}, null, 2)}</pre>
      </details>
    </section>
  );
}

function TelemetryMetric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="telemetry-metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function TelemetryBar({ label, value, tone = "ok" }: { label: string; value: number; tone?: "ok" | "danger" }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className="telemetry-bar">
      <div className="mb-2 flex items-center justify-between gap-3">
        <span>{label}</span>
        <strong>{clamped}%</strong>
      </div>
      <div className="telemetry-bar-track">
        <div className={tone === "danger" ? "telemetry-bar-fill danger" : "telemetry-bar-fill"} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}

function DataPanel({ title, data }: { title: string; data: unknown }) {
  if (!data) {
    return null;
  }
  const shouldOpen = data instanceof Error || data instanceof ApiError;
  return (
    <section className="panel p-4">
      <details open={shouldOpen}>
        <summary className="cursor-pointer text-sm font-bold text-slate-700">{title}</summary>
        <pre className="json-box mt-2">{JSON.stringify(serializeError(data), null, 2)}</pre>
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
      <section className="panel mt-4 p-4">
        <h3 className="mb-2 text-base font-bold">Execution Summary</h3>
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-800">
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

  return (
    <section className="panel mt-4 p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-bold">Execution Summary</h3>
          <p className="text-sm text-slate-600">{moduleId}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <span className={status === "done" ? "badge badge-low" : "badge badge-medium"}>{status}</span>
          <span className="badge">{duration}</span>
        </div>
      </div>
      {runError && (
        <p className="mb-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-800">
          {runError}
        </p>
      )}
      <div className="telemetry-grid mb-3">
        <TelemetryMetric label="Findings" value={String(findings.length)} detail="confirmed observations returned by the module" />
        <TelemetryMetric label="Validation results" value={String(validationCount)} detail="post-run checks linked to findings" />
        <TelemetryMetric label="Duration" value={duration} detail="server-side execution time" />
      </div>
      {findings.length > 0 ? (
        <div className="grid gap-2">
          {findings.map((finding, index) => (
            <div className="rounded-md border border-slate-200 p-3" key={finding.id ?? index}>
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div className="font-bold">{finding.title ?? `Finding ${index + 1}`}</div>
                  <div className="mt-1 text-sm text-slate-600">{String(finding.description ?? "")}</div>
                </div>
                <span className={opsecBadge(finding.severity)}>{finding.severity ?? "info"}</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {finding.host && <span className="badge">Host: {finding.host}</span>}
                {finding.mitre_technique && <span className="badge">{finding.mitre_technique}</span>}
                {typeof finding.confidence === "number" && <span className="badge">Confidence: {formatRate(finding.confidence)}</span>}
              </div>
              {finding.remediation ? (
                <p className="mt-2 text-sm text-slate-700">
                  <strong>Remediation:</strong> {String(finding.remediation)}
                </p>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState text={runError ? "No findings were recorded because the module stopped before producing observations." : "No findings returned for this run."} />
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
    <section className="panel mt-4 p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-bold">{plan.template}</h3>
          <p className="text-sm text-slate-600">{plan.description}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <span className="badge">{stages.length} stages</span>
          <span className="badge">{moduleCount} modules</span>
        </div>
      </div>
      <div className="grid gap-2">
        {stages.map((stage, index) => (
          <div className="rounded-md border border-slate-200 p-3" key={`${stage.name ?? "stage"}-${index}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-bold">{index + 1}. {stage.name ?? "stage"}</span>
              <span className="text-xs font-semibold text-slate-500">{stage.modules?.length ?? 0} modules</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {(stage.modules ?? []).map((moduleId) => <span className="badge" key={moduleId}>{moduleId}</span>)}
            </div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-sm text-slate-600">
        This generated plan is ready for campaign execution APIs and can be used as the structure for a campaign dry-run.
      </p>
    </section>
  );
}

function CampaignScopeSummary({ campaign, loading }: { campaign?: Campaign; loading?: boolean }) {
  if (loading) {
    return (
      <section className="panel p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-700">
          <Loader2 className="spin" size={16} /> Loading campaign...
        </div>
      </section>
    );
  }
  if (!campaign) {
    return <EmptyState text="Select a campaign to review its targets, scope, and stored findings." />;
  }
  const targets = campaignTargets(campaign);
  const scope = campaignScopeEntries(campaign);
  return (
    <section className="panel p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-bold">{campaign.name}</h3>
          <p className="text-sm text-slate-600">{campaign.client ?? "No client"} &middot; {campaign.status ?? "created"}</p>
        </div>
        <span className="badge">{campaign.operator ?? "operator"}</span>
      </div>
      <div className="telemetry-grid">
        <TelemetryMetric label="Targets" value={String(targets.length)} detail={targets.slice(0, 3).join(", ") || "none declared"} />
        <TelemetryMetric label="Scope CIDRs" value={String(scope.length)} detail={scope.slice(0, 3).join(", ") || "none declared"} />
        <TelemetryMetric label="Campaign ID" value={campaign.id.slice(0, 8)} detail="used by API and reports" />
      </div>
    </section>
  );
}

function CampaignPicker({
  campaigns,
  value,
  onChange
}: {
  campaigns: Campaign[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <select className="field" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">Select campaign</option>
      {campaigns.map((campaign) => (
        <option key={campaign.id} value={campaign.id}>
          {campaign.name || campaign.id}
        </option>
      ))}
    </select>
  );
}

function CampaignTable({ campaigns }: { campaigns: Campaign[] }) {
  return (
    <section className="panel overflow-auto p-4">
      {campaigns.length > 0 ? (
        <table className="table">
          <thead><tr><th>Name</th><th>Client</th><th>Status</th><th>Operator</th></tr></thead>
          <tbody>
            {campaigns.map((campaign) => (
              <tr key={campaign.id}>
                <td>{campaign.name}</td>
                <td>{campaign.client}</td>
                <td>{campaign.status}</td>
                <td>{campaign.operator}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <EmptyState text="No campaigns yet. Create one from the Campaigns page to unlock modules, reports, and graph views." />
      )}
    </section>
  );
}

function FindingsTable({ findings }: { findings: any[] }) {
  return (
    <section className="panel overflow-auto p-4">
      <h3 className="mb-2 font-bold">Findings</h3>
      {findings.length > 0 ? (
        <table className="table">
          <thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>MITRE</th><th>Host</th></tr></thead>
          <tbody>
            {findings.map((finding, index) => (
              <tr key={finding.id ?? index}>
                <td>{finding.severity}</td>
                <td>{finding.title}</td>
                <td>{finding.module_id}</td>
                <td>{finding.mitre_technique}</td>
                <td>{finding.host}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <EmptyState text="No findings recorded for the selected campaign yet." />
      )}
    </section>
  );
}

function ParamForm({
  schema,
  values,
  onChange
}: {
  schema: ModuleMeta["param_schema"];
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
}) {
  const entries = Object.entries(schema ?? {});
  if (entries.length === 0) {
    return <EmptyState text="No parameters" />;
  }
  return (
    <div className="grid gap-3">
      {entries.map(([name, field]) => (
        <label className="block text-sm font-semibold" key={name}>
          <span className="flex items-center gap-2">
            <span>
              {name}
              {field.required && <span className="text-red-700"> *</span>}
            </span>
            {!field.required && <span className="badge">optional</span>}
          </span>
          <ParamInput
            name={name}
            field={field}
            value={values[name]}
            onChange={(value) => {
              const next = { ...values };
              if (!field.required && isEmptyParamValue(value)) {
                delete next[name];
              } else {
                next[name] = value;
              }
              onChange(next);
            }}
          />
          {field.description && <span className="mt-1 block text-xs text-slate-600">{field.description}</span>}
          {fieldDefaultHint(field) && (
            <span className="mt-1 block text-xs font-medium text-slate-500">{fieldDefaultHint(field)}</span>
          )}
        </label>
      ))}
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
    <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
      <div className="panel p-5 text-center">
        <h1 className="text-xl font-bold">{title}</h1>
        <p className="mt-1 text-sm text-slate-600">{body}</p>
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-md border border-dashed border-slate-300 p-4 text-sm text-slate-600">{text}</div>;
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

function opsecBadge(level?: string): string {
  if (level === "high_noise") {
    return "badge badge-high";
  }
  if (level === "medium") {
    return "badge badge-medium";
  }
  return "badge badge-low";
}

function serializeError(value: unknown): unknown {
  if (value instanceof ApiError) {
    return { name: value.name, status: value.status, detail: value.detail };
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  return value;
}

export default App;
