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
  FormEvent,
  ReactNode,
  useContext,
  useEffect,
  useMemo,
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
import type { Campaign, ModuleMeta, ParamField, ReportItem, UserProfile } from "./api/types";

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

const REQUIRED_FIELD_MESSAGE = "This field is required.";

type ValidatableElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;

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
  if (loading) {
    return <ScreenMessage title="ARES" body="Loading session" />;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return (
    <div className="app-shell grid min-h-screen grid-cols-1 lg:grid-cols-[240px_1fr]">
      <aside className="sidebar p-4">
        <div className="mb-6 flex items-center gap-3">
          <img className="h-11 w-11 shrink-0 object-contain" src={brandMarkPath} alt="" aria-hidden="true" />
          <div>
            <div className="text-base font-bold">ARES</div>
            <div className="text-xs text-slate-300">{user.username} · {formatRole(user.role)}</div>
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
  return (
    <Page title="Overview">
      <div className="grid gap-4 md:grid-cols-3">
        <Stat title="Health" value={String(health.data?.status ?? "unknown")} icon={<Activity size={18} />} />
        <Stat title="Campaigns" value={String(campaigns.data?.length ?? 0)} icon={<ListChecks size={18} />} />
        <Stat title="Telemetry" value={telemetry.isSuccess ? "online" : "pending"} icon={<BarChart3 size={18} />} />
      </div>
      <DataPanel title="Telemetry Snapshot" data={telemetry.data} />
      <CampaignTable campaigns={campaigns.data ?? []} />
    </Page>
  );
}

function CampaignsPage() {
  const queryClient = useQueryClient();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("");
  const [client, setClient] = useState("Internal");
  const [targets, setTargets] = useState("");
  const [scope, setScope] = useState("");
  const [createWarning, setCreateWarning] = useState("");
  const [otherId, setOtherId] = useState("");
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
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const modules = useQuery({ queryKey: ["modules"], queryFn: api.modules });
  const [campaignId, setCampaignId] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [opsec, setOpsec] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [params, setParams] = useState<Record<string, unknown>>({});
  const run = useMutation({
    mutationFn: () => api.runModule(selectedId, buildModuleRunPayload(campaignId, params, dryRun))
  });
  const list = modules.data ?? [];
  const selected = list.find((item) => item.id === selectedId);
  const selectedCampaign = (campaigns.data ?? []).find((item) => item.id === campaignId);
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

  useEffect(() => {
    setParams({});
    setConfirmed(false);
    setDryRun(true);
  }, [selectedId]);

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
          </div>
        </section>
        <section className="panel p-4">
          <h2 className="mb-3 text-base font-bold">Run Module</h2>
          <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={setCampaignId} />
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
          <DataPanel title="Run Result" data={run.data ?? run.error} />
        </section>
      </div>
    </Page>
  );
}

function ReportsPage() {
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [campaignId, setCampaignId] = useState("");
  const [format, setFormat] = useState("html");
  const [warning, setWarning] = useState("");
  const queryClient = useQueryClient();
  const reports = useQuery({
    queryKey: ["reports", campaignId],
    queryFn: () => api.reports(campaignId),
    enabled: Boolean(campaignId)
  });
  const generate = useMutation({
    mutationFn: () => api.generateReport(campaignId, format),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["reports", campaignId] })
  });
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
            <FileText size={16} /> Generate
          </button>
        </div>
        {warning && <p className="mt-2 text-sm font-semibold text-red-700">{warning}</p>}
        <DataPanel title="Generate Result" data={generate.error ?? generate.data} />
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
        <DataPanel title="Download Result" data={download.error} />
      </section>
    </Page>
  );
}

function GraphPage() {
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [campaignId, setCampaignId] = useState("");
  const [jsonPath, setJsonPath] = useState("");
  const [warning, setWarning] = useState("");
  const graph = useQuery({ queryKey: ["graph", campaignId], queryFn: () => api.graph(campaignId), enabled: Boolean(campaignId) });
  const paths = useQuery({ queryKey: ["attack-paths", campaignId], queryFn: () => api.attackPaths(campaignId), enabled: Boolean(campaignId) });
  const ingest = useMutation({ mutationFn: () => api.ingestBloodhound(campaignId, jsonPath) });
  const nodes = Array.isArray(graph.data?.nodes) ? graph.data.nodes : [];
  const links = Array.isArray(graph.data?.links) ? graph.data.links : [];
  return (
    <Page title="Graph">
      <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={(id) => { setCampaignId(id); setWarning(""); }} />
      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_360px]">
        <section className="panel min-h-[360px] p-4">
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {nodes.slice(0, 24).map((node: any, index) => (
              <div className="rounded-md border border-slate-300 bg-slate-50 p-3" key={node.id ?? index}>
                <div className="font-bold">{node.label ?? node.id ?? `Node ${index + 1}`}</div>
                <div className="text-sm text-slate-600">{node.type ?? "artifact"}</div>
              </div>
            ))}
          </div>
          <div className="mt-4 text-sm text-slate-600">{nodes.length} nodes · {links.length} links</div>
        </section>
        <section className="panel p-4">
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
            <input className="field" required placeholder="BloodHound JSON path" value={jsonPath} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setJsonPath(e.target.value); setWarning(""); }} />
            <button className="btn" disabled={ingest.isPending} type="submit">
              <GitGraph size={16} /> Ingest
            </button>
          </form>
          {warning && <p className="mt-2 text-sm font-semibold text-red-700">{warning}</p>}
          <DataPanel title="Attack Paths" data={paths.data} />
          <DataPanel title="Ingest Result" data={ingest.data ?? ingest.error} />
        </section>
      </div>
    </Page>
  );
}

function TemplatesPage() {
  const templates = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const [name, setName] = useState("");
  const [params, setParams] = useState("{}");
  const plan = useMutation({
    mutationFn: () => api.templatePlan(name, safeJson(params))
  });
  return (
    <Page title="Templates">
      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <section className="panel p-4">
          <div className="grid gap-2">
            {(templates.data ?? []).map((item, index) => {
              const templateName = String(item.name ?? item.id ?? index);
              return (
                <button className="btn justify-start" key={templateName} onClick={() => setName(templateName)}>
                  {templateName}
                </button>
              );
            })}
          </div>
        </section>
        <section className="panel p-4">
          <input className="field" placeholder="Template name" value={name} onChange={(e) => setName(e.target.value)} />
          <textarea className="field mt-3 min-h-40" value={params} onChange={(e) => setParams(e.target.value)} />
          <button className="btn btn-primary mt-3" disabled={!name} onClick={() => plan.mutate()}>
            <Workflow size={16} /> Generate Plan
          </button>
          <DataPanel title="Plan" data={plan.data ?? plan.error} />
        </section>
      </div>
    </Page>
  );
}

function StrategyPage() {
  const { user } = useAuth();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const active = useQuery({ queryKey: ["strategy-active"], queryFn: api.activeStrategy });
  const [campaignId, setCampaignId] = useState("");
  const [goal, setGoal] = useState("domain_admin");
  const [authorizations, setAuthorizations] = useState("");
  const engage = useMutation({
    mutationFn: () =>
      api.engageStrategy({
        campaign_id: campaignId,
        goal,
        max_rounds: 5,
        authorizations: splitLines(authorizations)
      })
  });
  const allowed = user?.role === "team_lead" || user?.role === "operator";
  return (
    <Page title="Strategy">
      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <section className="panel p-4">
          <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={setCampaignId} />
          <select className="field mt-3" value={goal} onChange={(e) => setGoal(e.target.value)}>
            {["domain_admin", "enterprise_admin", "cloud_admin", "data_exfil", "persistence", "full_compromise"].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <textarea className="field mt-3 min-h-28" placeholder="Authorizations" value={authorizations} onChange={(e) => setAuthorizations(e.target.value)} />
          <button className="btn btn-primary mt-3" disabled={!allowed || !campaignId} onClick={() => engage.mutate()}>
            <ShieldCheck size={16} /> Engage
          </button>
        </section>
        <section>
          <DataPanel title="Active" data={active.data} />
          <DataPanel title="Engagement Result" data={engage.data ?? engage.error} />
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
  const change = useMutation({ mutationFn: () => api.changePassword({ current_password: currentPassword, new_password: newPassword }) });
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
          <div className="mb-3 text-sm">{user?.username} · {formatRole(user?.role)}</div>
          <input className="field mb-2" type="password" placeholder="Current password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
          <input className="field mb-2" type="password" placeholder="New password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
          <button className="btn" onClick={() => change.mutate()}><KeyRound size={16} /> Change Password</button>
          <DataPanel title="Password Result" data={change.data ?? change.error} />
        </section>
        <section className="panel p-4">
          <h2 className="mb-3 font-bold">API Keys</h2>
          <div className="mb-3 grid gap-2 sm:grid-cols-[1fr_120px_auto]">
            <input className="field" placeholder="Name" value={keyName} onChange={(e) => setKeyName(e.target.value)} />
            <select className="field" value={scopes} onChange={(e) => setScopes(e.target.value)}>
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn" onClick={() => create.mutate()}><KeyRound size={16} /> Create</button>
          </div>
          {(keys.data ?? []).map((key) => (
            <div className="mb-2 flex items-center justify-between rounded-md border border-slate-200 p-2" key={key.id}>
              <span>{key.name ?? key.prefix ?? key.id}</span>
              <button className="btn btn-danger" onClick={() => remove.mutate(key.id)}>Delete</button>
            </div>
          ))}
          <DataPanel title="New Key" data={create.data} />
        </section>
      </div>
      <DataPanel title="Security Audit" data={audit.data} />
      <DataPanel title="Users" data={users.data} />
    </Page>
  );
}

function EdrPage() {
  const stats = useQuery({ queryKey: ["edr-stats"], queryFn: api.edrStats });
  const [body, setBody] = useState('{"technique_id":"","edr_vendor":"","success":false}');
  const report = useMutation({ mutationFn: () => api.reportBypass(safeJson(body)) });
  return (
    <Page title="EDR/OPSEC">
      <DataPanel title="Stats" data={stats.data} />
      <section className="panel p-4">
        <textarea className="field min-h-40" value={body} onChange={(e) => setBody(e.target.value)} />
        <button className="btn btn-primary mt-3" onClick={() => report.mutate()}>
          <ShieldAlert size={16} /> Report Outcome
        </button>
      </section>
      <DataPanel title="Outcome Result" data={report.data ?? report.error} />
    </Page>
  );
}

function LivePage() {
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const [campaignId, setCampaignId] = useState("");
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    if (!connected || !campaignId || !getAccessToken()) {
      return;
    }
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}${campaignEventsPath(campaignId, getAccessToken()!)}`);
    socket.onmessage = (event) => {
      try {
        setEvents((items) => [JSON.parse(event.data), ...items].slice(0, 100));
      } catch {
        setEvents((items) => [event.data, ...items].slice(0, 100));
      }
    };
    socket.onclose = () => setConnected(false);
    return () => socket.close();
  }, [campaignId, connected]);

  return (
    <Page title="Live Events">
      <div className="panel p-4">
        <CampaignPicker campaigns={campaigns.data ?? []} value={campaignId} onChange={setCampaignId} />
        <button className="btn btn-primary mt-3" disabled={!campaignId} onClick={() => setConnected(true)}>
          <Radio size={16} /> Connect
        </button>
      </div>
      <DataPanel title="Event Stream" data={events} />
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

function DataPanel({ title, data }: { title: string; data: unknown }) {
  if (!data) {
    return null;
  }
  return (
    <section className="panel p-4">
      <h3 className="mb-2 text-sm font-bold text-slate-700">{title}</h3>
      <pre className="json-box">{JSON.stringify(serializeError(data), null, 2)}</pre>
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
    </section>
  );
}

function FindingsTable({ findings }: { findings: any[] }) {
  return (
    <section className="panel overflow-auto p-4">
      <h3 className="mb-2 font-bold">Findings</h3>
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
          {name}
          {field.required && <span className="text-red-700"> *</span>}
          <ParamInput
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
        </label>
      ))}
    </div>
  );
}

function ParamInput({
  field,
  value,
  onChange
}: {
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
    return JSON.parse(value) as Record<string, unknown>;
  } catch {
    return {};
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
