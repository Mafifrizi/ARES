import {
  AlertTriangle,
  ChevronDown,
  FileText,
  Info,
  Loader2,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../../api/client";
import { StructuredJsonViewer } from "../../../components/common/StructuredJsonViewer";
import { useAuth } from "../../auth/authContext";
import {
  useDashboardUi,
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  CampaignPicker,
  DataPanel,
  EmptyState,
  MiniStat,
  Page,
  PersistedResult,
  SectionHeader,
  StatusBadge,
  serializeError,
  splitLines,
} from "../dashboardComponents";

function StrategyActiveView({
  activeData,
  goal,
  llmBackend,
  allowed
}: {
  activeData?: Record<string, unknown>;
  goal: string;
  llmBackend: string;
  allowed: boolean;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const activeCount = typeof activeData?.count === "number" ? activeData.count : 0;
  const maxAllowed = typeof activeData?.max_allowed === "number" ? activeData.max_allowed : 1;
  const slotsAvailable = typeof activeData?.slots_available === "number" ? activeData.slots_available : 1;
  const llmBackends = (activeData?.llm_backends as Record<string, boolean> | undefined);
  const backendReady = llmBackends ? llmBackends[llmBackend] !== false : true;

  const stages = [
    { number: 1, name: "Surface Discovery", desc: "Network & service perimeter mapping, host discovery", status: activeCount > 0 ? "active" : "standby" },
    { number: 2, name: "Defense Feasibility", desc: "EDR telemetry inspection, AMSI bypass calibration", status: "standby" },
    { number: 3, name: "Credential Extraction", desc: "Memory dumps, Kerberoasting, AS-REP extraction", status: "standby" },
    { number: 4, name: "Lateral Movement", desc: "Pivoting via WinRM, SMB, token impersonation", status: "standby" },
    { number: 5, name: "Domain Escalation", desc: "Privilege elevation, DCSync, Domain Admin achievement", status: "standby" }
  ];

  return (
    <div className="grid gap-4">
      <section className="panel p-4">
        <SectionHeader
          title="Planning Snapshot"
          action={
            <div className="flex items-center gap-2">
              <span className={`badge ${activeCount > 0 ? "badge-low" : "badge-info"}`}>
                {activeCount > 0 ? `${activeCount} Active Engagement` : "Idle / Ready"}
              </span>
              <span className="badge font-mono text-xs">{slotsAvailable} slot{slotsAvailable === 1 ? "" : "s"} free</span>
            </div>
          }
        />
        <div className="mini-stat-grid">
          <MiniStat title="Strategic Goal" value={goal} detail="Objective target" />
          <MiniStat
            title="LLM Backend"
            value={llmBackend}
            detail={backendReady ? "Engine online" : "Unconfigured key"}
          />
          <MiniStat
            title="Concurrency Slots"
            value={`${activeCount} / ${maxAllowed}`}
            detail={`${slotsAvailable} slot${slotsAvailable === 1 ? "" : "s"} available`}
          />
          <MiniStat
            title="Authorization"
            value={allowed ? "authorized" : "restricted"}
            detail={allowed ? "Ready to engage" : "Requires operator"}
          />
        </div>
      </section>

      <section className="panel p-4">
        <SectionHeader
          title="Autonomous Engagement Lifecycle"
          description="Sequential execution stages executed during autonomous strategy engagement."
        />
        <div className="compact-list mt-3">
          {stages.map((st) => (
            <div key={st.number} className="compact-row flex items-center justify-between gap-3 p-3">
              <div className="flex items-center gap-3">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                  st.status === "active"
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/50"
                    : "bg-zinc-800 text-zinc-400 border border-zinc-700/60"
                }`}>
                  {st.status === "active" ? <Loader2 size={13} className="spin text-emerald-400" /> : st.number}
                </div>
                <div>
                  <div className="font-semibold text-sm text-zinc-100 flex items-center gap-2">
                    <span>{st.name}</span>
                    {st.status === "active" && (
                      <span className="badge badge-low text-[10px] uppercase font-mono">Running</span>
                    )}
                  </div>
                  <div className="text-xs text-zinc-400 mt-0.5">{st.desc}</div>
                </div>
              </div>
              <span className="badge font-mono text-xs">
                {st.status === "active" ? "In Progress" : "Standby"}
              </span>
            </div>
          ))}
        </div>

        {activeData && (
          <div className="mt-4 pt-3 border-t border-zinc-800/80">
            <button
              type="button"
              onClick={() => setShowRaw(!showRaw)}
              className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
            >
              <FileText size={12} />
              <span>{showRaw ? "Hide Raw Active State" : "View Raw Active State"}</span>
              <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
            </button>
            {showRaw && (
              <div className="mt-2">
                <StructuredJsonViewer data={activeData} title="Active Strategy State" maxHeightClass="max-h-72" />
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function StrategyResultView({
  resultData,
  isError
}: {
  resultData: unknown;
  isError?: boolean;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const data = (resultData ?? {}) as Record<string, unknown>;
  const status = typeof data.status === "string" ? data.status : isError ? "failed" : "completed";
  const goal = typeof data.goal === "string" ? data.goal : "objective";
  const campaignId = typeof data.campaign_id === "string" ? data.campaign_id : "";
  const modulesRun = typeof data.modules_run === "number" ? data.modules_run : 0;
  const children = Array.isArray(data.children) ? (data.children as Record<string, unknown>[]) : [];

  const totalFindings = children.reduce((acc, c) => acc + (typeof c.findings_count === "number" ? c.findings_count : 0), 0);
  const totalDurationMs = children.reduce((acc, c) => acc + (typeof c.duration_ms === "number" ? c.duration_ms : 0), 0);

  return (
    <div className="grid gap-4">
      {isError && (
        <p className="notice notice-danger">
          Engagement failed: {String(data.detail ?? data.error ?? "Unknown execution error")}
        </p>
      )}

      <section className="panel p-4">
        <SectionHeader
          title="Engagement Summary"
          action={<StatusBadge status={status} />}
        />
        <div className="mini-stat-grid">
          <MiniStat title="Status" value={status} detail={campaignId ? `Campaign ${campaignId.slice(0, 8)}` : "Finished"} />
          <MiniStat title="Objective Goal" value={goal} detail="Strategic target" />
          <MiniStat title="Modules Run" value={String(modulesRun || children.length)} detail="Autonomous pipeline" />
          <MiniStat title="Total Findings" value={String(totalFindings)} detail="Security telemetry" />
          <MiniStat title="Total Duration" value={`${(totalDurationMs / 1000).toFixed(2)}s`} detail={`${totalDurationMs} ms total`} />
        </div>
      </section>

      {children.length > 0 && (
        <section className="panel table-panel">
          <SectionHeader
            title="Module Execution Breakdown"
            action={<span className="badge">{children.length} step{children.length === 1 ? "" : "s"}</span>}
          />
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Stage</th>
                  <th>Module</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {children.map((child, index) => {
                  const stageOrdinal = typeof child.stage_ordinal === "number" ? child.stage_ordinal + 1 : index + 1;
                  const modId = typeof child.module_id === "string" ? child.module_id : `step-${index}`;
                  const modStatus = typeof child.status === "string" ? child.status : "unknown";
                  const findingsCount = typeof child.findings_count === "number" ? child.findings_count : 0;
                  const durMs = typeof child.duration_ms === "number" ? child.duration_ms : 0;
                  const errText = child.error ? String(child.error) : null;
                  return (
                    <tr key={`${modId}-${index}`}>
                      <td className="muted-cell">#{String(index + 1).padStart(2, "0")}</td>
                      <td>
                        <span className="badge font-mono text-[11px]">Stage {stageOrdinal}</span>
                      </td>
                      <td>
                        <span className="font-mono text-xs font-semibold text-zinc-100">{modId}</span>
                      </td>
                      <td>
                        <StatusBadge status={modStatus} />
                      </td>
                      <td>
                        <span className={`badge ${findingsCount > 0 ? "badge-info" : ""}`}>{findingsCount}</span>
                      </td>
                      <td className="font-mono text-xs text-zinc-400">{durMs} ms</td>
                      <td>
                        {errText ? (
                          <span className="text-xs text-rose-400 font-mono" title={errText}>{errText.slice(0, 40)}</span>
                        ) : (
                          <span className="text-zinc-500 text-xs">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="panel p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-zinc-400">Raw execution output and identity digest:</span>
          <button
            type="button"
            onClick={() => setShowRaw(!showRaw)}
            className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
          >
            <FileText size={12} />
            <span>{showRaw ? "Hide Raw Result" : "View Raw Result"}</span>
            <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
          </button>
        </div>
        {showRaw && (
          <div className="mt-3">
            <StructuredJsonViewer data={resultData} title="Raw Engagement Result" maxHeightClass="max-h-80" />
          </div>
        )}
      </section>
    </div>
  );
}

const VALID_TABS_STRATEGY = ["Objective", "Active", "Result"] as const;
type StrategyTab = typeof VALID_TABS_STRATEGY[number];

export function StrategyPage() {
  const { user } = useAuth();
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const active = useQuery({ queryKey: ["strategy-active"], queryFn: api.activeStrategy });
  const [goal, setGoal] = useSessionState("ares.dashboard.strategy.goal", "domain_admin");
  const [llmBackend, setLlmBackend] = useSessionState("ares.dashboard.strategy.llmBackend", "claude");
  const [authorizations, setAuthorizations] = useSessionState("ares.dashboard.strategy.authorizations", "");
  const [lastEngageResult, setLastEngageResult] = useSessionState<PersistedResult | null>("ares.dashboard.strategy.lastEngage", null);
  const [rawTab, setActiveTab] = useTabParam("Objective");
  const activeTab = (VALID_TABS_STRATEGY as readonly string[]).includes(rawTab)
    ? (rawTab as StrategyTab)
    : "Objective";
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
          {active.error ? (
            <DataPanel title="Active Strategy Error" data={active.error} />
          ) : active.data ? (
            <StrategyActiveView
              activeData={active.data as Record<string, unknown> | undefined}
              goal={goal}
              llmBackend={llmBackend}
              allowed={allowed}
            />
          ) : (
            <EmptyState text="No active strategy state is available yet." />
          )}
        </section>
      )}
      {activeTab === "Result" && (
        <section className="panel p-4">
          {(engage.data ?? engage.error ?? persistedEngageResult?.payload) ? (
            <StrategyResultView
              resultData={engage.data ?? engage.error ?? persistedEngageResult?.payload}
              isError={Boolean(engage.error ?? persistedEngageResult?.isError)}
            />
          ) : (
            <EmptyState text="Engage a strategy objective to see results here." />
          )}
        </section>
      )}
    </Page>
  );
}



export default StrategyPage;
