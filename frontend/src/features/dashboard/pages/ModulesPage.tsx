import {
  AlertTriangle,
  Info,
  Loader2,
  Lock,
  Search,
  Target,
  X,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, buildModuleRunPayload } from "../../../api/client";
import type {
  ExecutionChain,
} from "../../../api/types";
import {
  useDashboardUi,
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  CampaignPicker,
  DataPanel,
  EmptyState,
  ModuleRunRecord,
  ModuleRunSummary,
  Page,
  ParamForm,
  SectionHeader,
  isSensitiveModule,
  moduleRunHint,
  moduleScopeWarning,
  opsecBadge,
  serializeError,
  unique,
} from "../dashboardComponents";

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

const VALID_TABS_MODULES = ["Catalog", "Execution Chains", "Run Panel", "Results"] as const;
type ModulesTab = typeof VALID_TABS_MODULES[number];

export function ModulesPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const [searchParams] = useSearchParams();
  const location = useLocation();
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
  const [rawTab, setActiveTab] = useTabParam("Catalog");
  const activeTab = (VALID_TABS_MODULES as readonly string[]).includes(rawTab)
    ? (rawTab as ModulesTab)
    : "Catalog";
  const previousSelectedId = useRef(selectedId);

  useEffect(() => {
    const queryModule = searchParams.get("module") || (location.state as { moduleId?: string } | null)?.moduleId;

    if (queryModule) {
      setSelectedId(queryModule);
    }
  }, [searchParams, location.state, setSelectedId]);
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
        void queryClient.invalidateQueries({ queryKey: ["graph"] });
        void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
        void queryClient.invalidateQueries({ queryKey: ["campaign", campaignId] });
        void queryClient.invalidateQueries({ queryKey: ["attack-paths"] });
        void queryClient.invalidateQueries({ queryKey: ["findings"] });
        void queryClient.invalidateQueries({ queryKey: ["telemetry"] });
        void queryClient.invalidateQueries({ queryKey: ["monthlyStats"] });
      }
    },
    onError: (error) => {
      setLastRunRecord({ campaignId, moduleId: selectedId, payload: serializeError(error), isError: true });
      setActiveTab("Results");
      if (!dryRun) {
        void queryClient.invalidateQueries({ queryKey: ["graph"] });
        void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
        void queryClient.invalidateQueries({ queryKey: ["campaign", campaignId] });
        void queryClient.invalidateQueries({ queryKey: ["attack-paths"] });
        void queryClient.invalidateQueries({ queryKey: ["findings"] });
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
  const requiresConfirmation = sensitive;
  const dryRunSupported = selected?.dry_run_supported !== false;
  const kerberoastTargetMissing = selected?.id === "ad.kerberoast" && !String(params.target_user ?? "").trim();
  const [attemptedRun, setAttemptedRun] = useState(false);
  const executionConditionBlocked = (!requiresConfirmation || confirmed) && !run.isPending && (!dryRun || dryRunSupported) && !scopeWarning && !kerberoastTargetMissing;
  const runHint = moduleRunHint(campaignId, selected, selectedCampaign, sensitive, confirmed, dryRun);
  const activeRun = (run.data ? { campaignId, moduleId: selectedId, payload: run.data, isError: false } : null) ??
    (lastRunRecord?.campaignId === campaignId ? lastRunRecord : null);
  const runResult = (!activeRun?.isError ? activeRun?.payload : undefined) as Record<string, unknown> | undefined;
  const runError = run.error ?? (activeRun?.isError ? activeRun.payload : undefined);

  useEffect(() => {
    let incomingParams: Record<string, unknown> | null = null;
    try {
      const stored = sessionStorage.getItem("ares.dashboard.modules.params");
      if (stored) {
        incomingParams = JSON.parse(stored);
        sessionStorage.removeItem("ares.dashboard.modules.params");
      }
    } catch {
      incomingParams = null;
    }

    const queryTarget = searchParams.get("target") || (location.state as { target?: string } | null)?.target;
    const stateParams = (location.state as { params?: Record<string, unknown> } | null)?.params;
    if (queryTarget || stateParams) {
      incomingParams = {
        ...(incomingParams ?? {}),
        ...(queryTarget ? { target: queryTarget, host: queryTarget, dc: queryTarget, targets: [queryTarget] } : {}),
        ...(stateParams ?? {})
      };
    }

    if (previousSelectedId.current === selectedId && !incomingParams) {
      return;
    }
    previousSelectedId.current = selectedId;

    const currentTarget = String(
      incomingParams?.target ||
      incomingParams?.host ||
      incomingParams?.dc ||
      params.target ||
      params.host ||
      params.dc ||
      params.target_host ||
      params.rhost ||
      selectedCampaign?.targets?.[0] ||
      ""
    ).trim();

    const targetModule = list.find((item) => item.id === selectedId);
    const schema = targetModule?.param_schema ?? {};
    const schemaKeys = Object.keys(schema);

    const nextParams: Record<string, unknown> = {};

    // 1. Populate primary target/host/dc fields if supported by module schema
    if (schemaKeys.includes("target") && currentTarget) {
      nextParams.target = currentTarget;
    }
    if (schemaKeys.includes("host") && currentTarget) {
      nextParams.host = currentTarget;
    }
    if (schemaKeys.includes("dc") && currentTarget) {
      nextParams.dc = currentTarget;
    }
    if (schemaKeys.includes("targets") && currentTarget) {
      nextParams.targets = [currentTarget];
    }
    if (schemaKeys.includes("target_host") && currentTarget) {
      nextParams.target_host = currentTarget;
    }
    if (schemaKeys.includes("rhost") && currentTarget) {
      nextParams.rhost = currentTarget;
    }

    // 2. Transfer standard parameters across chains and pivots if valid in schema
    const contextualKeys = ["port", "ports", "service", "domain", "username", "target_user", "use_ldaps"];
    for (const key of contextualKeys) {
      if (schemaKeys.includes(key)) {
        if (incomingParams && incomingParams[key] !== undefined) {
          nextParams[key] = incomingParams[key];
        } else if (params[key] !== undefined) {
          nextParams[key] = params[key];
        }
      }
    }

    // 3. Merge any specific incoming params passed explicitly
    if (incomingParams) {
      for (const [k, v] of Object.entries(incomingParams)) {
        if (v !== undefined) {
          nextParams[k] = v;
        }
      }
    }

    setParams(nextParams);
    setConfirmed(false);
    setDryRun(true);
  }, [selectedId, list, selectedCampaign, setConfirmed, setDryRun, setParams, searchParams, location.state]);

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
          <div className="mt-3 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-900/30">
            <label htmlFor="module-campaign-select" className="block text-xs font-mono text-zinc-300 mb-1.5 font-medium">
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
            {campaignId && campaignDetail.isFetching && (
              <div className="notice mt-3 text-xs">
                <Loader2 className="spin" size={14} /> Loading campaign scope...
              </div>
            )}
            <DataPanel title="Campaign Scope Error" data={campaignDetail.error} />
          </div>

          {selected ? (
            <form
              aria-busy={run.isPending}
              className="mt-4 grid gap-4 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-900/30"
              autoComplete="off"
              data-lpignore="true"
              data-form-type="other"
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
              <div className="text-xs font-mono text-zinc-400 font-medium pb-2 border-b border-zinc-800/60 flex items-center justify-between">
                <span>Module Parameters</span>
                <span className="text-[11px] text-zinc-500 font-sans">{Object.keys(selected.param_schema || {}).length} field(s)</span>
              </div>

              {/* Quick Target Selector for In-Scope Campaign Hosts */}
              {((selectedCampaign?.targets && selectedCampaign.targets.length > 0) || (selectedCampaign?.scope_cidrs && selectedCampaign.scope_cidrs.length > 0)) && (
                <div className="p-2.5 rounded-sm bg-zinc-900/60 border border-zinc-800 space-y-1.5 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400 text-[11px] uppercase tracking-wider flex items-center gap-1.5 font-semibold">
                      <Target size={12} className="text-cyan-400 shrink-0" />
                      QUICK ENGAGEMENT TARGETS:
                    </span>
                    <span className="text-[10px] text-zinc-500 font-sans">1-click populate</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {selectedCampaign?.targets?.map((tgt) => (
                      <button
                        key={tgt}
                        type="button"
                        onClick={() => setParams((prev) => ({ ...prev, target: tgt, host: tgt, dc: tgt, targets: [tgt] }))}
                        className={`px-2 py-0.5 rounded-sm border text-[11px] transition-colors ${
                          params.target === tgt || params.host === tgt || params.dc === tgt
                            ? "bg-cyan-950 border-cyan-700 text-cyan-200 font-bold"
                            : "bg-zinc-800 border-zinc-700 text-zinc-300 hover:bg-zinc-700 hover:text-zinc-100"
                        }`}
                        title={`Set target to ${tgt}`}
                      >
                        {tgt}
                      </button>
                    ))}
                    {selectedCampaign?.scope_cidrs?.map((cidr) => (
                      <button
                        key={cidr}
                        type="button"
                        onClick={() => setParams((prev) => ({ ...prev, target: cidr, cidr }))}
                        className="px-2 py-0.5 rounded-sm border border-zinc-800 bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 text-[10px] transition-colors"
                        title={`Set scope to ${cidr}`}
                      >
                        {cidr}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <ParamForm
                schema={selected.param_schema}
                values={params}
                onChange={setParams}
                requiredOverrides={selected.id === "ad.kerberoast" ? { target_user: true } : undefined}
              />

              {/* Execution Mode Controls */}
              <div className="pt-2 border-t border-zinc-800/60 space-y-2.5">
                <label className="toggle-row text-xs text-zinc-300">
                  <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                  {dryRunSupported ? "Dry run (simulate without live network execution)" : "Dry run unavailable"}
                </label>

                {requiresConfirmation && (
                  <div className="notice notice-danger text-xs flex items-center gap-2.5 p-2.5 rounded border">
                    <input
                      id="confirm-override-checkbox"
                      className="cursor-pointer shrink-0"
                      type="checkbox"
                      checked={confirmed}
                      onChange={(e) => setConfirmed(e.target.checked)}
                    />
                    <label htmlFor="confirm-override-checkbox" className="cursor-pointer select-none">
                      Confirm authorized high-noise or sensitive execution
                    </label>
                  </div>
                )}

                {runHint && runHint !== "Select a campaign before running a module." && (
                  <p className="notice text-xs">{runHint}</p>
                )}
                {scopeWarning && (
                  <p className="notice notice-danger text-xs">{scopeWarning}</p>
                )}

                <div className="pt-2">
                  <button
                    className="btn btn-primary w-full py-2.5 text-xs font-mono font-medium tracking-wide flex items-center justify-center gap-2"
                    type="submit"
                    disabled={!selectedId || run.isPending || (campaignId ? !executionConditionBlocked : false)}
                  >
                    {run.isPending ? (
                      <>
                        <Loader2 className="spin shrink-0" size={14} /> Running {selectedId}...
                      </>
                    ) : (
                      `Execute ${selected.id}`
                    )}
                  </button>
                </div>

                {run.isPending && (
                  <div className="notice notice-info text-xs" role="status" aria-live="polite">
                    <Loader2 className="spin shrink-0" size={15} />
                    Module execution in progress. Keep this page open while ARES validates the target and collects results.
                  </div>
                )}
              </div>
            </form>
          ) : (
            <EmptyState text="Select a module from the catalog to configure and execute." />
          )}
        </section>
      )}
      {activeTab === "Results" && (
        <section className="panel p-4">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-zinc-800/80">
            <div>
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">
                {activeRun?.moduleId ? `Module: ${activeRun.moduleId}` : (selected ? selected.id : "Execution")}
              </span>
              <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                <span>Run Results</span>
                {activeRun && (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300 border border-zinc-700">
                    <Lock size={10} className="text-amber-400" />
                    <span>Locked View</span>
                  </span>
                )}
              </h2>
            </div>
            {activeRun && (
              <button
                type="button"
                onClick={() => {
                  setLastRunRecord(null);
                  run.reset();
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm border border-zinc-700 bg-zinc-800/80 hover:bg-zinc-700 text-zinc-300 hover:text-white text-xs font-mono transition-colors"
                title="Dismiss and close this run result"
              >
                <X size={12} />
                <span>Close Result</span>
              </button>
            )}
          </div>
          {runResult || runError ? (
            <>
              <ModuleRunSummary
                result={runResult}
                error={runError}
                onSelectModule={(modId, targetParams) => {
                  setSelectedId(modId);
                  if (targetParams) {
                    setParams((prev) => ({ ...prev, ...targetParams }));
                  }
                  setActiveTab("Run Panel");
                }}
              />
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



export default ModulesPage;
