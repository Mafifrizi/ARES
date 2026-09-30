import {
  Loader2,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../../api/client";
import {
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  DataPanel,
  EmptyState,
  Page,
  PersistedResult,
  SectionHeader,
  TemplatePlanResponse,
  TemplatePlanSummary,
  isJsonObject,
  safeJson,
  serializeError,
} from "../dashboardComponents";

const VALID_TABS_TEMPLATES = ["Templates", "Plan Builder"] as const;
type TemplatesTab = typeof VALID_TABS_TEMPLATES[number];

export function TemplatesPage() {
  const templates = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const [name, setName] = useSessionState("ares.dashboard.templates.name", "");
  const [params, setParams] = useSessionState("ares.dashboard.templates.params", "{}");
  const [warning, setWarning] = useState("");
  const [lastPlanResult, setLastPlanResult] = useSessionState<PersistedResult | null>("ares.dashboard.templates.lastPlan", null);
  const [rawTab, setActiveTab] = useTabParam("Templates");
  const activeTab = (VALID_TABS_TEMPLATES as readonly string[]).includes(rawTab)
    ? (rawTab as TemplatesTab)
    : "Templates";
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
          <div className="mt-3 block">
            <label htmlFor="template-global-params" className="block text-sm font-semibold mb-1 cursor-pointer">
              Global parameters
            </label>
            <textarea
              id="template-global-params"
              className="field min-h-32"
              value={params}
              placeholder={'{"target":"127.0.0.1","domain":"corp.local","dc":"10.0.0.5"}'}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setParams(e.target.value);
                setWarning("");
              }}
            />
          </div>
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



export default TemplatesPage;
