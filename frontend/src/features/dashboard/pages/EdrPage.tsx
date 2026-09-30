import {
  ChevronDown,
  FileText,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../../../api/client";
import { StructuredJsonViewer } from "../../../components/common/StructuredJsonViewer";
import {
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  DataPanel,
  MiniStat,
  Page,
  PersistedResult,
  SectionHeader,
  clearValidationMessage,
  serializeError,
  setRequiredMessage,
} from "../dashboardComponents";

function EdrStatsSummary({
  statsData,
  error
}: {
  statsData?: Record<string, unknown>;
  error?: unknown;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const technique = typeof statsData?.technique_id === "string" && statsData.technique_id ? statsData.technique_id : "All Techniques";
  const vendor = typeof statsData?.edr_vendor === "string" && statsData.edr_vendor ? statsData.edr_vendor : "All Vendors";
  const rate = typeof statsData?.success_rate === "number" ? statsData.success_rate : null;
  const message = typeof statsData?.message === "string" ? statsData.message : "Historical bypass knowledge base telemetry.";
  const statsList = Array.isArray(statsData?.stats) ? (statsData.stats as Record<string, unknown>[]) : [];

  const rateTone = rate != null ? (rate >= 0.8 ? "badge badge-low" : rate >= 0.5 ? "badge badge-medium" : "badge badge-high") : "badge";
  const rateLabel = rate != null ? `${(rate * 100).toFixed(0)}%` : "N/A";
  const evasionAssessment = rate != null ? (rate >= 0.8 ? "High Evasion" : rate >= 0.5 ? "Moderate Evasion" : "High Detection Risk") : "Insufficient Samples";

  return (
    <div className="grid gap-4">
      {error ? (
        <DataPanel title="Stats Error" data={error} />
      ) : (
        <>
          <section className="panel p-4">
            <SectionHeader
              title="Bypass Knowledge Base"
              description="Historical evasion success metrics calibrated against active endpoint detection agents."
              action={<span className={rateTone}>{evasionAssessment}</span>}
            />
            <div className="mini-stat-grid mt-3">
              <MiniStat
                title="Technique Under Test"
                value={technique}
                detail="MITRE / ARES technique ID"
              />
              <MiniStat
                title="Target EDR Vendor"
                value={vendor}
                detail="Security agent signature"
              />
              <MiniStat
                title="Historical Bypass Rate"
                value={rateLabel}
                detail={rate != null ? `${evasionAssessment} probability` : "Min 3 samples required"}
              />
              <MiniStat
                title="Telemetry Status"
                value={rate != null ? "Calibrated" : "Sampling"}
                detail={rate != null ? "Statistically valid" : "Pending further reports"}
              />
            </div>
            <div className="mt-3 p-3 rounded border border-zinc-800 bg-zinc-900/60 text-xs text-zinc-300 flex items-center gap-2">
              <ShieldCheck size={14} className="text-cyan-400 shrink-0" />
              <span>{message}</span>
            </div>
          </section>

          {statsList.length > 0 && (
            <section className="panel table-panel">
              <SectionHeader
                title="Historical Technique Records"
                action={<span className="badge">{statsList.length} records</span>}
              />
              <div className="table-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Technique</th>
                      <th>EDR Vendor</th>
                      <th>Success Rate</th>
                      <th>Samples</th>
                    </tr>
                  </thead>
                  <tbody>
                    {statsList.map((item, index) => {
                      const t = String(item.technique_id ?? `technique-${index}`);
                      const v = String(item.edr_vendor ?? "all");
                      const r = typeof item.success_rate === "number" ? item.success_rate : null;
                      const count = typeof item.sample_count === "number" ? item.sample_count : (item.count ?? "—");
                      return (
                        <tr key={`${t}-${v}-${index}`}>
                          <td className="font-mono text-xs font-semibold text-zinc-200">{t}</td>
                          <td>
                            <span className="badge font-mono text-[11px]">{v}</span>
                          </td>
                          <td>
                            <span className={r != null ? (r >= 0.8 ? "badge badge-low" : r >= 0.5 ? "badge badge-medium" : "badge badge-high") : "badge"}>
                              {r != null ? `${(r * 100).toFixed(0)}%` : "N/A"}
                            </span>
                          </td>
                          <td className="font-mono text-xs text-zinc-400">{String(count)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {statsData && (
            <section className="panel p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-400">Raw telemetry dataset:</span>
                <button
                  type="button"
                  onClick={() => setShowRaw(!showRaw)}
                  className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
                >
                  <FileText size={12} />
                  <span>{showRaw ? "Hide Raw Stats JSON" : "View Raw Stats JSON"}</span>
                  <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
                </button>
              </div>
              {showRaw && (
                <div className="mt-3">
                  <StructuredJsonViewer data={statsData} title="Raw EDR Bypass Stats" maxHeightClass="max-h-72" />
                </div>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

const VALID_TABS_EDR = ["Knowledge Base", "Report Outcome", "Stats"] as const;
type EdrTab = typeof VALID_TABS_EDR[number];

export function EdrPage() {
  const stats = useQuery({ queryKey: ["edr-stats"], queryFn: api.edrStats });
  const [techniqueId, setTechniqueId] = useSessionState("ares.dashboard.edr.techniqueId", "");
  const [vendor, setVendor] = useSessionState("ares.dashboard.edr.vendor", "");
  const [version, setVersion] = useSessionState("ares.dashboard.edr.version", "");
  const [success, setSuccess] = useSessionState("ares.dashboard.edr.success", false);
  const [notes, setNotes] = useSessionState("ares.dashboard.edr.notes", "");
  const [lastReportResult, setLastReportResult] = useSessionState<PersistedResult | null>("ares.dashboard.edr.lastReport", null);
  const [rawTab, setActiveTab] = useTabParam("Knowledge Base");
  const activeTab = (VALID_TABS_EDR as readonly string[]).includes(rawTab)
    ? (rawTab as EdrTab)
    : "Knowledge Base";
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
      activeTab={activeTab === "Stats" ? "Knowledge Base" : activeTab}
      onTabChange={setActiveTab}
    >
      {(activeTab === "Knowledge Base" || (activeTab as string) === "Stats") && (
        <EdrStatsSummary statsData={stats.data as Record<string, unknown> | undefined} error={stats.error} />
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
            <div className="block">
              <label htmlFor="edr-technique-id" className="block text-sm font-semibold mb-1 cursor-pointer">
                Technique ID <span className="text-red-700">*</span>
              </label>
              <input id="edr-technique-id" className="field" required autoComplete="off" spellCheck={false} placeholder="edr.bypass_adaptive / amsi-patch-reflection" value={techniqueId} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setTechniqueId(e.target.value); }} />
            </div>
            <div className="block">
              <label htmlFor="edr-vendor-name" className="block text-sm font-semibold mb-1 cursor-pointer">
                EDR vendor <span className="text-red-700">*</span>
              </label>
              <input id="edr-vendor-name" className="field" required autoComplete="off" spellCheck={false} placeholder="crowdstrike, defender_atp, sentinelone" value={vendor} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setVendor(e.target.value); }} />
            </div>
            <div className="block">
              <label htmlFor="edr-version-field" className="block text-sm font-semibold mb-1 cursor-pointer">
                EDR version
              </label>
              <input id="edr-version-field" className="field" autoComplete="off" spellCheck={false} placeholder="optional" value={version} onChange={(e) => setVersion(e.target.value)} />
            </div>
            <div className="block">
              <label htmlFor="edr-outcome-field" className="block text-sm font-semibold mb-1 cursor-pointer">
                Outcome
              </label>
              <select id="edr-outcome-field" className="field" value={success ? "success" : "blocked"} onChange={(e) => setSuccess(e.target.value === "success")}>
                <option value="blocked">Blocked / detected</option>
                <option value="success">Successful</option>
              </select>
            </div>
          </div>
          <div className="block">
            <label htmlFor="edr-notes-field" className="block text-sm font-semibold mb-1 cursor-pointer">
              Notes
            </label>
            <textarea id="edr-notes-field" className="field min-h-24" autoComplete="off" spellCheck={false} placeholder="Signal observed, lab context, or detection notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
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



export default EdrPage;
