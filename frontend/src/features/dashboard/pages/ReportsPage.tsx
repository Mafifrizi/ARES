import {
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { ReportItem } from "../../../api/types";
import { ConfirmModal } from "../../../components/ui/ConfirmModal";
import {
  useDashboardUi,
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  CampaignPicker,
  DataPanel,
  EmptyState,
  Page,
  PersistedResult,
  SectionHeader,
  formatBytes,
  formatReportDate,
  pdfFailureHint,
  readableError,
  serializeError,
} from "../dashboardComponents";

const VALID_TABS_REPORTS = ["Generate", "Library"] as const;
type ReportsTab = typeof VALID_TABS_REPORTS[number];

export function ReportsPage() {
  const { selectedCampaignId: campaignId, setSelectedCampaignId: setCampaignId, campaigns: campaignList } = useDashboardUi();
  const [format, setFormat] = useSessionState("ares.dashboard.reports.format", "html");
  const [warning, setWarning] = useState("");
  const [libraryError, setLibraryError] = useState("");
  const [deleteReportTarget, setDeleteReportTarget] = useState<ReportItem | null>(null);
  const [confirmClearAllReports, setConfirmClearAllReports] = useState(false);
  const [lastGenerateResult, setLastGenerateResult] = useSessionState<PersistedResult | null>("ares.dashboard.reports.lastGenerate", null);
  const [rawTab, setActiveTab] = useTabParam("Generate");
  const activeTab = (VALID_TABS_REPORTS as readonly string[]).includes(rawTab)
    ? (rawTab as ReportsTab)
    : "Generate";
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
              onClick={() => setConfirmClearAllReports(true)}
            >
              {clearReports.isPending ? (
                <Loader2 className="spin" size={15} />
              ) : null}
              Delete all
            </button>
          ) : null}
        />
        <div className="p-4 border-b border-zinc-800/80">
          <label htmlFor="library-campaign-select" className="block text-xs font-medium text-zinc-300 mb-1.5">
            Target Campaign
          </label>
          <CampaignPicker
            id="library-campaign-select"
            campaigns={campaignList}
            value={campaignId}
            onChange={(id) => {
              setCampaignId(id);
              setWarning("");
            }}
          />
        </div>
        {campaignId && reportItems.length > 0 && (
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
                        onClick={() => setDeleteReportTarget(item)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
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
      <ConfirmModal
        open={deleteReportTarget !== null}
        title="Delete Report"
        description={`Permanently delete report artifact "${deleteReportTarget?.filename ?? ""}". This action cannot be undone.`}
        confirmLabel="Delete Report"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={() => {
          if (deleteReportTarget) {
            setLibraryError("");
            deleteReport.mutate(deleteReportTarget);
            setDeleteReportTarget(null);
          }
        }}
        onCancel={() => setDeleteReportTarget(null)}
      />
      <ConfirmModal
        open={confirmClearAllReports}
        title="Delete All Reports"
        description={`Permanently delete all ${reportItems.length} report artifacts for this campaign. This action cannot be undone.`}
        confirmLabel="Delete All Reports"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={() => {
          setLibraryError("");
          clearReports.mutate();
          setConfirmClearAllReports(false);
        }}
        onCancel={() => setConfirmClearAllReports(false)}
      />
    </Page>
  );
}



export default ReportsPage;
