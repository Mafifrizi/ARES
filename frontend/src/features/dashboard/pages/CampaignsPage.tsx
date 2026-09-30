import {
  Loader2,
} from "lucide-react";
import {
  useState,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
} from "../../../api/client";
import type {
  ApiErrorPayload,
  Campaign,
  LiveExecutionResponse,
  TemplatePlanResult,
  VaultRestoreResult,
} from "../../../api/types";
import { ConfirmModal } from "../../../components/ui/ConfirmModal";
import {
  useDashboardUi,
  useSessionState,
  useTabParam,
} from "../dashboardUiState";
import {
  CampaignDiffCard,
  CampaignPicker,
  CampaignScopeSummary,
  CampaignTable,
  CvssScoreCard,
  DataPanel,
  EmptyState,
  FindingsTable,
  Page,
  SectionHeader,
  clearValidationMessage,
  findInvalidScopeEntries,
  setRequiredMessage,
  splitLines,
} from "../dashboardComponents";

const VALID_TABS_CAMPAIGNS = ["List", "Scope", "Findings"] as const;
type CampaignsTab = typeof VALID_TABS_CAMPAIGNS[number];

export function CampaignsPage() {
  const queryClient = useQueryClient();
  const {
    selectedCampaignId: selected,
    setSelectedCampaignId: setSelected,
    campaigns: campaignList,
    deleteCampaign,
    isDeletingCampaign,
    pushLiveEvent
  } = useDashboardUi();
  const [name, setName] = useSessionState("ares.dashboard.campaigns.create.name", "");
  const [client, setClient] = useSessionState("ares.dashboard.campaigns.create.client", "Internal");
  const [targets, setTargets] = useSessionState("ares.dashboard.campaigns.create.targets", "");
  const [scope, setScope] = useSessionState("ares.dashboard.campaigns.create.scope", "");
  const [noiseProfile, setNoiseProfile] = useSessionState("ares.dashboard.campaigns.create.noiseProfile", "stealth");
  const [createWarning, setCreateWarning] = useState("");
  const [otherId, setOtherId] = useSessionState("ares.dashboard.campaigns.compareId", "");
  const [rawTab, setActiveTab] = useTabParam("List");
  const activeTab = (VALID_TABS_CAMPAIGNS as readonly string[]).includes(rawTab)
    ? (rawTab as CampaignsTab)
    : "List";
  const [deleteError, setDeleteError] = useState<unknown>(null);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [localDeleting, setLocalDeleting] = useState(false);
  const isDeleting = localDeleting || Boolean(isDeletingCampaign);
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
  const restore = useMutation({
    mutationFn: () => api.restoreVault(selected),
    onSuccess: (data) => {
      const result = data as VaultRestoreResult;
      const count = result?.restored ?? 0;
      const campaignName = (detail.data ?? campaignList.find((c) => c.id === selected))?.name || selected;
      pushLiveEvent({
        type: "vault.restored",
        campaign_id: selected,
        message: `Credential vault synchronized: ${count} credential${count === 1 ? "" : "s"} rehydrated into runtime memory for '${campaignName}'.`,
        timestamp: Date.now(),
        restored: count
      });
    },
    onError: (err) => {
      const errorPayload = err as ApiErrorPayload;
      const msg = errorPayload?.detail || (err as Error)?.message || "The request failed.";
      pushLiveEvent({
        type: "vault.restore_failed",
        campaign_id: selected,
        message: `Credential vault synchronization failed: ${msg}`,
        timestamp: Date.now(),
        error: msg
      });
    }
  });
  const run = useMutation<TemplatePlanResult | LiveExecutionResponse>({
    mutationFn: () => {
      const selectedCampaign = detail.data ?? campaignList.find((item) => item.id === selected);
      const targetHost = selectedCampaign?.targets?.[0] || "10.0.0.1";
      return api.runCampaign(selected, {
        plan: {
          stages: [
            {
              name: "Stage 1: Perimeter Recon & Fingerprint",
              modules: ["recon.fingerprint", "network.service_detect"],
              params: {
                "recon.fingerprint": { target: targetHost },
                "network.service_detect": { target: targetHost }
              }
            },
            {
              name: "Stage 2: Defense Feasibility & Coverage",
              modules: ["opsec.coverage_predictor"],
              params: {
                "opsec.coverage_predictor": { target: targetHost }
              }
            }
          ]
        },
        global_params: {
          target: targetHost,
          noise_profile: selectedCampaign?.noise_profile || "stealth"
        },
        dry_run: true
      });
    },
    onSuccess: (data) => {
      const planResult = data as TemplatePlanResult;
      const isReady = planResult?.summary?.ready_to_run !== false;
      const stageCount = Array.isArray(planResult?.plan)
        ? planResult.plan.length
        : (planResult?.summary?.total_stages ?? 2);
      const campaignName = (detail.data ?? campaignList.find((c) => c.id === selected))?.name || selected;
      pushLiveEvent({
        type: isReady ? "campaign.dry_run_ready" : "campaign.dry_run_warning",
        campaign_id: selected,
        message: `Plan pre-flight check ${isReady ? "passed" : "completed with warnings"}: ${stageCount} stages verified for '${campaignName}'. Status: ${isReady ? "READY" : "WARNING"}.`,
        timestamp: Date.now(),
        plan: planResult?.plan,
        summary: planResult?.summary
      });
    },
    onError: (err) => {
      const errorPayload = err as ApiErrorPayload;
      const msg = errorPayload?.detail || (err as Error)?.message || "The request failed.";
      pushLiveEvent({
        type: "campaign.dry_run_failed",
        campaign_id: selected,
        message: `Dry-run plan validation failed: ${msg}`,
        timestamp: Date.now(),
        error: msg
      });
    }
  });

  const handleDelete = async (targetId: string) => {
    if (!targetId || isDeleting) return;
    setLocalDeleting(true);
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
      setLocalDeleting(false);
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
            <div className="mt-3 flex flex-wrap gap-2 items-center">
              <button
                className="btn"
                disabled={!selected || restore.isPending}
                onClick={() => restore.mutate()}
                type="button"
              >
                {restore.isPending && <Loader2 className="spin" size={14} />}
                <span>{restore.isPending ? "Restoring Vault…" : "Restore Vault"}</span>
              </button>
              <button
                className="btn"
                disabled={!selected || run.isPending}
                onClick={() => run.mutate()}
                type="button"
              >
                {run.isPending && <Loader2 className="spin" size={14} />}
                <span>{run.isPending ? "Simulating Dry Run…" : "Dry Run Plan"}</span>
              </button>
              <button
                className="btn btn-danger"
                disabled={!selected || isDeleting}
                onClick={() => setDeleteTarget(selected)}
              >
                {isDeleting ? "Deleting…" : "Delete"}
              </button>
              <input className="field max-w-xs" placeholder="Compare campaign ID" value={otherId} onChange={(e) => setOtherId(e.target.value)} />
            </div>
          </section>

          <DataPanel title="Vault Restore Error" data={restore.error} />
          <DataPanel title="Dry Run Error" data={run.error} />
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
      <ConfirmModal
        open={deleteTarget !== null}
        title="Delete Campaign"
        description="Permanently delete this campaign and all its stored findings, hosts, credentials, and loot artifacts. This action cannot be undone."
        confirmLabel="Delete Campaign"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={() => {
          if (deleteTarget) {
            const target = deleteTarget;
            setDeleteTarget(null);
            void handleDelete(target);
          }
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </Page>
  );
}



export default CampaignsPage;
