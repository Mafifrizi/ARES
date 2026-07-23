import type {
  ApiKeyCreateResponse,
  ApiKeyMeta,
  AttackPathsResponse,
  Campaign,
  CampaignGraph,
  ExecutionChain,
  Finding,
  ModuleMeta,
  MonthlyFindingStats,
  ReportItem,
  TemplateMeta,
  TokenResponse,
  UserProfile
} from "./types";
import { apiBlobRequest, apiRequest } from "./http";
import { clearTokens, setAccessToken, setRefreshToken } from "./session";

export async function login(username: string, password: string): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set("username", username);
  body.set("password", password);
  const token = await apiRequest<TokenResponse>(
    "/auth/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    },
    false
  );
  setAccessToken(token.access_token);
  setRefreshToken(token.refresh_token);
  return token;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<{ status: string }>("/auth/logout", { method: "POST" }, false);
  } finally {
    clearTokens();
  }
}

export function campaignEventsPath(campaignId: string, token: string): string {
  return `/ws/campaigns/${encodeURIComponent(campaignId)}/events?token=${encodeURIComponent(token)}`;
}

export function buildModuleRunPayload(
  campaignId: string,
  params: Record<string, unknown>,
  dryRun = true
): { campaign_id: string; params: Record<string, unknown>; dry_run: boolean } {
  return { campaign_id: campaignId, params, dry_run: dryRun };
}

export const api = {
  me: () => apiRequest<UserProfile>("/auth/me"),
  health: () => apiRequest<Record<string, unknown>>("/health"),
  telemetry: () => apiRequest<Record<string, unknown>>("/telemetry"),
  monthlyStats: () => apiRequest<MonthlyFindingStats>("/stats/monthly"),
  campaigns: () => apiRequest<Campaign[]>("/campaigns"),
  createCampaign: (body: { name: string; client: string; targets: string[]; scope_cidrs: string[]; noise_profile: string }) =>
    apiRequest<Campaign>("/campaigns", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  campaign: (id: string) => apiRequest<Campaign>(`/campaigns/${encodeURIComponent(id)}`),
  deleteCampaign: (id: string) =>
    apiRequest<Record<string, string>>(`/campaigns/${encodeURIComponent(id)}`, { method: "DELETE" }),
  findings: (id: string) => apiRequest<Finding[]>(`/campaigns/${encodeURIComponent(id)}/findings`),
  cvss: (id: string) => apiRequest<Record<string, unknown>>(`/campaigns/${encodeURIComponent(id)}/cvss`),
  restoreVault: (id: string) =>
    apiRequest<Record<string, unknown>>(`/campaigns/${encodeURIComponent(id)}/restore-vault`, { method: "POST" }),
  runCampaign: (id: string, body: Record<string, unknown>) =>
    apiRequest<Record<string, unknown>>(`/campaigns/${encodeURIComponent(id)}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  diffCampaign: (id: string, otherId: string) =>
    apiRequest<Record<string, unknown>>(
      `/campaigns/${encodeURIComponent(id)}/diff/${encodeURIComponent(otherId)}`
    ),
  modules: () => apiRequest<ModuleMeta[]>("/modules"),
  executionChains: () => apiRequest<ExecutionChain[]>("/modules/execution-chains"),
  runModule: (moduleId: string, payload: ReturnType<typeof buildModuleRunPayload>) =>
    apiRequest<Record<string, unknown>>(`/modules/${encodeURIComponent(moduleId)}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  generateReport: (campaignId: string, format: string) =>
    apiRequest<Record<string, string>>(
      `/reports/${encodeURIComponent(campaignId)}?fmt=${encodeURIComponent(format)}`,
      { method: "POST" }
    ),
  reports: (campaignId: string) =>
    apiRequest<{ campaign_id: string; reports: ReportItem[] }>(`/reports/${encodeURIComponent(campaignId)}`),
  reportDownloadUrl: (campaignId: string, filename: string) =>
    `/reports/${encodeURIComponent(campaignId)}/files/${encodeURIComponent(filename)}`,
  downloadReport: (campaignId: string, filename: string) =>
    apiBlobRequest(`/reports/${encodeURIComponent(campaignId)}/files/${encodeURIComponent(filename)}`),
  deleteReport: (campaignId: string, filename: string) =>
    apiRequest<Record<string, string>>(
      `/reports/${encodeURIComponent(campaignId)}/files/${encodeURIComponent(filename)}`,
      { method: "DELETE" }
    ),
  clearReports: (campaignId: string) =>
    apiRequest<{ status: string; campaign_id: string; deleted: number }>(
      `/reports/${encodeURIComponent(campaignId)}`,
      { method: "DELETE" }
    ),
  graph: (campaignId: string) => apiRequest<CampaignGraph>(`/graph/${encodeURIComponent(campaignId)}`),
  attackPaths: (campaignId: string) =>
    apiRequest<AttackPathsResponse>(`/graph/${encodeURIComponent(campaignId)}/attack-paths`),
  ingestBloodhound: (campaignId: string, jsonPath: string) =>
    apiRequest<Record<string, unknown>>(`/graph/${encodeURIComponent(campaignId)}/bloodhound`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ json_path: jsonPath })
    }),
  templates: () => apiRequest<TemplateMeta[]>("/templates"),
  templatePlan: (name: string, globalParams: Record<string, unknown>) =>
    apiRequest<Record<string, unknown>>(`/templates/${encodeURIComponent(name)}/plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ global_params: globalParams })
    }),
  activeStrategy: () => apiRequest<Record<string, unknown>>("/strategy/active"),
  engageStrategy: (body: Record<string, unknown>) =>
    apiRequest<Record<string, unknown>>("/strategy/engage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  changePassword: (body: { current_password: string; new_password: string }) =>
    apiRequest<Record<string, string>>("/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  apiKeys: () => apiRequest<ApiKeyMeta[]>("/auth/api-keys"),
  createApiKey: (body: { name: string; scopes: string; expires_days?: number }) =>
    apiRequest<ApiKeyCreateResponse>("/auth/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }),
  deleteApiKey: (id: string) => apiRequest<Record<string, string>>(`/auth/api-keys/${encodeURIComponent(id)}`, {
    method: "DELETE"
  }),
  securityAudit: () => apiRequest<Record<string, unknown>>("/security/audit"),
  users: () => apiRequest<Record<string, unknown>[]>("/security/users"),
  edrStats: () => apiRequest<Record<string, unknown>>("/edr/bypass/stats"),
  reportBypass: (body: Record<string, unknown>) =>
    apiRequest<Record<string, unknown>>("/edr/bypass/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    })
};
