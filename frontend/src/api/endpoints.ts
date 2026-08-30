import type {
  ApiKeyCreateResponse,
  ApiKeyMeta,
  AttackPathsResponse,
  Campaign,
  CampaignGraph,
  ExecutionChain,
  Finding,
  LiveExecutionResponse,
  LiveSubmissionOptions,
  ModuleMeta,
  MonthlyFindingStats,
  ReportItem,
  TemplateMeta,
  TokenResponse,
  UserProfile,
  WebSocketTicketResponse
} from "./types";
import {
  apiBlobRequest,
  apiRequest,
  ApiError,
  bootstrapBrowserCsrf,
  browserMutationRequest,
  withRefreshCookieLock
} from "./http";
import { beginIdentityTransition, installSessionIfCurrent } from "./session";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const pendingLiveSubmissions = new Map<string, string>();

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function liveSubmissionFingerprint(path: string, body: Record<string, unknown>): string {
  return `${path}\u0000${canonicalJson(body)}`;
}

function canonicalIdempotencyKey(value: string): string {
  if (!UUID_V4.test(value)) {
    throw new ApiError(422, "Idempotency-Key must be a canonical lowercase UUIDv4");
  }
  return value;
}

function createIdempotencyKey(): string {
  const value = globalThis.crypto?.randomUUID?.();
  if (typeof value !== "string") {
    throw new ApiError(503, "Secure UUID generation unavailable");
  }
  return canonicalIdempotencyKey(value);
}

function attachIdempotencyKey(error: unknown, key: string): never {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    Object.defineProperty(error, "idempotencyKey", {
      configurable: false,
      enumerable: true,
      value: key,
      writable: false
    });
  }
  throw error;
}

async function liveExecutionRequest(
  path: string,
  body: Record<string, unknown>,
  options: LiveSubmissionOptions = {}
): Promise<LiveExecutionResponse> {
  const fingerprint = liveSubmissionFingerprint(path, body);
  if (options.startNewSubmission) {
    pendingLiveSubmissions.delete(fingerprint);
  }
  const supplied = options.idempotencyKey === undefined
    ? undefined
    : canonicalIdempotencyKey(options.idempotencyKey);
  const key = supplied ?? pendingLiveSubmissions.get(fingerprint) ?? createIdempotencyKey();
  pendingLiveSubmissions.set(fingerprint, key);
  try {
    const result = await apiRequest<Record<string, unknown>>(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": key
      },
      body: JSON.stringify(body)
    });
    if (pendingLiveSubmissions.get(fingerprint) === key) {
      pendingLiveSubmissions.delete(fingerprint);
    }
    return { ...result, idempotency_key: key };
  } catch (error) {
    attachIdempotencyKey(error, key);
  }
}

function clearPendingLiveSubmissions(): void {
  pendingLiveSubmissions.clear();
}

export async function login(username: string, password: string): Promise<TokenResponse> {
  clearPendingLiveSubmissions();
  const loginSession = beginIdentityTransition();
  const token = await withRefreshCookieLock(async () => {
    await bootstrapBrowserCsrf();
    await browserMutationRequest<null>("/auth/logout");
    await bootstrapBrowserCsrf();
    const body = new URLSearchParams();
    body.set("username", username);
    body.set("password", password);
    return browserMutationRequest<TokenResponse>("/auth/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
  });
  if (!installSessionIfCurrent(
    loginSession,
    token.access_token,
    token.session_coordination_key,
    token.refresh_generation
  )) {
    throw new ApiError(401, "Session changed");
  }
  return token;
}

export async function logout(): Promise<void> {
  clearPendingLiveSubmissions();
  await withRefreshCookieLock(async () => {
    await browserMutationRequest<null>("/auth/logout");
  });
}

export async function logoutAll(): Promise<void> {
  clearPendingLiveSubmissions();
  await withRefreshCookieLock(async () => {
    await browserMutationRequest<null>("/auth/logout-all", {}, { authenticated: true });
  });
}

export function campaignEventsPath(campaignId: string, ticket: string): string {
  return `/ws/campaigns/${encodeURIComponent(campaignId)}/events?ticket=${encodeURIComponent(ticket)}`;
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
  websocketTicket: (id: string) =>
    apiRequest<WebSocketTicketResponse>(
      `/campaigns/${encodeURIComponent(id)}/websocket-ticket`,
      { method: "POST" }
    ),
  deleteCampaign: (id: string) =>
    apiRequest<Record<string, string>>(`/campaigns/${encodeURIComponent(id)}`, { method: "DELETE" }),
  findings: (id: string) => apiRequest<Finding[]>(`/campaigns/${encodeURIComponent(id)}/findings`),
  cvss: (id: string) => apiRequest<Record<string, unknown>>(`/campaigns/${encodeURIComponent(id)}/cvss`),
  restoreVault: (id: string) =>
    apiRequest<Record<string, unknown>>(`/campaigns/${encodeURIComponent(id)}/restore-vault`, { method: "POST" }),
  runCampaign: (
    id: string,
    body: Record<string, unknown>,
    options: LiveSubmissionOptions = {}
  ) => {
    const path = `/campaigns/${encodeURIComponent(id)}/run`;
    return body.dry_run === true
      ? apiRequest<Record<string, unknown>>(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        })
      : liveExecutionRequest(path, body, options);
  },
  diffCampaign: (id: string, otherId: string) =>
    apiRequest<Record<string, unknown>>(
      `/campaigns/${encodeURIComponent(id)}/diff/${encodeURIComponent(otherId)}`
    ),
  modules: () => apiRequest<ModuleMeta[]>("/modules"),
  executionChains: () => apiRequest<ExecutionChain[]>("/modules/execution-chains"),
  runModule: (
    moduleId: string,
    payload: ReturnType<typeof buildModuleRunPayload>,
    options: LiveSubmissionOptions = {}
  ) => {
    const path = `/modules/${encodeURIComponent(moduleId)}/run`;
    return payload.dry_run
      ? apiRequest<Record<string, unknown>>(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        })
      : liveExecutionRequest(path, payload, options);
  },
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
  engageStrategy: (
    body: Record<string, unknown>,
    options: LiveSubmissionOptions = {}
  ) => liveExecutionRequest("/strategy/engage", body, options),
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
