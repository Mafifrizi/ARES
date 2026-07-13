import type {
  ApiKeyCreateResponse,
  ApiKeyMeta,
  Campaign,
  Finding,
  ModuleMeta,
  ReportItem,
  TemplateMeta,
  TokenResponse,
  UserProfile
} from "./types";

const REFRESH_TOKEN_KEY = "ares.refreshToken";

let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setRefreshToken(token: string | null): void {
  if (token) {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, token);
    return;
  }
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return sessionStorage.getItem(REFRESH_TOKEN_KEY);
}

export function clearTokens(): void {
  accessToken = null;
  setRefreshToken(null);
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `Request failed with ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

async function parseResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return false;
  }
  const response = await fetch("/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  if (!response.ok) {
    clearTokens();
    return false;
  }
  const token = (await response.json()) as TokenResponse;
  setAccessToken(token.access_token);
  setRefreshToken(token.refresh_token);
  return true;
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<T> {
  const headers = new Headers(init.headers);
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && retry && (await refreshAccessToken())) {
    return apiRequest<T>(path, init, false);
  }
  const body = await parseResponse(response);
  if (!response.ok) {
    throw new ApiError(response.status, (body as any)?.detail ?? body);
  }
  return body as T;
}

async function apiBlobRequest(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<Blob> {
  const headers = new Headers(init.headers);
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && retry && (await refreshAccessToken())) {
    return apiBlobRequest(path, init, false);
  }
  if (!response.ok) {
    const body = await parseResponse(response);
    throw new ApiError(response.status, (body as any)?.detail ?? body);
  }
  return response.blob();
}

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
  graph: (campaignId: string) => apiRequest<Record<string, any>>(`/graph/${encodeURIComponent(campaignId)}`),
  attackPaths: (campaignId: string) =>
    apiRequest<Record<string, any>>(`/graph/${encodeURIComponent(campaignId)}/attack-paths`),
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
