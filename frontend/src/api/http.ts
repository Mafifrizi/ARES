import type { TokenResponse } from "./types";
import { clearTokens, getAccessToken, getRefreshToken, setAccessToken, setRefreshToken } from "./session";

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

function errorDetail(body: unknown): unknown {
  if (typeof body === "object" && body !== null && "detail" in body) {
    return body.detail ?? body;
  }
  return body;
}

export async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return false;
  }

  try {
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
    if (!token.access_token || !token.refresh_token) {
      clearTokens();
      return false;
    }
    setAccessToken(token.access_token);
    setRefreshToken(token.refresh_token);
    return true;
  } catch {
    clearTokens();
    return false;
  }
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<T> {
  const headers = new Headers(init.headers);
  const accessToken = getAccessToken();
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && retry && (await refreshAccessToken())) {
    return apiRequest<T>(path, init, false);
  }
  const body = await parseResponse(response);
  if (!response.ok) {
    throw new ApiError(response.status, errorDetail(body));
  }
  return body as T;
}

export async function apiBlobRequest(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<Blob> {
  const headers = new Headers(init.headers);
  const accessToken = getAccessToken();
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && retry && (await refreshAccessToken())) {
    return apiBlobRequest(path, init, false);
  }
  if (!response.ok) {
    const body = await parseResponse(response);
    throw new ApiError(response.status, errorDetail(body));
  }
  return response.blob();
}
