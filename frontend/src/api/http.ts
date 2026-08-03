import type { TokenResponse } from "./types";
import {
  REFRESH_COOKIE_LOCK,
  browserCoordinationAvailable,
  captureSession,
  invalidateSession,
  isSessionCurrent,
  markSessionUnavailable,
  readCoordinationRecord,
  replaceSessionIfCurrent,
  type CoordinationRecord,
  type SessionSnapshot
} from "./session";

const CSRF_HEADER = "X-ARES-CSRF";
const CSRF_COOKIE_NAMES = ["__Host-ares-csrf", "ares-dev-csrf"] as const;
const CSRF_PATTERN = /^[A-Za-z0-9_-]{43}$/;

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

function validTokenResponse(value: unknown): value is TokenResponse {
  return (
    typeof value === "object"
    && value !== null
    && "access_token" in value
    && typeof value.access_token === "string"
    && value.access_token.length > 0
    && !("refresh_token" in value)
    && "session_coordination_key" in value
    && typeof value.session_coordination_key === "string"
    && /^[A-Za-z0-9_-]{43}$/.test(value.session_coordination_key)
    && "refresh_generation" in value
    && typeof value.refresh_generation === "number"
    && Number.isSafeInteger(value.refresh_generation)
    && value.refresh_generation >= 0
  );
}

export function readBrowserCsrfToken(): string | null {
  let source: string;
  try {
    source = document.cookie;
  } catch {
    return null;
  }
  const found: string[] = [];
  for (const item of source.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 1) {
      continue;
    }
    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1);
    if ((CSRF_COOKIE_NAMES as readonly string[]).includes(name)) {
      found.push(value);
    }
  }
  source = "";
  return found.length === 1 && CSRF_PATTERN.test(found[0]) ? found[0] : null;
}

export async function bootstrapBrowserCsrf(): Promise<void> {
  const response = await fetch("/auth/csrf", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store"
  });
  if (response.status !== 204) {
    const body = await parseResponse(response);
    throw new ApiError(response.status, errorDetail(body));
  }
}

async function requireBrowserCsrf(): Promise<string> {
  let value = readBrowserCsrfToken();
  if (value === null) {
    await bootstrapBrowserCsrf();
    value = readBrowserCsrfToken();
  }
  if (value === null) {
    throw new ApiError(403, "Browser request rejected");
  }
  return value;
}

export async function withRefreshCookieLock<T>(operation: () => Promise<T>): Promise<T> {
  if (!browserCoordinationAvailable()) {
    throw new ApiError(401, "Browser session coordination unavailable");
  }
  return navigator.locks.request(REFRESH_COOKIE_LOCK, operation);
}

async function browserMutationResponse(
  path: string,
  init: RequestInit,
  options: { authenticated: boolean }
): Promise<Response> {
  const csrf = await requireBrowserCsrf();
  const headers = new Headers(init.headers);
  headers.set(CSRF_HEADER, csrf);
  const requestInit = {
    ...init,
    method: "POST",
    credentials: "same-origin" as RequestCredentials,
    cache: "no-store" as RequestCache,
    headers
  };
  return options.authenticated
    ? fetchWithSession(path, requestInit, false)
    : fetch(path, requestInit);
}

export async function browserMutationRequest<T>(
  path: string,
  init: RequestInit = {},
  options: { authenticated?: boolean } = {}
): Promise<T> {
  const response = await browserMutationResponse(path, init, {
    authenticated: options.authenticated ?? false
  });
  const body = await parseResponse(response);
  if (!response.ok) {
    throw new ApiError(response.status, errorDetail(body));
  }
  return body as T;
}

interface RefreshFlight {
  readonly revision: number;
  promise: Promise<boolean>;
}

let refreshFlight: RefreshFlight | null = null;
const INVALID_EXPECTATION = Symbol("invalid-refresh-expectation");

function refreshExpectation(
  snapshot: SessionSnapshot
): CoordinationRecord | null | typeof INVALID_EXPECTATION {
  const shared = readCoordinationRecord();
  if (shared === null) {
    return snapshot.coordinationKey === null ? null : INVALID_EXPECTATION;
  }
  if (shared.tombstone) {
    return INVALID_EXPECTATION;
  }
  if (
    snapshot.coordinationKey !== null
    && (shared.key !== snapshot.coordinationKey
      || snapshot.refreshGeneration === null
      || shared.generation < snapshot.refreshGeneration)
  ) {
    return INVALID_EXPECTATION;
  }
  return shared;
}

async function settleIndeterminateRefresh(snapshot: SessionSnapshot): Promise<void> {
  invalidateSession(snapshot);
  try {
    await browserMutationResponse("/auth/logout", {}, { authenticated: false });
  } catch {
    // Reauthentication is mandatory; no refresh or logout retry loop is permitted.
  }
}

async function performRefresh(snapshot: SessionSnapshot): Promise<boolean> {
  if (!isSessionCurrent(snapshot)) {
    return false;
  }
  const expected = refreshExpectation(snapshot);
  if (expected === INVALID_EXPECTATION) {
    invalidateSession(snapshot);
    return false;
  }
  try {
    const response = await browserMutationResponse("/auth/refresh", {}, {
      authenticated: false
    });
    if (!response.ok) {
      if (response.status === 503) {
        markSessionUnavailable(snapshot);
      } else {
        invalidateSession(snapshot);
      }
      return false;
    }
    const body = await parseResponse(response);
    if (!validTokenResponse(body)) {
      invalidateSession(snapshot);
      return false;
    }
    if (
      expected !== null
      && (body.session_coordination_key !== expected.key
        || body.refresh_generation !== expected.generation + 1)
    ) {
      invalidateSession(snapshot);
      return false;
    }
    return replaceSessionIfCurrent(
      snapshot,
      body.access_token,
      body.session_coordination_key,
      body.refresh_generation
    );
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 503) {
        markSessionUnavailable(snapshot);
      } else {
        invalidateSession(snapshot);
      }
      return false;
    }
    await settleIndeterminateRefresh(snapshot);
    return false;
  }
}

export function refreshAccessToken(snapshot = captureSession()): Promise<boolean> {
  if (!browserCoordinationAvailable()) {
    invalidateSession(snapshot);
    return Promise.resolve(false);
  }
  if (refreshFlight && refreshFlight.revision === snapshot.revision) {
    return refreshFlight.promise;
  }
  const flight: RefreshFlight = {
    revision: snapshot.revision,
    promise: Promise.resolve(false)
  };
  flight.promise = withRefreshCookieLock(() => performRefresh(snapshot)).finally(() => {
    if (refreshFlight === flight) {
      refreshFlight = null;
    }
  });
  refreshFlight = flight;
  return flight.promise;
}

function sessionChangedError(): ApiError {
  return new ApiError(401, "Session changed");
}

async function fetchWithSession(
  path: string,
  init: RequestInit,
  retry: boolean,
  snapshot = captureSession()
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (snapshot.accessToken) {
    headers.set("Authorization", `Bearer ${snapshot.accessToken}`);
  }
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers
  });

  if (snapshot.accessToken && !isSessionCurrent(snapshot)) {
    throw sessionChangedError();
  }
  if (response.status !== 401) {
    return response;
  }
  if (!retry) {
    if (snapshot.accessToken) {
      invalidateSession(snapshot);
    }
    return response;
  }
  const current = captureSession();
  if (!isSessionCurrent(snapshot)) {
    throw sessionChangedError();
  }
  if (current.accessToken && current.accessToken !== snapshot.accessToken) {
    return fetchWithSession(path, init, false, current);
  }
  if (await refreshAccessToken(current)) {
    const refreshed = captureSession();
    if (!isSessionCurrent(snapshot)) {
      throw sessionChangedError();
    }
    return fetchWithSession(path, init, false, refreshed);
  }
  return response;
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<T> {
  const response = await fetchWithSession(path, init, retry);
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
  const response = await fetchWithSession(path, init, retry);
  if (!response.ok) {
    const body = await parseResponse(response);
    throw new ApiError(response.status, errorDetail(body));
  }
  return response.blob();
}
