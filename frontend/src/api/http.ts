import type { TokenResponse } from "./types";
import {
  captureSession,
  invalidateSession,
  isSessionCurrent,
  readCoordinationRecord,
  replaceTokenPairIfCurrent,
  type SessionSnapshot
} from "./session";

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

interface RefreshFlight {
  readonly revision: number;
  readonly refreshToken: string;
  promise: Promise<boolean>;
}

let refreshFlight: RefreshFlight | null = null;

async function performRefresh(snapshot: SessionSnapshot): Promise<boolean> {
  if (
    !snapshot.refreshToken
    || !snapshot.coordinationKey
    || snapshot.refreshGeneration === null
  ) {
    return false;
  }

  try {
    const response = await fetch("/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: snapshot.refreshToken })
    });
    if (!response.ok) {
      invalidateSession(snapshot);
      return false;
    }
    const token = (await response.json()) as TokenResponse;
    if (
      !token.access_token
      || !token.refresh_token
      || token.session_coordination_key !== snapshot.coordinationKey
      || token.refresh_generation !== snapshot.refreshGeneration + 1
    ) {
      invalidateSession(snapshot);
      return false;
    }
    return replaceTokenPairIfCurrent(
      snapshot,
      token.access_token,
      token.refresh_token,
      token.session_coordination_key,
      token.refresh_generation
    );
  } catch {
    invalidateSession(snapshot);
    return false;
  }
}

export function refreshAccessToken(snapshot = captureSession()): Promise<boolean> {
  if (
    !snapshot.refreshToken
    || !snapshot.coordinationKey
    || snapshot.refreshGeneration === null
  ) {
    invalidateSession(snapshot);
    return Promise.resolve(false);
  }
  if (
    refreshFlight
    && refreshFlight.revision === snapshot.revision
    && refreshFlight.refreshToken === snapshot.refreshToken
  ) {
    return refreshFlight.promise;
  }

  const flight: RefreshFlight = {
    revision: snapshot.revision,
    refreshToken: snapshot.refreshToken,
    promise: Promise.resolve(false)
  };
  const execute = async () => {
    const current = captureSession();
    if (!isSessionCurrent(snapshot) || current.refreshToken !== snapshot.refreshToken) {
      return false;
    }
    const shared = readCoordinationRecord();
    if (
      shared === null
      || shared.key !== snapshot.coordinationKey
      || shared.tombstone
      || shared.generation !== snapshot.refreshGeneration
    ) {
      invalidateSession(snapshot);
      return false;
    }
    return performRefresh(snapshot);
  };
  const lockManager = navigator.locks;
  const coordinated: Promise<boolean> = (
    lockManager
      ? (async () => lockManager.request(
          `ares-refresh:${snapshot.coordinationKey}`,
          execute
        ))()
      : execute()
  );
  flight.promise = coordinated.finally(() => {
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
  const response = await fetch(path, { ...init, headers });

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

  invalidateSession(current);
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
