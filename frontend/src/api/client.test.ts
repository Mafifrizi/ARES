import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  api,
  beginIdentityTransition,
  buildModuleRunPayload,
  campaignEventsPath,
  captureSession,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  invalidateSession,
  login,
  refreshAccessToken,
  setAccessToken,
  subscribeToSessionInvalidation,
  setRefreshToken
} from "./client";
import { installTokenPairIfCurrent } from "./session";

function requireFixed(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function requireTokensUnavailable(): void {
  const accessTokenUnavailable = getAccessToken() === null;
  const refreshTokenUnavailable = getRefreshToken() === null;
  requireFixed(accessTokenUnavailable, "Access token should remain unavailable.");
  requireFixed(refreshTokenUnavailable, "Refresh token should remain unavailable.");
}

function resetTestSessionStorage(): void {
  const keys = Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index))
    .filter((key): key is string => key !== null);
  for (const key of keys) {
    sessionStorage.removeItem(key);
  }
}

describe("api client auth", () => {
  beforeEach(() => {
    clearTokens();
    resetTestSessionStorage();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("posts login as form-urlencoded and stores returned tokens", async () => {
    let loginCalls = 0;
    const fetchMock = vi.fn(async (_path: string, init?: RequestInit) => {
      loginCalls += 1;
      const headers = new Headers(init?.headers);
      requireFixed(
        headers.get("Content-Type") === "application/x-www-form-urlencoded",
        "expected form content type"
      );
      requireFixed(init?.body instanceof URLSearchParams, "expected form request body");
      const body = new URLSearchParams(String(init?.body));
      requireFixed(body.get("username") === "alice", "expected canonical login username");
      return new Response(
        JSON.stringify({
          access_token: "access",
          refresh_token: "refresh",
          token_type: "bearer",
          expires_in: 3600,
          role: "operator"
        }),
        { status: 200 }
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    await login("alice", "Secret123!");
    expect(loginCalls).toBe(1);
    const accessTokenInstalled = getAccessToken() === "access";
    const refreshTokenInstalled = getRefreshToken() === "refresh";
    requireFixed(accessTokenInstalled, "expected access token installation");
    requireFixed(refreshTokenInstalled, "expected refresh token installation");
  });

  it("refreshes the access token from the stored refresh token", async () => {
    setRefreshToken("refresh-old");
    const fetchMock = vi.fn(async (_path: string, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body)) as { refresh_token?: unknown };
      const refreshRequestTokenMatches = body.refresh_token === "refresh-old";
      requireFixed(refreshRequestTokenMatches, "expected refresh request token");
      return new Response(
        JSON.stringify({
          access_token: "access-new",
          refresh_token: "refresh-new",
          token_type: "bearer",
          expires_in: 3600,
          role: "operator"
        }),
        { status: 200 }
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(refreshAccessToken()).resolves.toBe(true);
    const rotatedAccessTokenCurrent = getAccessToken() === "access-new";
    const rotatedRefreshTokenCurrent = getRefreshToken() === "refresh-new";
    requireFixed(rotatedAccessTokenCurrent, "expected rotated access token");
    requireFixed(rotatedRefreshTokenCurrent, "expected rotated refresh token");
  });

  it("clears tokens when refresh fails", async () => {
    setRefreshToken("expired-refresh");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));

    await expect(refreshAccessToken()).resolves.toBe(false);
    requireTokensUnavailable();
  });

  it("fails closed when a login token pair cannot be persisted", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({
        access_token: "access",
        refresh_token: "refresh",
        token_type: "bearer",
        expires_in: 3600,
        role: "operator"
      }),
      { status: 200 }
    )));
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("unavailable", "SecurityError");
    });
    try {
      let rejectionStatus: number | undefined;
      try {
        await login("alice", "Secret123!");
      } catch (error) {
        rejectionStatus = error instanceof ApiError ? error.status : undefined;
      }
      requireFixed(rejectionStatus === 401, "expected failed token-pair installation");
      requireTokensUnavailable();
    } finally {
      setItem.mockRestore();
    }
  });

  it("clears the logical token pair when refresh-token removal fails", () => {
    setAccessToken("access");
    setRefreshToken("refresh");
    const originalRemoveItem = Storage.prototype.removeItem;
    const removeItem = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (
      this: Storage,
      key: string
    ) {
      if (key === "ares.refreshToken") {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalRemoveItem.call(this, key);
    });
    try {
      expect(() => clearTokens()).not.toThrow();
      requireTokensUnavailable();
      const refreshStorageNeutralized = sessionStorage.getItem("ares.refreshToken") === "";
      requireFixed(refreshStorageNeutralized, "Refresh-token storage should be neutralized.");
    } finally {
      removeItem.mockRestore();
      setRefreshToken(null);
    }
  });

  it("continues invalidation after a subscriber throws", () => {
    setAccessToken("access");
    setRefreshToken("refresh");
    let laterSubscriberCalls = 0;
    const unsubscribeThrowing = subscribeToSessionInvalidation(() => {
      throw new Error("subscriber failed");
    });
    const unsubscribeLater = subscribeToSessionInvalidation(() => {
      laterSubscriberCalls += 1;
    });
    try {
      const invalidated = invalidateSession(captureSession());
      expect(invalidated).toBe(true);
      expect(laterSubscriberCalls).toBe(1);
      requireTokensUnavailable();
    } finally {
      unsubscribeThrowing();
      unsubscribeLater();
    }
  });

  it("fails closed when refresh-token storage reads fail and recovers after a valid install", () => {
    setRefreshToken("refresh-before-read-failure");
    const originalGetItem = Storage.prototype.getItem;
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(function (
      this: Storage,
      key: string
    ) {
      if (key === "ares.refreshToken") {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalGetItem.call(this, key);
    });
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warningLog = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      let readThrew = false;
      let observedRefreshToken: string | null = null;
      try {
        observedRefreshToken = getRefreshToken();
      } catch {
        readThrew = true;
      }
      requireFixed(!readThrew, "expected storage read failure to remain internal");
      const observedRefreshTokenUnavailable = observedRefreshToken === null;
      const accessTokenUnavailable = getAccessToken() === null;
      requireFixed(observedRefreshTokenUnavailable, "Refresh token should remain unavailable.");
      requireFixed(accessTokenUnavailable, "Access token should remain unavailable.");
      expect(errorLog).not.toHaveBeenCalled();
      expect(warningLog).not.toHaveBeenCalled();
    } finally {
      getItem.mockRestore();
      errorLog.mockRestore();
      warningLog.mockRestore();
    }

    const recoveredSession = beginIdentityTransition();
    const installed = installTokenPairIfCurrent(
      recoveredSession,
      "access-after-read-failure",
      "refresh-after-read-failure"
    );
    requireFixed(installed, "expected valid token-pair recovery");
    const recoveredAccessTokenCurrent = getAccessToken() === "access-after-read-failure";
    const recoveredRefreshTokenCurrent = getRefreshToken() === "refresh-after-read-failure";
    requireFixed(recoveredAccessTokenCurrent, "expected recovered access session");
    requireFixed(recoveredRefreshTokenCurrent, "expected recovered refresh session");
  });

  it("keeps invalidation fail-closed when refresh-token removal and sentinel writes fail", () => {
    const activeSession = beginIdentityTransition();
    const installed = installTokenPairIfCurrent(
      activeSession,
      "access-before-clear-failure",
      "refresh-before-clear-failure"
    );
    requireFixed(installed, "expected active session setup");
    const beforeInvalidation = captureSession();
    let subscriberCalls = 0;
    const unsubscribe = subscribeToSessionInvalidation(() => {
      subscriberCalls += 1;
    });
    const originalRemoveItem = Storage.prototype.removeItem;
    const originalSetItem = Storage.prototype.setItem;
    const removeItem = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (
      this: Storage,
      key: string
    ) {
      if (key === "ares.refreshToken") {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalRemoveItem.call(this, key);
    });
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (
      this: Storage,
      key: string,
      value: string
    ) {
      if (key === "ares.refreshToken" && value === "") {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalSetItem.call(this, key, value);
    });
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warningLog = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      let invalidationThrew = false;
      let invalidated = false;
      try {
        invalidated = invalidateSession(beforeInvalidation);
      } catch {
        invalidationThrew = true;
      }
      const afterInvalidation = captureSession();
      requireFixed(!invalidationThrew, "expected storage cleanup failures to remain internal");
      expect(invalidated).toBe(true);
      requireTokensUnavailable();
      expect(afterInvalidation.revision).toBeGreaterThan(beforeInvalidation.revision);
      expect(subscriberCalls).toBe(1);
      expect(errorLog).not.toHaveBeenCalled();
      expect(warningLog).not.toHaveBeenCalled();
    } finally {
      removeItem.mockRestore();
      setItem.mockRestore();
      errorLog.mockRestore();
      warningLog.mockRestore();
      unsubscribe();
    }

    const recoveredSession = beginIdentityTransition();
    const recovered = installTokenPairIfCurrent(
      recoveredSession,
      "access-after-clear-failure",
      "refresh-after-clear-failure"
    );
    requireFixed(recovered, "expected token-pair recovery after cleanup failure");
    const recoveredAccessTokenCurrent = getAccessToken() === "access-after-clear-failure";
    const recoveredRefreshTokenCurrent = getRefreshToken() === "refresh-after-clear-failure";
    requireFixed(recoveredAccessTokenCurrent, "expected recovered access session");
    requireFixed(recoveredRefreshTokenCurrent, "expected recovered refresh session");
  });
});

describe("module execution helpers", () => {
  it("defaults UI module runs to dry_run true", () => {
    expect(buildModuleRunPayload("campaign-1", { target: "dc01" })).toEqual({
      campaign_id: "campaign-1",
      params: { target: "dc01" },
      dry_run: true
    });
  });
});

describe("live event helpers", () => {
  it("requests a fresh ticket with POST and parses the fixed response", async () => {
    let requestIsCanonical = false;
    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      requestIsCanonical =
        path === "/campaigns/camp%2Fone/websocket-ticket"
        && init?.method === "POST"
        && init.body === undefined;
      return new Response(JSON.stringify({
        ticket: "A".repeat(43),
        expires_in: 30
      }), { status: 201 });
    }));

    const response = await api.websocketTicket("camp/one");
    const responseIsCanonical =
      response.ticket.length === 43 && response.expires_in === 30;
    requireFixed(requestIsCanonical, "expected ticket issuance request contract");
    requireFixed(responseIsCanonical, "expected ticket issuance response contract");
  });

  it("uses only the one-time ticket on the campaign websocket route", () => {
    const path = campaignEventsPath("camp/one", "A".repeat(43));
    const matchesExpectedRoute =
      path === `/ws/campaigns/camp%2Fone/events?ticket=${"A".repeat(43)}`;
    const excludesLegacyCredentials =
      !path.includes("token=") && !path.includes("api_key=");
    requireFixed(matchesExpectedRoute, "expected encoded campaign WebSocket route");
    requireFixed(excludesLegacyCredentials, "expected ticket-only WebSocket query");
  });
});
