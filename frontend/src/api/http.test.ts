import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiBlobRequest, apiRequest } from "./http";
import {
  beginIdentityTransition,
  captureSession,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  installTokenPairIfCurrent,
  invalidateSession,
  subscribeToSessionInvalidation
} from "./session";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function tokenResponse(accessToken: string, refreshToken: string): Response {
  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "bearer",
    expires_in: 3600,
    role: "operator"
  }), { status: 200 });
}

function installSession(accessToken = "access-a", refreshToken = "refresh-a"): void {
  const session = beginIdentityTransition();
  if (!installTokenPairIfCurrent(session, accessToken, refreshToken)) {
    throw new Error("test session setup failed");
  }
}

function requireFixed(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function resetTestSessionStorage(): void {
  const keys = Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index))
    .filter((key): key is string => key !== null);
  for (const key of keys) {
    sessionStorage.removeItem(key);
  }
}

describe("HTTP auth boundary", () => {
  beforeEach(() => {
    clearTokens();
    resetTestSessionStorage();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shares one refresh across simultaneous JSON requests and retries both once", async () => {
    installSession();
    const releaseRefresh = deferred<void>();
    const refreshStarted = deferred<void>();
    let refreshCalls = 0;
    let initialCalls = 0;
    let retryCalls = 0;
    let incorrectRetryAuthorization = false;

    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get("Authorization");
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        refreshStarted.resolve();
        await releaseRefresh.promise;
        return tokenResponse("access-b", "refresh-b");
      }
      if (authorization === "Bearer access-a") {
        initialCalls += 1;
        return new Response(null, { status: 401 });
      }
      if (authorization !== "Bearer access-b") {
        incorrectRetryAuthorization = true;
        return new Response(null, { status: 403 });
      }
      retryCalls += 1;
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }));

    const first = apiRequest<{ status: string }>("/protected/one");
    const second = apiRequest<{ status: string }>("/protected/two");
    try {
      await refreshStarted.promise;
      releaseRefresh.resolve();

      const results = await Promise.all([first, second]);
      expect(results.map((result) => result.status)).toEqual(["ok", "ok"]);
      expect({ incorrectRetryAuthorization, initialCalls, refreshCalls, retryCalls }).toEqual({
        incorrectRetryAuthorization: false,
        initialCalls: 2,
        refreshCalls: 1,
        retryCalls: 2
      });
      const rotatedAccessTokenCurrent = getAccessToken() === "access-b";
      requireFixed(rotatedAccessTokenCurrent, "expected rotated access authorization");
    } finally {
      releaseRefresh.resolve();
      await Promise.allSettled([first, second]);
    }
  });

  it("shares the same refresh flight between JSON and blob requests", async () => {
    installSession();
    const releaseRefresh = deferred<void>();
    const refreshStarted = deferred<void>();
    let refreshCalls = 0;
    let incorrectRetryAuthorization = false;

    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get("Authorization");
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        refreshStarted.resolve();
        await releaseRefresh.promise;
        return tokenResponse("access-b", "refresh-b");
      }
      if (authorization === "Bearer access-a") {
        return new Response(null, { status: 401 });
      }
      if (authorization !== "Bearer access-b") {
        incorrectRetryAuthorization = true;
        return new Response(null, { status: 403 });
      }
      return path === "/blob"
        ? new Response("artifact", { status: 200 })
        : new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }));

    const jsonRequest = apiRequest<{ status: string }>("/json");
    const blobRequest = apiBlobRequest("/blob");
    try {
      await refreshStarted.promise;
      releaseRefresh.resolve();

      const [json, blob] = await Promise.all([jsonRequest, blobRequest]);
      expect(json.status).toBe("ok");
      expect(blob.size).toBeGreaterThan(0);
      expect({ incorrectRetryAuthorization, refreshCalls }).toEqual({
        incorrectRetryAuthorization: false,
        refreshCalls: 1
      });
    } finally {
      releaseRefresh.resolve();
      await Promise.allSettled([jsonRequest, blobRequest]);
    }
  });

  it("invalidates once when a shared refresh fails and does not retry protected requests", async () => {
    installSession();
    let refreshCalls = 0;
    let protectedCalls = 0;
    let invalidations = 0;
    const unsubscribe = subscribeToSessionInvalidation(() => {
      invalidations += 1;
    });
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        return new Response(null, { status: 401 });
      }
      protectedCalls += 1;
      return new Response(null, { status: 401 });
    }));

    try {
      const results = await Promise.allSettled([
        apiRequest("/protected/one"),
        apiRequest("/protected/two")
      ]);
      expect(results.every((result) => result.status === "rejected")).toBe(true);
      expect({ invalidations, protectedCalls, refreshCalls }).toEqual({
        invalidations: 1,
        protectedCalls: 2,
        refreshCalls: 1
      });
      const refreshTokenUnavailable = getRefreshToken() === null;
      requireFixed(refreshTokenUnavailable, "Refresh token should remain unavailable.");
    } finally {
      unsubscribe();
    }
  });

  it("invalidates after one retry receives a second 401 without recursion", async () => {
    installSession();
    let protectedCalls = 0;
    let refreshCalls = 0;
    let invalidations = 0;
    const unsubscribe = subscribeToSessionInvalidation(() => {
      invalidations += 1;
    });
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        return tokenResponse("access-b", "refresh-b");
      }
      protectedCalls += 1;
      return new Response(null, { status: 401 });
    }));

    try {
      await expect(apiRequest("/protected")).rejects.toMatchObject({ status: 401 });
      expect({ invalidations, protectedCalls, refreshCalls }).toEqual({
        invalidations: 1,
        protectedCalls: 2,
        refreshCalls: 1
      });
    } finally {
      unsubscribe();
    }
  });

  it("retries a delayed old-token 401 with the current token without a second refresh", async () => {
    installSession();
    const releaseDelayed = deferred<void>();
    const delayedStarted = deferred<void>();
    let refreshCalls = 0;
    let delayedCalls = 0;
    let incorrectRetryAuthorization = false;

    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get("Authorization");
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        return tokenResponse("access-b", "refresh-b");
      }
      if (path === "/delayed" && authorization === "Bearer access-a") {
        delayedStarted.resolve();
        await releaseDelayed.promise;
        return new Response(null, { status: 401 });
      }
      if (authorization === "Bearer access-a") {
        return new Response(null, { status: 401 });
      }
      if (authorization !== "Bearer access-b") {
        incorrectRetryAuthorization = true;
        return new Response(null, { status: 403 });
      }
      if (path === "/delayed") {
        delayedCalls += 1;
      }
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }));

    const delayed = apiRequest<{ status: string }>("/delayed");
    try {
      await delayedStarted.promise;
      await expect(apiRequest<{ status: string }>("/leading")).resolves.toEqual({ status: "ok" });
      releaseDelayed.resolve();
      await expect(delayed).resolves.toEqual({ status: "ok" });

      expect({ delayedCalls, incorrectRetryAuthorization, refreshCalls }).toEqual({
        delayedCalls: 1,
        incorrectRetryAuthorization: false,
        refreshCalls: 1
      });
    } finally {
      releaseDelayed.resolve();
      await Promise.allSettled([delayed]);
    }
  });

  it("does not restore a session when a refresh succeeds after logout", async () => {
    installSession();
    const releaseRefresh = deferred<void>();
    const refreshStarted = deferred<void>();
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path !== "/auth/refresh") {
        return new Response(null, { status: 401 });
      }
      refreshStarted.resolve();
      await releaseRefresh.promise;
      return tokenResponse("access-late", "refresh-late");
    }));

    const original = captureSession();
    const refresh = apiRequest("/protected");
    try {
      await refreshStarted.promise;
      invalidateSession(original);
      releaseRefresh.resolve();

      await expect(refresh).rejects.toMatchObject({ status: 401 });
      const accessTokenUnavailable = getAccessToken() === null;
      const refreshTokenUnavailable = getRefreshToken() === null;
      requireFixed(accessTokenUnavailable, "Access token should remain unavailable.");
      requireFixed(refreshTokenUnavailable, "Refresh token should remain unavailable.");
    } finally {
      releaseRefresh.resolve();
      await Promise.allSettled([refresh]);
    }
  });

  it.each(["success", "failure"] as const)(
    "does not let stale account-A refresh %s alter account B",
    async (outcome) => {
      installSession();
      const releaseRefresh = deferred<void>();
      const refreshStarted = deferred<void>();
      let invalidations = 0;
      const unsubscribe = subscribeToSessionInvalidation(() => {
        invalidations += 1;
      });
      vi.stubGlobal("fetch", vi.fn(async (path: string) => {
        if (path === "/auth/refresh") {
          refreshStarted.resolve();
          await releaseRefresh.promise;
          return outcome === "success"
            ? tokenResponse("access-a-late", "refresh-a-late")
            : new Response(null, { status: 401 });
        }
        return new Response(null, { status: 401 });
      }));

      try {
        const refresh = apiRequest("/protected");
        try {
          await refreshStarted.promise;
          const accountB = beginIdentityTransition();
          const installed = installTokenPairIfCurrent(accountB, "access-b", "refresh-b");
          expect(installed).toBe(true);
          releaseRefresh.resolve();
          await expect(refresh).rejects.toMatchObject({ status: 401 });
          const accountBAccessTokenCurrent = getAccessToken() === "access-b";
          const accountBRefreshTokenCurrent = getRefreshToken() === "refresh-b";
          requireFixed(accountBAccessTokenCurrent, "expected account B access token");
          requireFixed(accountBRefreshTokenCurrent, "expected account B refresh token");
          expect(invalidations).toBe(0);
        } finally {
          releaseRefresh.resolve();
          await Promise.allSettled([refresh]);
        }
      } finally {
        unsubscribe();
      }
    }
  );

  it("never retries an old-account request with the new account authorization", async () => {
    installSession();
    const releaseRequest = deferred<void>();
    const requestStarted = deferred<void>();
    let protectedCalls = 0;
    let refreshCalls = 0;
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/refresh") {
        refreshCalls += 1;
      } else {
        protectedCalls += 1;
        requestStarted.resolve();
        await releaseRequest.promise;
      }
      return new Response(null, { status: 401 });
    }));

    const request = apiRequest("/protected");
    try {
      await requestStarted.promise;
      const accountB = beginIdentityTransition();
      const installed = installTokenPairIfCurrent(accountB, "access-b", "refresh-b");
      expect(installed).toBe(true);
      releaseRequest.resolve();

      await expect(request).rejects.toMatchObject({ status: 401 });
      expect({ protectedCalls, refreshCalls }).toEqual({ protectedCalls: 1, refreshCalls: 0 });
      const accountBAccessTokenCurrent = getAccessToken() === "access-b";
      requireFixed(accountBAccessTokenCurrent, "expected account B access token");
    } finally {
      releaseRequest.resolve();
      await Promise.allSettled([request]);
    }
  });

  it("removes an invalidation subscriber cleanly", () => {
    installSession();
    let calls = 0;
    const unsubscribe = subscribeToSessionInvalidation(() => {
      calls += 1;
    });
    unsubscribe();
    invalidateSession(captureSession());
    expect(calls).toBe(0);
  });
});
