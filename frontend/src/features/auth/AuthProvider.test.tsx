import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "../../api/http";
import {
  beginIdentityTransition,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  installTokenPairIfCurrent,
  setRefreshToken
} from "../../api/session";
import { useDashboardSessionWriter } from "../dashboard/dashboardUiState";
import { AuthProvider } from "./AuthProvider";
import { type AuthState, useAuth } from "./authContext";

let currentAuth: AuthState | undefined;
let currentDashboardWriter: ((key: string, value: unknown) => boolean) | undefined;

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

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

function requireRefreshTokenUnavailable(): void {
  const refreshTokenUnavailable = getRefreshToken() === null;
  requireFixed(refreshTokenUnavailable, "Refresh token should remain unavailable.");
}

function AuthProbe() {
  currentAuth = useAuth();
  currentDashboardWriter = useDashboardSessionWriter();
  return <span>{currentAuth.user?.username ?? "logged-out"}</span>;
}

function tokenResponse(
  accessToken: string,
  refreshToken: string,
  generation = 0,
  coordinationKey = "coordination-a"
): Response {
  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "bearer",
    expires_in: 3600,
    role: "operator",
    refresh_generation: generation,
    session_coordination_key: coordinationKey
  }), { status: 200 });
}

function installStoredSession(refreshToken = "refresh-a"): void {
  const session = beginIdentityTransition();
  const installed = installTokenPairIfCurrent(
    session,
    "stale-access",
    refreshToken,
    "coordination-a",
    0
  );
  requireFixed(installed, "expected authoritative stored session");
}

function profileResponse(username: string, role = "operator"): Response {
  return new Response(JSON.stringify({ username, role }), { status: 200 });
}

function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false }
    }
  });
}

function renderProvider(queryClient: QueryClient, strict = false) {
  const tree = (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AuthProbe />
      </AuthProvider>
    </QueryClientProvider>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

function auth(): AuthState {
  if (!currentAuth) {
    throw new Error("auth probe has not rendered");
  }
  return currentAuth;
}

function dashboardWriter(): (key: string, value: unknown) => boolean {
  if (!currentDashboardWriter) {
    throw new Error("dashboard writer probe has not rendered");
  }
  return currentDashboardWriter;
}

async function waitForLoggedOut(): Promise<void> {
  await waitFor(() => {
    expect(auth().loading).toBe(false);
    expect(auth().user).toBeNull();
  });
}

function seedAccountState(queryClient: QueryClient): void {
  queryClient.setQueryData(["account-query"], { owner: "account-a" });
  queryClient.getMutationCache().build(queryClient, {
    mutationKey: ["account-mutation"],
    mutationFn: async () => ({ ok: true })
  });
  sessionStorage.setItem("ares.dashboard.modules.search", JSON.stringify("account-a"));
  sessionStorage.setItem("unrelated.same-origin", "keep");
}

function expectAccountStateCleared(queryClient: QueryClient): void {
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const dashboardStateRemoved = sessionStorage.getItem("ares.dashboard.modules.search") === null;
  const principalRemoved = sessionStorage.getItem("ares.dashboard.principal") === null;
  const unrelatedStatePreserved = sessionStorage.getItem("unrelated.same-origin") === "keep";
  requireFixed(dashboardStateRemoved, "Dashboard-owned state should be removed.");
  requireFixed(principalRemoved, "Dashboard principal should be removed.");
  requireFixed(unrelatedStatePreserved, "Unrelated session state should be preserved.");
}

function resetTestSessionStorage(): void {
  const keys = Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index))
    .filter((key): key is string => key !== null);
  for (const key of keys) {
    sessionStorage.removeItem(key);
  }
}

describe("AuthProvider session isolation", () => {
  beforeEach(() => {
    currentAuth = undefined;
    currentDashboardWriter = undefined;
    clearTokens();
    resetTestSessionStorage();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    cleanup();
    currentAuth = undefined;
    currentDashboardWriter = undefined;
    clearTokens();
    resetTestSessionStorage();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it.each(["success", "HTTP failure", "network failure"] as const)(
    "clears all local account state when logout has remote %s",
    async (outcome) => {
      const queryClient = createQueryClient();
      vi.stubGlobal("fetch", vi.fn(async (path: string) => {
        if (path === "/auth/token") {
          return tokenResponse("access-a", "refresh-a");
        }
        if (path === "/auth/me") {
          return profileResponse("alice");
        }
        if (path === "/auth/logout") {
          if (outcome === "network failure") {
            throw new TypeError("offline");
          }
          if (outcome === "HTTP failure") {
            return new Response(null, { status: 503 });
          }
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        }
        return new Response(null, { status: 404 });
      }));
      renderProvider(queryClient);
      await waitForLoggedOut();
      await act(async () => {
        await auth().login("alice", "password");
      });
      seedAccountState(queryClient);

      await act(async () => {
        await auth().logout();
      });

      expect(auth().user).toBeNull();
      requireTokensUnavailable();
      expectAccountStateCleared(queryClient);
    }
  );

  it("cleans account state and exits loading when startup refresh fails", async () => {
    const queryClient = createQueryClient();
    installStoredSession();
    seedAccountState(queryClient);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));

    renderProvider(queryClient);
    await waitForLoggedOut();

    requireRefreshTokenUnavailable();
    expectAccountStateCleared(queryClient);
  });

  it("purges legacy dashboard state when startup has no refresh token", async () => {
    const queryClient = createQueryClient();
    sessionStorage.setItem("ares.dashboard.modules.params", JSON.stringify({ field: "legacy" }));
    sessionStorage.setItem("ares.dashboard.live.events", JSON.stringify([{ kind: "legacy" }]));
    sessionStorage.setItem("unrelated.same-origin", "keep");

    renderProvider(queryClient);
    await waitForLoggedOut();

    const paramsRemoved = sessionStorage.getItem("ares.dashboard.modules.params") === null;
    const eventsRemoved = sessionStorage.getItem("ares.dashboard.live.events") === null;
    const unrelatedPreserved = sessionStorage.getItem("unrelated.same-origin") === "keep";
    requireFixed(paramsRemoved && eventsRemoved, "Unauthenticated startup should purge legacy dashboard state.");
    requireFixed(unrelatedPreserved, "Unauthenticated startup should preserve unrelated session state.");
  });

  it("cleans account state when startup profile resolution fails", async () => {
    const queryClient = createQueryClient();
    installStoredSession();
    seedAccountState(queryClient);
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/refresh") {
        return tokenResponse("access-a", "refresh-b", 1);
      }
      if (path === "/auth/me") {
        return new Response(null, { status: 503 });
      }
      return new Response(null, { status: 404 });
    }));

    renderProvider(queryClient);
    await waitForLoggedOut();

    requireTokensUnavailable();
    expectAccountStateCleared(queryClient);
  });

  it("reacts immediately to runtime refresh invalidation", async () => {
    const queryClient = createQueryClient();
    let runtime = false;
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/token") {
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        return profileResponse("alice");
      }
      if (path === "/runtime" && runtime) {
        return new Response(null, { status: 401 });
      }
      if (path === "/auth/refresh" && runtime) {
        return new Response(null, { status: 401 });
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    await act(async () => {
      await auth().login("alice", "password");
    });
    seedAccountState(queryClient);
    runtime = true;

    await act(async () => {
      await apiRequest("/runtime").catch(() => undefined);
    });

    expect(auth().user).toBeNull();
    expectAccountStateCleared(queryClient);
  });

  it("prevents a late refresh from restoring a session after provider logout", async () => {
    const queryClient = createQueryClient();
    const refreshStarted = deferred<void>();
    const releaseRefresh = deferred<void>();
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/token") {
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        return profileResponse("alice");
      }
      if (path === "/runtime") {
        return new Response(null, { status: 401 });
      }
      if (path === "/auth/refresh") {
        refreshStarted.resolve();
        await releaseRefresh.promise;
        return tokenResponse("access-late", "refresh-late", 1);
      }
      if (path === "/auth/logout") {
        return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    await act(async () => {
      await auth().login("alice", "password");
    });
    seedAccountState(queryClient);

    const runtimeRequest = apiRequest("/runtime");
    try {
      await refreshStarted.promise;
      await act(async () => {
        await auth().logout();
      });
      releaseRefresh.resolve();
      await act(async () => {
        await runtimeRequest.catch(() => undefined);
      });

      expect(auth().user).toBeNull();
      requireTokensUnavailable();
      expectAccountStateCleared(queryClient);
    } finally {
      releaseRefresh.resolve();
      await Promise.allSettled([runtimeRequest]);
    }
  });

  it.each(["success", "failure"] as const)(
    "keeps account B isolated from a late account-A refresh %s",
    async (outcome) => {
      const queryClient = createQueryClient();
      const refreshStarted = deferred<void>();
      const releaseRefresh = deferred<void>();
      let runtime = false;
      vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
        if (path === "/auth/token") {
          const username = new URLSearchParams(String(init?.body)).get("username");
          return username === "bob"
            ? tokenResponse("access-b", "refresh-b", 0, "coordination-b")
            : tokenResponse("access-a", "refresh-a");
        }
        if (path === "/auth/me") {
          const authorization = new Headers(init?.headers).get("Authorization");
          return profileResponse(authorization === "Bearer access-b" ? "bob" : "alice");
        }
        if (path === "/runtime" && runtime) {
          return new Response(null, { status: 401 });
        }
        if (path === "/auth/refresh" && runtime) {
          refreshStarted.resolve();
          await releaseRefresh.promise;
          return outcome === "success"
            ? tokenResponse("access-a-late", "refresh-a-late", 1)
            : new Response(null, { status: 401 });
        }
        return new Response(null, { status: 404 });
      }));
      renderProvider(queryClient);
      await waitForLoggedOut();
      await act(async () => {
        await auth().login("alice", "password");
      });
      seedAccountState(queryClient);
      runtime = true;

      const runtimeRequest = apiRequest("/runtime");
      try {
        await refreshStarted.promise;
        await act(async () => {
        await auth().login("bob", "password");
      });
      queryClient.setQueryData(["account-b"], { retained: true });
        sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
        releaseRefresh.resolve();
        await act(async () => {
          await runtimeRequest.catch(() => undefined);
        });

        expect(auth().user?.username).toBe("bob");
        expect(queryClient.getQueryData(["account-b"])).toEqual({ retained: true });
        const preferencePreserved =
          sessionStorage.getItem("ares.dashboard.modules.category") === JSON.stringify("network");
        const principalMatches =
          sessionStorage.getItem("ares.dashboard.principal")
          === JSON.stringify({ username: "bob", role: "operator" });
        requireFixed(preferencePreserved, "Account B preference should be preserved.");
        requireFixed(principalMatches, "Account B principal should remain current.");
        const accountBAccessTokenCurrent = getAccessToken() === "access-b";
        const accountBRefreshTokenCurrent = getRefreshToken() === "refresh-b";
        requireFixed(accountBAccessTokenCurrent, "expected account B access token");
        requireFixed(accountBRefreshTokenCurrent, "expected account B refresh token");
      } finally {
        releaseRefresh.resolve();
        await Promise.allSettled([runtimeRequest]);
      }
    }
  );

  it.each(["owned session", "newer session"] as const)(
    "rejects a deferred login after provider unmount without altering the %s",
    async (sessionOwner) => {
      const queryClient = createQueryClient();
      const profileStarted = deferred<void>();
      const releaseProfile = deferred<void>();
      vi.stubGlobal("fetch", vi.fn(async (path: string) => {
        if (path === "/auth/token") {
          return tokenResponse("access-a", "refresh-a");
        }
        if (path === "/auth/me") {
          profileStarted.resolve();
          await releaseProfile.promise;
          return profileResponse("alice");
        }
        return new Response(null, { status: 404 });
      }));
      const provider = renderProvider(queryClient);
      await waitForLoggedOut();

      let loginOutcome: Promise<"resolved" | "rejected"> | undefined;
      try {
        await act(async () => {
          const loginPromise = auth().login("alice", "password");
          loginOutcome = loginPromise.then(
            () => "resolved" as const,
            () => "rejected" as const
          );
          await profileStarted.promise;
        });

        provider.unmount();
        if (sessionOwner === "newer session") {
          const newerSession = beginIdentityTransition();
          const installed = installTokenPairIfCurrent(
            newerSession,
            "access-b",
            "refresh-b",
            "coordination-b",
            0
          );
          requireFixed(installed, "expected newer session installation");
        }
        releaseProfile.resolve();

        if (!loginOutcome) {
          throw new Error("login outcome observer was not installed");
        }
        const outcome = await loginOutcome;
        expect(outcome).toBe("rejected");
        expect(auth().user).toBeNull();
        const principalAbsent = sessionStorage.getItem("ares.dashboard.principal") === null;
        requireFixed(principalAbsent, "Abandoned login should not persist a principal.");
        if (sessionOwner === "owned session") {
          requireTokensUnavailable();
        } else {
          const newerAccessTokenCurrent = getAccessToken() === "access-b";
          const newerRefreshTokenCurrent = getRefreshToken() === "refresh-b";
          requireFixed(newerAccessTokenCurrent, "expected newer access session to survive");
          requireFixed(newerRefreshTokenCurrent, "expected newer refresh session to survive");
        }
      } finally {
        releaseProfile.resolve();
        if (loginOutcome) {
          await Promise.allSettled([loginOutcome]);
        }
        provider.unmount();
      }
    }
  );

  it("finishes local logout when refresh-token removal throws", async () => {
    const queryClient = createQueryClient();
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/token") {
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        return profileResponse("alice");
      }
      if (path === "/auth/logout") {
        return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    await act(async () => {
      await auth().login("alice", "password");
    });
    seedAccountState(queryClient);

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
      await act(async () => {
        await auth().logout();
      });
      expect(auth().user).toBeNull();
      requireTokensUnavailable();
      expectAccountStateCleared(queryClient);
    } finally {
      removeItem.mockRestore();
      setRefreshToken(null);
    }
  });

  it("shares startup refresh under StrictMode and applies one current profile", async () => {
    const queryClient = createQueryClient();
    installStoredSession();
    sessionStorage.setItem(
      "ares.dashboard.principal",
      JSON.stringify({ username: "alice", role: "operator" })
    );
    sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
    sessionStorage.setItem("ares.dashboard.modules.dryRun", JSON.stringify(false));
    let refreshCalls = 0;
    let profileCalls = 0;
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/refresh") {
        refreshCalls += 1;
        return tokenResponse("access-a", "refresh-b", 1);
      }
      if (path === "/auth/me") {
        profileCalls += 1;
        return profileResponse("alice");
      }
      return new Response(null, { status: 404 });
    }));

    renderProvider(queryClient, true);
    await waitFor(() => expect(auth().user?.username).toBe("alice"));

    expect({ profileCalls, refreshCalls }).toEqual({ profileCalls: 1, refreshCalls: 1 });
    const preferencePreserved =
      sessionStorage.getItem("ares.dashboard.modules.category") === JSON.stringify("network");
    const legacySafetyStatePurged =
      sessionStorage.getItem("ares.dashboard.modules.dryRun") === null;
    requireFixed(preferencePreserved, "StrictMode startup should preserve dashboard preference.");
    requireFixed(legacySafetyStatePurged, "StrictMode startup should purge disallowed legacy state.");
  });

  it("clears account A data before account B is authenticated or rendered", async () => {
    const queryClient = createQueryClient();
    let accountBStartedClean = false;
    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/auth/token") {
        const username = new URLSearchParams(String(init?.body)).get("username");
        if (username === "bob") {
          accountBStartedClean = (
            queryClient.getQueryCache().getAll().length === 0
            && queryClient.getMutationCache().getAll().length === 0
            && sessionStorage.getItem("ares.dashboard.modules.search") === null
          );
          return tokenResponse("access-b", "refresh-b", 0, "coordination-b");
        }
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        const authorization = new Headers(init?.headers).get("Authorization");
        return profileResponse(authorization === "Bearer access-b" ? "bob" : "alice");
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    await act(async () => {
      await auth().login("alice", "password");
    });
    seedAccountState(queryClient);
    const accountAWriter = dashboardWriter();

    await act(async () => {
      await auth().login("bob", "password");
    });

    expect(accountBStartedClean).toBe(true);
    expect(auth().user?.username).toBe("bob");
    const principalMatches =
      sessionStorage.getItem("ares.dashboard.principal")
      === JSON.stringify({ username: "bob", role: "operator" });
    const unrelatedStatePreserved = sessionStorage.getItem("unrelated.same-origin") === "keep";
    requireFixed(principalMatches, "Account B principal should be current.");
    requireFixed(unrelatedStatePreserved, "Unrelated session state should be preserved.");
    expect(accountAWriter("ares.dashboard.templates.tab", "stale")).toBe(false);
    expect(dashboardWriter()("ares.dashboard.templates.tab", "Plan Builder")).toBe(true);
    const currentWriterPersisted =
      sessionStorage.getItem("ares.dashboard.templates.tab") === JSON.stringify("Plan Builder");
    requireFixed(currentWriterPersisted, "Current dashboard writer should persist state.");
  });

  it("leaves no local session when profile resolution fails after login", async () => {
    const queryClient = createQueryClient();
    vi.stubGlobal("fetch", vi.fn(async (path: string) => {
      if (path === "/auth/token") {
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        return new Response(null, { status: 500 });
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    seedAccountState(queryClient);

    let rejected = false;
    await act(async () => {
      try {
        await auth().login("alice", "password");
      } catch {
        rejected = true;
      }
    });

    expect(rejected).toBe(true);
    expect(auth().user).toBeNull();
    requireTokensUnavailable();
    expectAccountStateCleared(queryClient);
  });

  it("preserves user, cache, and dashboard preferences after same-session runtime refresh", async () => {
    const queryClient = createQueryClient();
    let runtime = false;
    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/auth/token") {
        return tokenResponse("access-a", "refresh-a");
      }
      if (path === "/auth/me") {
        return profileResponse("alice");
      }
      if (path === "/auth/refresh" && runtime) {
        return tokenResponse("access-b", "refresh-b", 1);
      }
      if (path === "/runtime" && runtime) {
        const authorization = new Headers(init?.headers).get("Authorization");
        return authorization === "Bearer access-b"
          ? new Response(JSON.stringify({ status: "ok" }), { status: 200 })
          : new Response(null, { status: 401 });
      }
      return new Response(null, { status: 404 });
    }));
    renderProvider(queryClient);
    await waitForLoggedOut();
    await act(async () => {
      await auth().login("alice", "password");
    });
    queryClient.setQueryData(["safe-preference"], { retained: true });
    sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
    runtime = true;

    await act(async () => {
      await apiRequest("/runtime");
    });

    expect(auth().user?.username).toBe("alice");
    expect(queryClient.getQueryData(["safe-preference"])).toEqual({ retained: true });
    const preferencePreserved =
      sessionStorage.getItem("ares.dashboard.modules.category") === JSON.stringify("network");
    requireFixed(preferencePreserved, "Same-session refresh should preserve dashboard preference.");
    const rotatedAccessTokenCurrent = getAccessToken() === "access-b";
    requireFixed(rotatedAccessTokenCurrent, "expected same-session rotated access token");
  });
});
