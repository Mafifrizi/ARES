import { beforeEach, describe, expect, it, vi } from "vitest";

const CSRF = "A".repeat(43);
const KEY = "B".repeat(43);

function installBrowserPrimitives(): void {
  localStorage.clear();
  sessionStorage.clear();
  document.cookie = `ares-dev-csrf=${CSRF}; Path=/`;
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: { request: vi.fn(async (_name: string, operation: () => unknown) => operation()) }
  });
}

function tokenResponse(generation = 1): Response {
  return new Response(JSON.stringify({
    access_token: "memory-access",
    token_type: "bearer",
    expires_in: 3600,
    role: "operator",
    refresh_generation: generation,
    session_coordination_key: KEY
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("cookie-backed HTTP transport", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
    installBrowserPrimitives();
  });

  it("reads only one canonical CSRF cookie", async () => {
    const http = await import("./http");
    expect(http.readBrowserCsrfToken()).toBe(CSRF);
  });

  it("rejects duplicate canonical CSRF cookie names", async () => {
    vi.spyOn(document, "cookie", "get").mockReturnValue(
      `ares-dev-csrf=${CSRF}; ares-dev-csrf=${CSRF}`
    );
    const http = await import("./http");
    expect(http.readBrowserCsrfToken()).toBeNull();
  });

  it("CSRF bootstrap uses a same-origin credentialed GET", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const http = await import("./http");
    await http.bootstrapBrowserCsrf();
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/auth/csrf");
    expect(init.credentials).toBe("same-origin");
    expect(init.method).toBe("GET");
  });

  it("refresh sends an empty cookie-authoritative request", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return tokenResponse();
    });
    vi.stubGlobal("fetch", fetchMock);
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    session.installSessionIfCurrent(snapshot, "old-access", KEY, 0);
    const http = await import("./http");
    await expect(http.refreshAccessToken(session.captureSession())).resolves.toBe(true);
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/auth/refresh");
    expect(init.body).toBeUndefined();
    expect(init.credentials).toBe("same-origin");
    expect(headers.get("X-ARES-CSRF")).toBe(CSRF);
    expect(headers.has("Authorization")).toBe(false);
  });

  it("refresh rejects a response containing a raw refresh token", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      access_token: "access",
      refresh_token: "forbidden",
      refresh_generation: 1,
      session_coordination_key: KEY
    }), { status: 200 })));
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    session.installSessionIfCurrent(snapshot, "old", KEY, 0);
    const http = await import("./http");
    await expect(http.refreshAccessToken(session.captureSession())).resolves.toBe(false);
    expect(session.getAccessToken()).toBeNull();
  });

  it("same-tab concurrent refreshes share one flight", async () => {
    let release: (() => void) | undefined;
    const barrier = new Promise<void>((resolve) => { release = resolve; });
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      await barrier;
      return tokenResponse();
    });
    vi.stubGlobal("fetch", fetchMock);
    const session = await import("./session");
    const start = session.beginIdentityTransition();
    session.installSessionIfCurrent(start, "old", KEY, 0);
    const http = await import("./http");
    const snapshot = session.captureSession();
    const first = http.refreshAccessToken(snapshot);
    const second = http.refreshAccessToken(snapshot);
    release?.();
    await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("a peer generation allows the next sequential rotation", async () => {
    localStorage.setItem("ares.sessionCoordination.v2", JSON.stringify({
      version: 2, key: KEY, generation: 2, tombstone: false
    }));
    vi.stubGlobal("fetch", vi.fn(async () => tokenResponse(3)));
    const http = await import("./http");
    await expect(http.refreshAccessToken()).resolves.toBe(true);
  });

  it("a tombstone prevents refresh", async () => {
    localStorage.setItem("ares.sessionCoordination.v2", JSON.stringify({
      version: 2, key: KEY, generation: 0, tombstone: true
    }));
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const session = await import("./session");
    const start = session.beginIdentityTransition();
    session.installSessionIfCurrent(start, "old", KEY, 0);
    localStorage.setItem("ares.sessionCoordination.v2", JSON.stringify({
      version: 2, key: KEY, generation: 0, tombstone: true
    }));
    const http = await import("./http");
    await expect(http.refreshAccessToken(session.captureSession())).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("a 503 produces fixed unavailable state without retry", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(null, { status: 503 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const http = await import("./http");
    const session = await import("./session");
    await expect(http.refreshAccessToken()).resolves.toBe(false);
    expect(session.isSessionUnavailable()).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("an indeterminate refresh performs one logout and never retries refresh", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError("network"))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const http = await import("./http");
    await expect(http.refreshAccessToken()).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      "/auth/refresh", "/auth/logout"
    ]);
  });

  it("missing Web Locks fails closed before network", async () => {
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const http = await import("./http");
    await expect(http.refreshAccessToken()).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ordinary API requests include same-origin credentials and memory bearer", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const session = await import("./session");
    session.setAccessToken("memory-bearer");
    const http = await import("./http");
    await http.apiRequest("/health", {}, false);
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.credentials).toBe("same-origin");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer memory-bearer");
  });
});
