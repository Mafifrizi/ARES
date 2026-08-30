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

function loginResponse(): Response {
  return new Response(JSON.stringify({
    access_token: "memory-access",
    token_type: "bearer",
    expires_in: 3600,
    role: "operator",
    refresh_generation: 0,
    session_coordination_key: KEY
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("browser auth API facade", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
    installBrowserPrimitives();
  });

  it("login performs CSRF, locked logout, CSRF, then credential form", async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      void init;
      if (path === "/auth/csrf") return new Response(null, { status: 204 });
      if (path === "/auth/logout") return new Response(null, { status: 204 });
      return loginResponse();
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const response = await client.login("alice", "Secret123!");
    expect(response.access_token).toBe("memory-access");
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      "/auth/csrf", "/auth/logout", "/auth/csrf", "/auth/token"
    ]);
  });

  it("login response and browser storage contain no refresh token", async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      void init;
      return path === "/auth/token" ? loginResponse() : new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const response = await client.login("alice", "Secret123!");
    expect("refresh_token" in response).toBe(false);
    expect(sessionStorage.getItem("ares.refreshToken")).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain("memory-access");
  });

  it("login form carries credentials only in the form body", async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      void init;
      return path === "/auth/token" ? loginResponse() : new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    await client.login("alice", "Secret123!");
    const tokenCall = fetchMock.mock.calls.find((call) => call[0] === "/auth/token");
    const init = tokenCall?.[1] as RequestInit;
    expect(init.body).toBeInstanceOf(URLSearchParams);
    expect(new Headers(init.headers).has("Authorization")).toBe(false);
    expect(init.credentials).toBe("same-origin");
  });

  it("login fails closed without Web Locks", async () => {
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    await expect(client.login("alice", "Secret123!")).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("logout is cookie-authoritative and has an empty body", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    await client.logout();
    const call = fetchMock.mock.calls[0];
    const init = call?.[1] as RequestInit;
    expect(call?.[0]).toBe("/auth/logout");
    expect(init.body).toBeUndefined();
    expect(new Headers(init.headers).has("Authorization")).toBe(false);
  });

  it("logout-all sends in-memory bearer plus CSRF", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    client.setAccessToken("memory-access");
    await client.logoutAll();
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer memory-access");
    expect(headers.get("X-ARES-CSRF")).toBe(CSRF);
  });

  it("campaign WebSocket tickets remain bearer API requests", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(JSON.stringify({
        ticket: "ticket-value", expires_in: 30
      }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    client.setAccessToken("memory-access");
    await client.api.websocketTicket("campaign-a");
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer memory-access");
  });

  it("WebSocket URL contains only the one-time ticket query", async () => {
    const client = await import("./client");
    const path = client.campaignEventsPath("campaign-a", "ticket-value");
    expect(path).toBe("/ws/campaigns/campaign-a/events?ticket=ticket-value");
    expect(path).not.toContain("access_token");
    expect(path).not.toContain("api_key");
  });

  it("account replacement publishes an old-family tombstone", async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      void init;
      return path === "/auth/token" ? loginResponse() : new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    await client.login("alice", "Secret123!");
    await client.login("bob", "Secret123!");
    expect(fetchMock.mock.calls.filter((call) => call[0] === "/auth/logout")).toHaveLength(2);
  });

  it("API errors keep fixed status metadata", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "Denied" }), { status: 403 })));
    const client = await import("./client");
    await expect(client.api.health()).rejects.toMatchObject({ status: 403 });
  });

  it("all generic requests use same-origin credentials", async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      void input;
      void init;
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    await client.api.health();
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).credentials).toBe("same-origin");
  });
});

describe("C-LIVE-v1 idempotency", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
    installBrowserPrimitives();
  });

  it("generates one Idempotency-Key for an effectful submission", async () => {
    const generated = "123e4567-e89b-42d3-a456-426614174000";
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(generated);
    const fetchMock = vi.fn<(
      input: RequestInfo | URL,
      init?: RequestInit
    ) => Promise<Response>>(async () => new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const result = await client.api.runModule(
      "recon.test",
      client.buildModuleRunPayload("campaign-a", {}, false)
    );
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.get("Idempotency-Key")).toBe(generated);
    expect(result.idempotency_key).toBe(generated);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reuses the same Idempotency-Key for a transport retry", async () => {
    const generated = "123e4567-e89b-42d3-a456-426614174001";
    const uuid = vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(generated);
    const fetchMock = vi.fn<(
      input: RequestInfo | URL,
      init?: RequestInit
    ) => Promise<Response>>()
      .mockRejectedValueOnce(new TypeError("network lost"))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }));
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const payload = client.buildModuleRunPayload("campaign-a", { target: "host-a" }, false);
    await expect(client.api.runModule("recon.test", payload)).rejects.toMatchObject({
      idempotencyKey: generated
    });
    await client.api.runModule("recon.test", payload);
    const keys = fetchMock.mock.calls.map((call) => new Headers(call[1]?.headers).get("Idempotency-Key"));
    expect(keys).toEqual([generated, generated]);
    expect(uuid).toHaveBeenCalledTimes(1);
  });

  it("generates a different key for a distinct logical submission", async () => {
    const uuid = vi.spyOn(globalThis.crypto, "randomUUID")
      .mockReturnValueOnce("123e4567-e89b-42d3-a456-426614174002")
      .mockReturnValueOnce("123e4567-e89b-42d3-a456-426614174003");
    const fetchMock = vi.fn<(
      input: RequestInfo | URL,
      init?: RequestInit
    ) => Promise<Response>>(async () => new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const payload = client.buildModuleRunPayload("campaign-a", {}, false);
    await client.api.runModule("recon.test", payload);
    await client.api.runModule("recon.test", payload);
    const keys = fetchMock.mock.calls.map((call) => new Headers(call[1]?.headers).get("Idempotency-Key"));
    expect(keys[0]).not.toBe(keys[1]);
    expect(uuid).toHaveBeenCalledTimes(2);
  });

  it("preserves and displays a caller-supplied Idempotency-Key", async () => {
    const supplied = "123e4567-e89b-42d3-a456-426614174004";
    const uuid = vi.spyOn(globalThis.crypto, "randomUUID");
    const fetchMock = vi.fn<(
      input: RequestInfo | URL,
      init?: RequestInit
    ) => Promise<Response>>(async () => new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = await import("./client");
    const result = await client.api.engageStrategy(
      { campaign_id: "campaign-a", goal: "domain_admin" },
      { idempotencyKey: supplied }
    );
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.get("Idempotency-Key")).toBe(supplied);
    expect(result.idempotency_key).toBe(supplied);
    expect(JSON.stringify(result)).toContain(supplied);
    expect(uuid).not.toHaveBeenCalled();
  });
});
