import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "./http";
import { clearTokens, getAccessToken, setAccessToken, setRefreshToken } from "./session";

describe("HTTP auth boundary", () => {
  beforeEach(() => {
    clearTokens();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("refreshes once and retries the original request with the refreshed access token", async () => {
    setAccessToken("expired-access");
    setRefreshToken("refresh-token");
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/auth/refresh") {
        expect(init?.method).toBe("POST");
        return new Response(JSON.stringify({
          access_token: "fresh-access",
          refresh_token: "fresh-refresh",
          token_type: "bearer",
          expires_in: 3600,
          role: "operator"
        }), { status: 200 });
      }
      const authorization = new Headers(init?.headers).get("Authorization");
      if (authorization === "Bearer expired-access") {
        return new Response(null, { status: 401 });
      }
      expect(authorization).toBe("Bearer fresh-access");
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest<{ status: string }>("/protected")).resolves.toEqual({ status: "ok" });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(getAccessToken()).toBe("fresh-access");
  });
});
