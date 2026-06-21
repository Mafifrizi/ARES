import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildModuleRunPayload,
  campaignEventsPath,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  login
} from "./client";

describe("api client auth", () => {
  beforeEach(() => {
    clearTokens();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("posts login as form-urlencoded and stores returned tokens", async () => {
    const fetchMock = vi.fn(async (_path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("Content-Type")).toBe("application/x-www-form-urlencoded");
      expect(init?.body).toBeInstanceOf(URLSearchParams);
      expect(String(init?.body)).toContain("username=alice");
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
    expect(fetchMock).toHaveBeenCalledWith("/auth/token", expect.any(Object));
    expect(getAccessToken()).toBe("access");
    expect(getRefreshToken()).toBe("refresh");
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
  it("uses the backend campaign websocket route", () => {
    expect(campaignEventsPath("camp/one", "token value")).toBe(
      "/ws/campaigns/camp%2Fone/events?token=token%20value"
    );
  });
});
