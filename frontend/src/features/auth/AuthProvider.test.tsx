import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

const runtime = vi.hoisted(() => ({
  revision: 0,
  refresh: vi.fn(async () => false),
  login: vi.fn(async () => undefined),
  logout: vi.fn(async () => undefined),
  logoutAll: vi.fn(async () => undefined),
  me: vi.fn(async () => ({ username: "alice", role: "operator" })),
  invalidation: null as (() => void) | null
}));

vi.mock("../../api/client", () => ({
  api: { me: runtime.me },
  browserCoordinationAvailable: () => true,
  captureSession: () => ({
    revision: runtime.revision,
    accessToken: null,
    coordinationKey: null,
    refreshGeneration: null
  }),
  clearTokens: vi.fn(() => { runtime.revision += 1; }),
  invalidateSession: vi.fn((snapshot?: { revision: number }) => {
    if (snapshot && snapshot.revision !== runtime.revision) return false;
    runtime.revision += 1;
    runtime.invalidation?.();
    return true;
  }),
  isSessionCurrent: (snapshot: { revision: number }) => snapshot.revision === runtime.revision,
  login: runtime.login,
  logout: runtime.logout,
  logoutAll: runtime.logoutAll,
  refreshAccessToken: runtime.refresh,
  subscribeToSessionInvalidation: (listener: () => void) => {
    runtime.invalidation = listener;
    return () => { runtime.invalidation = null; };
  }
}));

vi.mock("../dashboard/dashboardUiState", () => ({
  bindDashboardPrincipal: vi.fn(),
  clearDashboardSession: vi.fn()
}));

import { AuthProvider } from "./AuthProvider";
import { useAuth } from "./authContext";

let latestAuth: ReturnType<typeof useAuth> | null = null;

function Probe() {
  latestAuth = useAuth();
  return <div>{latestAuth.user?.username ?? "signed-out"}</div>;
}

function renderProvider(children: ReactNode = <Probe />) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>{children}</AuthProvider>
    </QueryClientProvider>
  );
}

describe("AuthProvider cookie bootstrap", () => {
  beforeEach(() => {
    runtime.revision = 0;
    runtime.refresh.mockReset().mockResolvedValue(false);
    runtime.login.mockReset().mockResolvedValue(undefined);
    runtime.logout.mockReset().mockResolvedValue(undefined);
    runtime.logoutAll.mockReset().mockResolvedValue(undefined);
    runtime.me.mockReset().mockResolvedValue({ username: "alice", role: "operator" });
    runtime.invalidation = null;
    latestAuth = null;
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => cleanup());

  it("performs exactly one startup cookie refresh", async () => {
    renderProvider();
    await waitFor(() => expect(screen.getByText("signed-out")).toBeTruthy());
    expect(runtime.refresh).toHaveBeenCalledTimes(1);
  });

  it("loads the current profile after a valid cookie bootstrap", async () => {
    runtime.refresh.mockResolvedValue(true);
    renderProvider();
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    expect(runtime.me).toHaveBeenCalledTimes(1);
  });

  it("does not call the profile endpoint when the cookie is invalid", async () => {
    renderProvider();
    await waitFor(() => expect(screen.getByText("signed-out")).toBeTruthy());
    expect(runtime.me).not.toHaveBeenCalled();
  });

  it("login resolves the current profile", async () => {
    renderProvider();
    await waitFor(() => expect(latestAuth?.loading).toBe(false));
    await act(async () => { await latestAuth?.login("alice", "password"); });
    expect(runtime.login).toHaveBeenCalledTimes(1);
    expect(screen.getByText("alice")).toBeTruthy();
  });

  it("logout clears local state even when remote revocation fails", async () => {
    runtime.refresh.mockResolvedValue(true);
    runtime.logout.mockRejectedValue(new Error("unavailable"));
    renderProvider();
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    await act(async () => { await latestAuth?.logout(); });
    expect(screen.getByText("signed-out")).toBeTruthy();
  });

  it("logout-all clears local state after remote success", async () => {
    runtime.refresh.mockResolvedValue(true);
    renderProvider();
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    await act(async () => { await latestAuth?.logoutAll(); });
    expect(runtime.logoutAll).toHaveBeenCalledTimes(1);
    expect(screen.getByText("signed-out")).toBeTruthy();
  });

  it("a session invalidation notification clears current UI authority", async () => {
    runtime.refresh.mockResolvedValue(true);
    renderProvider();
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    act(() => runtime.invalidation?.());
    expect(screen.getByText("signed-out")).toBeTruthy();
  });

  it("a late startup profile cannot restore an unmounted provider", async () => {
    let release: ((value: { username: string; role: string }) => void) | undefined;
    runtime.refresh.mockResolvedValue(true);
    runtime.me.mockReturnValue(new Promise((resolve) => { release = resolve; }));
    const view = renderProvider();
    await waitFor(() => expect(runtime.me).toHaveBeenCalledTimes(1));
    view.unmount();
    await act(async () => { release?.({ username: "alice", role: "operator" }); });
    expect(latestAuth?.user ?? null).toBeNull();
  });

  it("browser-readable storage never receives a refresh token", async () => {
    runtime.refresh.mockResolvedValue(true);
    renderProvider();
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    expect(sessionStorage.getItem("ares.refreshToken")).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain("refresh_token");
  });
});
