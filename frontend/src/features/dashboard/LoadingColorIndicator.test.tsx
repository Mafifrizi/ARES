// @vitest-environment jsdom
import "../../test/setup";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "operator", role: "operator" },
    loading: false,
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

let pendingModuleRun = false;

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual("../../api/client");
  return {
    ...actual,
    api: {
      health: vi.fn(async () => ({ status: "ok" })),
      telemetry: vi.fn(async () => ({})),
      campaigns: vi.fn(async () => [
        { id: "cmp-1", name: "Campaign 1", status: "active" }
      ]),
      modules: vi.fn(async () => [
        { id: "recon.portscan", name: "Port Scanner", description: "Scans ports", category: "recon" }
      ]),
      templates: vi.fn(async () => []),
      executionChains: vi.fn(async () => []),
      reports: vi.fn(async () => ({ campaign_id: "", reports: [] })),
      monthlyStats: vi.fn(async () => ({ total: 0, confirmed_findings: 0, series: [] })),
      runModule: vi.fn(() => new Promise((resolve) => {
        if (!pendingModuleRun) {
          resolve({ status: "success" });
        }
      }))
    }
  };
});

import { clearDashboardSession } from "./dashboardUiState";
import { DashboardShell, ModulesPage, OverviewPage } from "./DashboardPages";

describe("Loading & Empty State Non-Alarmist Color Consistency (ITEM 5)", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearDashboardSession();
    pendingModuleRun = false;
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("OverviewPage empty state uses cyan styling instead of red alert", async () => {
    const { api } = await import("../../api/client");
    vi.mocked(api.campaigns).mockResolvedValueOnce([]);

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: 0 } }
    });

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <DashboardShell>
            <Routes>
              <Route path="/" element={<OverviewPage />} />
            </Routes>
          </DashboardShell>
        </MemoryRouter>
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText("No Campaigns Initialized")).toBeInTheDocument();
    });

    const heroWrap = document.querySelector(".fresh-hero-icon-wrap");
    expect(heroWrap).toBeInTheDocument();

    // Verify alarmist ShieldAlert with text-rose-500 is gone
    const roseAlert = heroWrap?.querySelector(".text-rose-500");
    expect(roseAlert).toBeNull();

    // Verify cyan Target icon is present
    const cyanIcon = heroWrap?.querySelector(".text-cyan-400");
    expect(cyanIcon).toBeInTheDocument();
  });

  it("ModulesPage in-progress execution notice uses notice-info instead of notice-danger", async () => {
    pendingModuleRun = true;

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: 0 } }
    });

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/modules"]}>
          <DashboardShell>
            <Routes>
              <Route path="/modules" element={<ModulesPage />} />
            </Routes>
          </DashboardShell>
        </MemoryRouter>
      </QueryClientProvider>
    );

    // Wait for modules to load
    await waitFor(() => {
      expect(screen.getByText("recon.portscan")).toBeInTheDocument();
    });

    // Select module
    fireEvent.click(screen.getByText("recon.portscan"));

    // Switch to Run Panel tab
    fireEvent.click(screen.getByRole("tab", { name: "Run Panel" }));

    // Select campaign
    const campaignPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    fireEvent.change(campaignPicker, { target: { value: "cmp-1" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Execute recon.portscan/i })).toBeInTheDocument();
    });

    // Execute module to trigger run.isPending
    fireEvent.click(screen.getByRole("button", { name: /Execute recon.portscan/i }));

    await waitFor(() => {
      expect(screen.getByText(/Module execution in progress/i)).toBeInTheDocument();
    });

    const runningNotice = screen.getByText(/Module execution in progress/i).closest(".notice");
    expect(runningNotice).toBeInTheDocument();

    // Must NOT have danger/red class
    expect(runningNotice).not.toHaveClass("notice-danger");

    // Must have info/active class
    expect(runningNotice).toHaveClass("notice-info");
  });
});
