// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { Campaign } from "../../api/types";

let mockCampaigns: Campaign[] = [];

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "admin", role: "team_lead" },
    loading: false,
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual("../../api/client");
  return {
    ...actual,
    api: {
      health: vi.fn(async () => ({ status: "ok" })),
      telemetry: vi.fn(async () => ({})),
      campaigns: vi.fn(async () => [...mockCampaigns]),
      campaign: vi.fn(async (id: string) => mockCampaigns.find((c) => c.id === id) ?? null),
      deleteCampaign: vi.fn(async (id: string) => {
        const found = mockCampaigns.find((c) => c.id === id);
        if (!found) {
          throw new Error("Campaign not found");
        }
        mockCampaigns = mockCampaigns.filter((c) => c.id !== id);
        return { status: "deleted", campaign_id: id };
      }),
      modules: vi.fn(async () => []),
      templates: vi.fn(async () => []),
      reports: vi.fn(async () => ({ campaign_id: "", reports: [] })),
      monthlyStats: vi.fn(async () => ({ total: 0, confirmed_findings: 0, series: [] })),
      activeStrategy: vi.fn(async () => ({ active: false, llm_backends: { claude: true, openai: true, local: false } })),
      findings: vi.fn(async () => []),
      cvss: vi.fn(async () => ({})),
      diffCampaign: vi.fn(async () => ({})),
      executionChains: vi.fn(async () => []),
      runCampaign: vi.fn(async () => ({}))
    }
  };
});

import { api } from "../../api/client";
import { clearDashboardSession } from "./dashboardUiState";
import {
  CampaignsPage,
  DashboardShell,
  ModulesPage,
  OverviewPage,
  ReportsPage,
  StrategyPage
} from "./DashboardPages";

function renderWithShell(initialRoute = "/campaigns") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: 0
      }
    }
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialRoute]}>
        <DashboardShell>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/campaigns" element={<CampaignsPage />} />
            <Route path="/modules" element={<ModulesPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/strategy" element={<StrategyPage />} />
          </Routes>
        </DashboardShell>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Campaign deletion state synchronization across consumers", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    clearDashboardSession();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    mockCampaigns = [
      {
        id: "camp-001",
        name: "Enterprise Simulation",
        client: "Acme Corp",
        status: "created",
        noise_profile: "stealth",
        operator: "admin"
      },
      {
        id: "camp-002",
        name: "AD Lab Pivot",
        client: "Internal",
        status: "created",
        noise_profile: "normal",
        operator: "admin"
      }
    ];
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("synchronously removes deleted campaign from badge, scope dropdown, table, and selection without page refresh", async () => {
    renderWithShell("/campaigns");

    // Wait for initial load
    await waitFor(() => {
      expect(screen.getAllByText("Enterprise Simulation").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("AD Lab Pivot").length).toBeGreaterThanOrEqual(1);
    });

    // 1. Assert initial badge count in sidebar is "2"
    const navCountBadges = document.querySelectorAll(".nav-count-badge");
    const campaignsBadge = Array.from(navCountBadges).find(
      (el) => el.closest("a")?.getAttribute("href") === "/campaigns"
    );
    expect(campaignsBadge?.textContent).toBe("2");

    // 2. Switch to Scope tab to select camp-001 and trigger deletion
    const scopeTabBtn = screen.getByRole("tab", { name: "Scope" });
    fireEvent.click(scopeTabBtn);

    const targetPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    expect(targetPicker).toBeInTheDocument();
    expect(targetPicker.querySelectorAll("option").length).toBe(3); // "Select campaign" + 2 campaigns

    // Select camp-001
    fireEvent.change(targetPicker, { target: { value: "camp-001" } });

    // The Delete button should be enabled for the selected campaign
    const deleteBtn = screen.getByRole("button", { name: "Delete" });
    expect(deleteBtn).not.toBeDisabled();

    // 3. Click Delete
    await act(async () => {
      fireEvent.click(deleteBtn);
    });

    // 4. Assert backend delete was called with camp-001
    await waitFor(() => {
      expect(api.deleteCampaign).toHaveBeenCalledWith("camp-001");
    });

    // 5. Assert camp-001 is immediately removed from the UI:
    // User was automatically switched to "List" tab
    await waitFor(() => {
      expect(screen.queryByText("Enterprise Simulation")).not.toBeInTheDocument();
      expect(screen.getAllByText("AD Lab Pivot").length).toBeGreaterThanOrEqual(1);
    });

    // 6. Assert sidebar badge count automatically updated to "1"
    const updatedBadge = Array.from(document.querySelectorAll(".nav-count-badge")).find(
      (el) => el.closest("a")?.getAttribute("href") === "/campaigns"
    );
    expect(updatedBadge?.textContent).toBe("1");

    // 7. Assert topbar scope select no longer includes camp-001 and defaulted to Global
    const topbarSelect = screen.getByLabelText("Active campaign scope") as HTMLSelectElement;
    const topbarOptions = Array.from(topbarSelect.options).map((opt) => opt.value);
    expect(topbarOptions).not.toContain("camp-001");
    expect(topbarOptions).toContain("camp-002");
    expect(topbarSelect.value).toBe(""); // Reset to empty / Global

    // 8. Navigate to Scope tab again and verify Target Campaign dropdown has only camp-002
    fireEvent.click(screen.getByRole("tab", { name: "Scope" }));
    const refreshedPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    const refreshedOptions = Array.from(refreshedPicker.options).map((opt) => opt.value);
    expect(refreshedOptions).not.toContain("camp-001");
    expect(refreshedOptions).toContain("camp-002");
    expect(refreshedPicker.value).toBe(""); // Value reset, not stuck on deleted campaign

    // 9. Navigate to Overview and assert Campaign Activity table only contains camp-002
    fireEvent.click(screen.getByRole("link", { name: /Overview/i }));
    await waitFor(() => {
      expect(screen.queryByText("Enterprise Simulation")).not.toBeInTheDocument();
      expect(screen.getAllByText("AD Lab Pivot").length).toBeGreaterThanOrEqual(1);
    });

    // 10. Navigate to Strategy and assert Target Campaign dropdown only contains camp-002
    fireEvent.click(screen.getByRole("link", { name: /Strategy/i }));
    await waitFor(() => {
      const stratPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      const stratOptions = Array.from(stratPicker.options).map((opt) => opt.value);
      expect(stratOptions).not.toContain("camp-001");
      expect(stratOptions).toContain("camp-002");
    });

    // 11. Navigate to Modules, switch to Run Panel, and assert Target Campaign dropdown has only camp-002
    fireEvent.click(screen.getByRole("link", { name: /Modules/i }));
    fireEvent.click(screen.getByRole("tab", { name: "Run Panel" }));
    await waitFor(() => {
      const modPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      const modOptions = Array.from(modPicker.options).map((opt) => opt.value);
      expect(modOptions).not.toContain("camp-001");
      expect(modOptions).toContain("camp-002");
    });

    // 12. Navigate to Reports and assert Target Campaign dropdown has only camp-002
    fireEvent.click(screen.getByRole("link", { name: /Reports/i }));
    await waitFor(() => {
      const repPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      const repOptions = Array.from(repPicker.options).map((opt) => opt.value);
      expect(repOptions).not.toContain("camp-001");
      expect(repOptions).toContain("camp-002");
    });
  });

  it("deleting all campaigns immediately renders the Fresh Install Hero in Overview", async () => {
    // Start with 1 campaign
    mockCampaigns = [
      {
        id: "camp-002",
        name: "AD Lab Pivot",
        client: "Internal",
        status: "created",
        noise_profile: "normal",
        operator: "admin"
      }
    ];

    renderWithShell("/campaigns");

    await waitFor(() => {
      expect(screen.getAllByText("AD Lab Pivot").length).toBeGreaterThanOrEqual(1);
    });

    // Go to Scope tab and delete the last campaign
    fireEvent.click(screen.getByRole("tab", { name: "Scope" }));
    const picker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    fireEvent.change(picker, { target: { value: "camp-002" } });

    const deleteBtn = screen.getByRole("button", { name: "Delete" });
    await act(async () => {
      fireEvent.click(deleteBtn);
    });

    await waitFor(() => {
      expect(api.deleteCampaign).toHaveBeenCalledWith("camp-002");
    });

    // In List tab, the empty state message should now appear
    await waitFor(() => {
      expect(screen.getByText(/No campaigns yet/i)).toBeInTheDocument();
    });

    // Sidebar badge should be gone
    const badge = Array.from(document.querySelectorAll(".nav-count-badge")).find(
      (el) => el.closest("a")?.getAttribute("href") === "/campaigns"
    );
    expect(badge).toBeUndefined();
  });
});
