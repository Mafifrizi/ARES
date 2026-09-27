import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation, useNavigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  CampaignsPage,
  ModulesPage,
  ReportsPage,
  TemplatesPage,
  StrategyPage,
  SecurityPage,
  EdrPage,
  LivePage
} from "./DashboardPages";
import { DashboardUiProvider } from "./dashboardUi";
import type { DashboardUiState } from "./dashboardUiState";

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      campaigns: vi.fn().mockResolvedValue([
        { id: "camp-123", name: "Alpha", client: "SecOps", targets: ["10.0.0.1"], scope_cidrs: ["10.0.0.0/24"], noise_profile: "stealth" }
      ]),
      campaign: vi.fn().mockResolvedValue({ id: "camp-123", name: "Alpha", client: "SecOps", targets: ["10.0.0.1"], scope_cidrs: ["10.0.0.0/24"], noise_profile: "stealth" }),
      findings: vi.fn().mockResolvedValue([]),
      cvss: vi.fn().mockResolvedValue([]),
      diffCampaign: vi.fn().mockResolvedValue({}),
      modules: vi.fn().mockResolvedValue([
        { id: "recon.fingerprint", name: "Recon", description: "Fingerprint target", category: "recon", opsec_level: "LOW" },
        { id: "ad.kerberoast", name: "Kerberoast", description: "Request TGS", category: "ad", opsec_level: "MEDIUM" }
      ]),
      executionChains: vi.fn().mockResolvedValue([]),
      reports: vi.fn().mockResolvedValue({ reports: [{ filename: "audit.html", format: "html" }] }),
      templates: vi.fn().mockResolvedValue([{ id: "tpl-1", name: "Standard Recon", description: "Default recon plan", stages: 2, modules: 4 }]),
      activeStrategy: vi.fn().mockResolvedValue({ llm_backends: { claude: true, local: true } }),
      apiKeys: vi.fn().mockResolvedValue({ keys: [{ id: "key-1", name: "CI Key", prefix: "ares_ci", created_at: "2026-01-01" }] }),
      securityAudit: vi.fn().mockResolvedValue({ events: [] }),
      users: vi.fn().mockResolvedValue([]),
      edrStats: vi.fn().mockResolvedValue({ message: "Ready", success_rate: 0.9 }),
      liveEvents: vi.fn().mockResolvedValue([])
    }
  };
});

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "operator", role: "team_lead" },
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

const mockDashboardUi: DashboardUiState = {
  selectedCampaignId: "camp-123",
  setSelectedCampaignId: vi.fn(),
  liveCampaignId: "camp-123",
  setLiveCampaignId: vi.fn(),
  liveConnected: true,
  setLiveConnected: vi.fn(),
  liveEvents: [],
  pushLiveEvent: vi.fn(),
  clearLiveEvents: vi.fn(),
  campaigns: [
    { id: "camp-123", name: "Alpha", client: "SecOps", targets: ["10.0.0.1"], scope_cidrs: ["10.0.0.0/24"], noise_profile: "stealth" }
  ],
  campaignsLoading: false,
  campaignsError: null,
  deleteCampaign: vi.fn().mockResolvedValue(true),
  isDeletingCampaign: false,
  refetchCampaigns: vi.fn().mockResolvedValue(undefined)
};

// Helper component that displays the current URL search query for assertions
function UrlTracker() {
  const location = useLocation();
  return <div data-testid="url-tracker">{`${location.pathname}${location.search}`}</div>;
}

describe("Tab Navigation URL Synchronization (Item 6)", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: 0 }
      }
    });
    queryClient.setQueryData(["modules"], [
      { id: "recon.fingerprint", name: "Recon", description: "Fingerprint target", category: "recon", opsec_level: "LOW" },
      { id: "ad.kerberoast", name: "Kerberoast", description: "Request TGS", category: "ad", opsec_level: "MEDIUM" }
    ]);
    queryClient.setQueryData(["campaign", "camp-123"], {
      id: "camp-123", name: "Alpha", client: "SecOps", targets: ["10.0.0.1"], scope_cidrs: ["10.0.0.0/24"], noise_profile: "stealth"
    });
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("syncs /campaigns to URL /campaigns?tab=List on mount", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/campaigns"]}>
            <UrlTracker />
            <Routes>
              <Route path="/campaigns" element={<CampaignsPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/campaigns?tab=List");
    });
  });

  it("updates URL to /campaigns?tab=Scope when clicking Scope tab", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/campaigns?tab=List"]}>
            <UrlTracker />
            <Routes>
              <Route path="/campaigns" element={<CampaignsPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    const scopeTabBtn = screen.getByRole("tab", { name: "Scope" });
    fireEvent.click(scopeTabBtn);

    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/campaigns?tab=Scope");
    });
  });

  it("activates API Keys tab directly when opening /security?tab=API+Keys", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/security?tab=API+Keys"]}>
            <UrlTracker />
            <Routes>
              <Route path="/security" element={<SecurityPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    const apiKeyTab = screen.getByRole("tab", { name: "API Keys" });
    expect(apiKeyTab.classList.contains("active")).toBe(true);
    expect(screen.getByRole("heading", { name: "API Keys" })).toBeDefined();
  });

  it("activates Users tab directly when opening /security?tab=Users", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/security?tab=Users"]}>
            <UrlTracker />
            <Routes>
              <Route path="/security" element={<SecurityPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    const usersTab = screen.getByRole("tab", { name: "Users" });
    expect(usersTab.classList.contains("active")).toBe(true);
    expect(screen.getByRole("heading", { name: "Platform Users" })).toBeDefined();
  });

  it("falls back to default List tab when opening /campaigns?tab=xyz without crashing", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/campaigns?tab=xyz"]}>
            <UrlTracker />
            <Routes>
              <Route path="/campaigns" element={<CampaignsPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    const listTab = screen.getByRole("tab", { name: "List" });
    expect(listTab.classList.contains("active")).toBe(true);
    expect(screen.getByRole("heading", { name: "Create Campaign" })).toBeDefined();
  });

  it("activates Run Panel and selects module when opening /modules?tab=Run+Panel&module=recon.fingerprint", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/modules?tab=Run+Panel&module=recon.fingerprint"]}>
            <UrlTracker />
            <Routes>
              <Route path="/modules" element={<ModulesPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    // Run Panel tab should be active
    const runPanelTab = screen.getByRole("tab", { name: "Run Panel" });
    expect(runPanelTab.classList.contains("active")).toBe(true);

    // Module should be selected
    await waitFor(() => {
      expect(screen.getByText("recon.fingerprint")).toBeDefined();
    });
  });

  it("synchronizes ReportsPage default tab to /reports?tab=Generate", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/reports"]}>
            <UrlTracker />
            <Routes>
              <Route path="/reports" element={<ReportsPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/reports?tab=Generate");
    });
  });

  it("synchronizes TemplatesPage default tab to /templates?tab=Templates", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/templates"]}>
            <UrlTracker />
            <Routes>
              <Route path="/templates" element={<TemplatesPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/templates?tab=Templates");
    });
  });

  it("synchronizes StrategyPage default tab to /strategy?tab=Objective", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/strategy"]}>
            <UrlTracker />
            <Routes>
              <Route path="/strategy" element={<StrategyPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/strategy?tab=Objective");
    });
  });

  it("synchronizes EdrPage default tab to /edr?tab=Knowledge+Base", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/edr"]}>
            <UrlTracker />
            <Routes>
              <Route path="/edr" element={<EdrPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/edr?tab=Knowledge+Base");
    });
  });

  it("synchronizes LivePage default tab to /live?tab=Stream", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/live"]}>
            <UrlTracker />
            <Routes>
              <Route path="/live" element={<LivePage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/live?tab=Stream");
    });
  });

  it("does not accumulate browser history entries when switching tabs due to replace: true", async () => {
    function BackButton() {
      const nav = useNavigate();
      return (
        <button data-testid="back-btn" onClick={() => nav(-1)}>
          Back
        </button>
      );
    }

    render(
      <QueryClientProvider client={queryClient}>
        <DashboardUiProvider value={mockDashboardUi}>
          <MemoryRouter initialEntries={["/modules?tab=Catalog", "/campaigns?tab=List"]} initialIndex={1}>
            <BackButton />
            <UrlTracker />
            <Routes>
              <Route path="/campaigns" element={<CampaignsPage />} />
              <Route path="/modules" element={<ModulesPage />} />
            </Routes>
          </MemoryRouter>
        </DashboardUiProvider>
      </QueryClientProvider>
    );

    // Switch to Scope tab (replace: true)
    const scopeTab = screen.getByRole("tab", { name: "Scope" });
    fireEvent.click(scopeTab);
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/campaigns?tab=Scope");
    });

    // Switch to Findings tab (replace: true)
    const findingsTab = screen.getByRole("tab", { name: "Findings" });
    fireEvent.click(findingsTab);
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/campaigns?tab=Findings");
    });

    // Now click Back — because replace: true was used on both tab changes, Back goes to the previous route (/modules?tab=Catalog)
    fireEvent.click(screen.getByTestId("back-btn"));
    await waitFor(() => {
      expect(screen.getByTestId("url-tracker").textContent).toBe("/modules?tab=Catalog");
    });
  });
});
