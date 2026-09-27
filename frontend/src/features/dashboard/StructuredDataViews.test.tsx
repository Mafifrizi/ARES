// @vitest-environment jsdom
import "../../test/setup";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { DashboardUiProvider } from "./dashboardUi";
import type { DashboardUiState } from "./dashboardUiState";
import {
  CampaignsPage,
  EdrPage,
  SecurityPage,
  StrategyPage
} from "./DashboardPages";

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "admin", role: "team_lead" },
    loading: false,
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

describe("Item 8: Structured Data Views (No Raw JSON Dump)", () => {
  let queryClient: QueryClient;

  const mockCampaign = {
    id: "camp-structured-01",
    name: "Operation Citadel",
    client: "Internal Red Team",
    operator: "lead_operator",
    status: "active",
    noise_profile: "stealth",
    targets: ["10.0.1.10", "10.0.1.20"],
    scope_cidrs: ["10.0.1.0/24", "192.168.100.0/24"],
    excluded_hosts: ["10.0.1.254", "192.168.100.1"],
    created_at: "2026-09-28T00:00:00Z"
  };

  const mockUi: DashboardUiState = {
    selectedCampaignId: "camp-structured-01",
    setSelectedCampaignId: vi.fn(),
    liveCampaignId: "camp-structured-01",
    setLiveCampaignId: vi.fn(),
    liveConnected: true,
    setLiveConnected: vi.fn(),
    liveEvents: [],
    pushLiveEvent: vi.fn(),
    clearLiveEvents: vi.fn(),
    campaigns: [mockCampaign],
    campaignsLoading: false,
    campaignsError: null,
    deleteCampaign: vi.fn().mockResolvedValue(true),
    isDeletingCampaign: false,
    refetchCampaigns: vi.fn().mockResolvedValue(undefined)
  };

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false }
      }
    });

    vi.spyOn(api, "campaigns").mockResolvedValue([mockCampaign]);
    vi.spyOn(api, "campaign").mockResolvedValue(mockCampaign);
    vi.spyOn(api, "findings").mockResolvedValue([]);
    vi.spyOn(api, "cvss").mockResolvedValue({});
    vi.spyOn(api, "apiKeys").mockResolvedValue([]);
    vi.spyOn(api, "activeStrategy").mockResolvedValue({
      count: 1,
      max_allowed: 2,
      slots_available: 1,
      active_engagements: { eng1: { status: "running" } },
      llm_backends: { claude: true, openai: false, local: true }
    });
    vi.spyOn(api, "securityAudit").mockResolvedValue({
      events: [
        {
          id: "evt-1",
          timestamp: "2026-09-28T01:00:00Z",
          actor: "lead_operator",
          action: "campaign_scope_update",
          resource: "Operation Citadel",
          status: "success"
        },
        {
          id: "evt-2",
          timestamp: "2026-09-28T02:00:00Z",
          actor: "auth-system",
          action: "token_issued",
          resource: "api_key",
          status: "logged"
        }
      ]
    });
    vi.spyOn(api, "users").mockResolvedValue([
      {
        id: "usr-1",
        username: "admin",
        role: "team_lead",
        is_active: true,
        last_login: "2026-09-28T03:00:00Z"
      },
      {
        id: "usr-2",
        username: "operator_bob",
        role: "operator",
        is_active: false,
        last_login: null
      }
    ]);
    vi.spyOn(api, "edrStats").mockResolvedValue({
      technique_id: "amsi-patch-reflection",
      edr_vendor: "defender_atp",
      success_rate: 0.85,
      message: "Historical rate for amsi-patch-reflection vs defender_atp: 85%",
      stats: [
        {
          technique_id: "amsi-patch-reflection",
          edr_vendor: "defender_atp",
          success_rate: 0.85,
          sample_count: 12
        }
      ]
    });
  });

  afterEach(() => {
    cleanup();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  describe("Campaigns Scope Tab", () => {
    it("renders IP ranges, targets, and excluded hosts as structured badges, not raw JSON dump", async () => {
      render(
        <QueryClientProvider client={queryClient}>
          <DashboardUiProvider value={mockUi}>
            <MemoryRouter initialEntries={["/campaigns?tab=Scope"]}>
              <CampaignsPage />
            </MemoryRouter>
          </DashboardUiProvider>
        </QueryClientProvider>
      );

      // Verify structured badges are present
      await waitFor(() => {
        expect(screen.getByText("10.0.1.0/24")).toBeInTheDocument();
        expect(screen.getByText("192.168.100.0/24")).toBeInTheDocument();
      });

      expect(screen.getByText("10.0.1.10")).toBeInTheDocument();
      expect(screen.getByText("10.0.1.254")).toBeInTheDocument();
      expect(screen.getByText("192.168.100.1")).toBeInTheDocument();

      // Verify raw JSON viewer is not open by default
      const viewRawBtn = screen.getByRole("button", { name: /View Raw Scope JSON/i });
      expect(viewRawBtn).toBeInTheDocument();
      expect(screen.queryByText("Campaign Scope & Target Configuration")).toBeNull();

      // Clicking View Raw toggles JSON display
      fireEvent.click(viewRawBtn);
      expect(screen.getByText("Campaign Scope & Target Configuration")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Hide Raw Scope JSON/i })).toBeInTheDocument();
    });
  });

  describe("Strategy Active Tab", () => {
    it("renders step indicator / progress list of lifecycle stages and collapsible raw state", async () => {
      render(
        <QueryClientProvider client={queryClient}>
          <DashboardUiProvider value={mockUi}>
            <MemoryRouter initialEntries={["/strategy?tab=Active"]}>
              <StrategyPage />
            </MemoryRouter>
          </DashboardUiProvider>
        </QueryClientProvider>
      );

      // Verify lifecycle stages are displayed
      await waitFor(() => {
        expect(screen.getByText("Autonomous Engagement Lifecycle")).toBeInTheDocument();
      });

      expect(screen.getByText("Surface Discovery")).toBeInTheDocument();
      expect(screen.getByText("Defense Feasibility")).toBeInTheDocument();
      expect(screen.getByText("Credential Extraction")).toBeInTheDocument();
      expect(screen.getByText("Lateral Movement")).toBeInTheDocument();
      expect(screen.getByText("Domain Escalation")).toBeInTheDocument();

      // Concurrency slot info is structured
      expect(screen.getByText("Concurrency Slots")).toBeInTheDocument();
      expect(screen.getByText("1 / 2")).toBeInTheDocument();

      // Raw JSON view toggle
      const viewRawBtn = screen.getByRole("button", { name: /View Raw Active State/i });
      expect(viewRawBtn).toBeInTheDocument();
      expect(screen.queryByText("Active Strategy State")).toBeNull();

      fireEvent.click(viewRawBtn);
      expect(screen.getByText("Active Strategy State")).toBeInTheDocument();
    });
  });

  describe("Security Audit Tab & Users Tab", () => {
    it("renders Audit log table with Timestamp, Actor, Action, Resource, Status and sorting", async () => {
      render(
        <QueryClientProvider client={queryClient}>
          <DashboardUiProvider value={mockUi}>
            <MemoryRouter initialEntries={["/security?tab=Audit"]}>
              <SecurityPage />
            </MemoryRouter>
          </DashboardUiProvider>
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Security Audit Log" })).toBeInTheDocument();
        expect(screen.getByText("lead_operator")).toBeInTheDocument();
      });

      // Verify table headers
      expect(screen.getByText("Timestamp")).toBeInTheDocument();
      expect(screen.getByText("Actor")).toBeInTheDocument();
      expect(screen.getByText("Action")).toBeInTheDocument();
      expect(screen.getByText("Resource")).toBeInTheDocument();
      expect(screen.getByText("Status")).toBeInTheDocument();

      // Verify rows
      expect(screen.getByText("lead_operator")).toBeInTheDocument();
      expect(screen.getByText("campaign_scope_update")).toBeInTheDocument();
      expect(screen.getByText("Operation Citadel")).toBeInTheDocument();

      // Sorting toggle
      const sortBtn = screen.getByRole("button", { name: /Newest First/i });
      expect(sortBtn).toBeInTheDocument();
      fireEvent.click(sortBtn);
      expect(screen.getByRole("button", { name: /Oldest First/i })).toBeInTheDocument();

      // View Raw button
      const viewRawBtn = screen.getByRole("button", { name: /View Raw Audit JSON/i });
      expect(viewRawBtn).toBeInTheDocument();
      expect(screen.queryByText("Raw Audit Payload")).toBeNull();

      fireEvent.click(viewRawBtn);
      expect(screen.getByText("Raw Audit Payload")).toBeInTheDocument();
    });

    it("renders Users table with Username, Role badge, Last Active, and Status badge", async () => {
      render(
        <QueryClientProvider client={queryClient}>
          <DashboardUiProvider value={mockUi}>
            <MemoryRouter initialEntries={["/security?tab=Users"]}>
              <SecurityPage />
            </MemoryRouter>
          </DashboardUiProvider>
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Platform Users" })).toBeInTheDocument();
        expect(screen.getByText("operator_bob")).toBeInTheDocument();
      });

      // Verify table headers
      expect(screen.getByText("Username")).toBeInTheDocument();
      expect(screen.getByText("Role")).toBeInTheDocument();
      expect(screen.getByText("Last Active")).toBeInTheDocument();
      expect(screen.getByText("Status")).toBeInTheDocument();

      // Verify user rows and badges
      expect(screen.getByText("admin")).toBeInTheDocument();
      expect(screen.getAllByText("Team Lead").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("Active")).toBeInTheDocument();

      expect(screen.getByText("Operator")).toBeInTheDocument();
      expect(screen.getByText("Disabled")).toBeInTheDocument();
      expect(screen.getByText("Never")).toBeInTheDocument();

      // View Raw button
      const viewRawBtn = screen.getByRole("button", { name: /View Raw Users JSON/i });
      expect(viewRawBtn).toBeInTheDocument();
      expect(screen.queryByText("Raw User Records")).toBeNull();

      fireEvent.click(viewRawBtn);
      expect(screen.getByText("Raw User Records")).toBeInTheDocument();
    });
  });

  describe("EDR Stats Tab", () => {
    it("renders metric cards and historical technique records instead of raw JSON blob", async () => {
      render(
        <QueryClientProvider client={queryClient}>
          <DashboardUiProvider value={mockUi}>
            <MemoryRouter initialEntries={["/edr?tab=Knowledge+Base"]}>
              <EdrPage />
            </MemoryRouter>
          </DashboardUiProvider>
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Bypass Knowledge Base" })).toBeInTheDocument();
        expect(screen.getAllByText("amsi-patch-reflection").length).toBeGreaterThanOrEqual(1);
      });

      // Verify metric cards
      expect(screen.getByText("Technique Under Test")).toBeInTheDocument();
      expect(screen.getByText("Target EDR Vendor")).toBeInTheDocument();
      expect(screen.getAllByText("defender_atp").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("Historical Bypass Rate")).toBeInTheDocument();
      expect(screen.getAllByText("85%").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("High Evasion")).toBeInTheDocument();

      // Message banner
      expect(screen.getByText(/Historical rate for amsi-patch-reflection vs defender_atp: 85%/)).toBeInTheDocument();

      // Technique records table
      expect(screen.getByRole("heading", { name: "Historical Technique Records" })).toBeInTheDocument();

      // View Raw button
      const viewRawBtn = screen.getByRole("button", { name: /View Raw Stats JSON/i });
      expect(viewRawBtn).toBeInTheDocument();
      expect(screen.queryByText("Raw EDR Bypass Stats")).toBeNull();

      fireEvent.click(viewRawBtn);
      expect(screen.getByText("Raw EDR Bypass Stats")).toBeInTheDocument();
    });
  });
});
