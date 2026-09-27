// @vitest-environment jsdom
import "../../test/setup";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "admin", role: "team_lead" },
    loading: false,
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

let mockCampaigns = [
  {
    id: "camp-alpha",
    name: "Alpha Operation",
    client: "CyberDyne",
    status: "created",
    noise_profile: "stealth",
    operator: "admin",
    targets: ["10.0.0.1"]
  }
];

let mockReports = [
  {
    filename: "ares-report-alpha-2026.pdf",
    format: "pdf",
    size_bytes: 1048576,
    modified_at: 1774000000
  },
  {
    filename: "ares-report-alpha-2026.html",
    format: "html",
    size_bytes: 524288,
    modified_at: 1774000100
  }
];

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
        mockCampaigns = mockCampaigns.filter((c) => c.id !== id);
        return { status: "deleted", campaign_id: id };
      }),
      modules: vi.fn(async () => []),
      templates: vi.fn(async () => []),
      reports: vi.fn(async (id: string) => ({
        campaign_id: id,
        reports: id === "camp-alpha" ? [...mockReports] : []
      })),
      generateReport: vi.fn(async () => ({ status: "generated", filename: "test.html" })),
      deleteReport: vi.fn(async (campId: string, filename: string) => {
        mockReports = mockReports.filter((r) => r.filename !== filename);
        return { status: "deleted" };
      }),
      clearReports: vi.fn(async () => {
        mockReports = [];
        return { status: "cleared" };
      }),
      downloadReport: vi.fn(async () => new Blob(["test"])),
      monthlyStats: vi.fn(async () => ({ total: 0, confirmed_findings: 0, series: [] })),
      activeStrategy: vi.fn(async () => ({ active: false, llm_backends: { claude: true, openai: true, local: false } })),
      findings: vi.fn(async () => []),
      cvss: vi.fn(async () => ({})),
      diffCampaign: vi.fn(async () => ({})),
      executionChains: vi.fn(async () => []),
      restoreVault: vi.fn(async () => ({ restored: 0 })),
      executeWorkflow: vi.fn(async () => ({ status: "executed" })),
      createCampaign: vi.fn(async (data: any) => ({ ...data, id: "new-camp" }))
    }
  };
});

import { api } from "../../api/client";
import { clearDashboardSession } from "./dashboardUiState";
import { CampaignsPage, DashboardShell, ReportsPage } from "./DashboardPages";

function renderWithProviders(element: React.ReactNode, initialPath = "/") {
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
      <MemoryRouter initialEntries={[initialPath]}>
        <DashboardShell>
          <Routes>
            <Route path="/campaigns" element={element} />
            <Route path="/reports" element={element} />
          </Routes>
        </DashboardShell>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Item 7: Destructive Action ConfirmModal Consistency", () => {
  let confirmSpy: any;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearDashboardSession();
    vi.clearAllMocks();
    confirmSpy = vi.spyOn(window, "confirm");

    mockCampaigns = [
      {
        id: "camp-alpha",
        name: "Alpha Operation",
        client: "CyberDyne",
        status: "created",
        noise_profile: "stealth",
        operator: "admin",
        targets: ["10.0.0.1"]
      }
    ];

    mockReports = [
      {
        filename: "ares-report-alpha-2026.pdf",
        format: "pdf",
        size_bytes: 1048576,
        modified_at: 1774000000
      },
      {
        filename: "ares-report-alpha-2026.html",
        format: "html",
        size_bytes: 524288,
        modified_at: 1774000100
      }
    ];
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  describe("CampaignsPage Delete Confirmation", () => {
    it("opens ConfirmModal with specific title and description when Delete is clicked, cancel does nothing", async () => {
      renderWithProviders(<CampaignsPage />, "/campaigns");

      // Wait for initial load
      await waitFor(() => {
        expect(screen.getAllByText("Alpha Operation").length).toBeGreaterThanOrEqual(1);
      });

      // Switch to Scope tab
      fireEvent.click(screen.getByRole("tab", { name: "Scope" }));

      // Select target campaign
      const picker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      expect(picker).toBeInTheDocument();
      fireEvent.change(picker, { target: { value: "camp-alpha" } });

      const deleteBtn = screen.getByRole("button", { name: "Delete" });
      expect(deleteBtn).not.toBeDisabled();

      // Click Delete
      await act(async () => {
        fireEvent.click(deleteBtn);
      });

      // ConfirmModal should be visible
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Delete Campaign" })).toBeInTheDocument();
      expect(
        screen.getByText(
          "Permanently delete this campaign and all its stored findings, hosts, credentials, and loot artifacts. This action cannot be undone."
        )
      ).toBeInTheDocument();

      // Click Cancel
      const cancelBtn = screen.getByRole("button", { name: "Cancel" });
      await act(async () => {
        fireEvent.click(cancelBtn);
      });

      // Modal closed, backend NOT called, window.confirm NEVER called
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.deleteCampaign).not.toHaveBeenCalled();
      expect(confirmSpy).not.toHaveBeenCalled();
    });

    it("confirms campaign deletion in ConfirmModal and executes deleteCampaign", async () => {
      renderWithProviders(<CampaignsPage />, "/campaigns");

      // Wait for initial load
      await waitFor(() => {
        expect(screen.getAllByText("Alpha Operation").length).toBeGreaterThanOrEqual(1);
      });

      // Switch to Scope tab
      fireEvent.click(screen.getByRole("tab", { name: "Scope" }));

      const picker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      fireEvent.change(picker, { target: { value: "camp-alpha" } });

      const deleteBtn = screen.getByRole("button", { name: "Delete" });
      expect(deleteBtn).not.toBeDisabled();

      await act(async () => {
        fireEvent.click(deleteBtn);
      });

      // Click the Confirm button in the modal
      const modalConfirmBtn = screen.getByRole("button", { name: "Delete Campaign" });
      await act(async () => {
        fireEvent.click(modalConfirmBtn);
      });

      // Backend called with camp-alpha, window.confirm NEVER called
      await waitFor(() => {
        expect(api.deleteCampaign).toHaveBeenCalledWith("camp-alpha");
      });
      expect(confirmSpy).not.toHaveBeenCalled();
    });
  });

  describe("ReportsPage Delete Confirmation", () => {
    it("opens ConfirmModal for single report deletion, cancel aborts, confirm executes deleteReport", async () => {
      // Set active campaign in storage
      sessionStorage.setItem("ares.dashboard.selectedCampaignId", JSON.stringify("camp-alpha"));
      renderWithProviders(<ReportsPage />, "/reports?tab=Library");

      // Wait for reports table to load
      await waitFor(() => {
        expect(screen.getByText("ares-report-alpha-2026.pdf")).toBeInTheDocument();
      });

      // Get delete buttons in the table
      const deleteButtons = screen.getAllByRole("button", { name: "Delete" });
      expect(deleteButtons.length).toBe(2);

      // Click Delete on first report
      await act(async () => {
        fireEvent.click(deleteButtons[0]);
      });

      // ConfirmModal should be visible with specific description
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Delete Report" })).toBeInTheDocument();
      expect(
        screen.getByText(
          'Permanently delete report artifact "ares-report-alpha-2026.pdf". This action cannot be undone.'
        )
      ).toBeInTheDocument();

      // Click Cancel first
      const cancelBtn = screen.getByRole("button", { name: "Cancel" });
      await act(async () => {
        fireEvent.click(cancelBtn);
      });
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.deleteReport).not.toHaveBeenCalled();

      // Open modal again and confirm
      await act(async () => {
        fireEvent.click(deleteButtons[0]);
      });
      const confirmModalBtn = screen.getByRole("button", { name: "Delete Report" });
      await act(async () => {
        fireEvent.click(confirmModalBtn);
      });

      await waitFor(() => {
        expect(api.deleteReport).toHaveBeenCalledWith("camp-alpha", "ares-report-alpha-2026.pdf");
      });
      expect(confirmSpy).not.toHaveBeenCalled();
    });

    it("opens ConfirmModal for 'Delete all' reports, cancel aborts, confirm executes clearReports", async () => {
      sessionStorage.setItem("ares.dashboard.selectedCampaignId", JSON.stringify("camp-alpha"));
      renderWithProviders(<ReportsPage />, "/reports?tab=Library");

      await waitFor(() => {
        expect(screen.getByRole("button", { name: "Delete all" })).toBeInTheDocument();
      });

      const deleteAllBtn = screen.getByRole("button", { name: "Delete all" });
      await act(async () => {
        fireEvent.click(deleteAllBtn);
      });

      // ConfirmModal should be open with count
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Delete All Reports" })).toBeInTheDocument();
      expect(
        screen.getByText(
          "Permanently delete all 2 report artifacts for this campaign. This action cannot be undone."
        )
      ).toBeInTheDocument();

      // Cancel test
      const cancelBtn = screen.getByRole("button", { name: "Cancel" });
      await act(async () => {
        fireEvent.click(cancelBtn);
      });
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.clearReports).not.toHaveBeenCalled();

      // Open and confirm
      await act(async () => {
        fireEvent.click(deleteAllBtn);
      });
      const confirmAllBtn = screen.getByRole("button", { name: "Delete All Reports" });
      await act(async () => {
        fireEvent.click(confirmAllBtn);
      });

      await waitFor(() => {
        expect(api.clearReports).toHaveBeenCalledWith("camp-alpha");
      });
      expect(confirmSpy).not.toHaveBeenCalled();
    });
  });
});
