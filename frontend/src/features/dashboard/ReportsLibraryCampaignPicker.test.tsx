// @vitest-environment jsdom
import "../../test/setup";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { Campaign } from "../../api/types";

const mockCampaigns: Campaign[] = [
  {
    id: "cmp-alpha",
    name: "Operation Alpha",
    target: "10.0.0.1",
    status: "active",
    created_at: "2026-03-01T00:00:00Z"
  } as unknown as Campaign,
  {
    id: "cmp-beta",
    name: "Operation Beta",
    target: "10.0.0.2",
    status: "completed",
    created_at: "2026-03-02T00:00:00Z"
  } as unknown as Campaign
];

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "operator", role: "operator" },
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
      campaigns: vi.fn(async () => mockCampaigns),
      campaign: vi.fn(async (id: string) => mockCampaigns.find((c) => c.id === id) ?? null),
      modules: vi.fn(async () => []),
      templates: vi.fn(async () => []),
      reports: vi.fn(async (id: string) => {
        if (id === "cmp-alpha") {
          return {
            campaign_id: "cmp-alpha",
            reports: [
              {
                filename: "ares-report-alpha.html",
                format: "html",
                size_bytes: 1048576,
                modified_at: "2026-03-01T12:00:00Z"
              }
            ]
          };
        }
        if (id === "cmp-beta") {
          return {
            campaign_id: "cmp-beta",
            reports: [
              {
                filename: "ares-report-beta.pdf",
                format: "pdf",
                size_bytes: 2097152,
                modified_at: "2026-03-02T12:00:00Z"
              }
            ]
          };
        }
        return { campaign_id: id, reports: [] };
      }),
      deleteReport: vi.fn(async () => ({})),
      clearReports: vi.fn(async () => ({})),
      generateReport: vi.fn(async () => ({ status: "generated", filename: "test.html" })),
      downloadReport: vi.fn(async () => new Blob(["test"]))
    }
  };
});

import { clearDashboardSession } from "./dashboardUiState";
import { DashboardShell, ReportsPage } from "./DashboardPages";

function renderReportsPage() {
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
      <MemoryRouter initialEntries={["/reports"]}>
        <DashboardShell>
          <Routes>
            <Route path="/reports" element={<ReportsPage />} />
          </Routes>
        </DashboardShell>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ReportsPage Library Tab CampaignPicker (REP-01)", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearDashboardSession();
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders CampaignPicker above 'Select a campaign to list reports.' when no campaign is selected", async () => {
    renderReportsPage();

    // Switch to Library tab
    const libraryTabBtn = screen.getByRole("tab", { name: "Library" });
    fireEvent.click(libraryTabBtn);

    // Verify CampaignPicker is visible in the Library tab
    await waitFor(() => {
      const picker = screen.getByLabelText("Target Campaign");
      expect(picker).toBeInTheDocument();
      expect(picker).toHaveAttribute("id", "library-campaign-select");
    });

    // Verify empty state message is shown
    expect(screen.getByText("Select a campaign to list reports.")).toBeInTheDocument();
  });

  it("selecting a campaign in Library tab lists reports and hides the empty message", async () => {
    renderReportsPage();

    const libraryTabBtn = screen.getByRole("tab", { name: "Library" });
    fireEvent.click(libraryTabBtn);

    await waitFor(() => {
      expect(screen.getAllByText("Operation Alpha").length).toBeGreaterThanOrEqual(1);
    });

    const picker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    fireEvent.change(picker, { target: { value: "cmp-alpha" } });

    // Reports for cmp-alpha should appear and empty state should disappear
    await waitFor(() => {
      expect(screen.getByText("ares-report-alpha.html")).toBeInTheDocument();
    });

    expect(screen.queryByText("Select a campaign to list reports.")).not.toBeInTheDocument();
  });

  it("synchronizes campaign selection between Library and Generate tabs bidirectionally", async () => {
    renderReportsPage();

    // 1. In Library tab, select cmp-alpha
    fireEvent.click(screen.getByRole("tab", { name: "Library" }));
    await waitFor(() => {
      expect(screen.getAllByText("Operation Alpha").length).toBeGreaterThanOrEqual(1);
    });

    const libraryPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    fireEvent.change(libraryPicker, { target: { value: "cmp-alpha" } });

    await waitFor(() => {
      expect(screen.getByText("ares-report-alpha.html")).toBeInTheDocument();
    });

    // 2. Switch to Generate tab -> cmp-alpha should already be selected
    fireEvent.click(screen.getByRole("tab", { name: "Generate" }));

    await waitFor(() => {
      const generatePicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      expect(generatePicker.id).toBe("report-campaign-select");
      expect(generatePicker.value).toBe("cmp-alpha");
    });

    // 3. In Generate tab, change selection to cmp-beta
    const generatePicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
    fireEvent.change(generatePicker, { target: { value: "cmp-beta" } });
    expect(generatePicker.value).toBe("cmp-beta");

    // 4. Switch back to Library tab -> cmp-beta should be selected and its report listed
    fireEvent.click(screen.getByRole("tab", { name: "Library" }));

    await waitFor(() => {
      const updatedLibraryPicker = screen.getByLabelText("Target Campaign") as HTMLSelectElement;
      expect(updatedLibraryPicker.id).toBe("library-campaign-select");
      expect(updatedLibraryPicker.value).toBe("cmp-beta");
      expect(screen.getByText("ares-report-beta.pdf")).toBeInTheDocument();
    });
  });
});
