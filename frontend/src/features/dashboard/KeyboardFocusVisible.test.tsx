// @vitest-environment jsdom
import "../../test/setup";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import fs from "node:fs";
import path from "node:path";

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
      campaigns: vi.fn(async () => [
        { id: "cmp-1", name: "Campaign 1", status: "active" }
      ]),
      modules: vi.fn(async () => []),
      templates: vi.fn(async () => []),
      executionChains: vi.fn(async () => []),
      reports: vi.fn(async () => ({ campaign_id: "", reports: [] })),
      monthlyStats: vi.fn(async () => ({ total: 0, confirmed_findings: 0, series: [] }))
    }
  };
});

import { clearDashboardSession } from "./dashboardUiState";
import { DashboardShell, OverviewPage } from "./DashboardPages";

describe("Keyboard Focus Visible & Accessibility (ITEM 9)", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearDashboardSession();
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("verifies styles.css contains the global focus-visible rules and ARES accent token", () => {
    const cssPath = path.resolve(__dirname, "../../styles.css");
    const cssContent = fs.readFileSync(cssPath, "utf-8");

    // 1. Accent color variable defined
    expect(cssContent).toMatch(/--ares-accent:\s*#b91c1c/i);

    // 2. Global *:focus outline: none reset
    expect(cssContent).toMatch(/\*:focus\s*\{\s*outline:\s*none;?\s*\}/);

    // 3. Global *:focus-visible rule with 2px accent outline, 2px offset, and 4px border-radius
    expect(cssContent).toMatch(
      /\*:focus-visible\s*\{[\s\S]*?outline:\s*2px\s+solid\s+var\(--ares-accent,\s*#b91c1c\);?[\s\S]*?outline-offset:\s*2px;?[\s\S]*?border-radius:\s*4px;?[\s\S]*?\}/
    );

    // 4. Input fields custom focus-visible preserved without weird 2px outer outline
    expect(cssContent).toMatch(
      /\.field:focus,\s*\.field:focus-visible,\s*\.field-with-icon:focus-within\s*\{[\s\S]*?border-color:\s*#52525b;?[\s\S]*?outline:\s*1px\s+solid\s+#52525b;?[\s\S]*?outline-offset:\s*0;?[\s\S]*?\}/
    );

    // 5. Input within wrapper has outline: none on focus-visible
    expect(cssContent).toMatch(/\.topbar-search input:focus-visible\s*\{\s*outline:\s*none;?\s*\}/);
    expect(cssContent).toMatch(/\.field-with-icon input:focus-visible\s*\{\s*outline:\s*none;?\s*\}/);
    expect(cssContent).toMatch(/\.topbar-scope-select:focus-visible\s*\{\s*outline:\s*none;?\s*\}/);

    // 6. Search results button has focus-visible companion
    expect(cssContent).toMatch(
      /\.search-results button:focus-visible\s*\{[\s\S]*?outline:\s*2px\s+solid\s+var\(--ares-accent,\s*#b91c1c\);?[\s\S]*?outline-offset:\s*-2px;?[\s\S]*?\}/
    );

    // 7. Component-specific border-radius overrides
    expect(cssContent).toMatch(/\.btn:focus-visible[\s\S]*?border-radius:\s*6px/);
    expect(cssContent).toMatch(/\.panel:focus-visible[\s\S]*?border-radius:\s*8px/);
    expect(cssContent).toMatch(/\.rounded-full:focus-visible[\s\S]*?border-radius:\s*999px/);
  });

  it("renders interactive elements in DashboardShell and supports keyboard focus navigation", async () => {
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

    // Topbar search input
    const searchInput = screen.getByPlaceholderText(/Search campaigns, modules, reports/i);
    expect(searchInput).toBeInTheDocument();

    // Focus via keyboard
    searchInput.focus();
    expect(document.activeElement).toBe(searchInput);

    // Topbar buttons
    const notifBtn = screen.getByLabelText("Notifications");
    expect(notifBtn).toBeInTheDocument();
    notifBtn.focus();
    expect(document.activeElement).toBe(notifBtn);

    // Mouse click on button should focus element without throwing or breaking
    fireEvent.mouseDown(notifBtn);
    fireEvent.click(notifBtn);
    expect(notifBtn).toBeInTheDocument();

    // Topbar scope select
    const scopeSelect = screen.getByLabelText("Active campaign scope");
    expect(scopeSelect).toBeInTheDocument();
    scopeSelect.focus();
    expect(document.activeElement).toBe(scopeSelect);

    // Navigation links in sidebar
    const navLinks = screen.getAllByRole("link");
    expect(navLinks.length).toBeGreaterThan(0);
    const firstLink = navLinks[0];
    firstLink.focus();
    expect(document.activeElement).toBe(firstLink);
  });
});
