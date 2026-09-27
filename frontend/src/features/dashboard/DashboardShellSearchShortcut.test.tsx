// @vitest-environment jsdom
import "../../test/setup";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual("../../api/client");
  return {
    ...actual,
    api: {
      health: vi.fn(async () => ({ status: "ok" })),
      telemetry: vi.fn(async () => ({})),
      campaigns: vi.fn(async () => []),
      modules: vi.fn(async () => []),
      templates: vi.fn(async () => []),
      reports: vi.fn(async () => ({ campaign_id: "", reports: [] }))
    }
  };
});

import { clearDashboardSession } from "./dashboardUiState";
import { DashboardShell } from "./DashboardPages";

function DummyContent() {
  return (
    <div>
      <h1>Test Page</h1>
      <input data-testid="form-input" placeholder="Type here" />
      <textarea data-testid="form-textarea" placeholder="Multi-line here" />
      <div data-testid="editable-div" contentEditable="true" suppressContentEditableWarning>Editable content</div>
    </div>
  );
}

function renderShell() {
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
      <MemoryRouter initialEntries={["/"]}>
        <DashboardShell>
          <Routes>
            <Route path="/" element={<DummyContent />} />
          </Routes>
        </DashboardShell>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("DashboardShell Global '/' Search Shortcut (SHL-01)", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearDashboardSession();
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("focuses search input and selects its text when '/' is pressed from page body", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;
    searchInput.value = "existing-query";
    expect(document.activeElement).not.toBe(searchInput);

    const selectSpy = vi.spyOn(searchInput, "select");

    // Press '/' on window/body
    fireEvent.keyDown(window, { key: "/" });

    expect(document.activeElement).toBe(searchInput);
    expect(selectSpy).toHaveBeenCalled();
  });

  it("does not focus search bar when '/' is typed inside an input element", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;
    const formInput = screen.getByTestId("form-input") as HTMLInputElement;

    formInput.focus();
    expect(document.activeElement).toBe(formInput);

    const defaultPrevented = !fireEvent.keyDown(formInput, { key: "/" });

    expect(document.activeElement).toBe(formInput);
    expect(document.activeElement).not.toBe(searchInput);
    expect(defaultPrevented).toBe(false);
  });

  it("does not focus search bar when '/' is typed inside a textarea", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;
    const textarea = screen.getByTestId("form-textarea") as HTMLTextAreaElement;

    textarea.focus();
    expect(document.activeElement).toBe(textarea);

    const defaultPrevented = !fireEvent.keyDown(textarea, { key: "/" });

    expect(document.activeElement).toBe(textarea);
    expect(document.activeElement).not.toBe(searchInput);
    expect(defaultPrevented).toBe(false);
  });

  it("does not focus search bar when '/' is typed inside a contentEditable element", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;
    const editableDiv = screen.getByTestId("editable-div");

    editableDiv.focus();

    const defaultPrevented = !fireEvent.keyDown(editableDiv, { key: "/" });

    expect(document.activeElement).not.toBe(searchInput);
    expect(defaultPrevented).toBe(false);
  });

  it("ignores modifier keys like Ctrl+'/', Alt+'/', or Meta+'/'", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;

    // Ctrl + /
    fireEvent.keyDown(window, { key: "/", ctrlKey: true });
    expect(document.activeElement).not.toBe(searchInput);

    // Alt + /
    fireEvent.keyDown(window, { key: "/", altKey: true });
    expect(document.activeElement).not.toBe(searchInput);

    // Meta + /
    fireEvent.keyDown(window, { key: "/", metaKey: true });
    expect(document.activeElement).not.toBe(searchInput);
  });

  it("loses focus when Escape is pressed while focused on search input", () => {
    renderShell();

    const searchInput = screen.getByLabelText("Search dashboard") as HTMLInputElement;

    // Focus via shortcut
    fireEvent.keyDown(window, { key: "/" });
    expect(document.activeElement).toBe(searchInput);

    // Press Escape
    fireEvent.keyDown(searchInput, { key: "Escape" });
    expect(document.activeElement).not.toBe(searchInput);
  });
});
