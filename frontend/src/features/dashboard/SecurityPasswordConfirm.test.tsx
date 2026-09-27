// @vitest-environment jsdom
import "../../test/setup";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { SecurityPage } from "./DashboardPages";

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    user: { username: "admin", role: "team_lead" },
    loading: false,
    logout: vi.fn(),
    logoutAll: vi.fn()
  })
}));

describe("SecurityPage Password Confirmation (SEC-02)", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false }
      }
    });
  });

  afterEach(() => {
    cleanup();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  function renderPage() {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/security?tab=Account"]}>
          <SecurityPage />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it("renders 3 password fields: current, new, and confirm new password", () => {
    renderPage();

    expect(screen.getByPlaceholderText("Current password")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("New password")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Confirm new password")).toBeInTheDocument();
  });

  it("disables submit button and shows no error on initial load when fields are empty", () => {
    renderPage();

    const submitBtn = screen.getByRole("button", { name: "Change Password" });
    expect(submitBtn).toBeDisabled();
    expect(screen.queryByText("Passwords do not match")).toBeNull();
  });

  it("shows inline error and disables submit when passwords do not match", () => {
    renderPage();

    const currentInput = screen.getByPlaceholderText("Current password");
    const newInput = screen.getByPlaceholderText("New password");
    const confirmInput = screen.getByPlaceholderText("Confirm new password");
    const submitBtn = screen.getByRole("button", { name: "Change Password" });

    fireEvent.change(currentInput, { target: { value: "oldsecret12345" } });
    fireEvent.change(newInput, { target: { value: "newsecret12345" } });
    fireEvent.change(confirmInput, { target: { value: "mismatch12345" } });

    expect(screen.getByRole("alert")).toHaveTextContent("Passwords do not match");
    expect(confirmInput.className).toContain("border-rose-500");
    expect(submitBtn).toBeDisabled();
  });

  it("clears inline error and enables submit when passwords match", () => {
    renderPage();

    const currentInput = screen.getByPlaceholderText("Current password");
    const newInput = screen.getByPlaceholderText("New password");
    const confirmInput = screen.getByPlaceholderText("Confirm new password");
    const submitBtn = screen.getByRole("button", { name: "Change Password" });

    fireEvent.change(currentInput, { target: { value: "oldsecret12345" } });
    fireEvent.change(newInput, { target: { value: "newsecret12345" } });
    fireEvent.change(confirmInput, { target: { value: "newsecret12345" } });

    expect(screen.queryByText("Passwords do not match")).toBeNull();
    expect(confirmInput.className).not.toContain("border-rose-500");
    expect(submitBtn).not.toBeDisabled();
  });

  it("submits changePassword with current_password and new_password without payload alteration", async () => {
    const changeSpy = vi.spyOn(api, "changePassword").mockResolvedValue({
      status: "ok",
      message: "Password changed successfully"
    });

    renderPage();

    const currentInput = screen.getByPlaceholderText("Current password");
    const newInput = screen.getByPlaceholderText("New password");
    const confirmInput = screen.getByPlaceholderText("Confirm new password");
    const submitBtn = screen.getByRole("button", { name: "Change Password" });

    fireEvent.change(currentInput, { target: { value: "currentPass123!" } });
    fireEvent.change(newInput, { target: { value: "newSecurePass123!" } });
    fireEvent.change(confirmInput, { target: { value: "newSecurePass123!" } });

    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(changeSpy).toHaveBeenCalledWith({
        current_password: "currentPass123!",
        new_password: "newSecurePass123!"
      });
    });

    // On success, fields should be reset
    await waitFor(() => {
      expect(currentInput).toHaveValue("");
      expect(newInput).toHaveValue("");
      expect(confirmInput).toHaveValue("");
    });
  });
});
