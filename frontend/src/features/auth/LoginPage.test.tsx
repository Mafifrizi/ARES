import "../../test/setup";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LoginPage } from "./LoginPage";

const mockLogin = vi.fn();
let mockUser: { username: string; role?: string } | null = null;
const mockNavigate = vi.fn();
const mockInitiateSso = vi.fn();

vi.mock("./authContext", () => ({
  useAuth: () => ({
    login: mockLogin,
    user: mockUser,
    logout: vi.fn(),
    logoutAll: vi.fn(),
    token: null,
    isLoading: false,
    refreshTokens: vi.fn()
  })
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate
  };
});

vi.mock("../../api/client", () => ({
  initiateSso: (provider: string) => mockInitiateSso(provider)
}));

describe("LoginPage Integration Tests (AUD-009)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUser = null;
    mockLogin.mockResolvedValue(undefined);
    mockInitiateSso.mockResolvedValue({ redirect_url: "https://idp.example.com/login" });
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the sign-in form with header, inputs, and action buttons", () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    expect(screen.getByRole("heading", { name: "ARES Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sign In" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Username \/ Operator ID/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Password$/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Sign in$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /continue with SSO/i })).toBeInTheDocument();
  });

  it("toggles password visibility between masked and plaintext", () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    const passwordInput = screen.getByLabelText(/^Password$/i);
    expect(passwordInput).toHaveAttribute("type", "password");

    const toggleButton = screen.getByRole("button", { name: /show password/i });
    fireEvent.click(toggleButton);
    expect(passwordInput).toHaveAttribute("type", "text");

    const hideButton = screen.getByRole("button", { name: /hide password/i });
    fireEvent.click(hideButton);
    expect(passwordInput).toHaveAttribute("type", "password");
  });

  it("submits operator credentials and navigates on success", async () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    const usernameInput = screen.getByLabelText(/Username \/ Operator ID/i);
    const passwordInput = screen.getByLabelText(/^Password$/i);
    const submitBtn = screen.getByRole("button", { name: /^Sign in$/i });

    fireEvent.change(usernameInput, { target: { value: "operator-ares" } });
    fireEvent.change(passwordInput, { target: { value: "SuperSecretKey123!" } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith("operator-ares", "SuperSecretKey123!");
      expect(mockNavigate).toHaveBeenCalledWith("/", { replace: true });
    });
  });

  it("displays an error alert when authentication fails", async () => {
    mockLogin.mockRejectedValueOnce(new Error("Invalid operator credentials"));

    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    const usernameInput = screen.getByLabelText(/Username \/ Operator ID/i);
    const passwordInput = screen.getByLabelText(/^Password$/i);
    const submitBtn = screen.getByRole("button", { name: /^Sign in$/i });

    fireEvent.change(usernameInput, { target: { value: "operator-ares" } });
    fireEvent.change(passwordInput, { target: { value: "wrong-password" } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText("Invalid operator credentials")).toBeInTheDocument();
    });
  });

  it("handles SSO initiation and displays error notice if SSO is not configured", async () => {
    mockInitiateSso.mockRejectedValueOnce(new Error("SSO provider disabled"));

    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    const ssoButton = screen.getByRole("button", { name: /continue with SSO/i });
    fireEvent.click(ssoButton);

    await waitFor(() => {
      expect(mockInitiateSso).toHaveBeenCalledWith("default");
      expect(screen.getByText(/SSO is not configured for this organization/i)).toBeInTheDocument();
    });
  });

  it("redirects authenticated users away from login page", () => {
    mockUser = { username: "active-operator", role: "admin" };

    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    // If authenticated, LoginPage immediately returns <Navigate to="/" replace />
    expect(screen.queryByRole("heading", { name: "Sign In" })).not.toBeInTheDocument();
  });
});
