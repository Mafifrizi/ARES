// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DiscoveredSecretHit,
  DiscoveredSecretsEvidenceViewer,
  getPatternBadgeClass,
  maskSecret
} from "./DashboardPages";

describe("DiscoveredSecretsEvidenceViewer & Credential Helpers", () => {
  afterEach(() => {
    cleanup();
  });

  describe("maskSecret helper", () => {
    it("handles empty or very short strings safely", () => {
      expect(maskSecret("")).toBe("••••");
      expect(maskSecret("abc")).toBe("••••");
      expect(maskSecret("test")).toBe("••••");
    });

    it("masks medium credentials properly", () => {
      const masked = maskSecret("P@ss1234");
      expect(masked.startsWith("P@")).toBe(true);
      expect(masked.endsWith("4")).toBe(true);
      expect(masked.includes("••••")).toBe(true);
    });

    it("masks long tokens preserving boundary characters", () => {
      const masked = maskSecret("AKIAIOSFODNN7EXAMPLE");
      expect(masked.startsWith("AKI")).toBe(true);
      expect(masked.endsWith("PLE")).toBe(true);
      expect(masked.includes("••••••••")).toBe(true);
      expect(masked.includes("IOSFODNN7")).toBe(false);
    });
  });

  describe("getPatternBadgeClass helper", () => {
    it("assigns distinct colors per credential classification", () => {
      expect(getPatternBadgeClass("aws_access_key")).toContain("amber");
      expect(getPatternBadgeClass("connection_string")).toContain("cyan");
      expect(getPatternBadgeClass("password_field")).toContain("rose");
      expect(getPatternBadgeClass("generic_api_key")).toContain("purple");
      expect(getPatternBadgeClass("private_rsa_key")).toContain("emerald");
      expect(getPatternBadgeClass("custom_unclassified")).toContain("zinc");
    });
  });

  describe("DiscoveredSecretsEvidenceViewer component", () => {
    const mockHits: DiscoveredSecretHit[] = [
      {
        file: "C:\\inetpub\\wwwroot\\web.config",
        line: 42,
        pattern: "connection_string",
        snippet: "connectionString=\"Server=db01;Password=P@ss1234\"",
        extracted_secret: "Server=db01;Password=P@ss1234",
        secret_value: "P@ss1234",
        entropy: 3.78,
        confidence: 0.92,
        is_placeholder: false
      },
      {
        file: "C:\\Users\\svc_deploy\\.aws\\credentials",
        line: 3,
        pattern: "aws_access_key",
        snippet: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        extracted_secret: "AKIAIOSFODNN7EXAMPLE",
        secret_value: "AKIAIOSFODNN7EXAMPLE",
        entropy: 2.15,
        confidence: 0.40,
        is_placeholder: true
      }
    ];

    it("renders table with source files, entropy, and dynamic confidence", () => {
      render(<DiscoveredSecretsEvidenceViewer hits={mockHits} />);

      // Title & count
      expect(screen.getByText(/Discovered Secrets & Hardcoded Credentials \(2\)/)).not.toBeNull();
      expect(screen.getByText("LOOT EXTRACTED")).not.toBeNull();
      expect(screen.getByText("SAMPLE / TEST IDENTIFIED")).not.toBeNull();

      // Files & lines
      expect(screen.getByText(/web\.config/)).not.toBeNull();
      expect(screen.getByText(":42")).not.toBeNull();
      expect(screen.getByText(/\.aws\/credentials/)).not.toBeNull();
      expect(screen.getByText(":3")).not.toBeNull();

      // Entropy scores
      expect(screen.getByText("3.78")).not.toBeNull();
      expect(screen.getByText("2.15")).not.toBeNull();

      // Confidence badges
      expect(screen.getByText("92%")).not.toBeNull();
      expect(screen.getByText("40%")).not.toBeNull();

      // Placeholder pill
      expect(screen.getByText("Placeholder")).not.toBeNull();
    });

    it("masks secrets by default and toggles revelation on eye icon click", () => {
      render(<DiscoveredSecretsEvidenceViewer hits={mockHits} />);

      // By default secrets should be masked
      expect(screen.queryByText("P@ss1234")).toBeNull();
      expect(screen.queryByText("AKIAIOSFODNN7EXAMPLE")).toBeNull();

      // Click the first row's reveal button (title="Reveal full secret value")
      const revealButtons = screen.getAllByTitle("Reveal full secret value");
      expect(revealButtons.length).toBe(2);

      fireEvent.click(revealButtons[0]);

      // First secret should now be unmasked and visible
      expect(screen.getByText("P@ss1234")).not.toBeNull();
      // Second secret should remain masked
      expect(screen.queryByText("AKIAIOSFODNN7EXAMPLE")).toBeNull();
    });

    it("supports global Reveal All / Mask All action", () => {
      render(<DiscoveredSecretsEvidenceViewer hits={mockHits} />);

      const revealAllBtn = screen.getByTitle("Reveal all discovered secret values");
      expect(revealAllBtn).not.toBeNull();

      fireEvent.click(revealAllBtn);

      // Both secrets must be visible simultaneously
      expect(screen.getByText("P@ss1234")).not.toBeNull();
      expect(screen.getByText("AKIAIOSFODNN7EXAMPLE")).not.toBeNull();

      // Click again to mask all
      const maskAllBtn = screen.getByTitle("Mask all discovered secret values");
      fireEvent.click(maskAllBtn);

      expect(screen.queryByText("P@ss1234")).toBeNull();
      expect(screen.queryByText("AKIAIOSFODNN7EXAMPLE")).toBeNull();
    });

    it("copies secret value to clipboard when copy button clicked", async () => {
      const writeTextMock = vi.fn().mockResolvedValue(undefined);
      Object.assign(navigator, {
        clipboard: { writeText: writeTextMock }
      });

      render(<DiscoveredSecretsEvidenceViewer hits={mockHits} />);

      const copyButtons = screen.getAllByTitle("Copy secret value");
      expect(copyButtons.length).toBe(2);

      fireEvent.click(copyButtons[0]);
      expect(writeTextMock).toHaveBeenCalledWith("P@ss1234");
    });
  });
});
