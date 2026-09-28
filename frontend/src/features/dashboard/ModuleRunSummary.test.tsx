// @vitest-environment jsdom
import "../../test/setup";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ModuleRunSummary } from "./DashboardPages";

afterEach(() => {
  cleanup();
});

describe("ModuleRunSummary filtered_findings indicator (Step 4 Verification)", () => {
  it("renders 1 finding filtered as low-confidence (below reporting threshold) for lateral.winrm", () => {
    const winrmResult = {
      module_id: "lateral.winrm",
      status: "done",
      findings: [],
      raw_output: { target: "10.0.0.5" },
      filtered_findings: {
        count: 1,
        reasons: { below_confidence_threshold: 1 },
      },
    };

    render(<ModuleRunSummary result={winrmResult} />);

    const notice = screen.getByTestId("filtered-findings-notice");
    expect(notice).not.toBeNull();
    expect(notice.textContent).toContain("1 finding filtered as low-confidence (below reporting threshold)");
  });

  it("renders 1 finding filtered as low-confidence (no evidence) for ad.kerberoast", () => {
    const kerbResult = {
      module_id: "ad.kerberoast",
      status: "done",
      findings: [],
      raw_output: { spns: [] },
      filtered_findings: {
        count: 1,
        reasons: { no_evidence: 1 },
      },
    };

    render(<ModuleRunSummary result={kerbResult} />);

    const notice = screen.getByTestId("filtered-findings-notice");
    expect(notice).not.toBeNull();
    expect(notice.textContent).toContain("1 finding filtered as low-confidence (no evidence)");
  });

  it("renders 3 findings filtered as low-confidence with pluralization and top reason", () => {
    const multiResult = {
      module_id: "ad.kerberoast",
      status: "done",
      findings: [],
      filtered_findings: {
        count: 3,
        reasons: { below_confidence_threshold: 2, no_evidence: 1 },
      },
    };

    render(<ModuleRunSummary result={multiResult} />);

    const notice = screen.getByTestId("filtered-findings-notice");
    expect(notice).not.toBeNull();
    expect(notice.textContent).toContain("3 findings filtered as low-confidence (below reporting threshold)");
  });

  it("renders mixed reasons using the highest-count reason (no evidence)", () => {
    const mixedResult = {
      module_id: "ad.kerberoast",
      status: "done",
      findings: [],
      filtered_findings: {
        count: 3,
        reasons: { no_evidence: 2, below_confidence_threshold: 1 },
      },
    };

    render(<ModuleRunSummary result={mixedResult} />);

    const notice = screen.getByTestId("filtered-findings-notice");
    expect(notice).not.toBeNull();
    expect(notice.textContent).toContain("3 findings filtered as low-confidence (no evidence)");
  });

  it("does NOT render indicator when filtered_findings.count is 0 (network.port_scan)", () => {
    const portScanResult = {
      module_id: "network.port_scan",
      status: "done",
      findings: [
        {
          id: "f-1",
          title: "Open Port 80/http",
          severity: "info",
          confidence: 1.0,
          validated: true,
        },
      ],
      raw_output: { open_ports: [80] },
      filtered_findings: {
        count: 0,
        reasons: {},
      },
    };

    render(<ModuleRunSummary result={portScanResult} />);

    const notice = screen.queryByTestId("filtered-findings-notice");
    expect(notice).toBeNull();
    expect(screen.queryByText(/filtered as low-confidence/i)).toBeNull();
  });

  it("does NOT render indicator when filtered_findings is undefined (older responses)", () => {
    const legacyResult = {
      module_id: "network.port_scan",
      status: "done",
      findings: [],
      raw_output: {},
    };

    render(<ModuleRunSummary result={legacyResult} />);

    const notice = screen.queryByTestId("filtered-findings-notice");
    expect(notice).toBeNull();
    expect(screen.queryByText(/filtered as low-confidence/i)).toBeNull();
  });
});

