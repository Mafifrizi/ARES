import "../../test/setup";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AttackPathsResponse, Campaign } from "../../api/types";

const mockCampaigns: Campaign[] = [
  { id: "camp-001", name: "Alpha Engagement", targets: ["10.0.0.1", "10.0.0.2"] },
  { id: "camp-002", name: "Bravo Assessment", targets: ["192.168.1.1"] }
];

const mockGraphData = {
  nodes: [
    { id: "node:firewall", label: "Perimeter Firewall", type: "firewall" },
    { id: "node:dc01", label: "DC01.CORP.LOCAL", type: "dc" }
  ],
  edges: [
    { id: "edge:fw-dc", source: "node:firewall", target: "node:dc01", label: "SMB" }
  ]
};

const mockAttackPaths: AttackPathsResponse = {
  paths: [
    {
      total_score: 90,
      steps: [
        { from: "node:firewall", to: "node:dc01", attack: "SMB Relay" }
      ]
    }
  ]
};

vi.mock("../../api/client", () => ({
  api: {
    campaigns: vi.fn(async () => mockCampaigns),
    graph: vi.fn(async () => mockGraphData),
    attackPaths: vi.fn(async () => mockAttackPaths),
    ingestBloodhound: vi.fn(async () => ({ status: "ok" }))
  }
}));

import GraphPage from "./GraphPage";

function renderGraphPage(props: {
  campaignId?: string;
  onCampaignIdChange?: (id: string) => void;
} = {}) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 }
    }
  });

  const onCampaignIdChange = props.onCampaignIdChange || vi.fn();
  const campaignId = props.campaignId !== undefined ? props.campaignId : "camp-001";

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <GraphPage
          campaignId={campaignId}
          onCampaignIdChange={onCampaignIdChange}
        />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("GraphPage Test Harness (AUD-009)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders Cobalt Strike C2 Console with title bar, controls, and session dock", async () => {
    renderGraphPage();

    expect(screen.getByLabelText("Cobalt Strike C2 Console")).toBeInTheDocument();
    expect(screen.getAllByText("ARES").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("Cobalt Strike Pivot Graph")).toBeInTheDocument();

    // Toolbar legend items
    expect(screen.getAllByText(/SYSTEM \*/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/SMB Pivot/i)).toBeInTheDocument();

    // Session dock terminal
    await waitFor(() => {
      expect(screen.getByText("beacon>")).toBeInTheDocument();
    });
  });

  it("renders campaign selector and triggers onCampaignIdChange on switch", async () => {
    const handleCampaignChange = vi.fn();
    renderGraphPage({ campaignId: "camp-001", onCampaignIdChange: handleCampaignChange });

    // Wait for campaigns to load and populate options
    await waitFor(() => {
      expect(screen.getByText("Alpha Engagement")).toBeInTheDocument();
      expect(screen.getByText("Bravo Assessment")).toBeInTheDocument();
    });

    const select = screen.getByLabelText(/Campaign:/i);
    fireEvent.change(select, { target: { value: "camp-002" } });

    await waitFor(() => {
      expect(handleCampaignChange).toHaveBeenCalledWith("camp-002");
    });
  });

  it("toggles lateral pivot route focus [P] and displays HUD toast notice", async () => {
    renderGraphPage();

    const pivotBtn = screen.getByTitle(/Toggle Lateral Pivot Route Focus/i);
    expect(pivotBtn).toBeInTheDocument();

    fireEvent.click(pivotBtn);

    await waitFor(() => {
      expect(screen.getByText(/Pivot Focus: ACTIVE/i)).toBeInTheDocument();
    });

    fireEvent.click(pivotBtn);

    await waitFor(() => {
      expect(screen.getByText(/Pivot Focus: OFF/i)).toBeInTheDocument();
    });
  });

  it("opens and closes the Attack Paths Explorer dialog", async () => {
    renderGraphPage();

    const attackPathsBtn = screen.getByTitle(/Attack Paths Explorer/i);
    fireEvent.click(attackPathsBtn);

    await waitFor(() => {
      expect(screen.getByText("Attack Paths Explorer")).toBeInTheDocument();
    });

    const closeBtn = screen.getByRole("button", { name: "Close" });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText("Calculated lateral movement paths for active engagement campaign:")).not.toBeInTheDocument();
    });
  });

  it("opens and closes the Help dialog with keyboard shortcuts reference", async () => {
    renderGraphPage();

    const helpItem = screen.getByTitle(/Operator Help, Shortcuts & Command Reference/i);
    fireEvent.click(helpItem);

    await waitFor(() => {
      expect(screen.getByText(/ARES C2 - Operator Reference & Help Manual/i)).toBeInTheDocument();
      expect(screen.getByText(/Interactive Canvas Controls:/i)).toBeInTheDocument();
      expect(screen.getByText(/Clear locked pathway highlight and unlock topology view/i)).toBeInTheDocument();
    });

    const closeBtn = screen.getByRole("button", { name: "Close" });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/ARES C2 - Operator Reference & Help Manual/i)).not.toBeInTheDocument();
    });
  });
});
