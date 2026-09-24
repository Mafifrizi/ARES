import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { afterEach, describe, expect, it } from "vitest";
import { CobaltSessionDock } from "./CobaltSessionDock";
import { PivotFirewallNode } from "./CobaltStrikeNodes";
import {
  adaptApiGraphToCobalt,
  generateCobaltPivotTopology,
  inferCobaltNodeData,
  type SafeGraph
} from "./graphModel";

describe("Cobalt Strike Visualizer Components & Integration", () => {
  afterEach(() => {
    cleanup();
  });

  describe("CobaltSessionDock", () => {
    it("renders default multi-row tabs and status bar correctly", () => {
      render(
        <CobaltSessionDock
          selectedNodeId={null}
          selectedNodeLabel={null}
          campaignId="c-alpha"
          campaignName="Campaign Alpha"
        />
      );

      // Check default active session or tabs
      expect(screen.getByText("beacon>")).toBeDefined();
      expect(screen.getByText(/DEVELOPER45/i)).toBeDefined();
      expect(screen.getByText(/last:/i)).toBeDefined();
    });

    it("executes beacon terminal commands and outputs formatted results", () => {
      render(
        <CobaltSessionDock
          selectedNodeId={null}
          selectedNodeLabel={null}
          campaignId="c-alpha"
          campaignName="Campaign Alpha"
        />
      );

      const input = screen.getByRole("textbox");

      // 1. Test whoami command
      fireEvent.change(input, { target: { value: "whoami" } });
      fireEvent.submit(input.closest("form")!);
      expect(screen.getByText(/beacon> whoami/i)).toBeDefined();
      expect(screen.getByText(/Integrity:/i)).toBeDefined();

      // 2. Test hashdump command
      fireEvent.change(input, { target: { value: "hashdump" } });
      fireEvent.submit(input.closest("form")!);
      expect(screen.getByText(/beacon> hashdump/i)).toBeDefined();
      expect(screen.getByText(/Administrator:500:/i)).toBeDefined();

      // 3. Test help command
      fireEvent.change(input, { target: { value: "help" } });
      fireEvent.submit(input.closest("form")!);
      expect(screen.getByText(/Beacon commands:/i)).toBeDefined();

      // 4. Test clear command
      fireEvent.change(input, { target: { value: "clear" } });
      fireEvent.submit(input.closest("form")!);
      expect(screen.queryByText(/Administrator:500:/i)).toBeNull();
    });

    it("dynamically synchronizes when user selects a node from the pivot graph", () => {
      const { rerender } = render(
        <CobaltSessionDock
          selectedNodeId={null}
          selectedNodeLabel={null}
          campaignId="c-alpha"
          campaignName="Campaign Alpha"
        />
      );

      // Simulate clicking host 'DC01' on the graph
      rerender(
        <CobaltSessionDock
          selectedNodeId="node:dc01"
          selectedNodeLabel="DC01"
          campaignId="c-alpha"
          campaignName="Campaign Alpha"
        />
      );

      // Tab for DC01 should be created and activated
      expect(screen.getByText("Beacon: DC01")).toBeDefined();
      expect(screen.getByText(/established link to host: DC01/i)).toBeDefined();
      expect(screen.getByText(/Cryptographic auth: AES-256-GCM/i)).toBeDefined();
    });
  });

  describe("Cobalt Node Data Inference", () => {
    it("correctly identifies Firewalls and Gateways", () => {
      const node = {
        id: "node:k8s-ingress",
        type: "firewall",
        label: "K8S-INGRESS-01",
        color: "#991b1b",
        metadata: {}
      };
      const inf = inferCobaltNodeData(node);
      expect(inf.os).toBe("firewall");
      expect(inf.privilege).toBe("system");
    });

    it("correctly identifies Tier-0 Domain Controllers with SYSTEM *", () => {
      const node = {
        id: "node:dc01",
        type: "dc",
        label: "CORP-DC01",
        color: "#ef4444",
        metadata: { is_dc: true }
      };
      const inf = inferCobaltNodeData(node);
      expect(inf.os).toBe("windows-server");
      expect(inf.privilege).toBe("system");
    });

    it("correctly identifies High-Value Admin Servers", () => {
      const node = {
        id: "node:sql-prod",
        type: "host",
        label: "PROD-SQL-01",
        color: "#f59e0b",
        metadata: { privilege: "admin" }
      };
      const inf = inferCobaltNodeData(node);
      expect(inf.privilege).toBe("admin");
    });

    it("correctly identifies Linux Footholds with Tux emblem", () => {
      const node = {
        id: "node:ubuntu-jump",
        type: "host",
        label: "UBUNTU-JUMP-01",
        color: "#06b6d4",
        metadata: { os: "linux" }
      };
      const inf = inferCobaltNodeData(node);
      expect(inf.os).toBe("linux");
    });
  });

  describe("Cobalt Topology Filtering and Generation", () => {
    it("filters out abstract findings and only retains real network infrastructure", () => {
      const apiGraph: SafeGraph = {
        nodes: [
          { id: "h1", type: "host", label: "WS01", color: "#fff", metadata: {} },
          { id: "f1", type: "finding", label: "CVE-2023-1234", color: "#f00", metadata: {} },
          { id: "c1", type: "credential", label: "NTLM Hash", color: "#0f0", metadata: {} },
          { id: "h2", type: "host", label: "DC01", color: "#f00", metadata: {} }
        ],
        edges: [
          { id: "e1", source: "h1", target: "f1", type: "compromise", label: "", weight: 1, dashed: false, metadata: {} },
          { id: "e2", source: "h1", target: "h2", type: "smb", label: "", weight: 1, dashed: false, metadata: {} }
        ]
      };

      const adapted = adaptApiGraphToCobalt(apiGraph, { name: "Test" });
      expect(adapted.nodes.map((n) => n.id)).toEqual(["h1", "h2"]);
      expect(adapted.edges.map((e) => e.id)).toEqual(["e2"]);
      expect(adapted.edges[0].label).toBe("\\pipe\\browser");
    });

    it("generates exact 9-node reference benchmark topology", () => {
      const benchmark = generateCobaltPivotTopology();
      expect(benchmark.nodes).toHaveLength(9);
      expect(benchmark.edges).toHaveLength(9);
      expect(benchmark.nodes[0].id).toBe("node:firewall");
      expect(benchmark.nodes.some((n) => n.id === "node:dc01")).toBe(true);
    });
  });

  describe("PivotFirewallNode (PERIMETER INGRESS)", () => {
    it("renders animated firewall flames and authentic brick wall without dragon elements", () => {
      const { container } = render(
        <ReactFlowProvider>
          <PivotFirewallNode
            {...({
              id: "node:firewall",
              data: { label: "FIREWALL", subLabel: "Ingress / Egress", os: "firewall" },
              selected: false,
              type: "pivotFirewall",
              zIndex: 1,
              isConnectable: false,
              positionAbsoluteX: 0,
              positionAbsoluteY: 0,
              dragging: false,
              draggable: false,
              selectable: true,
              deletable: false,
            } as any)}
          />
        </ReactFlowProvider>
      );

      // Verify node container and label
      expect(container.querySelector(".cobalt-firewall-node")).toBeDefined();
      expect(screen.getByText("FIREWALL")).toBeDefined();
      expect(screen.getByText("Ingress / Egress")).toBeDefined();

      // Verify authentic brick wall elements are intact
      const brickRect = container.querySelector('rect[fill="#991b1b"]');
      expect(brickRect).not.toBeNull();
      const mortarLines = container.querySelectorAll("line");
      expect(mortarLines.length).toBeGreaterThanOrEqual(7);

      // Verify animated flames & embers are intact
      expect(container.querySelector(".ares-firewall-flame-group")).not.toBeNull();
      expect(container.querySelector(".ares-flame-ambient-aura")).not.toBeNull();
      expect(container.querySelector(".ares-flame-tongue-center")).not.toBeNull();
      expect(container.querySelector(".ares-ember-1")).not.toBeNull();

      // Verify dragon character element is completely removed
      expect(container.querySelector(".ares-cyber-dragon")).toBeNull();
      expect(container.querySelector(".ares-dragon-body-tail")).toBeNull();
      expect(container.querySelector(".ares-dragon-wing-left")).toBeNull();
    });
  });
});

