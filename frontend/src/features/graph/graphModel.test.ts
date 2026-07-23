import { describe, expect, it } from "vitest";
import type { AttackPath, CampaignGraph } from "../../api/types";
import { filterGraph, getPathHighlight, isGraphEmpty, toSafeGraph } from "./graphModel";

const payload: CampaignGraph = {
  nodes: [
    {
      id: "host:10.0.0.5",
      type: "host",
      label: "app01",
      color: "#0dcaf0",
      data: {
        hostname: "app01",
        access_token: "must-not-render",
        nested: { password_hash: "nope", raw_evidence: "not-for-ui", role: "web" }
      }
    },
    {
      id: "finding:1",
      type: "finding",
      label: "Critical service exposure",
      color: "#dc3545",
      data: { severity: "critical", secret_enc: "nope", module_id: "network.safe_probe" }
    },
    {
      id: "pivot:1",
      type: "pivot",
      label: "Approved route",
      color: "#64748b",
      data: { route: "10.0.0.0/24" }
    }
  ],
  edges: [
    { source: "host:10.0.0.5", target: "finding:1", type: "compromise", label: "exposed" },
    { source: "finding:1", target: "pivot:1", type: "pivot", label: "route" }
  ]
};

describe("graph model", () => {
  it("never forwards secret-like metadata to a node or safe detail payload", () => {
    const graph = toSafeGraph(payload);

    expect(JSON.stringify(graph)).not.toContain("must-not-render");
    expect(JSON.stringify(graph)).not.toContain("secret_enc");
    expect(JSON.stringify(graph)).not.toContain("password");
    expect(JSON.stringify(graph)).not.toContain("evidence");
    expect(graph.nodes[0]?.metadata).toEqual({ hostname: "app01", nested: { role: "web" } });
  });

  it("represents an empty API graph as an explicit empty state", () => {
    expect(isGraphEmpty(toSafeGraph({ nodes: [], edges: [] }))).toBe(true);
  });

  it("filters node type and finding severity without inventing graph elements", () => {
    const graph = toSafeGraph(payload);
    const filtered = filterGraph(
      graph,
      { nodeTypes: ["finding", "host"], severity: "critical", activePathOnly: false },
      { nodeIds: new Set(), edgeIds: new Set() }
    );

    expect(filtered.nodes.map((node) => node.id)).toEqual(["host:10.0.0.5", "finding:1"]);
    expect(filtered.edges).toHaveLength(1);
  });

  it("highlights exactly the API-selected attack path nodes and edges", () => {
    const graph = toSafeGraph(payload);
    const path: AttackPath = {
      steps: [
        { from: "app01", to: "Critical service exposure", edge: "exposed" },
        { from: "Critical service exposure", to: "Approved route", edge: "route" }
      ]
    };
    const highlight = getPathHighlight(path, graph);

    expect(highlight.nodeIds).toEqual(new Set(["host:10.0.0.5", "finding:1", "pivot:1"]));
    expect(highlight.edgeIds).toEqual(new Set(["edge:host:10.0.0.5:finding:1:0", "edge:finding:1:pivot:1:1"]));
  });

  it("drops malformed API nodes and edges instead of crashing the renderer", () => {
    const graph = toSafeGraph({
      nodes: [null, { id: 12 }, { id: "safe", type: "host", label: "safe" }],
      edges: [{ source: "safe" }, { source: "safe", target: "missing" }, { source: "safe", target: "safe" }]
    });

    expect(graph.nodes).toHaveLength(1);
    expect(graph.edges).toHaveLength(1);
  });
});
