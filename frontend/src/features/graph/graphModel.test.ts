import { describe, expect, it } from "vitest";
import type { AttackPath, CampaignGraph } from "../../api/types";
import { adaptApiGraphToCobalt, filterGraph, getPathHighlight, isGraphEmpty, toSafeGraph } from "./graphModel";

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

  it("cleans dangling open parenthesis from truncated finding titles without stripping valid parentheses", () => {
    const testGraph = toSafeGraph({
      nodes: [
        { id: "host:192.168.56.105", type: "host", label: "192.168.56.105", data: { ip: "192.168.56.105" } },
        {
          id: "finding:1",
          type: "finding",
          label: "Dangerous Linux Capabilities (",
          data: { severity: "high", title: "Dangerous Linux Capabilities (" }
        },
        {
          id: "finding:2",
          type: "finding",
          label: "Dangerous Linux Capabilities (3)",
          data: { severity: "high", title: "Dangerous Linux Capabilities (3)" }
        }
      ],
      edges: [
        { source: "host:192.168.56.105", target: "finding:1", type: "finding" },
        { source: "host:192.168.56.105", target: "finding:2", type: "finding" }
      ]
    });

    const adapted = adaptApiGraphToCobalt(testGraph);
    const hostNode = adapted.nodes.find((n) => n.id === "host:192.168.56.105");
    expect(hostNode).toBeDefined();
    const findings = (hostNode?.metadata?.findings ?? []) as Array<{ title: string }>;
    expect(findings).toHaveLength(2);
    expect(findings[0].title).toBe("Dangerous Linux Capabilities");
    expect(findings[1].title).toBe("Dangerous Linux Capabilities (3)");
  });
});
