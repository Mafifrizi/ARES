import type { AttackPath, AttackPathStep, CampaignGraph, SafeGraphValue } from "../../api/types";

export const SENSITIVE_GRAPH_FIELDS = new Set([
  "secret",
  "secret_enc",
  "password",
  "passwd",
  "token",
  "api_key",
  "private_key",
  "hash",
  "hash_value",
  "nt_hash",
  "lm_hash",
  "cracked_value",
  "evidence",
  "raw_evidence"
]);

type UnknownRecord = Record<string, unknown>;

export interface SafeGraphNode {
  id: string;
  type: string;
  label: string;
  color: string;
  severity?: string;
  metadata: Record<string, SafeGraphValue>;
}

export interface SafeGraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  weight: number;
  color?: string;
  dashed: boolean;
  metadata: Record<string, SafeGraphValue>;
}

export interface SafeGraph {
  nodes: SafeGraphNode[];
  edges: SafeGraphEdge[];
}

export interface GraphFilters {
  nodeTypes: string[];
  severity: string;
  activePathOnly: boolean;
}

export interface GraphHighlight {
  nodeIds: Set<string>;
  edgeIds: Set<string>;
}

function isRecord(value: unknown): value is UnknownRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function safeString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function safeBoolean(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function isSensitiveGraphField(key: string): boolean {
  const normalized = key.toLowerCase();
  return SENSITIVE_GRAPH_FIELDS.has(normalized)
    || /(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|hash|cracked|evidence)/.test(normalized);
}

export function sanitizeGraphValue(value: unknown): SafeGraphValue | undefined {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      const sanitized = sanitizeGraphValue(item);
      return sanitized === undefined ? [] : [sanitized];
    });
  }
  if (isRecord(value)) {
    const sanitized: Record<string, SafeGraphValue> = {};
    Object.entries(value).forEach(([key, item]) => {
      if (isSensitiveGraphField(key)) return;
      const safeValue = sanitizeGraphValue(item);
      if (safeValue !== undefined) {
        sanitized[key] = safeValue;
      }
    });
    return sanitized;
  }
  return undefined;
}

export function sanitizeGraphMetadata(value: unknown): Record<string, SafeGraphValue> {
  const sanitized = sanitizeGraphValue(value);
  return isRecord(sanitized) ? sanitized as Record<string, SafeGraphValue> : {};
}

function toSafeNode(raw: unknown): SafeGraphNode | null {
  if (!isRecord(raw)) return null;
  const id = safeString(raw.id);
  if (!id) return null;
  const data = sanitizeGraphMetadata(raw.data);
  const style = isRecord(raw.style) ? raw.style : {};
  const rawType = safeString(raw.type, "artifact");
  const severity = safeString(data.severity).toLowerCase() || undefined;
  return {
    id,
    type: rawType,
    label: safeString(raw.label, id),
    color: safeString(raw.color, safeString(style.color, "#64748b")),
    severity,
    metadata: data
  };
}

function toSafeEdge(raw: unknown, index: number): SafeGraphEdge | null {
  if (!isRecord(raw)) return null;
  const source = safeString(raw.source);
  const target = safeString(raw.target);
  if (!source || !target) return null;
  const data = sanitizeGraphMetadata(raw.data);
  const style = isRecord(raw.style) ? raw.style : {};
  return {
    id: graphEdgeId(source, target, index),
    source,
    target,
    type: safeString(raw.type, "related"),
    label: safeString(raw.label),
    weight: safeNumber(raw.weight, 1),
    color: safeString(style.color) || undefined,
    dashed: safeBoolean(style.dashed),
    metadata: data
  };
}

export function graphEdgeId(source: string, target: string, index: number): string {
  return `edge:${source}:${target}:${index}`;
}

export function toSafeGraph(payload: CampaignGraph | unknown): SafeGraph {
  const source = isRecord(payload) ? payload : {};
  const rawNodes = Array.isArray(source.nodes) ? source.nodes : [];
  const rawEdges = Array.isArray(source.edges) ? source.edges : [];
  const nodeIds = new Set<string>();
  const nodes = rawNodes.flatMap((node) => {
    const safeNode = toSafeNode(node);
    if (!safeNode || nodeIds.has(safeNode.id)) return [];
    nodeIds.add(safeNode.id);
    return [safeNode];
  });
  const edges = rawEdges.flatMap((edge, index) => {
    const safeEdge = toSafeEdge(edge, index);
    if (!safeEdge || !nodeIds.has(safeEdge.source) || !nodeIds.has(safeEdge.target)) return [];
    return [safeEdge];
  });
  return { nodes, edges };
}

function samePathEndpoint(value: string, node: SafeGraphNode): boolean {
  return value === node.id || value === node.label;
}

function pathNodeId(value: string, nodes: SafeGraphNode[]): string | undefined {
  return nodes.find((node) => samePathEndpoint(value, node))?.id;
}

function pathEdgeIds(step: AttackPathStep, nodes: SafeGraphNode[], edges: SafeGraphEdge[]): string[] {
  const source = pathNodeId(step.from, nodes);
  const target = pathNodeId(step.to, nodes);
  if (!source || !target) return [];
  return edges.filter((edge) => edge.source === source && edge.target === target).map((edge) => edge.id);
}

export function getPathHighlight(path: AttackPath | null | undefined, graph: SafeGraph): GraphHighlight {
  const nodeIds = new Set<string>();
  const edgeIds = new Set<string>();
  if (!path) return { nodeIds, edgeIds };
  path.steps.forEach((step) => {
    const source = pathNodeId(step.from, graph.nodes);
    const target = pathNodeId(step.to, graph.nodes);
    if (source) nodeIds.add(source);
    if (target) nodeIds.add(target);
    pathEdgeIds(step, graph.nodes, graph.edges).forEach((edgeId) => edgeIds.add(edgeId));
  });
  return { nodeIds, edgeIds };
}

export function filterGraph(graph: SafeGraph, filters: GraphFilters, highlight: GraphHighlight): SafeGraph {
  const selectedTypes = new Set(filters.nodeTypes);
  const hasTypeFilter = selectedTypes.size > 0;
  const nodes = graph.nodes.filter((node) => {
    if (hasTypeFilter && !selectedTypes.has(node.type)) return false;
    if (filters.severity !== "all" && node.type === "finding" && node.severity !== filters.severity) return false;
    if (filters.activePathOnly && !highlight.nodeIds.has(node.id)) return false;
    return true;
  });
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return false;
    return !filters.activePathOnly || highlight.edgeIds.has(edge.id);
  });
  return { nodes, edges };
}

export function graphNodeTypes(graph: SafeGraph): string[] {
  return [...new Set(graph.nodes.map((node) => node.type))].sort();
}

export function isGraphEmpty(graph: SafeGraph): boolean {
  return graph.nodes.length === 0;
}

export function attackPathSummary(path: AttackPath): string {
  const start = path.start || path.steps[0]?.from || "Unknown source";
  const end = path.end || path.steps[path.steps.length - 1]?.to || "Unknown target";
  return `${start} → ${end}`;
}

export interface CobaltNodeInference {
  os: "windows" | "windows-server" | "linux" | "firewall";
  privilege: "system" | "admin" | "user" | "uncompromised";
  status: "active" | "dormant" | "mapped";
  process?: string;
  ip?: string;
  pid?: number | string;
  subLabel?: string;
}

export function inferCobaltNodeData(node: SafeGraphNode): CobaltNodeInference {
  const labelLower = (node.label || "").toLowerCase();
  const typeLower = (node.type || "").toLowerCase();
  const meta = node.metadata || {};

  let os: "windows" | "windows-server" | "linux" | "firewall" = "windows";
  if (meta.os === "firewall" || meta.os === "windows-server" || meta.os === "windows" || meta.os === "linux") {
    os = meta.os;
  } else if (typeLower.includes("firewall") || labelLower.includes("firewall") || labelLower.includes("gateway")) {
    os = "firewall";
  } else if (typeLower.includes("dc") || labelLower.includes("dc") || labelLower.includes("server") || typeLower.includes("domain")) {
    os = "windows-server";
  } else if (labelLower.includes("linux") || labelLower.includes("ubuntu") || labelLower.includes("kali")) {
    os = "linux";
  }

  let privilege: "system" | "admin" | "user" | "uncompromised" = "user";
  if (meta.privilege === "system" || meta.privilege === "admin" || meta.privilege === "user" || meta.privilege === "uncompromised") {
    privilege = meta.privilege;
  } else if (node.severity === "critical" || labelLower.includes("system") || labelLower.includes("admin") || labelLower.includes("root")) {
    privilege = "system";
  } else if (node.severity === "high") {
    privilege = "admin";
  } else if (typeLower === "finding" || typeLower === "host") {
    privilege = "user";
  } else if (typeLower === "domain" || typeLower === "group") {
    privilege = "uncompromised";
  }

  const ip = typeof meta.ip === "string" ? meta.ip : typeof meta.host === "string" ? meta.host : undefined;
  const process = typeof meta.process === "string" ? meta.process : typeof meta.binary === "string" ? meta.binary : undefined;
  const pid = typeof meta.pid === "number" || typeof meta.pid === "string" ? meta.pid : undefined;
  let explicitSubLabel = typeof meta.subLabel === "string" ? meta.subLabel : undefined;
  if (explicitSubLabel) {
    if (explicitSubLabel.includes("\n")) {
      explicitSubLabel = explicitSubLabel.split("\n")[1] || explicitSubLabel.split("\n")[0];
    }
    if (explicitSubLabel.length > 24) {
      explicitSubLabel = explicitSubLabel.slice(0, 22) + "…";
    }
  }

  let finalSubLabel = explicitSubLabel !== undefined ? explicitSubLabel : (ip || (pid ? `PID: ${pid}` : undefined));
  if (finalSubLabel && finalSubLabel.length > 24) {
    finalSubLabel = finalSubLabel.slice(0, 22) + "…";
  }

  return {
    os,
    privilege,
    status: "active",
    ip,
    process,
    pid,
    subLabel: finalSubLabel
  };
}

/**
 * Adapts real API graph and Campaign into Cobalt Strike Pivot Topology.
 * - If API graph has nodes, it maps them with Cobalt node inference (OS, privilege, status, protocol).
 * - If API graph has no session nodes yet, but campaign has defined targets,
 *   it synthesizes target host nodes so the operator sees the campaign attack surface.
 * - If completely empty, returns empty graph so operator sees true campaign status.
 */
export function adaptApiGraphToCobalt(
  apiGraph: SafeGraph,
  campaign?: { name?: string; targets?: string[]; scope_cidrs?: string[] } | null
): SafeGraph {
  if (apiGraph.nodes.length > 0) {
    const nodes: SafeGraphNode[] = apiGraph.nodes.map((n) => {
      const inference = inferCobaltNodeData(n);
      return {
        ...n,
        metadata: {
          ...n.metadata,
          os: inference.os,
          privilege: inference.privilege,
          status: inference.status,
          ip: inference.ip || (n.label.includes(".") ? n.label : null),
          process: inference.process || null,
          pid: inference.pid !== undefined ? inference.pid : null,
          subLabel: inference.subLabel || null
        }
      };
    });

    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges: SafeGraphEdge[] = apiGraph.edges
      .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
      .map((e) => {
        let label = e.label || "";
        const typeLower = (e.type || "").toLowerCase();
        if (!label) {
          if (typeLower.includes("egress") || typeLower.includes("web") || typeLower.includes("http")) {
            label = "HTTPS 443";
          } else if (typeLower.includes("lateral") || typeLower.includes("smb") || typeLower.includes("pivot")) {
            label = "\\pipe\\browser";
          } else if (typeLower.includes("session") || typeLower.includes("ssh")) {
            label = "SSH 22";
          } else if (typeLower.includes("discovery")) {
            label = "discovered";
          } else {
            label = "link";
          }
        }
        return {
          ...e,
          label
        };
      });

    return { nodes, edges };
  }

  // Fallback: If campaign has targets but no modules have run yet, display the target hosts
  if (campaign && Array.isArray(campaign.targets) && campaign.targets.length > 0) {
    const firewallNode: SafeGraphNode = {
      id: "node:ingress-fw",
      type: "firewall",
      label: "INGRESS / SCOPE",
      color: "#06b6d4",
      metadata: {
        os: "firewall",
        privilege: "user",
        ip: campaign.scope_cidrs?.[0] || "10.0.0.0/24",
        subLabel: `${campaign.name || "Target Scope"}`
      }
    };

    const targetNodes: SafeGraphNode[] = campaign.targets.slice(0, 12).map((tgt, idx) => {
      const tgtLower = tgt.toLowerCase();
      const isDc = tgtLower.includes("dc") || tgtLower.includes("server") || idx === campaign.targets!.length - 1;
      const isLinux = tgtLower.includes("linux") || tgtLower.includes("ubuntu") || tgtLower.includes("deb");
      return {
        id: `node:target-${idx}`,
        type: isDc ? "dc" : "host",
        label: tgt,
        color: isDc ? "#e11d48" : "#f59e0b",
        severity: isDc ? "high" : "low",
        metadata: {
          os: isDc ? "windows-server" : (isLinux ? "linux" : "windows"),
          privilege: "uncompromised",
          status: "mapped",
          ip: tgt,
          subLabel: isDc ? "TARGET DC (UNPWNED)" : "TARGET HOST"
        }
      };
    });

    const edges: SafeGraphEdge[] = targetNodes.map((tgtNode, idx) => ({
      id: `edge:fw-tgt-${idx}`,
      source: firewallNode.id,
      target: tgtNode.id,
      type: "discovery",
      label: "in-scope",
      weight: 1,
      color: "#f59e0b",
      dashed: true,
      metadata: { protocol: "TCP/SCAN" }
    }));

    return { nodes: [firewallNode, ...targetNodes], edges };
  }

  return { nodes: [], edges: [] };
}

export function generateCobaltPivotTopology(): SafeGraph {
  const nodes: SafeGraphNode[] = [
    {
      id: "node:firewall",
      type: "firewall",
      label: "FIREWALL",
      color: "#e11d48",
      severity: "critical",
      metadata: { os: "firewall", privilege: "system", ip: "10.10.10.1", subLabel: "" }
    },
    {
      id: "node:entry-ws",
      type: "host",
      label: "10.10.10.191",
      color: "#06b6d4",
      metadata: { os: "windows", privilege: "user", user: "10.10.10.191", pid: 4844, subLabel: "4844" }
    },
    {
      id: "node:parent-198",
      type: "host",
      label: "SYSTEM *",
      color: "#ef4444",
      severity: "critical",
      metadata: { os: "windows", privilege: "system", user: "SYSTEM *", pid: 2000, subLabel: "10.10.10.198 @ 2000" }
    },
    {
      id: "node:mimikatz",
      type: "host",
      label: "SYSTEM *",
      color: "#ef4444",
      severity: "critical",
      metadata: { os: "windows", privilege: "system", user: "SYSTEM *", pid: 2956, subLabel: "PENGREC @ 2956" }
    },
    {
      id: "node:engineer",
      type: "host",
      label: "SYSTEM *",
      color: "#ef4444",
      severity: "critical",
      metadata: { os: "windows", privilege: "system", user: "SYSTEM *", pid: 1512, subLabel: "ENGINEER @ 1512" }
    },
    {
      id: "node:dc01",
      type: "dc",
      label: "SYSTEM *",
      color: "#ef4444",
      severity: "critical",
      metadata: { os: "windows-server", privilege: "system", user: "SYSTEM *", pid: 2308, subLabel: "DC @ 2308" }
    },
    {
      id: "node:dev45",
      type: "host",
      label: "SYSTEM *",
      color: "#ef4444",
      severity: "critical",
      metadata: { os: "windows", privilege: "system", user: "SYSTEM *", pid: 8040, subLabel: "DEVELOPER45 @ 8040" }
    },
    {
      id: "node:dev-child",
      type: "host",
      label: "Jamie.Grins",
      color: "#06b6d4",
      metadata: { os: "windows", privilege: "user", user: "Jamie.Grins", pid: 6984, subLabel: "DEVELOPER45 @ 6984" }
    },
    {
      id: "node:ubuntu",
      type: "host",
      label: "jgrins",
      color: "#f59e0b",
      metadata: { os: "linux", privilege: "user", user: "jgrins", subLabel: "ubuntu" }
    }
  ];

  const edges: SafeGraphEdge[] = [
    {
      id: "edge:fw-entry",
      source: "node:firewall",
      target: "node:entry-ws",
      type: "egress",
      label: "Egress",
      weight: 1,
      color: "#00cc44",
      dashed: false,
      metadata: { protocol: "HTTPS", port: 443 }
    },
    {
      id: "edge:entry-parent",
      source: "node:entry-ws",
      target: "node:parent-198",
      type: "pivot",
      label: "SMB Pipe",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { pipe: "\\pipe\\spoolss" }
    },
    {
      id: "edge:parent-mimikatz",
      source: "node:parent-198",
      target: "node:mimikatz",
      type: "pivot",
      label: "SMB Pipe",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { pipe: "\\pipe\\samr" }
    },
    {
      id: "edge:mimikatz-engineer",
      source: "node:mimikatz",
      target: "node:engineer",
      type: "pivot",
      label: "SMB Pipe",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { pipe: "\\pipe\\srvsvc" }
    },
    {
      id: "edge:parent-dc01",
      source: "node:parent-198",
      target: "node:dc01",
      type: "pivot",
      label: "SMB Pipe",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { pipe: "\\pipe\\netlogon" }
    },
    {
      id: "edge:entry-dev45",
      source: "node:entry-ws",
      target: "node:dev45",
      type: "pivot",
      label: "SMB Pipe",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { pipe: "\\pipe\\browser" }
    },
    {
      id: "edge:dev45-child",
      source: "node:dev45",
      target: "node:dev-child",
      type: "session",
      label: "Interactive Link",
      weight: 1,
      color: "#00d4ff",
      dashed: false,
      metadata: { channel: "staged_tcp" }
    },
    {
      id: "edge:child-ubuntu",
      source: "node:dev-child",
      target: "node:ubuntu",
      type: "pivot",
      label: "SSH Pivot",
      weight: 1,
      color: "#ff9900",
      dashed: false,
      metadata: { protocol: "SSH", port: 22 }
    },
    {
      id: "edge:fw-reverse",
      source: "node:dev-child",
      target: "node:firewall",
      type: "reverse",
      label: "Reverse Route",
      weight: 1,
      color: "#ffff00",
      dashed: true,
      metadata: { listener: "TCP Reverse" }
    }
  ];

  return { nodes, edges };
}

