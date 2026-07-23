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
