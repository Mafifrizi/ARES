import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, GitGraph, Loader2, RotateCcw, Route, X } from "lucide-react";
import { useMemo, useState, type CSSProperties } from "react";
import { api } from "../../api/client";
import type { AttackPath, Campaign, SafeGraphValue } from "../../api/types";
import {
  attackPathSummary,
  filterGraph,
  getPathHighlight,
  graphNodeTypes,
  isGraphEmpty,
  type GraphFilters,
  type SafeGraph,
  type SafeGraphEdge,
  type SafeGraphNode,
  toSafeGraph
} from "./graphModel";

interface CanvasNodeData extends Record<string, unknown> {
  label: string;
  type: string;
  color: string;
  severity?: string;
  dimmed: boolean;
}

type CanvasNode = Node<CanvasNodeData, "ares">;
type CanvasEdge = Edge;

type GraphSelection =
  | { kind: "node"; value: SafeGraphNode }
  | { kind: "edge"; value: SafeGraphEdge }
  | null;

const nodeTypes: NodeTypes = { ares: AresGraphNode };

function AresGraphNode({ data, selected }: NodeProps<CanvasNode>) {
  return (
    <div
      className={`ares-flow-node${selected ? " selected" : ""}${data.dimmed ? " dimmed" : ""}`}
      style={{ "--node-color": data.color } as CSSProperties}
    >
      <Handle type="target" position={Position.Left} />
      <span className="ares-flow-node-type">{data.type}</span>
      <strong>{data.label}</strong>
      {data.severity && <small className={`status-${data.severity}`}>{data.severity}</small>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function graphLayout(graph: SafeGraph, highlightedNodeIds: Set<string>, highlightedEdgeIds: Set<string>) {
  const ordered = [...graph.nodes].sort((left, right) => (
    left.type.localeCompare(right.type) || left.label.localeCompare(right.label)
  ));
  const rowsByType = new Map<string, number>();
  const columnByType = new Map<string, number>();
  [...new Set(ordered.map((node) => node.type))].forEach((type, index) => columnByType.set(type, index));
  const shouldDim = highlightedNodeIds.size > 0;
  const nodes: CanvasNode[] = ordered.map((node) => {
    const row = rowsByType.get(node.type) ?? 0;
    rowsByType.set(node.type, row + 1);
    return {
      id: node.id,
      type: "ares",
      position: {
        x: (columnByType.get(node.type) ?? 0) * 255,
        y: (row % 8) * 118 + Math.floor(row / 8) * 36
      },
      data: {
        label: node.label,
        type: node.type,
        color: node.color,
        severity: node.severity,
        dimmed: shouldDim && !highlightedNodeIds.has(node.id)
      }
    };
  });
  const edges: CanvasEdge[] = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label || edge.type,
    animated: highlightedEdgeIds.has(edge.id),
    markerEnd: { type: MarkerType.ArrowClosed },
    style: {
      stroke: edge.color || "#94a3b8",
      strokeWidth: highlightedEdgeIds.has(edge.id) ? 3 : 1.5,
      opacity: highlightedEdgeIds.size > 0 && !highlightedEdgeIds.has(edge.id) ? 0.18 : 1,
      strokeDasharray: edge.dashed ? "5 4" : undefined
    },
    labelStyle: { fill: "#475569", fontSize: 11, fontWeight: 600 },
    labelBgStyle: { fill: "#ffffff", fillOpacity: 0.9 },
    labelBgPadding: [4, 3]
  }));
  return { nodes, edges };
}

function safeValueText(value: SafeGraphValue): string {
  if (value === null) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(safeValueText).join(", ");
  return Object.entries(value).map(([key, item]) => `${key}: ${safeValueText(item)}`).join(" · ");
}

function CampaignSelect({ campaigns, value, onChange }: {
  campaigns: Campaign[];
  value: string;
  onChange: (campaignId: string) => void;
}) {
  return (
    <label className="graph-campaign-select">
      <span>Campaign</span>
      <select className="field" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">Select campaign</option>
        {campaigns.map((campaign) => (
          <option key={campaign.id} value={campaign.id}>{campaign.name || campaign.id}</option>
        ))}
      </select>
    </label>
  );
}

function GraphFiltersPanel({ graph, filters, onChange }: {
  graph: SafeGraph;
  filters: GraphFilters;
  onChange: (filters: GraphFilters) => void;
}) {
  const types = graphNodeTypes(graph);
  return (
    <div className="graph-filters" aria-label="Graph filters">
      <span className="graph-filter-title">Filters</span>
      <div className="graph-filter-group">
        <span>Node type</span>
        <div className="graph-filter-options">
          {types.map((type) => {
            const active = filters.nodeTypes.includes(type);
            return (
              <button
                className={`filter-chip${active ? " active" : ""}`}
                key={type}
                onClick={() => onChange({
                  ...filters,
                  nodeTypes: active ? filters.nodeTypes.filter((item) => item !== type) : [...filters.nodeTypes, type]
                })}
                type="button"
              >
                {type}
              </button>
            );
          })}
        </div>
      </div>
      <label className="graph-filter-group">
        <span>Finding severity</span>
        <select
          className="field"
          value={filters.severity}
          onChange={(event) => onChange({ ...filters, severity: event.target.value })}
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </label>
      <label className="toggle-row graph-path-only-toggle">
        <input
          checked={filters.activePathOnly}
          disabled={false}
          onChange={(event) => onChange({ ...filters, activePathOnly: event.target.checked })}
          type="checkbox"
        />
        Only active attack path
      </label>
    </div>
  );
}

function GraphDetailPanel({ selection, onClear }: { selection: GraphSelection; onClear: () => void }) {
  if (!selection) {
    return (
      <div className="graph-detail-empty">
        Select a node or edge to review its safe metadata.
      </div>
    );
  }
  const value = selection.value;
  const edge = selection.kind === "edge" ? selection.value : null;
  const entries = Object.entries(value.metadata);
  return (
    <div className="graph-detail-content">
      <div className="graph-detail-heading">
        <div>
          <span>{selection.kind === "node" ? value.type : `edge · ${value.type}`}</span>
          <strong>{selection.kind === "node" ? value.label : value.label || `${edge?.source} → ${edge?.target}`}</strong>
        </div>
        <button aria-label="Clear graph detail" className="icon-button icon-button-small" onClick={onClear} type="button">
          <X size={14} />
        </button>
      </div>
      {edge && (
        <p className="graph-detail-route">{edge.source} → {edge.target}</p>
      )}
      {entries.length > 0 ? (
        <dl className="graph-detail-list">
          {entries.map(([key, item]) => (
            <div key={key}>
              <dt>{key.replace(/_/g, " ")}</dt>
              <dd>{safeValueText(item)}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="graph-detail-empty">No additional safe metadata is available.</p>
      )}
    </div>
  );
}

function AttackPathList({ paths, selectedIndex, onSelect }: {
  paths: AttackPath[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
}) {
  if (paths.length === 0) {
    return <div className="graph-detail-empty">No attack paths are available yet. Run reconnaissance or ingest a graph snapshot first.</div>;
  }
  return (
    <div className="attack-path-list">
      {paths.map((path, index) => (
        <button
          className={`attack-path-card${selectedIndex === index ? " active" : ""}`}
          key={`${attackPathSummary(path)}:${index}`}
          onClick={() => onSelect(index)}
          type="button"
        >
          <span>Path {index + 1}</span>
          <strong>{attackPathSummary(path)}</strong>
          <small>{path.path_length ?? path.steps.length + 1} nodes · score {path.total_score ?? "—"}</small>
        </button>
      ))}
    </div>
  );
}

function GraphCanvas({ graph, highlightedNodeIds, highlightedEdgeIds, onSelect }: {
  graph: SafeGraph;
  highlightedNodeIds: Set<string>;
  highlightedEdgeIds: Set<string>;
  onSelect: (selection: GraphSelection) => void;
}) {
  const canvas = useMemo(
    () => graphLayout(graph, highlightedNodeIds, highlightedEdgeIds),
    [graph, highlightedEdgeIds, highlightedNodeIds]
  );
  const nodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const edgeById = useMemo(() => new Map(graph.edges.map((edge) => [edge.id, edge])), [graph.edges]);
  return (
    <div className="graph-canvas" aria-label="Interactive attack graph">
      <ReactFlow
        edges={canvas.edges}
        fitView
        maxZoom={1.8}
        minZoom={0.25}
        nodes={canvas.nodes}
        nodeTypes={nodeTypes}
        onEdgeClick={(_event, edge) => {
          const selectedEdge = edgeById.get(edge.id);
          if (selectedEdge) onSelect({ kind: "edge", value: selectedEdge });
        }}
        onNodeClick={(_event, node) => {
          const selectedNode = nodeById.get(node.id);
          if (selectedNode) onSelect({ kind: "node", value: selectedNode });
        }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#dbe5f0" gap={18} />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  );
}

function GraphWorkspace({ graph, paths, view, filters, onFiltersChange, selectedPathIndex, onSelectPath, selection, onSelect }: {
  graph: SafeGraph;
  paths: AttackPath[];
  view: "entities" | "paths";
  filters: GraphFilters;
  onFiltersChange: (filters: GraphFilters) => void;
  selectedPathIndex: number | null;
  onSelectPath: (index: number) => void;
  selection: GraphSelection;
  onSelect: (selection: GraphSelection) => void;
}) {
  const selectedPath = selectedPathIndex === null ? null : paths[selectedPathIndex] ?? null;
  const highlight = useMemo(() => getPathHighlight(selectedPath, graph), [graph, selectedPath]);
  const filteredGraph = useMemo(() => filterGraph(graph, filters, highlight), [filters, graph, highlight]);
  return (
    <div className="graph-workspace">
      <GraphFiltersPanel graph={graph} filters={filters} onChange={onFiltersChange} />
      {selectedPath && (
        <div className="graph-active-path">
          <Route size={16} />
          <span>Highlighting {attackPathSummary(selectedPath)}</span>
          <button className="btn btn-compact" onClick={() => onSelectPath(-1)} type="button">
            <X size={14} /> Clear selection
          </button>
        </div>
      )}
      {filteredGraph.nodes.length > 0 ? (
        <div className="graph-layout">
          <GraphCanvas
            graph={filteredGraph}
            highlightedEdgeIds={highlight.edgeIds}
            highlightedNodeIds={highlight.nodeIds}
            onSelect={onSelect}
          />
          <aside className="panel graph-side-panel">
            <div className="graph-side-heading">
              <GitGraph size={16} />
              <strong>{view === "paths" ? "Top attack paths" : "Safe detail"}</strong>
            </div>
            {view === "paths"
              ? <AttackPathList paths={paths} selectedIndex={selectedPathIndex} onSelect={onSelectPath} />
              : <GraphDetailPanel selection={selection} onClear={() => onSelect(null)} />}
          </aside>
        </div>
      ) : (
        <div className="empty-state">No graph elements match the active filters or selected attack path.</div>
      )}
    </div>
  );
}

export default function GraphPage({ campaignId, onCampaignIdChange }: {
  campaignId: string;
  onCampaignIdChange: (campaignId: string) => void;
}) {
  const queryClient = useQueryClient();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });
  const graphQuery = useQuery({ queryKey: ["graph", campaignId], queryFn: () => api.graph(campaignId), enabled: Boolean(campaignId) });
  const pathsQuery = useQuery({ queryKey: ["attack-paths", campaignId], queryFn: () => api.attackPaths(campaignId), enabled: Boolean(campaignId) });
  const [activeTab, setActiveTab] = useState<"Entities" | "Attack Paths" | "Ingest">("Entities");
  const [filters, setFilters] = useState<GraphFilters>({ nodeTypes: [], severity: "all", activePathOnly: false });
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [selectedPathIndex, setSelectedPathIndex] = useState<number | null>(null);
  const [jsonPath, setJsonPath] = useState("");
  const [ingestNotice, setIngestNotice] = useState("");
  const safeGraph = useMemo(() => toSafeGraph(graphQuery.data), [graphQuery.data]);
  const paths = useMemo(() => Array.isArray(pathsQuery.data?.paths) ? pathsQuery.data.paths : [], [pathsQuery.data]);
  const ingest = useMutation({
    mutationFn: () => api.ingestBloodhound(campaignId, jsonPath.trim()),
    onSuccess: async () => {
      setIngestNotice("Import request completed. The graph will show imported data only after the API returns a durable snapshot.");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["graph", campaignId] }),
        queryClient.invalidateQueries({ queryKey: ["attack-paths", campaignId] })
      ]);
    }
  });

  function chooseCampaign(nextCampaignId: string): void {
    onCampaignIdChange(nextCampaignId);
    setSelection(null);
    setSelectedPathIndex(null);
    setFilters({ nodeTypes: [], severity: "all", activePathOnly: false });
    setIngestNotice("");
  }

  function selectPath(index: number): void {
    setSelectedPathIndex(index < 0 ? null : index);
    if (index >= 0) setFilters((current) => ({ ...current, activePathOnly: false }));
  }

  const loading = Boolean(campaignId) && (graphQuery.isLoading || pathsQuery.isLoading);
  const error = graphQuery.isError || pathsQuery.isError;
  return (
    <section className="page">
      <header className="page-header">
        <div className="page-heading">
          <span className="page-icon"><GitGraph size={19} /></span>
          <div>
            <p className="page-eyebrow">Intelligence</p>
            <h1>Graph</h1>
            <p>Durable campaign entities, relationships, and API-calculated attack paths.</p>
          </div>
        </div>
        <div className="page-actions">
          <span className="status-pill">{safeGraph.nodes.length} nodes / {safeGraph.edges.length} edges</span>
          {campaignId && <button className="btn btn-compact" onClick={() => void graphQuery.refetch()} type="button"><RotateCcw size={14} /> Retry</button>}
        </div>
      </header>
      <div className="page-tabs" role="tablist" aria-label="Graph sections">
        {(["Entities", "Attack Paths", "Ingest"] as const).map((tab) => (
          <button className={activeTab === tab ? "active" : ""} key={tab} onClick={() => setActiveTab(tab)} role="tab" type="button">{tab}</button>
        ))}
      </div>
      <section className="panel p-4 graph-panel">
        <div className="graph-toolbar">
          <CampaignSelect campaigns={campaigns.data ?? []} value={campaignId} onChange={chooseCampaign} />
          {campaigns.isError && <span className="notice notice-danger"><AlertTriangle size={15} /> Campaigns could not be loaded.</span>}
        </div>
        {!campaignId ? (
          <div className="empty-state">Select a campaign to load durable graph data.</div>
        ) : loading ? (
          <div className="loading-row"><Loader2 className="spin" size={18} /> Loading graph and attack paths…</div>
        ) : error ? (
          <div className="notice notice-danger graph-request-error"><AlertTriangle size={16} /> Graph data could not be loaded. Retry when the campaign API is available.</div>
        ) : activeTab === "Ingest" ? (
          <form className="graph-ingest-form" onSubmit={(event) => {
            event.preventDefault();
            setIngestNotice("");
            if (jsonPath.trim()) ingest.mutate();
          }}>
            <div>
              <h2>BloodHound ingest</h2>
              <p>Use a server-local path. The graph only reflects imported data after a durable API snapshot is returned.</p>
            </div>
            <label>
              <span>JSON path</span>
              <input className="field" onChange={(event) => setJsonPath(event.target.value)} placeholder="C:\\labs\\bloodhound\\results.json" required value={jsonPath} />
            </label>
            <button className="btn btn-primary" disabled={ingest.isPending} type="submit">
              {ingest.isPending ? <><Loader2 className="spin" size={16} /> Importing…</> : <><GitGraph size={16} /> Request import</>}
            </button>
            {ingestNotice && <p className="notice">{ingestNotice}</p>}
            {ingest.isError && <p className="notice notice-danger">The import request could not be completed. Confirm the allowed server-local path and retry.</p>}
          </form>
        ) : isGraphEmpty(safeGraph) ? (
          <div className="empty-state">This campaign has no durable graph data yet. Run authorized reconnaissance or ingest a BloodHound/SharpHound snapshot, then reload this page.</div>
        ) : (
          <GraphWorkspace
            filters={filters}
            graph={safeGraph}
            onFiltersChange={setFilters}
            onSelect={setSelection}
            onSelectPath={selectPath}
            paths={paths}
            selectedPathIndex={selectedPathIndex}
            selection={selection}
            view={activeTab === "Attack Paths" ? "paths" : "entities"}
          />
        )}
      </section>
    </section>
  );
}
