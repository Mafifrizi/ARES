import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./graphCobalt.css";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { api } from "../../api/client";
import type { AttackPath, Campaign, SafeGraphValue } from "../../api/types";
import {
  adaptApiGraphToCobalt,
  attackPathSummary,
  filterGraph,
  generateCobaltPivotTopology,
  getPathHighlight,
  graphNodeTypes,
  inferCobaltNodeData,
  isGraphEmpty,
  type GraphFilters,
  type SafeGraph,
  type SafeGraphEdge,
  type SafeGraphNode,
  toSafeGraph
} from "./graphModel";
import { PivotComputerNode, PivotFirewallNode, type PivotNodeData } from "./CobaltStrikeNodes";
import { CobaltSessionDock } from "./CobaltSessionDock";

type CanvasNode = Node<PivotNodeData, string>;
type CanvasEdge = Edge;

type GraphSelection =
  | { kind: "node"; value: SafeGraphNode }
  | { kind: "edge"; value: SafeGraphEdge }
  | null;

const nodeTypes: NodeTypes = {
  pivotComputer: PivotComputerNode,
  pivotFirewall: PivotFirewallNode,
  ares: PivotComputerNode
};

/**
 * Cobalt Strike Hierarchical Pivot Graph Layout Generator
 * Positions Firewall/Ingress on the left, Pivot Workstations in the center,
 * and Domain Controllers/Crown Jewels on the right.
 */
function cobaltPivotLayout(
  graph: SafeGraph,
  highlightedNodeIds: Set<string>,
  highlightedEdgeIds: Set<string>,
  selectedNodeId?: string | null
) {
  // Pre-configured coordinate map for canonical Cobalt Strike Pivot nodes matching reference screenshot
  const FIXED_COORDINATES: Record<string, { x: number; y: number }> = {
    "node:firewall": { x: 35, y: 155 },
    "node:entry-ws": { x: 195, y: 125 },
    "node:parent-198": { x: 380, y: 75 },
    "node:dev45": { x: 380, y: 255 },
    "node:mimikatz": { x: 570, y: 20 },
    "node:dc01": { x: 570, y: 140 },
    "node:dev-child": { x: 570, y: 260 },
    "node:engineer": { x: 760, y: 20 },
    "node:ubuntu": { x: 760, y: 260 }
  };

  const shouldDim = highlightedNodeIds.size > 0;

  // Build adjacency for dynamic positioning if nodes are not in FIXED_COORDINATES
  const columnLevels = new Map<string, number>();
  const nodes = graph.nodes;
  const edges = graph.edges;

  // Assign column levels via safe BFS with cycle detection
  const inDegree = new Map<string, number>();
  nodes.forEach((n) => inDegree.set(n.id, 0));
  edges.forEach((e) => {
    if (inDegree.has(e.target)) {
      inDegree.set(e.target, (inDegree.get(e.target) ?? 0) + 1);
    }
  });

  const queue: string[] = [];
  const visited = new Set<string>();

  nodes.forEach((n) => {
    if ((inDegree.get(n.id) ?? 0) === 0 || n.type === "firewall") {
      columnLevels.set(n.id, 0);
      visited.add(n.id);
      queue.push(n.id);
    }
  });

  if (queue.length === 0 && nodes.length > 0) {
    columnLevels.set(nodes[0].id, 0);
    visited.add(nodes[0].id);
    queue.push(nodes[0].id);
  }

  // Guaranteed termination: Each node visited at most once, depth capped at 6 columns
  while (queue.length > 0) {
    const currId = queue.shift()!;
    const currCol = columnLevels.get(currId) ?? 0;
    const outgoing = edges.filter((e) => e.source === currId);
    for (const edge of outgoing) {
      const nextId = edge.target;
      if (!visited.has(nextId)) {
        visited.add(nextId);
        columnLevels.set(nextId, Math.min(currCol + 1, 6));
        queue.push(nextId);
      }
    }
  }

  // Any remaining nodes not reachable from root get assigned columns gracefully
  nodes.forEach((n, idx) => {
    if (!columnLevels.has(n.id)) {
      columnLevels.set(n.id, (idx % 3) + 1);
    }
  });

  // Count items per column to space vertically
  const colRows = new Map<number, number>();
  const isDemoTopology = nodes.length <= 9 && nodes.every((n) => Boolean(FIXED_COORDINATES[n.id]));

  const canvasNodes: CanvasNode[] = nodes.map((node, index) => {
    const inferred = inferCobaltNodeData(node);
    let x: number;
    let y: number;

    if (isDemoTopology && FIXED_COORDINATES[node.id]) {
      x = FIXED_COORDINATES[node.id].x;
      y = FIXED_COORDINATES[node.id].y;
    } else {
      const col = columnLevels.get(node.id) ?? (index % 4);
      const row = colRows.get(col) ?? 0;
      colRows.set(col, row + 1);
      x = 50 + col * 220;
      y = 50 + row * 140;
    }

    const nodeType = inferred.os === "firewall" ? "pivotFirewall" : "pivotComputer";
    const isNodeSelected = selectedNodeId ? node.id === selectedNodeId : false;

    return {
      id: node.id,
      type: nodeType,
      position: { x, y },
      selected: isNodeSelected,
      data: {
        label: node.label,
        subLabel: inferred.subLabel,
        os: inferred.os,
        privilege: inferred.privilege,
        status: inferred.status,
        process: inferred.process,
        pid: inferred.pid,
        ip: inferred.ip,
        dimmed: shouldDim && !highlightedNodeIds.has(node.id)
      }
    };
  });

  const nodeMap = new Map(canvasNodes.map((n) => [n.id, n]));

  const canvasEdges: CanvasEdge[] = edges.map((edge) => {
    const isHighlighted = highlightedEdgeIds.has(edge.id);
    const hasAnyHighlight = highlightedEdgeIds.size > 0;
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);

    // Protocol color mapping
    let edgeColor = "#f59e0b"; // Gold SMB pipe default
    let edgeClass = "cobalt-edge-smb";
    let isAnimated = false;

    const edgeTypeLower = (edge.type || "").toLowerCase();
    const labelLower = (edge.label || "").toLowerCase();

    if (edgeTypeLower.includes("egress") || labelLower.includes("https") || labelLower.includes("http")) {
      edgeColor = "#10b981"; // Emerald green egress
      edgeClass = "cobalt-edge-egress";
    } else if (edgeTypeLower.includes("session") || labelLower.includes("ssh") || labelLower.includes("interactive")) {
      edgeColor = "#06b6d4"; // Cyan session
      edgeClass = "cobalt-edge-session";
    } else if (edgeTypeLower.includes("reverse") || edge.dashed) {
      edgeColor = "#eab308"; // Yellow dashed reverse
      edgeClass = "cobalt-edge-reverse";
      isAnimated = true;
    }

    let sourceHandle = "right-source";
    let targetHandle = "left-target";

    if (edgeTypeLower.includes("reverse") || edge.dashed) {
      sourceHandle = "bottom-source";
      targetHandle = "bottom-target";
    } else if (sourceNode && targetNode) {
      if (sourceNode.position.x < targetNode.position.x) {
        sourceHandle = "right-source";
        targetHandle = "left-target";
      } else if (sourceNode.position.x > targetNode.position.x) {
        sourceHandle = "left-source";
        targetHandle = "right-target";
      } else {
        sourceHandle = "bottom-source";
        targetHandle = "top-target";
      }
    }

    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle,
      targetHandle,
      type: "smoothstep",
      animated: isAnimated || isHighlighted,
      className: edgeClass,
      // Edge labels removed per operator instructions: avoids clutter, overlaps, and unreadable thick text
      label: undefined,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 14,
        height: 14,
        color: edgeColor
      },
      style: {
        stroke: edgeColor,
        strokeWidth: isHighlighted ? 3 : 2.2,
        opacity: hasAnyHighlight && !isHighlighted ? 0.2 : 0.95
      }
    };
  });

  return { nodes: canvasNodes, edges: canvasEdges };
}

function safeValueText(value: SafeGraphValue): string {
  if (value === null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(safeValueText).join(", ");
  return Object.entries(value).map(([key, item]) => `${key}: ${safeValueText(item)}`).join(" · ");
}

function CampaignSelect({
  campaigns,
  value,
  onChange
}: {
  campaigns: Campaign[];
  value: string;
  onChange: (campaignId: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-xs font-mono text-zinc-300">
      <span className="text-zinc-400">Campaign:</span>
      <select
        className="bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-red-500"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">Select campaign</option>
        {campaigns.map((campaign) => (
          <option key={campaign.id} value={campaign.id}>
            {campaign.name || campaign.id}
          </option>
        ))}
      </select>
    </label>
  );
}

function FlowControlsBridge({ onZoomIn, onZoomOut, onFitView }: {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitView: () => void;
}) {
  return null;
}

function CobaltGraphInner({
  graph,
  highlightedNodeIds,
  highlightedEdgeIds,
  onSelect,
  selection,
  bindControls
}: {
  graph: SafeGraph;
  highlightedNodeIds: Set<string>;
  highlightedEdgeIds: Set<string>;
  onSelect: (selection: GraphSelection) => void;
  selection: GraphSelection;
  bindControls?: (controls: { zoomIn: () => void; zoomOut: () => void; fitView: () => void }) => void;
}) {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  const controlsBound = useRef(false);

  useEffect(() => {
    if (bindControls && !controlsBound.current) {
      controlsBound.current = true;
      bindControls({
        zoomIn: () => zoomIn({ duration: 250 }),
        zoomOut: () => zoomOut({ duration: 250 }),
        fitView: () => fitView({ padding: 0.18, duration: 300 })
      });
    }
  }, [bindControls, zoomIn, zoomOut, fitView]);

  const canvas = useMemo(
    () =>
      cobaltPivotLayout(
        graph,
        highlightedNodeIds,
        highlightedEdgeIds,
        selection?.kind === "node" ? selection.value.id : null
      ),
    [graph, highlightedEdgeIds, highlightedNodeIds, selection]
  );

  const nodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const edgeById = useMemo(() => new Map(graph.edges.map((edge) => [edge.id, edge])), [graph.edges]);

  return (
    <div className="cobalt-canvas-area" aria-label="Cobalt Strike Pivot Graph">
      <ReactFlow
        nodes={canvas.nodes}
        edges={canvas.edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.25}
        maxZoom={2.0}
        onNodeClick={(_event, node) => {
          const selectedNode = nodeById.get(node.id);
          if (selectedNode) onSelect({ kind: "node", value: selectedNode });
        }}
        onEdgeClick={(_event, edge) => {
          const selectedEdge = edgeById.get(edge.id);
          if (selectedEdge) onSelect({ kind: "edge", value: selectedEdge });
        }}
        proOptions={{ hideAttribution: true }}
      />
    </div>
  );
}

export default function GraphPage({
  campaignId,
  onCampaignIdChange
}: {
  campaignId: string;
  onCampaignIdChange: (campaignId: string) => void;
}) {
  const queryClient = useQueryClient();
  const campaigns = useQuery({ queryKey: ["campaigns"], queryFn: api.campaigns });

  useEffect(() => {
    if (!campaignId && campaigns.data && campaigns.data.length > 0) {
      onCampaignIdChange(campaigns.data[0].id);
    }
  }, [campaignId, campaigns.data, onCampaignIdChange]);

  const graphQuery = useQuery({
    queryKey: ["graph", campaignId],
    queryFn: () => api.graph(campaignId),
    enabled: Boolean(campaignId)
  });
  const pathsQuery = useQuery({
    queryKey: ["attack-paths", campaignId],
    queryFn: () => api.attackPaths(campaignId),
    enabled: Boolean(campaignId)
  });

  const [showAttackPathsDialog, setShowAttackPathsDialog] = useState(false);
  const [showIngestDialog, setShowIngestDialog] = useState(false);
  const [filters, setFilters] = useState<GraphFilters>({ nodeTypes: [], severity: "all", activePathOnly: false });
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [selectedPathIndex, setSelectedPathIndex] = useState<number | null>(null);
  const [jsonPath, setJsonPath] = useState("");
  const [ingestNotice, setIngestNotice] = useState("");

  // Ingest Mutation
  const ingest = useMutation({
    mutationFn: () => api.ingestBloodhound(campaignId, jsonPath.trim()),
    onSuccess: async () => {
      setIngestNotice("Import request completed. Graph snapshot updated.");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["graph", campaignId] }),
        queryClient.invalidateQueries({ queryKey: ["attack-paths", campaignId] })
      ]);
    }
  });

  const currentCampaign = useMemo(() => {
    return campaigns.data?.find((c) => c.id === campaignId) || null;
  }, [campaigns.data, campaignId]);

  const [useSampleTopology, setUseSampleTopology] = useState(false);
  const [flowControls, setFlowControls] = useState<{
    zoomIn: () => void;
    zoomOut: () => void;
    fitView: () => void;
  } | null>(null);

  const safeApiGraph = useMemo(() => toSafeGraph(graphQuery.data), [graphQuery.data]);
  const paths = useMemo(() => (Array.isArray(pathsQuery.data?.paths) ? pathsQuery.data.paths : []), [pathsQuery.data]);

  // Determine active graph: By default uses real campaign graph adapted to Cobalt model.
  // When user toggles Demo Sample, displays the reference screenshot topology.
  const activeGraph = useMemo(() => {
    if (useSampleTopology) {
      return generateCobaltPivotTopology();
    }
    return adaptApiGraphToCobalt(safeApiGraph, currentCampaign);
  }, [safeApiGraph, currentCampaign, useSampleTopology]);

  const selectedPath = selectedPathIndex === null ? null : paths[selectedPathIndex] ?? null;
  const highlight = useMemo(() => getPathHighlight(selectedPath, activeGraph), [activeGraph, selectedPath]);
  const filteredGraph = useMemo(() => filterGraph(activeGraph, filters, highlight), [activeGraph, filters, highlight]);

  function chooseCampaign(nextCampaignId: string): void {
    onCampaignIdChange(nextCampaignId);
    setSelection(null);
    setSelectedPathIndex(null);
    setFilters({ nodeTypes: [], severity: "all", activePathOnly: false });
    setIngestNotice("");
  }

  return (
    <div className="cobalt-graph-container" aria-label="Cobalt Strike C2 Console">
      {/* Authentic Cobalt Strike Desktop Window Title Bar */}
      <div className="cobalt-window-titlebar">
        <div className="cobalt-window-title">
          <Shield size={13} />
          <span>Cobalt Strike</span>
        </div>
        <div className="cobalt-window-controls">
          <button className="cobalt-win-btn" type="button" title="Minimize">─</button>
          <button className="cobalt-win-btn" type="button" title="Maximize">▢</button>
          <button className="cobalt-win-btn close" type="button" title="Close">✕</button>
        </div>
      </div>

      {/* Classic Cobalt Strike Desktop Window Menu Bar */}
      <div className="cobalt-menubar">
        <div className="cobalt-menubar-items">
          <span className="cobalt-menu-item font-bold">Cobalt Strike</span>
          <span className="cobalt-menu-item" onClick={() => setShowAttackPathsDialog(true)} title="View Attack Paths">View</span>
          <span className="cobalt-menu-item" onClick={() => setShowIngestDialog(true)} title="Ingest BloodHound Graph Dump">Attacks</span>
          <span className="cobalt-menu-item">Reporting</span>
          <span className="cobalt-menu-item">Help</span>
        </div>

        <div className="cobalt-menubar-right">
          <label className="flex items-center gap-1.5 text-[11px] text-zinc-900 font-medium">
            <span>Campaign:</span>
            <select
              className="bg-white border border-zinc-500 text-black text-[11px] px-1 py-0.5 rounded-none font-sans"
              value={campaignId}
              onChange={(e) => chooseCampaign(e.target.value)}
            >
              {campaigns.data?.map((c) => (
                <option key={c.id} value={c.id}>{c.name || c.id}</option>
              ))}
            </select>
          </label>
          <span className="text-zinc-600">|</span>
          <span className="text-zinc-900 font-semibold font-mono text-[11px]">
            {filteredGraph.nodes.length} Hosts / {filteredGraph.edges.length} Links
          </span>
          <span className="text-zinc-600">|</span>
          <button
            className={`cobalt-tool-btn text-[10px] py-0 px-1.5 ${useSampleTopology ? "active font-bold" : ""}`}
            onClick={() => setUseSampleTopology((v) => !v)}
            type="button"
            title="Toggle between Live Campaign data and Reference Demo Topology"
          >
            {useSampleTopology ? "Mode: DEMO SAMPLE" : "Mode: LIVE CAMPAIGN"}
          </button>
        </div>
      </div>

      {/* Authentic Cobalt Strike Action Icon Toolbar */}
      <div className="cobalt-toolbar">
        <div className="cobalt-toolbar-left">
          <button
            className="cobalt-tool-btn font-bold"
            onClick={() => flowControls?.zoomIn()}
            type="button"
            title="Zoom In"
          >
            +
          </button>
          <button
            className="cobalt-tool-btn font-bold"
            onClick={() => flowControls?.zoomOut()}
            type="button"
            title="Zoom Out"
          >
            -
          </button>
          <button
            className="cobalt-tool-btn"
            onClick={() => flowControls?.fitView()}
            type="button"
            title="Reset View"
          >
            ⛶
          </button>
          <div className="cobalt-toolbar-sep" />
          <button
            className="cobalt-tool-btn"
            type="button"
            title="Attack Paths Explorer"
            onClick={() => setShowAttackPathsDialog(true)}
          >
            ▦
          </button>
          <button className="cobalt-tool-btn active" type="button" title="Pivot Graph">[P]</button>
          <button
            className="cobalt-tool-btn"
            onClick={() => void graphQuery.refetch()}
            type="button"
            title="Refresh / Sync"
          >
            [R]
          </button>
          <div className="cobalt-toolbar-sep" />
          <button className="cobalt-tool-btn" type="button" title="Session Preferences">[S]</button>
          <button className="cobalt-tool-btn" type="button" title="Beacon Sleep Delay">[Z]</button>
          <button className="cobalt-tool-btn" type="button" title="Link / Unlink Session">[L]</button>
          <button
            className="cobalt-tool-btn"
            type="button"
            title="Import BloodHound AD Graph Dump"
            onClick={() => setShowIngestDialog(true)}
          >
            [I]
          </button>
          <div className="cobalt-toolbar-sep" />
          <button
            className={`cobalt-tool-btn ${filters.activePathOnly ? "active font-bold" : ""}`}
            onClick={() => setFilters((f) => ({ ...f, activePathOnly: !f.activePathOnly }))}
            type="button"
          >
            Active Pivots Only
          </button>
          {selection && (
            <button
              className="cobalt-tool-btn text-red-700 font-bold"
              onClick={() => setSelection(null)}
              type="button"
            >
              Clear Selection
            </button>
          )}
        </div>

        {/* Legend matching Cobalt Strike visual indicators */}
        <div className="cobalt-toolbar-right">
          <div className="cobalt-badge-legend">
            <div className="cobalt-legend-item">
              <span className="cobalt-legend-dot system" />
              <span>SYSTEM *</span>
            </div>
            <div className="cobalt-legend-item">
              <span className="cobalt-legend-dot beacon" />
              <span>Beacon</span>
            </div>
            <div className="cobalt-legend-item">
              <span className="cobalt-legend-dot pivot" />
              <span>SMB Pivot</span>
            </div>
            <div className="cobalt-legend-item">
              <span className="cobalt-legend-dot gateway" />
              <span>Firewall</span>
            </div>
          </div>
        </div>
      </div>

      {/* Split View: Graph Canvas (Top) & Beacon Terminal (Bottom) */}
      <div className="cobalt-split-view">
        <ReactFlowProvider>
          <CobaltGraphInner
            graph={filteredGraph}
            highlightedEdgeIds={highlight.edgeIds}
            highlightedNodeIds={highlight.nodeIds}
            onSelect={setSelection}
            selection={selection}
            bindControls={setFlowControls}
          />
        </ReactFlowProvider>

        {/* Authentic Textured Splitter Bar with 3-Ripple Grip */}
        <div className="cobalt-splitter-bar" title="Drag to adjust terminal split">
          <div className="cobalt-splitter-grip">
            <span />
            <span />
            <span />
          </div>
        </div>

        {/* Bottom Interactive Cobalt Strike Beacon Console */}
        <CobaltSessionDock
          selectedNodeId={selection?.kind === "node" ? selection.value.id : null}
          selectedNodeLabel={selection?.kind === "node" ? selection.value.label : null}
          campaignId={campaignId}
          campaignName={currentCampaign?.name}
          activeNodes={filteredGraph.nodes}
          onNodeSelect={(id) => {
            const node = activeGraph.nodes.find((n) => n.id === id);
            if (node) setSelection({ kind: "node", value: node });
          }}
        />
      </div>

      {/* Java Swing Modal Dialog: Attack Paths Explorer */}
      {showAttackPathsDialog && (
        <div className="cobalt-dialog-overlay" onClick={() => setShowAttackPathsDialog(false)}>
          <div className="cobalt-dialog-window" onClick={(e) => e.stopPropagation()}>
            <div className="cobalt-dialog-titlebar">
              <span>Attack Paths Explorer</span>
              <button className="cobalt-win-btn close" onClick={() => setShowAttackPathsDialog(false)} type="button">✕</button>
            </div>
            <div className="cobalt-dialog-body">
              <div className="mb-2 text-[11px] text-zinc-800">
                Calculated lateral movement paths for active engagement campaign:
              </div>
              {paths.length === 0 ? (
                <div className="p-4 text-center bg-white border border-zinc-400 text-zinc-600 mb-3 font-mono text-[11px]">
                  No attack paths generated yet. Ingest BloodHound AD data or run automated reconnaissance.
                </div>
              ) : (
                <div className="max-h-60 overflow-y-auto border border-zinc-500 bg-white mb-3 divide-y divide-zinc-200">
                  {paths.map((path, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 cursor-pointer text-[11px] ${
                        selectedPathIndex === idx ? "bg-blue-100 font-semibold" : "hover:bg-zinc-100"
                      }`}
                      onClick={() => {
                        setSelectedPathIndex(selectedPathIndex === idx ? null : idx);
                        setShowAttackPathsDialog(false);
                      }}
                    >
                      <div className="flex justify-between text-zinc-700 font-mono text-[10px] mb-0.5">
                        <span>Path #{idx + 1} ({path.steps.length} lateral steps)</span>
                        <span className="text-red-600 font-bold">Score: {path.total_score ?? "High"}</span>
                      </div>
                      <div className="text-black">{attackPathSummary(path)}</div>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex justify-end gap-2">
                {selectedPathIndex !== null && (
                  <button
                    className="cobalt-btn-swing"
                    onClick={() => setSelectedPathIndex(null)}
                    type="button"
                  >
                    Clear Path Highlight
                  </button>
                )}
                <button
                  className="cobalt-btn-swing"
                  onClick={() => setShowAttackPathsDialog(false)}
                  type="button"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Java Swing Modal Dialog: Ingest BloodHound JSON */}
      {showIngestDialog && (
        <div className="cobalt-dialog-overlay" onClick={() => setShowIngestDialog(false)}>
          <div className="cobalt-dialog-window" onClick={(e) => e.stopPropagation()}>
            <div className="cobalt-dialog-titlebar">
              <span>Import BloodHound / SharpHound Data</span>
              <button className="cobalt-win-btn close" onClick={() => setShowIngestDialog(false)} type="button">✕</button>
            </div>
            <form
              className="cobalt-dialog-body"
              onSubmit={(e) => {
                e.preventDefault();
                setIngestNotice("");
                if (jsonPath.trim()) ingest.mutate();
              }}
            >
              <div className="mb-2 text-[11px] text-zinc-800">
                Specify server filesystem path to BloodHound JSON export file:
              </div>
              <input
                className="cobalt-swing-input mb-3"
                value={jsonPath}
                onChange={(e) => setJsonPath(e.target.value)}
                placeholder="C:\\recon\\bloodhound_dump.json"
                required
                autoFocus
              />
              {ingestNotice && (
                <div className="mb-3 p-2 bg-green-100 border border-green-500 text-green-800 font-mono text-[10px]">
                  {ingestNotice}
                </div>
              )}
              {ingest.isError && (
                <div className="mb-3 p-2 bg-red-100 border border-red-500 text-red-800 font-mono text-[10px]">
                  Failed to ingest BloodHound data. Verify server file path.
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button
                  className="cobalt-btn-swing font-bold"
                  type="submit"
                  disabled={ingest.isPending}
                >
                  {ingest.isPending ? "Importing..." : "Import"}
                </button>
                <button
                  className="cobalt-btn-swing"
                  type="button"
                  onClick={() => setShowIngestDialog(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
