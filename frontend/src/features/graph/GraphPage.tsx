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

export interface TrackedPathway {
  activeNodeId: string;
  isLocked: boolean;
  nodeIds: Set<string>;
  edgeIds: Set<string>;
  hopCount: number;
}

/**
 * Computes the full attack chain lineage (upstream ancestors + downstream lateral pivots)
 * for a target focus node.
 */
function computeRelevantPathway(
  targetNodeId: string,
  edges: SafeGraphEdge[],
  isLocked: boolean
): TrackedPathway {
  const nodeIds = new Set<string>([targetNodeId]);
  const edgeIds = new Set<string>();

  const incomingMap = new Map<string, SafeGraphEdge[]>();
  const outgoingMap = new Map<string, SafeGraphEdge[]>();

  edges.forEach((edge) => {
    if (!incomingMap.has(edge.target)) incomingMap.set(edge.target, []);
    incomingMap.get(edge.target)!.push(edge);

    if (!outgoingMap.has(edge.source)) outgoingMap.set(edge.source, []);
    outgoingMap.get(edge.source)!.push(edge);
  });

  // Upstream Ancestry Traversal: trace backward along incoming edges all the way to roots (Firewall/Ingress)
  const upQueue = [targetNodeId];
  const upVisited = new Set<string>([targetNodeId]);
  while (upQueue.length > 0) {
    const curr = upQueue.shift()!;
    const inEdges = incomingMap.get(curr) || [];
    for (const edge of inEdges) {
      edgeIds.add(edge.id);
      nodeIds.add(edge.source);
      if (!upVisited.has(edge.source)) {
        upVisited.add(edge.source);
        upQueue.push(edge.source);
      }
    }
  }

  // Downstream Branch Traversal: trace forward along outgoing edges to all lateral pivot targets
  const downQueue = [targetNodeId];
  const downVisited = new Set<string>([targetNodeId]);
  while (downQueue.length > 0) {
    const curr = downQueue.shift()!;
    const outEdges = outgoingMap.get(curr) || [];
    for (const edge of outEdges) {
      edgeIds.add(edge.id);
      nodeIds.add(edge.target);
      if (!downVisited.has(edge.target)) {
        downVisited.add(edge.target);
        downQueue.push(edge.target);
      }
    }
  }

  return {
    activeNodeId: targetNodeId,
    isLocked,
    nodeIds,
    edgeIds,
    hopCount: edgeIds.size
  };
}

/**
 * Cobalt Strike Hierarchical Pivot Graph Layout Generator
 * Positions Firewall/Ingress on the left, Pivot Workstations in the center,
 * and Domain Controllers/Crown Jewels on the right.
 */
function cobaltPivotLayout(
  graph: SafeGraph,
  highlightedNodeIds: Set<string>,
  highlightedEdgeIds: Set<string>,
  selectedNodeId?: string | null,
  trackedPathway?: TrackedPathway | null
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
  const nodes = graph.nodes;
  const edges = graph.edges;

  const isDemoTopology = nodes.length <= 9 && nodes.every((n) => Boolean(FIXED_COORDINATES[n.id]));
  const dynamicCoords = new Map<string, { x: number; y: number }>();

  if (!isDemoTopology) {
    // 1. Build adjacency graph for safe BFS and stage derivation
    const inDegree = new Map<string, number>();
    const outgoingEdges = new Map<string, string[]>();
    nodes.forEach((n) => {
      inDegree.set(n.id, 0);
      outgoingEdges.set(n.id, []);
    });
    edges.forEach((e) => {
      if (inDegree.has(e.target)) {
        inDegree.set(e.target, (inDegree.get(e.target) ?? 0) + 1);
      }
      outgoingEdges.get(e.source)?.push(e.target);
    });

    // 2. Identify roots: firewall / perimeter ingress or nodes with in-degree 0
    const depthMap = new Map<string, number>();
    const visited = new Set<string>();
    const queue: string[] = [];

    nodes.forEach((n) => {
      const isFw = n.type === "firewall" || n.id.includes("firewall") || n.id.includes("ingress");
      if (isFw || (inDegree.get(n.id) ?? 0) === 0) {
        depthMap.set(n.id, 0);
        visited.add(n.id);
        queue.push(n.id);
      }
    });

    if (queue.length === 0 && nodes.length > 0) {
      depthMap.set(nodes[0].id, 0);
      visited.add(nodes[0].id);
      queue.push(nodes[0].id);
    }

    // 3. BFS traversal to calculate horizontal progression depth
    while (queue.length > 0) {
      const currId = queue.shift()!;
      const currDepth = depthMap.get(currId) ?? 0;
      const targets = outgoingEdges.get(currId) ?? [];
      for (const targetId of targets) {
        if (!visited.has(targetId)) {
          visited.add(targetId);
          depthMap.set(targetId, currDepth + 1);
          queue.push(targetId);
        }
      }
    }

    // 4. Assign semantic depths for any disconnected or isolated target nodes
    nodes.forEach((n) => {
      if (!depthMap.has(n.id)) {
        const inf = inferCobaltNodeData(n);
        const isDc = n.type === "dc" || n.label.toLowerCase().includes("dc") || inf.os === "windows-server";
        const isElevated = inf.privilege === "system" || inf.privilege === "admin";
        if (isDc) {
          depthMap.set(n.id, 4); // Far right: Crown Jewels / Domain Controllers
        } else if (isElevated) {
          depthMap.set(n.id, 3); // Internal Servers & Footholds
        } else if (inf.status === "active") {
          depthMap.set(n.id, 2); // Lateral Workstations
        } else {
          depthMap.set(n.id, 1); // DMZ / Perimeter targets
        }
      }
    });

    // 5. Ensure Crown Jewels and Domain Controllers always sit on the far-right tier
    const calculatedMaxDepth = Math.max(...Array.from(depthMap.values()), 1);
    nodes.forEach((n) => {
      const inf = inferCobaltNodeData(n);
      const isDc = n.type === "dc" || n.label.toLowerCase().includes("dc") || inf.os === "windows-server";
      if (isDc) {
        depthMap.set(n.id, Math.max(depthMap.get(n.id) ?? 0, calculatedMaxDepth));
      }
    });

    // 6. Group nodes by horizontal depth tiers
    const stageBuckets = new Map<number, SafeGraphNode[]>();
    nodes.forEach((n) => {
      const d = depthMap.get(n.id) ?? 0;
      if (!stageBuckets.has(d)) stageBuckets.set(d, []);
      stageBuckets.get(d)!.push(n);
    });

    const sortedDepths = Array.from(stageBuckets.keys()).sort((a, b) => a - b);

    // 7. Horizontal Layout Discipline (Menyamping):
    // Vertical height is strictly capped at MAX_ROWS (3 rows) so nodes NEVER cascade downwards!
    // Additional nodes in the same stage expand horizontally into sub-columns side-by-side.
    const MAX_ROWS = 3;
    const COL_PITCH = 240; // Horizontal spacing between adjacent node centers
    const ROW_PITCH = 150; // Vertical pitch allowing room for monitor + stand + 2-line badge
    const STAGE_GAP = 55;  // Visual breathing gap between major architectural stages
    const START_X = 50;
    const START_Y = 50;

    let cursorX = START_X;

    sortedDepths.forEach((d) => {
      const stageNodes = stageBuckets.get(d)!;

      // Sort within stage for visual hierarchy and consistent lateral alignment:
      // Firewalls first, then SYSTEM/Admin elevations, then user beacons, then mapped targets
      stageNodes.sort((a, b) => {
        if (a.type === "firewall") return -1;
        if (b.type === "firewall") return 1;
        const aInf = inferCobaltNodeData(a);
        const bInf = inferCobaltNodeData(b);
        const prio = (priv?: string) => (priv === "system" ? 3 : priv === "admin" ? 2 : priv === "user" ? 1 : 0);
        const diff = prio(bInf.privilege) - prio(aInf.privilege);
        if (diff !== 0) return diff;
        return a.label.localeCompare(b.label);
      });

      const count = stageNodes.length;
      const numSubCols = Math.max(1, Math.ceil(count / MAX_ROWS));

      for (let i = 0; i < count; i++) {
        const node = stageNodes[i];
        const subCol = Math.floor(i / MAX_ROWS);
        const row = i % MAX_ROWS;

        // Vertically center columns that have fewer than MAX_ROWS items
        const itemsInThisSubCol = Math.min(MAX_ROWS, count - subCol * MAX_ROWS);
        const verticalCenterOffset = ((MAX_ROWS - itemsInThisSubCol) * ROW_PITCH) / 2;

        const x = cursorX + subCol * COL_PITCH;
        const y = START_Y + row * ROW_PITCH + verticalCenterOffset;

        dynamicCoords.set(node.id, { x, y });
      }

      cursorX += numSubCols * COL_PITCH + STAGE_GAP;
    });
  }

  const hasTrackedPathway = Boolean(trackedPathway && trackedPathway.nodeIds.size > 0);

  const canvasNodes: CanvasNode[] = nodes.map((node) => {
    const inferred = inferCobaltNodeData(node);
    let x: number;
    let y: number;

    if (isDemoTopology && FIXED_COORDINATES[node.id]) {
      x = FIXED_COORDINATES[node.id].x;
      y = FIXED_COORDINATES[node.id].y;
    } else {
      const coord = dynamicCoords.get(node.id) ?? { x: 50, y: 150 };
      x = coord.x;
      y = coord.y;
    }

    const nodeType = inferred.os === "firewall" ? "pivotFirewall" : "pivotComputer";
    const isNodeSelected = selectedNodeId ? node.id === selectedNodeId : false;
    const isNodeInPathway = trackedPathway ? trackedPathway.nodeIds.has(node.id) : true;
    const isDimmed = (shouldDim && !highlightedNodeIds.has(node.id)) || (hasTrackedPathway && !isNodeInPathway);

    return {
      id: node.id,
      type: nodeType,
      position: { x, y },
      selected: isNodeSelected,
      zIndex: isNodeSelected ? 35 : (hasTrackedPathway && isNodeInPathway ? 25 : 10),
      data: {
        label: node.label,
        subLabel: inferred.subLabel,
        os: inferred.os,
        privilege: inferred.privilege,
        status: inferred.status,
        process: inferred.process,
        pid: inferred.pid,
        ip: inferred.ip,
        dimmed: isDimmed,
        isTracked: hasTrackedPathway && isNodeInPathway
      }
    };
  });

  const nodeMap = new Map(canvasNodes.map((n) => [n.id, n]));

  const canvasEdges: CanvasEdge[] = edges.map((edge) => {
    const isHighlighted = highlightedEdgeIds.has(edge.id);
    const hasAnyHighlight = highlightedEdgeIds.size > 0;
    const isTrackedEdge = trackedPathway ? trackedPathway.edgeIds.has(edge.id) : false;
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);

    // Protocol color mapping with clear visual semantics
    let edgeColor = "#f59e0b"; // Warm Amber Gold (SMB Named Pipe default)
    let edgeClass = "cobalt-edge-smb";

    const edgeTypeLower = (edge.type || "").toLowerCase();
    const labelLower = (edge.label || "").toLowerCase();
    const isTargetDc =
      targetNode?.data.os === "windows-server" ||
      (targetNode?.id || "").toLowerCase().includes("dc") ||
      (targetNode?.data.label || "").toLowerCase().includes("dc");

    if (edgeTypeLower.includes("egress") || labelLower.includes("https") || labelLower.includes("http")) {
      edgeColor = "#10b981"; // Emerald green egress
      edgeClass = "cobalt-edge-egress";
    } else if (edgeTypeLower.includes("session") || labelLower.includes("ssh") || labelLower.includes("interactive")) {
      edgeColor = "#06b6d4"; // Electric Cyan interactive session
      edgeClass = "cobalt-edge-session";
    } else if (isTargetDc) {
      edgeColor = "#ef4444"; // Crimson Red high-value attack link to Domain Controller
      edgeClass = "cobalt-edge-crown";
    } else if (edgeTypeLower.includes("reverse") || edge.dashed) {
      edgeColor = "#eab308"; // Yellow dashed reverse
      edgeClass = "cobalt-edge-reverse";
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
        sourceHandle = sourceNode.position.y < targetNode.position.y ? "bottom-source" : "top-source";
        targetHandle = sourceNode.position.y < targetNode.position.y ? "top-target" : "bottom-target";
      }
    }

    // Interactive focus state:
    // When pathway tracking is active (locked via click or previewed via hover):
    // Edges in the pathway pop with 4.0px thickness, flowing pulse stream, and glowing drop-shadow.
    // Unrelated edges dim to 0.08 opacity.
    const strokeWidth = isTrackedEdge ? 4.0 : isHighlighted ? 3.0 : 2.0;
    const opacity = hasTrackedPathway
      ? (isTrackedEdge ? 1.0 : 0.08)
      : (hasAnyHighlight && !isHighlighted ? 0.2 : 0.90);

    const markerColor = isTrackedEdge ? (isTargetDc ? "#ff3333" : edgeColor) : edgeColor;

    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle,
      targetHandle,
      type: "default", // Smooth curved Bezier eliminating overlapping 90-degree rail tracks
      animated: true,  // Flowing dash stream communicates directional movement instantly
      className: `${edgeClass}${isTrackedEdge ? " edge-hover-pulse" : ""}`,
      label: undefined,
      zIndex: isTrackedEdge ? 6 : (isHighlighted ? 4 : 1),
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: isTrackedEdge ? 22 : 18,
        height: isTrackedEdge ? 22 : 18,
        color: markerColor
      },
      style: {
        stroke: edgeColor,
        strokeWidth,
        opacity,
        filter: isTrackedEdge ? `drop-shadow(0 0 10px ${edgeColor})` : undefined
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
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  useEffect(() => {
    if (bindControls && !controlsBound.current) {
      controlsBound.current = true;
      bindControls({
        zoomIn: () => zoomIn({ duration: 250 }),
        zoomOut: () => zoomOut({ duration: 250 }),
        fitView: () => fitView({ padding: 0.14, duration: 300 })
      });
    }
  }, [bindControls, zoomIn, zoomOut, fitView]);

  // Priority: Clicked Selected Node > Hovered Node (preview when nothing is selected)
  const isLocked = selection?.kind === "node";
  const activeFocusNodeId = isLocked ? selection.value.id : hoveredNodeId;

  const trackedPathway = useMemo(() => {
    if (!activeFocusNodeId) return null;
    return computeRelevantPathway(activeFocusNodeId, graph.edges, isLocked);
  }, [activeFocusNodeId, graph.edges, isLocked]);

  const canvas = useMemo(
    () =>
      cobaltPivotLayout(
        graph,
        highlightedNodeIds,
        highlightedEdgeIds,
        selection?.kind === "node" ? selection.value.id : null,
        trackedPathway
      ),
    [graph, highlightedEdgeIds, highlightedNodeIds, selection, trackedPathway]
  );

  const nodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const edgeById = useMemo(() => new Map(graph.edges.map((edge) => [edge.id, edge])), [graph.edges]);

  // Keyboard shortcut: ESC to clear selection and unlock pathway
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && selection) {
        onSelect(null);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selection, onSelect]);

  const activeNodeData = selection?.kind === "node" ? selection.value : null;

  return (
    <div className="cobalt-canvas-area" aria-label="Cobalt Strike Pivot Graph">
      {/* Tactical Locked Pathway Tracking HUD Banner */}
      {isLocked && trackedPathway && (
        <div className="cobalt-track-hud" role="status" aria-live="polite">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span className="text-amber-300 font-bold uppercase tracking-wider">
              PATHWAY LOCKED:
            </span>
            <span className="text-white font-semibold">
              {activeNodeData?.label || activeFocusNodeId}
            </span>
            <span className="text-zinc-600">|</span>
            <span className="text-emerald-400 font-mono font-medium">
              {trackedPathway.nodeIds.size} NODES
            </span>
            <span className="text-zinc-600">|</span>
            <span className="text-cyan-400 font-mono font-medium">
              {trackedPathway.hopCount} HOPS
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-zinc-400 font-mono hidden sm:inline">
              [Zoom/Pan freely · Click canvas or ESC to unlock]
            </span>
            <button
              type="button"
              className="cobalt-hud-unlock-btn"
              onClick={() => onSelect(null)}
              title="Unlock and return to full topology"
            >
              CLEAR TRACK [ESC]
            </button>
          </div>
        </div>
      )}

      <ReactFlow
        nodes={canvas.nodes}
        edges={canvas.edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.14 }}
        minZoom={0.25}
        maxZoom={2.0}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={true}
        nodeClickDistance={8}
        paneClickDistance={8}
        onPaneClick={() => {
          if (selection) onSelect(null);
        }}
        onPaneMouseEnter={() => {
          if (!isLocked) setHoveredNodeId(null);
        }}
        onNodeMouseEnter={(_event, node) => {
          if (!isLocked) {
            setHoveredNodeId((curr) => (curr === node.id ? curr : node.id));
          }
        }}
        onNodeMouseLeave={(_event, node) => {
          if (!isLocked) {
            setHoveredNodeId((curr) => (curr === node.id ? null : curr));
          }
        }}
        onNodeClick={(_event, node) => {
          const selectedNode = nodeById.get(node.id);
          if (selectedNode) {
            if (selection?.kind === "node" && selection.value.id === node.id) {
              onSelect(null);
            } else {
              onSelect({ kind: "node", value: selectedNode });
            }
          }
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
