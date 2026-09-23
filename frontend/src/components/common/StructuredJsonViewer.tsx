import { useState, useMemo } from "react";
import {
  Copy,
  CheckCircle2,
  ChevronRight,
  ChevronDown,
  Search,
  Code2,
  ListTree,
  Table as TableIcon,
  Minimize2,
  Maximize2,
  WrapText,
  Filter,
  Sparkles
} from "lucide-react";

export interface StructuredJsonViewerProps {
  data: unknown;
  title?: string;
  defaultExpandedDepth?: number;
  maxHeightClass?: string;
  className?: string;
  showSummaryStrip?: boolean;
}

export function StructuredJsonViewer({
  data,
  title,
  defaultExpandedDepth = 1,
  maxHeightClass = "max-h-80",
  className = "",
  showSummaryStrip = true
}: StructuredJsonViewerProps) {
  const [viewMode, setViewMode] = useState<"tree" | "table" | "raw">("tree");
  const [searchTerm, setSearchTerm] = useState("");
  const [copied, setCopied] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({});
  const [forceExpandAll, setForceExpandAll] = useState<boolean | null>(null);
  const [wrapRaw, setWrapRaw] = useState(true);

  const rawJson = useMemo(() => {
    try {
      return JSON.stringify(data, null, 2) ?? "{}";
    } catch {
      return String(data);
    }
  }, [data]);

  const byteSize = useMemo(() => {
    const bytes = new Blob([rawJson]).size;
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  }, [rawJson]);

  const keyCount = useMemo(() => {
    if (data && typeof data === "object" && !Array.isArray(data)) {
      return Object.keys(data).length;
    }
    if (Array.isArray(data)) {
      return data.length;
    }
    return 1;
  }, [data]);

  // Extract executive key metrics (top-level scalar primitives and short arrays) for fast scanning
  const summaryPills = useMemo(() => {
    if (!showSummaryStrip || !data || typeof data !== "object" || Array.isArray(data)) {
      return [];
    }
    const record = data as Record<string, unknown>;
    const pills: { key: string; value: string; tone: "green" | "amber" | "cyan" | "purple" | "zinc" }[] = [];

    const priorityKeys = [
      "status", "outcome", "target", "host", "port", "module_id",
      "duration_ms", "score", "severity", "findings_count", "open_ports"
    ];

    // First collect known priority keys
    for (const k of priorityKeys) {
      if (k in record && record[k] !== undefined && record[k] !== null) {
        const val = record[k];
        let str = String(val);
        let tone: "green" | "amber" | "cyan" | "purple" | "zinc" = "zinc";

        if (k === "status" || k === "outcome") {
          tone = str.includes("fail") || str.includes("err") ? "amber" : "green";
        } else if (k === "target" || k === "host") {
          tone = "cyan";
        } else if (k === "severity") {
          tone = str.includes("high") || str.includes("crit") ? "amber" : "purple";
        } else if (k === "open_ports" && Array.isArray(val)) {
          str = `[${val.slice(0, 4).join(", ")}${val.length > 4 ? "..." : ""}]`;
          tone = "cyan";
        } else if (typeof val === "number") {
          tone = "amber";
        }
        pills.push({ key: k, value: str, tone });
      }
    }

    // If few priority keys found, add up to 4 other primitive properties
    if (pills.length < 4) {
      for (const [k, val] of Object.entries(record)) {
        if (pills.some((p) => p.key === k)) continue;
        if (typeof val === "string" || typeof val === "number" || typeof val === "boolean") {
          const str = String(val);
          if (str.length < 35) {
            pills.push({ key: k, value: str, tone: "zinc" });
            if (pills.length >= 5) break;
          }
        }
      }
    }

    return pills;
  }, [data, showSummaryStrip]);

  // Determine if tabular view is appropriate (array of objects or object of objects)
  const isTableEligible = useMemo(() => {
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === "object" && data[0] !== null) {
      return true;
    }
    return false;
  }, [data]);

  const handleCopy = () => {
    void navigator.clipboard.writeText(rawJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleCopyValue = (valStr: string, fieldId: string) => {
    void navigator.clipboard.writeText(valStr);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 1200);
  };

  const toggleNode = (path: string, defaultOpen: boolean) => {
    setExpandedNodes((prev) => {
      const current = prev[path] ?? defaultOpen;
      return { ...prev, [path]: !current };
    });
  };

  const handleExpandAll = () => {
    setForceExpandAll(true);
  };

  const handleCollapseAll = () => {
    setForceExpandAll(false);
    setExpandedNodes({});
  };

  return (
    <div className={`border border-zinc-800 rounded-sm bg-zinc-950 font-mono text-xs overflow-hidden ${className}`}>
      {/* Control Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 bg-zinc-900/90 border-b border-zinc-800 text-[11px]">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-zinc-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            {title ?? "STRUCTURED TELEMETRY"}
          </span>
          <span className="text-[10px] text-zinc-500 font-mono bg-zinc-950 px-1.5 py-0.5 rounded border border-zinc-800/80">
            {byteSize} · {keyCount} {Array.isArray(data) ? "entries" : "keys"}
          </span>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          {/* Search Filter in Tree View */}
          {viewMode === "tree" && (
            <div className="relative flex items-center">
              <Search size={11} className="absolute left-2 text-zinc-500 pointer-events-none" />
              <input
                type="text"
                placeholder="Search keys & values..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-zinc-950 border border-zinc-800 rounded-sm pl-6 pr-2 py-0.5 text-[11px] text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500 w-32 sm:w-44 transition-colors"
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={() => setSearchTerm("")}
                  className="absolute right-1.5 text-zinc-500 hover:text-zinc-300 text-[10px]"
                >
                  ✕
                </button>
              )}
            </div>
          )}

          {/* Expand/Collapse All Buttons */}
          {viewMode === "tree" && (
            <div className="flex items-center gap-0.5 bg-zinc-950 p-0.5 rounded border border-zinc-800">
              <button
                type="button"
                onClick={handleExpandAll}
                className="px-1.5 py-0.5 text-[10px] text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 rounded transition-colors flex items-center gap-1"
                title="Expand All Fields"
              >
                <Maximize2 size={10} />
                <span className="hidden sm:inline">Expand</span>
              </button>
              <button
                type="button"
                onClick={handleCollapseAll}
                className="px-1.5 py-0.5 text-[10px] text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 rounded transition-colors flex items-center gap-1"
                title="Collapse All Fields"
              >
                <Minimize2 size={10} />
                <span className="hidden sm:inline">Fold</span>
              </button>
            </div>
          )}

          {/* Mode Switcher */}
          <div className="flex items-center rounded bg-zinc-950 p-0.5 border border-zinc-800">
            <button
              type="button"
              onClick={() => setViewMode("tree")}
              className={`px-2 py-0.5 rounded text-[10px] flex items-center gap-1 transition-colors ${
                viewMode === "tree" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <ListTree size={11} />
              <span>Tree</span>
            </button>
            {isTableEligible && (
              <button
                type="button"
                onClick={() => setViewMode("table")}
                className={`px-2 py-0.5 rounded text-[10px] flex items-center gap-1 transition-colors ${
                  viewMode === "table" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
                }`}
                title="View as tabular grid"
              >
                <TableIcon size={11} />
                <span>Table</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => setViewMode("raw")}
              className={`px-2 py-0.5 rounded text-[10px] flex items-center gap-1 transition-colors ${
                viewMode === "raw" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Code2 size={11} />
              <span>Raw</span>
            </button>
          </div>

          {/* Wrap toggle for raw view */}
          {viewMode === "raw" && (
            <button
              type="button"
              onClick={() => setWrapRaw((w) => !w)}
              className={`p-1 rounded border text-[10px] transition-colors ${
                wrapRaw ? "bg-zinc-800 text-zinc-200 border-zinc-700" : "bg-zinc-950 text-zinc-500 border-zinc-800 hover:text-zinc-300"
              }`}
              title="Toggle line wrapping"
            >
              <WrapText size={11} />
            </button>
          )}

          {/* Copy Full Payload */}
          <button
            type="button"
            onClick={handleCopy}
            className="px-2 py-0.5 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[10px] flex items-center gap-1 transition-colors"
            title="Copy entire JSON payload"
          >
            {copied ? (
              <>
                <CheckCircle2 size={11} className="text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy size={11} />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Executive Key Metrics Strip (Instant scan of status, target, duration, etc.) */}
      {summaryPills.length > 0 && viewMode === "tree" && (
        <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-900/40 border-b border-zinc-800/80 overflow-x-auto text-[11px] scrollbar-none">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider shrink-0 flex items-center gap-1">
            <Sparkles size={10} className="text-amber-400/80" />
            SUMMARY:
          </span>
          <div className="flex items-center gap-1.5 flex-nowrap">
            {summaryPills.map((pill) => {
              const toneClasses =
                pill.tone === "green"
                  ? "border-emerald-800/60 bg-emerald-950/30 text-emerald-300"
                  : pill.tone === "amber"
                  ? "border-amber-800/60 bg-amber-950/30 text-amber-300"
                  : pill.tone === "cyan"
                  ? "border-cyan-800/60 bg-cyan-950/30 text-cyan-300"
                  : pill.tone === "purple"
                  ? "border-purple-800/60 bg-purple-950/30 text-purple-300"
                  : "border-zinc-800 bg-zinc-900 text-zinc-300";

              return (
                <div
                  key={pill.key}
                  className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono whitespace-nowrap shrink-0 ${toneClasses}`}
                  title={`${pill.key}: ${pill.value}`}
                >
                  <span className="text-zinc-500 font-medium">{pill.key}:</span>
                  <span className="font-semibold">{pill.value}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Content Area */}
      <div className={`overflow-auto p-3 ${maxHeightClass} bg-zinc-950/95 leading-relaxed text-zinc-300 font-mono text-[11px]`}>
        {viewMode === "raw" ? (
          <pre
            className={`select-all text-zinc-300 font-mono text-[11px] leading-relaxed ${
              wrapRaw ? "whitespace-pre-wrap break-all" : "whitespace-pre"
            }`}
          >
            {rawJson}
          </pre>
        ) : viewMode === "table" && isTableEligible ? (
          <JsonTableView data={data as Record<string, unknown>[]} />
        ) : (
          <JsonTreeBranch
            value={data}
            path="root"
            depth={0}
            defaultDepth={defaultExpandedDepth}
            expandedNodes={expandedNodes}
            toggleNode={toggleNode}
            searchTerm={searchTerm.toLowerCase()}
            forceExpandAll={forceExpandAll}
            onCopyValue={handleCopyValue}
            copiedField={copiedField}
          />
        )}
      </div>
    </div>
  );
}

interface JsonTreeBranchProps {
  keyName?: string;
  value: unknown;
  path: string;
  depth: number;
  defaultDepth: number;
  expandedNodes: Record<string, boolean>;
  toggleNode: (path: string, defaultOpen: boolean) => void;
  searchTerm: string;
  forceExpandAll: boolean | null;
  onCopyValue: (val: string, id: string) => void;
  copiedField: string | null;
}

function JsonTreeBranch({
  keyName,
  value,
  path,
  depth,
  defaultDepth,
  expandedNodes,
  toggleNode,
  searchTerm,
  forceExpandAll,
  onCopyValue,
  copiedField
}: JsonTreeBranchProps) {
  const [arrayLimit, setArrayLimit] = useState(8);
  const isObject = value !== null && typeof value === "object" && !Array.isArray(value);
  const isArray = Array.isArray(value);
  const isExpandable = isObject || isArray;

  // Auto-expand if search query matches something inside
  const hasSearchMatch = useMemo(() => {
    if (!searchTerm) return false;
    const str = JSON.stringify(value)?.toLowerCase() ?? "";
    return str.includes(searchTerm);
  }, [value, searchTerm]);

  const defaultOpen = forceExpandAll !== null ? forceExpandAll : hasSearchMatch || depth < defaultDepth;
  const isExpanded = expandedNodes[path] ?? defaultOpen;

  // Search filtering for leaf nodes
  if (searchTerm && !isExpandable) {
    const keyMatch = keyName ? keyName.toLowerCase().includes(searchTerm) : false;
    const valMatch = String(value).toLowerCase().includes(searchTerm);
    if (!keyMatch && !valMatch) return null;
  }

  // Leaf Node (Primitive)
  if (!isExpandable) {
    const valStr = typeof value === "string" ? value : JSON.stringify(value);
    const isThisCopied = copiedField === path;

    return (
      <div className="flex items-start justify-between gap-2 py-0.5 pl-3 hover:bg-zinc-900/60 rounded transition-colors group">
        <div className="flex items-start gap-1.5 min-w-0">
          {keyName !== undefined && (
            <span className="text-zinc-400 font-medium select-none shrink-0 group-hover:text-zinc-300">
              "{keyName}":
            </span>
          )}
          <span className="break-all">{formatPrimitive(value, searchTerm)}</span>
        </div>
        <button
          type="button"
          onClick={() => onCopyValue(valStr, path)}
          className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 text-zinc-500 hover:text-zinc-200 shrink-0"
          title={`Copy value for "${keyName ?? path}"`}
        >
          {isThisCopied ? (
            <CheckCircle2 size={11} className="text-emerald-400" />
          ) : (
            <Copy size={11} />
          )}
        </button>
      </div>
    );
  }

  const entries = isArray
    ? (value as unknown[]).map((v, i) => [String(i), v] as const)
    : Object.entries(value as Record<string, unknown>);

  const itemCount = entries.length;
  const visibleEntries = isArray && itemCount > arrayLimit && forceExpandAll !== true
    ? entries.slice(0, arrayLimit)
    : entries;

  // Inline preview when collapsed (e.g. "{ status: 'ok', port: 22 }" or "[ 22, 80, 443 ]")
  const collapsedPreview = useMemo(() => {
    if (isArray) {
      const previews = (value as unknown[]).slice(0, 3).map((item) => {
        if (typeof item === "object" && item !== null) return "{...}";
        return String(item);
      });
      return `[ ${previews.join(", ")}${itemCount > 3 ? `, +${itemCount - 3} more` : ""} ]`;
    }
    const keys = Object.keys(value as Record<string, unknown>).slice(0, 3);
    return `{ ${keys.join(", ")}${itemCount > 3 ? `, +${itemCount - 3} more` : ""} }`;
  }, [value, isArray, itemCount]);

  return (
    <div className="space-y-0.5">
      <div
        onClick={() => toggleNode(path, defaultOpen)}
        className="flex items-center justify-between gap-2 py-0.5 px-1.5 cursor-pointer hover:bg-zinc-900/70 rounded text-zinc-300 transition-colors select-none group"
      >
        <div className="flex items-center gap-1.5 min-w-0">
          <button
            type="button"
            className="text-zinc-500 group-hover:text-zinc-200 transition-colors shrink-0"
          >
            {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>

          {keyName !== undefined && (
            <span className="text-sky-300 font-semibold shrink-0 group-hover:text-sky-200">
              "{keyName}":
            </span>
          )}

          <span className="text-zinc-500 text-[10px] font-mono shrink-0">
            {isArray ? `Array(${itemCount})` : `{${itemCount} keys}`}
          </span>

          {!isExpanded && (
            <span className="text-zinc-600 text-[10px] font-mono truncate max-w-xs group-hover:text-zinc-500">
              {collapsedPreview}
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onCopyValue(JSON.stringify(value, null, 2), path);
          }}
          className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 text-zinc-500 hover:text-zinc-200 shrink-0"
          title={`Copy entire subtree for "${keyName ?? path}"`}
        >
          {copiedField === path ? (
            <CheckCircle2 size={11} className="text-emerald-400" />
          ) : (
            <Copy size={11} />
          )}
        </button>
      </div>

      {isExpanded && (
        <div className="border-l border-zinc-800/80 ml-3 pl-2.5 space-y-0.5">
          {visibleEntries.map(([childKey, childVal]) => (
            <JsonTreeBranch
              key={childKey}
              keyName={isArray ? undefined : childKey}
              value={childVal}
              path={`${path}.${childKey}`}
              depth={depth + 1}
              defaultDepth={defaultDepth}
              expandedNodes={expandedNodes}
              toggleNode={toggleNode}
              searchTerm={searchTerm}
              forceExpandAll={forceExpandAll}
              onCopyValue={onCopyValue}
              copiedField={copiedField}
            />
          ))}

          {/* Show more button if array is long and truncated */}
          {isArray && itemCount > arrayLimit && forceExpandAll !== true && (
            <button
              type="button"
              onClick={() => setArrayLimit((lim) => lim + 20)}
              className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 py-1 pl-2 hover:underline block"
            >
              + Show {itemCount - arrayLimit} more items...
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function formatPrimitive(value: unknown, searchTerm?: string) {
  if (value === null) {
    return <span className="text-zinc-500 italic">null</span>;
  }
  if (value === undefined) {
    return <span className="text-zinc-600 italic">undefined</span>;
  }
  if (typeof value === "boolean") {
    return <span className="text-purple-400 font-bold">{String(value)}</span>;
  }
  if (typeof value === "number") {
    return <span className="text-amber-300 font-semibold">{value}</span>;
  }
  if (typeof value === "string") {
    const isSearchMatch = searchTerm && value.toLowerCase().includes(searchTerm);
    return (
      <span className={`font-sans break-all ${isSearchMatch ? "bg-amber-500/20 text-amber-200 px-0.5 rounded" : "text-emerald-400"}`}>
        "{value}"
      </span>
    );
  }
  return <span className="text-zinc-300">{String(value)}</span>;
}

function JsonTableView({ data }: { data: Record<string, unknown>[] }) {
  const headers = useMemo(() => {
    const set = new Set<string>();
    data.slice(0, 10).forEach((item) => {
      if (item && typeof item === "object") {
        Object.keys(item).forEach((k) => set.add(k));
      }
    });
    return Array.from(set).slice(0, 8);
  }, [data]);

  return (
    <div className="overflow-x-auto border border-zinc-800 rounded-sm">
      <table className="w-full text-[11px] text-left border-collapse">
        <thead>
          <tr className="bg-zinc-900 border-b border-zinc-800 text-zinc-400">
            <th className="p-1.5 font-semibold text-[10px] uppercase w-8">#</th>
            {headers.map((h) => (
              <th key={h} className="p-1.5 font-semibold text-[10px] uppercase text-zinc-300">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/60">
          {data.map((row, idx) => (
            <tr key={idx} className="hover:bg-zinc-900/40">
              <td className="p-1.5 text-zinc-500 text-[10px]">{idx + 1}</td>
              {headers.map((h) => {
                const val = row[h];
                const str = typeof val === "object" ? JSON.stringify(val) : String(val ?? "-");
                return (
                  <td key={h} className="p-1.5 text-zinc-300 max-w-xs truncate" title={str}>
                    {str}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
