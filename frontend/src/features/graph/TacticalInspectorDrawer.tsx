import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  Copy,
  CheckCircle2,
  X,
  Wifi,
  Layers
} from "lucide-react";
import type { SafeGraphNode, SafeGraphEdge } from "./graphModel";
import { inferCobaltNodeData } from "./graphModel";
import { StructuredJsonViewer } from "../../components/common/StructuredJsonViewer";

interface TacticalInspectorDrawerProps {
  selection: { kind: "node"; value: SafeGraphNode } | { kind: "edge"; value: SafeGraphEdge } | null;
  onClose: () => void;
  campaignId?: string;
}

export function TacticalInspectorDrawer({
  selection,
  onClose
}: TacticalInspectorDrawerProps) {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  // Derivations are null-safe so the useMemo below runs unconditionally
  // (React rules of hooks). The null-selection early return is placed after
  // all hooks have run; the parent only mounts this with a selection anyway.
  const isNode = selection?.kind === "node";
  const node = selection && isNode ? selection.value : null;
  const edge = selection && !isNode ? selection.value : null;

  const nodeInfo = node ? inferCobaltNodeData(node) : null;
  const metadata = (node?.metadata ?? edge?.metadata ?? {}) as Record<string, unknown>;

  // Target extraction
  const targetIp = (metadata.ip as string) || (nodeInfo?.ip) || (node?.id?.startsWith("host:") ? node.id.replace("host:", "") : "");
  const targetOs = (nodeInfo?.os) || (typeof metadata.os === "string" && metadata.os !== "target" && metadata.os !== "Unknown" ? metadata.os : "linux");
  const openPorts = Array.isArray(metadata.open_ports) ? (metadata.open_ports as (number | string)[]) : [];
  const serviceVersions = (metadata.service_versions ?? {}) as Record<string, string>;
  const findings = Array.isArray(metadata.findings) ? (metadata.findings as Record<string, unknown>[]) : [];
  const cvssMax = typeof metadata.cvss_max === "number" ? metadata.cvss_max : null;

  const targetVal = targetIp || node?.label || "";

  // Deduplicate and group findings to present a clean, high-signal list
  const groupedFindings = useMemo(() => {
    const map = new Map<string, { finding: Record<string, unknown>; count: number }>();
    for (const f of findings) {
      let cleanTitle = String(f.title ?? "").trim();
      cleanTitle = cleanTitle.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*/i, "").trim();
      if ((cleanTitle.endsWith(" on") || cleanTitle.endsWith(" on ")) && targetVal) {
        cleanTitle = `${cleanTitle.trim()} ${targetVal}`;
      }
      if (/\(\d*\s*$/.test(cleanTitle)) {
        cleanTitle = cleanTitle.replace(/\(\d*\s*$/, "").trim();
      }
      const sev = String(f.severity ?? "info").toLowerCase();
      const tech = String(f.mitre_technique ?? "");
      const desc = String(f.description ?? "").trim();
      const key = `${cleanTitle.toLowerCase()}:::${sev}:::${tech}`;
      const existing = map.get(key);
      if (existing) {
        existing.count += 1;
        if (!existing.finding.description && desc) {
          existing.finding.description = desc;
        }
      } else {
        map.set(key, { finding: { ...f, title: cleanTitle, description: desc || null }, count: 1 });
      }
    }
    return Array.from(map.values());
  }, [findings, targetVal]);

  // All hooks have now run; safe to bail out when there is no selection.
  if (!selection) return null;

  const hasPrivescFinding = findings.some((f) => {
    const title = String(f.title || f.label || "").toLowerCase();
    const tech = String(f.mitre_technique || f.mitre || "");
    const sev = String(f.severity || "").toLowerCase();
    return (
      tech.includes("T1548") ||
      title.includes("suid") ||
      title.includes("sudo") ||
      title.includes("privilege") ||
      (sev === "critical" && (title.includes("root") || title.includes("admin") || title.includes("binaries")))
    );
  });

  const nodePriv = String(nodeInfo?.privilege || metadata.privilege || "").toLowerCase();
  const metaTags = Array.isArray(metadata.tags) ? (metadata.tags as string[]) : [];
  const isTaggedRoot = metaTags.some((t) => ["root", "system", "elevated", "domain_admin"].includes(String(t).toLowerCase()));
  const isElevated = nodePriv === "system" || nodePriv === "root" || nodePriv === "admin" || hasPrivescFinding || isTaggedRoot;
  const isCompromised = isElevated || nodeInfo?.status === "active" || Boolean(metadata.compromised) || Boolean(metadata.owned) || findings.length > 0;

  const handleCopyTarget = () => {
    if (!targetIp && !node?.label && !edge?.id) return;
    const textToCopy = targetIp || node?.label || edge?.id || "";
    void navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handlePivotModule = (moduleId: string, customParams?: Record<string, unknown>) => {
    try {
      const armParams: Record<string, unknown> = {
        target: targetVal,
        host: targetVal,
        dc: targetVal,
        targets: targetVal ? [targetVal] : [],
        ...(customParams ?? {})
      };
      sessionStorage.setItem("ares.dashboard.modules.selectedId", JSON.stringify(moduleId));
      navigate(`/modules?module=${encodeURIComponent(moduleId)}&target=${encodeURIComponent(targetVal)}&tab=Run+Panel`, {
        state: { moduleId, target: targetVal, params: armParams, tab: "Run Panel" }
      });
    } catch {
      navigate(`/modules?module=${encodeURIComponent(moduleId)}&target=${encodeURIComponent(targetVal)}&tab=Run+Panel`);
    }
  };

  return (
    <aside className="cobalt-inspector-drawer" aria-label="Tactical Inspector">
      {/* Header */}
      <div className="cobalt-inspector-header">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-2 h-2 rounded-full shrink-0 ${isCompromised ? "bg-red-500 animate-pulse" : "bg-cyan-400"}`} />
          <div className="min-w-0">
            <h3 className="text-xs font-mono font-bold text-white truncate leading-tight flex items-center gap-1.5">
              <span>{node ? node.label || node.id : `LINK: ${edge?.type ?? "EDGE"}`}</span>
              <button
                type="button"
                onClick={handleCopyTarget}
                className="text-zinc-500 hover:text-zinc-200 transition-colors shrink-0"
                title="Copy Target Identifier"
              >
                {copied ? <CheckCircle2 size={11} className="text-emerald-400" /> : <Copy size={11} />}
              </button>
            </h3>
            <span className="text-[11px] text-zinc-400 block">
              {isNode ? `Node · ${node?.type}` : `${edge?.source} → ${edge?.target}`}
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="text-zinc-400 hover:text-white p-1 rounded hover:bg-zinc-800 transition-colors"
          title="Close Inspector [ESC]"
        >
          <X size={14} />
        </button>
      </div>

      {/* Body */}
      <div className="cobalt-inspector-body">
        {/* Tactical Status & Metrics Banner */}
        {isNode && (
          <div className="grid grid-cols-2 gap-2 bg-zinc-900/80 p-2.5 rounded-md border border-zinc-800 text-xs">
            <div>
              <span className="text-[11px] text-zinc-500 block">Compromise state</span>
              <span className={`font-medium text-[12px] ${isCompromised ? "text-rose-400" : "text-emerald-400"}`}>
                {isCompromised ? "Compromised" : "Recon target"}
              </span>
            </div>
            <div>
              <span className="text-[11px] text-zinc-500 block">Operating system</span>
              <span className="font-medium text-zinc-200 text-[12px] truncate block">
                {targetOs}
              </span>
            </div>
            {openPorts.length > 0 && (
              <div>
                <span className="text-[11px] text-zinc-500 block">Perimeter access</span>
                <span className="font-medium text-zinc-200 text-[12px] tabular-nums">
                  {openPorts.length} open {openPorts.length === 1 ? "port" : "ports"}
                </span>
              </div>
            )}
            {cvssMax !== null && (
              <div>
                <span className="text-[11px] text-zinc-500 block">CVSS severity</span>
                <span className="font-medium text-amber-400 text-[12px] tabular-nums">
                  {cvssMax.toFixed(1)} / 10.0
                </span>
              </div>
            )}
          </div>
        )}


        {/* Discovered Open Ports Matrix */}
        {openPorts.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-[11px] text-zinc-400 flex items-center gap-1.5 font-medium">
              <Wifi size={11} className="text-cyan-400" />
              Discovered perimeter ports ({openPorts.length})
            </span>
            <div className="flex flex-wrap gap-1.5">
              {openPorts.map((p) => {
                const portStr = String(p);
                const version = serviceVersions[portStr];
                return (
                  <button
                    key={portStr}
                    type="button"
                    onClick={() => handlePivotModule("network.service_detect", { ports: portStr })}
                    className="inline-flex items-center gap-1.5 px-2 py-1 bg-zinc-900 border border-zinc-700 rounded-sm hover:border-cyan-500 hover:bg-zinc-800 text-[11px] font-mono text-zinc-200 transition-colors group"
                    title={`Click to run targeted fingerprint on port ${portStr}`}
                  >
                    <span className="font-bold text-cyan-300">{portStr}/TCP</span>
                    {version && <span className="text-zinc-400 text-[10px] truncate max-w-[140px]">({version})</span>}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Associated Findings */}
        {findings.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-[11px] text-zinc-400 flex items-center gap-1.5 font-medium">
              <ShieldAlert size={11} className="text-rose-400" />
              Confirmed findings ({findings.length})
            </span>
            <div className="space-y-2">
              {groupedFindings.map(({ finding: f, count }, idx) => {
                const sev = String(f.severity ?? "info").toLowerCase();
                const sevBadge =
                  sev.includes("high") || sev.includes("crit")
                    ? "bg-rose-950/90 text-rose-300 border-rose-800"
                    : sev.includes("med")
                    ? "bg-amber-950/90 text-amber-300 border-amber-800"
                    : "bg-zinc-900 text-zinc-300 border-zinc-800";

                const cleanTitle = String(f.title ?? `Finding #${idx + 1}`);
                const desc = f.description ? String(f.description).trim() : null;

                return (
                  <div
                    key={idx}
                    className="p-2.5 bg-zinc-900/80 border border-zinc-800 rounded-sm space-y-1.5 hover:border-zinc-700 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-1 text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded border font-medium text-[11px] capitalize ${sevBadge}`}>
                          {sev}
                        </span>
                        {count > 1 && (
                          <span
                            className="px-1.5 py-0.5 rounded border border-zinc-700/80 bg-zinc-800/90 text-zinc-300 text-[11px] tabular-nums"
                            title={`${count} instances detected`}
                          >
                            ×{count}
                          </span>
                        )}
                      </div>
                      {Boolean(f.mitre_technique) && (
                        <span className="text-zinc-300 bg-zinc-950 border border-zinc-700/80 px-1.5 py-0.5 rounded font-mono text-[10px] tabular-nums">
                          {String(f.mitre_technique)}
                        </span>
                      )}
                    </div>
                    <h4 className="text-[12px] font-semibold text-zinc-100 leading-snug break-words">
                      {cleanTitle}
                    </h4>
                    {desc && (
                      <p className="text-[11px] text-zinc-400 font-sans leading-relaxed break-words">
                        {desc}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Edge Hop Details */}
        {!isNode && edge && (
          <div className="bg-zinc-900/80 p-3 rounded-md border border-zinc-800 space-y-2 text-xs">
            <span className="text-[11px] text-zinc-400 block font-medium">
              Lateral traversal
            </span>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-500">Source</span>
              <span className="text-zinc-200 font-mono tabular-nums">{edge.source}</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-500">Target</span>
              <span className="text-zinc-200 font-mono tabular-nums">{edge.target}</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-500">Edge type</span>
              <span className="text-cyan-400 font-medium capitalize">{edge.type || "pivot"}</span>
            </div>
          </div>
        )}

        {/* Structured Node/Edge Telemetry via StructuredJsonViewer */}
        <div className="space-y-1.5">
          <span className="text-[11px] text-zinc-400 flex items-center gap-1.5 font-medium">
            <Layers size={11} className="text-zinc-400" />
            Node telemetry &amp; attributes
          </span>
          <StructuredJsonViewer
            data={metadata}
            title={isNode ? "Node attributes" : "Link attributes"}
            defaultExpandedDepth={1}
            maxHeightClass="max-h-64"
            showSummaryStrip={false}
          />
        </div>
      </div>
    </aside>
  );
}
