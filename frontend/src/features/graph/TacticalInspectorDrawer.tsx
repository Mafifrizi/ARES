import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Server,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  ArrowRight,
  Copy,
  CheckCircle2,
  X,
  Activity,
  Flame,
  Zap,
  Lock,
  Wifi,
  ExternalLink,
  Layers,
  Crosshair,
  Key,
  Share2
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
  onClose,
  campaignId
}: TacticalInspectorDrawerProps) {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  if (!selection) return null;

  const isNode = selection.kind === "node";
  const node = isNode ? selection.value : null;
  const edge = !isNode ? selection.value : null;

  const nodeInfo = node ? inferCobaltNodeData(node) : null;
  const metadata = (node?.metadata ?? edge?.metadata ?? {}) as Record<string, unknown>;

  // Target extraction
  const targetIp = (metadata.ip as string) || (nodeInfo?.ip) || (node?.id?.startsWith("host:") ? node.id.replace("host:", "") : "");
  const targetOs = (nodeInfo?.os) || (typeof metadata.os === "string" && metadata.os !== "target" && metadata.os !== "Unknown" ? metadata.os : "linux");
  const openPorts = Array.isArray(metadata.open_ports) ? (metadata.open_ports as (number | string)[]) : [];
  const serviceVersions = (metadata.service_versions ?? {}) as Record<string, string>;
  const findings = Array.isArray(metadata.findings) ? (metadata.findings as Record<string, unknown>[]) : [];
  const riskScore = typeof metadata.risk_score === "number" ? metadata.risk_score : null;
  const cvssMax = typeof metadata.cvss_max === "number" ? metadata.cvss_max : null;

  const targetVal = targetIp || node?.label || "";
  const isWindows = targetOs.toLowerCase().includes("win");

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

  const hasHarvestFinding = findings.some((f) => {
    const title = String(f.title || f.label || "").toLowerCase();
    const mod = String(f.module_id || "").toLowerCase();
    const tech = String(f.mitre_technique || f.mitre || "").toLowerCase();
    return (
      mod.includes("ccache") ||
      mod.includes("sssd") ||
      mod.includes("secrets") ||
      mod.includes("lsass") ||
      mod.includes("lsa_secrets") ||
      tech.includes("t1558") ||
      tech.includes("t1552") ||
      tech.includes("t1003") ||
      title.includes("secret") ||
      title.includes("credential") ||
      title.includes("ticket") ||
      title.includes("ccache") ||
      title.includes("shadow") ||
      title.includes("hash")
    );
  });

  const hasLateralFinding = findings.some((f) => {
    const title = String(f.title || f.label || "").toLowerCase();
    const mod = String(f.module_id || "").toLowerCase();
    const tech = String(f.mitre_technique || f.mitre || "").toLowerCase();
    return (
      mod.includes("ssh_pivot") ||
      mod.includes("lateral") ||
      mod.includes("wmiexec") ||
      mod.includes("psexec") ||
      mod.includes("smb") ||
      tech.includes("t1021") ||
      title.includes("lateral") ||
      title.includes("pivot") ||
      title.includes("ssh pivot")
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
      sessionStorage.setItem("ares.dashboard.modules.tab", JSON.stringify("Run Panel"));
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
            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block">
              {isNode ? `TYPE: ${node?.type}` : `HOP: ${edge?.source} → ${edge?.target}`}
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
          <div className="grid grid-cols-2 gap-2 bg-zinc-900/80 p-2.5 rounded-sm border border-zinc-800 text-xs font-mono">
            <div>
              <span className="text-[10px] text-zinc-500 uppercase block">COMPROMISE STATE</span>
              <span className={`font-semibold text-[11px] ${isCompromised ? "text-red-400" : "text-emerald-400"}`}>
                {isCompromised ? "COMPROMISED (ACTIVE)" : "RECON TARGET"}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-zinc-500 uppercase block">OPERATING SYSTEM</span>
              <span className="font-semibold text-zinc-200 text-[11px] truncate block">
                {targetOs}
              </span>
            </div>
            {openPorts.length > 0 && (
              <div>
                <span className="text-[10px] text-zinc-500 uppercase block">PERIMETER ACCESS</span>
                <span className="font-semibold text-cyan-400 text-[11px]">
                  {openPorts.length} Open {openPorts.length === 1 ? "Port" : "Ports"}
                </span>
              </div>
            )}
            {cvssMax !== null && (
              <div>
                <span className="text-[10px] text-zinc-500 uppercase block">CVSS SEVERITY</span>
                <span className="font-semibold text-amber-400 text-[11px]">
                  {cvssMax.toFixed(1)} / 10.0
                </span>
              </div>
            )}
          </div>
        )}

        {/* Execution Lifecycle & Action Plan */}
        {isNode && targetIp && (
          <div className="space-y-2">
            <div className="flex items-center justify-between pb-1 border-b border-zinc-800/60">
              <span className="text-[11px] font-sans font-semibold text-zinc-300 flex items-center gap-1.5">
                <Crosshair size={13} className="text-cyan-400" />
                Execution Plan
              </span>
              <span className="text-[10px] font-mono text-zinc-400">
                {isElevated ? "Stage 4 of 5" : isCompromised ? "Stage 3 of 5" : "Stage 1 of 5"}
              </span>
            </div>

            <div className="space-y-1.5">
              {/* STAGE 1: Service Recon */}
              <div className="p-2.5 rounded-sm border border-emerald-500/30 bg-emerald-950/20 hover:border-emerald-500/50 transition-colors flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="p-1.5 rounded-sm bg-emerald-900/40 text-emerald-400 shrink-0">
                    <Activity size={13} />
                  </div>
                  <div className="min-w-0">
                    <strong className="text-[11px] font-mono text-emerald-300 block truncate">
                      Stage 1: Service Recon
                    </strong>
                    <span className="text-[10px] text-zinc-400 block font-sans truncate">
                      {openPorts.length > 0 ? `${openPorts.join(", ")}/TCP Active · Services identified` : "Perimeter discovered · Host reachable"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <CheckCircle2 size={13} className="text-emerald-400" />
                  <button
                    type="button"
                    onClick={() => handlePivotModule("network.service_detect", { ports: openPorts.join(",") || "22,80,443" })}
                    className="text-[10px] font-mono text-zinc-400 hover:text-emerald-300 transition-colors"
                    title="Re-run fingerprint scan"
                  >
                    Re-scan ↗
                  </button>
                </div>
              </div>

              {/* STAGE 2: Foothold & Spray */}
              <div className={`p-2.5 rounded-sm border transition-colors flex items-center justify-between gap-3 ${
                isCompromised
                  ? "border-emerald-500/30 bg-emerald-950/20 hover:border-emerald-500/50"
                  : "border-zinc-800 bg-zinc-900/70 hover:border-zinc-700"
              }`}>
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className={`p-1.5 rounded-sm shrink-0 ${
                    isCompromised ? "bg-emerald-900/40 text-emerald-400" : "bg-amber-900/40 text-amber-400"
                  }`}>
                    <Terminal size={13} />
                  </div>
                  <div className="min-w-0">
                    <strong className={`text-[11px] font-mono block truncate ${
                      isCompromised ? "text-emerald-300" : "text-zinc-200"
                    }`}>
                      Stage 2: {isWindows ? "Domain Authentication" : "SSH Foothold & Spray"}
                    </strong>
                    <span className="text-[10px] text-zinc-400 block font-sans truncate">
                      {isCompromised
                        ? "Session authenticated: \\kraii active"
                        : (isWindows ? "Password spray across SMB & LDAP surface" : "Low-and-slow authentication audit on port 22")}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isCompromised ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      <button
                        type="button"
                        onClick={() => handlePivotModule(
                          isWindows ? "credential.pass_spray" : "credential.ssh_spray",
                          isWindows
                            ? { domain: "local" }
                            : { target: targetVal, port: 22, users: ["root", "admin", "kali", "ubuntu", "kraii"], passwords: ["Password123!", "admin", "root", "toor", "kraii"] }
                        )}
                        className="text-[10px] font-mono text-zinc-400 hover:text-emerald-300 transition-colors"
                        title="Re-run spray"
                      >
                        Pivot ↗
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      onClick={() => handlePivotModule(
                        isWindows ? "credential.pass_spray" : "credential.ssh_spray",
                        isWindows
                          ? { domain: "local" }
                          : { target: targetVal, port: 22, users: ["root", "admin", "kali", "ubuntu", "kraii"], passwords: ["Password123!", "admin", "root", "toor", "kraii"] }
                      )}
                      className="px-2 py-1 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/40 rounded-sm text-amber-300 text-[10px] font-mono flex items-center gap-1 transition-colors"
                    >
                      <span>Execute</span>
                      <ArrowRight size={11} />
                    </button>
                  )}
                </div>
              </div>

              {/* STAGE 3: Privilege Escalation */}
              <div className={`p-2.5 rounded-sm border transition-colors flex items-center justify-between gap-3 ${
                isElevated
                  ? "border-emerald-500/30 bg-emerald-950/20 hover:border-emerald-500/50"
                  : isCompromised
                  ? "border-rose-600/40 bg-zinc-900/80 hover:border-rose-500/60"
                  : "border-zinc-800/80 bg-zinc-900/30 opacity-60"
              }`}>
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className={`p-1.5 rounded-sm shrink-0 ${
                    isElevated
                      ? "bg-emerald-900/40 text-emerald-400"
                      : isCompromised
                      ? "bg-rose-900/40 text-rose-400"
                      : "bg-zinc-800 text-zinc-500"
                  }`}>
                    <Flame size={13} />
                  </div>
                  <div className="min-w-0">
                    <strong className={`text-[11px] font-mono block truncate ${
                      isElevated ? "text-emerald-300" : isCompromised ? "text-zinc-200" : "text-zinc-400"
                    }`}>
                      Stage 3: Privilege Escalation
                    </strong>
                    <span className="text-[10px] text-zinc-400 block font-sans truncate">
                      {isElevated
                        ? "Root / System privilege confirmed"
                        : isCompromised
                        ? (isWindows ? "Token impersonation & AD ACL escalation" : "Sudo, SUID binaries & capabilities audit")
                        : "Requires initial foothold session"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {isElevated ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      <button
                        type="button"
                        onClick={() => handlePivotModule(isWindows ? "windows.token_impersonation" : "linux.privesc", isWindows ? {} : { host: targetVal, ssh_user: "kraii", ssh_port: 22 })}
                        className="text-[10px] font-mono text-zinc-400 hover:text-emerald-300 transition-colors"
                        title="Re-run privilege escalation"
                      >
                        Re-check ↗
                      </button>
                    </>
                  ) : isCompromised ? (
                    <button
                      type="button"
                      onClick={() => handlePivotModule(isWindows ? "windows.token_impersonation" : "linux.privesc", isWindows ? {} : { host: targetVal, ssh_user: "kraii", ssh_port: 22 })}
                      className="px-2 py-1 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/40 rounded-sm text-rose-300 text-[10px] font-mono flex items-center gap-1 transition-colors"
                    >
                      <span>Execute</span>
                      <ArrowRight size={11} />
                    </button>
                  ) : (
                    <div className="flex items-center gap-1 text-[10px] font-mono text-zinc-500">
                      <Lock size={11} />
                      <span>Locked</span>
                    </div>
                  )}
                </div>
              </div>

              {/* STAGE 4: Credential & Kerberos Harvesting */}
              <div className={`p-2.5 rounded-sm border transition-colors flex items-center justify-between gap-3 ${
                hasHarvestFinding
                  ? "border-emerald-500/30 bg-emerald-950/20 hover:border-emerald-500/50"
                  : isElevated
                  ? "border-amber-600/40 bg-zinc-900/80 hover:border-amber-500/60"
                  : "border-zinc-800/80 bg-zinc-900/30 opacity-60"
              }`}>
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className={`p-1.5 rounded-sm shrink-0 ${
                    hasHarvestFinding
                      ? "bg-emerald-900/40 text-emerald-400"
                      : isElevated
                      ? "bg-amber-900/40 text-amber-400"
                      : "bg-zinc-800 text-zinc-500"
                  }`}>
                    <Key size={13} />
                  </div>
                  <div className="min-w-0">
                    <strong className={`text-[11px] font-mono block truncate ${
                      hasHarvestFinding
                        ? "text-emerald-300"
                        : isElevated
                        ? "text-zinc-200"
                        : "text-zinc-400"
                    }`}>
                      Stage 4: {isWindows ? "LSASS & Kerberos Roasting" : "Kerberos Ccache & SSSD"}
                    </strong>
                    <span className="text-[10px] text-zinc-400 block font-sans truncate">
                      {hasHarvestFinding
                        ? (isWindows ? "LSASS memory & credential loot harvested" : "Credential loot & filesystem secrets collected")
                        : isElevated
                        ? (isWindows ? "Harvest LSASS memory & ticket cache" : "Dump TGTs, ccache tickets & SSSD cache via root")
                        : "Requires elevated root / system access"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {hasHarvestFinding ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      <button
                        type="button"
                        onClick={() => handlePivotModule(isWindows ? "windows.lsass_dump" : (isWindows ? "linux.ccache_hunt" : "exfil.secrets_scan"), isWindows ? {} : { host: targetVal, ssh_user: "kraii" })}
                        className="text-[10px] font-mono text-zinc-400 hover:text-emerald-300 transition-colors"
                        title="Re-harvest credentials"
                      >
                        Re-harvest ↗
                      </button>
                    </>
                  ) : isElevated ? (
                    <button
                      type="button"
                      onClick={() => handlePivotModule(isWindows ? "windows.lsass_dump" : "linux.ccache_hunt", isWindows ? {} : { host: targetVal, ssh_user: "kraii" })}
                      className="px-2 py-1 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/40 rounded-sm text-amber-300 text-[10px] font-mono flex items-center gap-1 transition-colors"
                    >
                      <span>Harvest</span>
                      <ArrowRight size={11} />
                    </button>
                  ) : (
                    <div className="flex items-center gap-1 text-[10px] font-mono text-zinc-500">
                      <Lock size={11} />
                      <span>Locked</span>
                    </div>
                  )}
                </div>
              </div>

              {/* STAGE 5: Lateral Movement */}
              <div className={`p-2.5 rounded-sm border transition-colors flex items-center justify-between gap-3 ${
                hasLateralFinding
                  ? "border-emerald-500/30 bg-emerald-950/20 hover:border-emerald-500/50"
                  : isElevated
                  ? "border-zinc-800 bg-zinc-900/70 hover:border-zinc-700"
                  : "border-zinc-800/80 bg-zinc-900/30 opacity-60"
              }`}>
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className={`p-1.5 rounded-sm shrink-0 ${
                    hasLateralFinding
                      ? "bg-emerald-900/40 text-emerald-400"
                      : isElevated
                      ? "bg-cyan-900/40 text-cyan-400"
                      : "bg-zinc-800 text-zinc-500"
                  }`}>
                    <Share2 size={13} />
                  </div>
                  <div className="min-w-0">
                    <strong className={`text-[11px] font-mono block truncate ${
                      hasLateralFinding
                        ? "text-emerald-300"
                        : isElevated
                        ? "text-zinc-200"
                        : "text-zinc-400"
                    }`}>
                      Stage 5: Lateral Movement
                    </strong>
                    <span className="text-[10px] text-zinc-400 block font-sans truncate">
                      {hasLateralFinding
                        ? "Lateral pivot active on target endpoint"
                        : (isWindows ? "lateral.wmiexec / psexec to adjacent targets" : "persistence.scheduled_task & SSH pivoting")}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {hasLateralFinding ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-400" />
                      <button
                        type="button"
                        onClick={() => handlePivotModule(isWindows ? "lateral.wmiexec" : "lateral.ssh_pivot", { target: targetVal })}
                        className="text-[10px] font-mono text-zinc-400 hover:text-emerald-300 transition-colors"
                        title="Re-run lateral movement"
                      >
                        Re-pivot ↗
                      </button>
                    </>
                  ) : isElevated ? (
                    <button
                      type="button"
                      onClick={() => handlePivotModule(isWindows ? "lateral.wmiexec" : "persistence.scheduled_task", { target: targetVal })}
                      className="px-2 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/40 rounded-sm text-cyan-300 text-[10px] font-mono flex items-center gap-1 transition-colors"
                    >
                      <span>Expand</span>
                      <ArrowRight size={11} />
                    </button>
                  ) : (
                    <div className="flex items-center gap-1 text-[10px] font-mono text-zinc-500">
                      <Lock size={11} />
                      <span>Locked</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Discovered Open Ports Matrix */}
        {openPorts.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1 font-semibold">
              <Wifi size={11} className="text-cyan-400" />
              DISCOVERED PERIMETER PORTS ({openPorts.length})
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
            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1 font-semibold">
              <ShieldAlert size={11} className="text-rose-400" />
              CONFIRMED VULNERABILITIES & FINDINGS ({findings.length})
            </span>
            <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
              {findings.map((f, idx) => {
                const sev = String(f.severity ?? "info").toLowerCase();
                const sevBadge =
                  sev.includes("high") || sev.includes("crit")
                    ? "bg-rose-950 text-rose-300 border-rose-800"
                    : sev.includes("med")
                    ? "bg-amber-950 text-amber-300 border-amber-800"
                    : "bg-zinc-900 text-zinc-300 border-zinc-800";

                return (
                  <div
                    key={idx}
                    className="p-2 bg-zinc-900/70 border border-zinc-800/80 rounded-sm space-y-1"
                  >
                    <div className="flex items-center justify-between gap-1 text-[10px] font-mono">
                      <span className={`px-1 py-0.5 rounded border uppercase font-semibold ${sevBadge}`}>
                        {sev}
                      </span>
                      {Boolean(f.mitre_technique) && (
                        <span className="text-zinc-500 border border-zinc-800 px-1 py-0.5 rounded">
                          {String(f.mitre_technique)}
                        </span>
                      )}
                    </div>
                    <h4 className="text-[11px] font-semibold text-zinc-200 leading-snug">
                      {String(f.title ?? `Finding #${idx + 1}`)}
                    </h4>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Edge Hop Details */}
        {!isNode && edge && (
          <div className="bg-zinc-900/80 p-3 rounded-sm border border-zinc-800 space-y-2 text-xs font-mono">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wider block font-semibold">
              LATERAL TRAVERSAL DETAILS
            </span>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">SOURCE:</span>
              <span className="text-zinc-200 font-semibold">{edge.source}</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">TARGET:</span>
              <span className="text-zinc-200 font-semibold">{edge.target}</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">EDGE TYPE:</span>
              <span className="text-cyan-400 font-semibold uppercase">{edge.type || "pivot"}</span>
            </div>
          </div>
        )}

        {/* Structured Node/Edge Telemetry via StructuredJsonViewer */}
        <div className="space-y-1.5">
          <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1 font-semibold">
            <Layers size={11} className="text-zinc-400" />
            TELEMETRY & ATTRIBUTES
          </span>
          <StructuredJsonViewer
            data={metadata}
            title={isNode ? "Node Attributes" : "Link Attributes"}
            defaultExpandedDepth={1}
            maxHeightClass="max-h-64"
            showSummaryStrip={false}
          />
        </div>
      </div>
    </aside>
  );
}
