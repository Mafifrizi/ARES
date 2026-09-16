import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo, type ReactNode } from "react";

export interface PivotNodeData extends Record<string, unknown> {
  label: string;
  subLabel?: string;
  os: "windows" | "windows-server" | "linux" | "firewall";
  privilege?: "system" | "admin" | "user" | "uncompromised";
  status?: "active" | "dormant" | "mapped";
  ip?: string;
  pid?: number | string;
  process?: string;
  dimmed?: boolean;
  isTracked?: boolean;
  metadata?: Record<string, unknown>;
}

/**
 * Windows 7 / XP authentic 4-quadrant waving flag (crisp vector, zero blur)
 */
function Windows7WavingFlag() {
  return (
    <svg className="w-10 h-10" viewBox="0 0 40 40" fill="none">
      {/* Windows 7 authentic circular glowing sky-blue orb */}
      <circle cx="20" cy="20" r="14.5" fill="#1e3a8a" stroke="#93c5fd" strokeWidth="1.2" />
      <path d="M11 12.5C14 11.2 17 13.2 19 12.2V18.8C17 19.8 14 17.8 11 19V12.5Z" fill="#ef4444" />
      <path d="M21 12.2C23 11.2 26 13.2 29 11.8V18.2C26 19.5 23 17.5 21 18.5V12.2Z" fill="#22c55e" />
      <path d="M11 20.2C14 19.2 17 21.2 19 20.2V26.8C17 27.8 14 25.8 11 27V20.2Z" fill="#0284c7" />
      <path d="M21 20.2C23 19.2 26 21.2 29 19.8V26.2C26 27.5 23 25.5 21 26.5V20.2Z" fill="#eab308" />
    </svg>
  );
}

/**
 * Modern Windows 10/11 Cyan Flag
 */
function WindowsModernFlag() {
  return (
    <svg className="w-10 h-10" viewBox="0 0 40 40" fill="none">
      <path d="M5 8.5L17.5 6.8V18.2H5V8.5Z" fill="#00a4ef" />
      <path d="M19.5 6.5L35 4.5V18.2H19.5V6.5Z" fill="#00a4ef" />
      <path d="M5 19.8H17.5V31.2L5 29.5V19.8Z" fill="#00a4ef" />
      <path d="M19.5 19.8H35V33.5L19.5 31.5V19.8Z" fill="#00a4ef" />
    </svg>
  );
}

/**
 * Windows Server / Domain Controller Emblem
 */
function WindowsServerEmblem() {
  return (
    <svg className="w-9 h-9" viewBox="0 0 36 36" fill="none">
      <rect x="5" y="6" width="26" height="6" rx="1" fill="#1e293b" stroke="#38bdf8" strokeWidth="1.2" />
      <circle cx="9" cy="9" r="1.2" fill="#22c55e" />
      <circle cx="13" cy="9" r="1.2" fill="#38bdf8" />
      <line x1="17" y1="9" x2="27" y2="9" stroke="#64748b" strokeWidth="1" strokeDasharray="2 2" />

      <rect x="5" y="15" width="26" height="6" rx="1" fill="#1e293b" stroke="#38bdf8" strokeWidth="1.2" />
      <circle cx="9" cy="18" r="1.2" fill="#22c55e" />
      <circle cx="13" cy="18" r="1.2" fill="#38bdf8" />
      <line x1="17" y1="18" x2="27" y2="18" stroke="#64748b" strokeWidth="1" strokeDasharray="2 2" />

      <rect x="5" y="24" width="26" height="6" rx="1" fill="#1e293b" stroke="#38bdf8" strokeWidth="1.2" />
      <circle cx="9" cy="27" r="1.2" fill="#22c55e" />
      <circle cx="13" cy="27" r="1.2" fill="#38bdf8" />
      <line x1="17" y1="27" x2="27" y2="27" stroke="#64748b" strokeWidth="1" strokeDasharray="2 2" />
    </svg>
  );
}

/**
 * Linux Tux Penguin emblem
 */
function LinuxTuxEmblem() {
  return (
    <svg className="w-9 h-9" viewBox="0 0 40 40" fill="none">
      <ellipse cx="20" cy="23" rx="11" ry="13" fill="#18181b" stroke="#52525b" strokeWidth="1" />
      <ellipse cx="20" cy="24" rx="7" ry="9" fill="#f4f4f5" />
      <circle cx="20" cy="12" r="7" fill="#18181b" />
      <ellipse cx="18" cy="11" rx="1.5" ry="2" fill="#ffffff" />
      <circle cx="18" cy="11" r="0.8" fill="#000000" />
      <ellipse cx="22" cy="11" rx="1.5" ry="2" fill="#ffffff" />
      <circle cx="22" cy="11" r="0.8" fill="#000000" />
      <polygon points="17,14 23,14 20,18" fill="#f59e0b" />
      <ellipse cx="14" cy="35" rx="4" ry="2" fill="#f59e0b" />
      <ellipse cx="26" cy="35" rx="4" ry="2" fill="#f59e0b" />
    </svg>
  );
}


/**
 * Brick Wall + Flames (Cobalt Strike Gateway / Firewall Node)
 */
export const PivotFirewallNode = memo(function PivotFirewallNode({ data, selected }: NodeProps) {
  const nodeData = data as unknown as PivotNodeData;
  return (
    <div className={`cobalt-firewall-node${selected ? " selected" : ""}${nodeData.dimmed ? " dimmed opacity-30" : ""}${nodeData.isTracked ? " in-pathway" : ""}`}>
      <Handle type="target" position={Position.Left} id="left-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Left} id="left-source" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="target" position={Position.Top} id="top-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Top} id="top-source" className="opacity-0 pointer-events-none" isConnectable={false} />

      <div className="cobalt-firewall-brick">
        {/* Stylized Flames and Brickwork */}
        <svg className="w-20 h-16" viewBox="0 0 80 64" fill="none">
          {/* Flames behind wall */}
          <path
            d="M12 36C8 28 14 16 20 8C22 18 28 22 30 14C34 6 42 2 48 10C54 18 56 12 60 4C66 12 70 24 64 36H12Z"
            fill="url(#fireGradient)"
          />
          {/* Brick Wall Grid */}
          <rect x="10" y="32" width="60" height="28" rx="2" fill="#991b1b" stroke="#f87171" strokeWidth="1.5" />
          {/* Mortar horizontal lines */}
          <line x1="10" y1="41" x2="70" y2="41" stroke="#450a0a" strokeWidth="1.5" />
          <line x1="10" y1="50" x2="70" y2="50" stroke="#450a0a" strokeWidth="1.5" />
          {/* Mortar vertical joints */}
          <line x1="25" y1="32" x2="25" y2="41" stroke="#450a0a" strokeWidth="1.5" />
          <line x1="55" y1="32" x2="55" y2="41" stroke="#450a0a" strokeWidth="1.5" />
          <line x1="40" y1="41" x2="40" y2="50" stroke="#450a0a" strokeWidth="1.5" />
          <line x1="25" y1="50" x2="25" y2="60" stroke="#450a0a" strokeWidth="1.5" />
          <line x1="55" y1="50" x2="55" y2="60" stroke="#450a0a" strokeWidth="1.5" />
          {/* Flame gradient definition */}
          <defs>
            <linearGradient id="fireGradient" x1="40" y1="0" x2="40" y2="36" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#fef08a" />
              <stop offset="35%" stopColor="#f97316" />
              <stop offset="100%" stopColor="#dc2626" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      <div className="cobalt-node-caption">
        <span className="cobalt-node-privilege system">{nodeData.label || "FIREWALL"}</span>
        <span className="cobalt-node-subtext">{nodeData.subLabel || "Ingress / Egress"}</span>
      </div>

      <Handle type="target" position={Position.Right} id="right-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Right} id="right-source" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="target" position={Position.Bottom} id="bottom-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Bottom} id="bottom-source" className="opacity-0 pointer-events-none" isConnectable={false} />
    </div>
  );
});

/**
 * CRT / LCD Monitor Host Node (Windows / Linux / Server)
 */
export const PivotComputerNode = memo(function PivotComputerNode({ data, selected }: NodeProps) {
  const nodeData = data as unknown as PivotNodeData;
  const privilege = nodeData.privilege ?? "uncompromised";
  const isElevated = privilege === "system" || privilege === "admin";
  const isActiveBeacon = privilege === "user" || nodeData.status === "active";
  const isMapped = privilege === "uncompromised";

  let auraClass = "mapped";
  if (isElevated) auraClass = "elevated";
  else if (isActiveBeacon) auraClass = "active-beacon";

  let screenContent: ReactNode;
  if (nodeData.os === "linux") {
    screenContent = <LinuxTuxEmblem />;
  } else if (nodeData.os === "windows-server") {
    screenContent = <WindowsServerEmblem />;
  } else if (isElevated) {
    screenContent = <Windows7WavingFlag />;
  } else {
    screenContent = <WindowsModernFlag />;
  }

  let privilegeText =
    isElevated ? "SYSTEM *" :
    privilege === "user" ? (nodeData.metadata?.user ? String(nodeData.metadata.user) : (nodeData.process || "BEACON")) :
    (nodeData.label || "TARGET");

  if (privilegeText.length > 26) {
    privilegeText = privilegeText.slice(0, 24) + "…";
  }

  let subText = nodeData.subLabel || nodeData.ip || nodeData.label || "10.0.0.1";
  if (subText.includes("\n")) {
    subText = subText.split("\n")[1] || subText.split("\n")[0];
  }
  // Clean noisy prefixes like 'Exploit-Target: ' so meaningful hostnames/IPs are visible
  subText = subText.replace(/^(?:Exploit-Target|Target):\s*/i, "");
  if (subText.length > 28) {
    subText = subText.slice(0, 26) + "…";
  }

  return (
    <div className={`cobalt-node-wrapper ${auraClass}${selected ? " selected" : ""}${nodeData.dimmed ? " dimmed opacity-30" : ""}${nodeData.isTracked ? " in-pathway" : ""}`}>
      {/* Handles on all 4 directions for clean directional pivot routing */}
      <Handle type="target" position={Position.Left} id="left-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Left} id="left-source" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="target" position={Position.Top} id="top-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Top} id="top-source" className="opacity-0 pointer-events-none" isConnectable={false} />

      {/* Monitor Display Unit */}
      <div className="cobalt-monitor-housing">
        <div className="cobalt-monitor-screen">
          {screenContent}
        </div>

        <div className="cobalt-monitor-chin">
          <div className="cobalt-monitor-logo-dot" />
        </div>
      </div>

      {/* Monitor Stand & Base */}
      <div className="cobalt-monitor-stand" />
      <div className="cobalt-monitor-base" />

      {/* Under-Monitor Monospace Telemetry Badges */}
      <div className="cobalt-node-caption">
        <span className={`cobalt-node-privilege ${isElevated ? "system" : isActiveBeacon ? "user" : "neutral"}`}>
          {privilegeText}
        </span>
        {subText && (
          <span className="cobalt-node-subtext" title={nodeData.subLabel || nodeData.label || subText}>
            {subText}
          </span>
        )}
      </div>

      <Handle type="target" position={Position.Right} id="right-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Right} id="right-source" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="target" position={Position.Bottom} id="bottom-target" className="opacity-0 pointer-events-none" isConnectable={false} />
      <Handle type="source" position={Position.Bottom} id="bottom-source" className="opacity-0 pointer-events-none" isConnectable={false} />
    </div>
  );
});
