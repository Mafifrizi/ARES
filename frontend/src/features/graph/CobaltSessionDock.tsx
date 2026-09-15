import { X, Terminal as TerminalIcon, Shield, Play, RotateCcw, ChevronDown, ChevronUp } from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";

export interface BeaconSession {
  id: string;
  name: string;
  type: "beacon" | "processes" | "desktop";
  host: string;
  user: string;
  pid: number | string;
  lastSeen: string;
  row: 1 | 2;
  logs: Array<{ type: "success" | "info" | "warn" | "cmd"; text: string }>;
}

const DEFAULT_SESSIONS: BeaconSession[] = [
  // Row 1 tabs from reference screenshot
  {
    id: "session-8040",
    name: "Beacon 10.10.10.191@8040",
    type: "beacon",
    host: "DEVELOPER45",
    user: "SYSTEM *",
    pid: 8040,
    lastSeen: "3s",
    row: 1,
    logs: [
      { type: "success", text: "[+] Initialized lateral link on SMB pipe \\pipe\\browser" },
      { type: "info", text: "[*] Impersonating token: SYSTEM" },
      { type: "cmd", text: "beacon> rev2self" },
      { type: "success", text: "[+] Reverted security context" }
    ]
  },
  {
    id: "session-proc-6984",
    name: "Processes 10.10.10.198@6984",
    type: "processes",
    host: "10.10.10.198",
    user: "SYSTEM *",
    pid: 6984,
    lastSeen: "1s",
    row: 1,
    logs: [
      { type: "info", text: "[*] Enumerating process hierarchy on target host..." },
      { type: "success", text: "[+] PID 1512: lsass.exe (SYSTEM) [x64]" },
      { type: "success", text: "[+] PID 2000: explorer.exe (Jamie.Grins)" },
      { type: "success", text: "[+] PID 2888: svchost.exe (SYSTEM)" }
    ]
  },

  // Row 2 tabs from reference screenshot
  {
    id: "session-desktop",
    name: "Desktop 192.168.58.35@1512",
    type: "desktop",
    host: "ENGINEER-WS",
    user: "ENGINEER",
    pid: 1512,
    lastSeen: "5s",
    row: 2,
    logs: [
      { type: "info", text: "[*] Remote VNC frame buffer streaming active: 1024x768 16bpp" },
      { type: "success", text: "[+] Keystrokes interceptor attached to target session" }
    ]
  },
  {
    id: "session-active-4844",
    name: "Beacon 10.10.10.191@4844",
    type: "beacon",
    host: "DEVELOPER45",
    user: "Jamie.Grins/6984",
    pid: 6984,
    lastSeen: "2s",
    row: 2,
    logs: [
      { type: "success", text: "[+] established link to parent beacon: 10.10.10.198" },
      { type: "success", text: "[+] host called home, sent: 12 bytes" },
      { type: "cmd", text: "beacon> ppid 2000" },
      { type: "info", text: "[*] Tasked beacon to spoof 2888 as parent process" },
      { type: "success", text: "[+] host called home, sent: 12 bytes" },
      { type: "cmd", text: "beacon> ssh 192.168.57.18 jgrins jrocks" },
      { type: "info", text: "[*] Tasked beacon to SSH to 192.168.57.18:22 as jgrins" },
      { type: "success", text: "[+] host called home, sent: 437307 bytes" },
      { type: "success", text: "[+] host called home, sent: 34 bytes" },
      { type: "success", text: "[+] established link to child session: 192.168.57.18" }
    ]
  },
  {
    id: "session-beacon-6984",
    name: "Beacon 10.10.10.198@6984",
    type: "beacon",
    host: "DEVELOPER45",
    user: "Jamie.Grins",
    pid: 6984,
    lastSeen: "2s",
    row: 2,
    logs: [
      { type: "success", text: "[+] established link to parent beacon: 10.10.10.198" },
      { type: "info", text: "[*] Named pipe channel live: \\\\.\\pipe\\status_6984" }
    ]
  }
];

export function CobaltSessionDock({
  selectedNodeId,
  selectedNodeLabel,
  onNodeSelect,
  campaignId,
  campaignName,
  activeNodes = []
}: {
  selectedNodeId?: string | null;
  selectedNodeLabel?: string | null;
  onNodeSelect?: (id: string) => void;
  campaignId?: string;
  campaignName?: string;
  activeNodes?: Array<{ id: string; label: string; type?: string; metadata?: Record<string, any> }>;
}) {
  const [sessions, setSessions] = useState<BeaconSession[]>(() => {
    if (activeNodes.length > 0) {
      return activeNodes.slice(0, 5).map((node, idx) => ({
        id: `node-${node.id}`,
        name: `Beacon ${node.label}@${node.metadata?.pid || 1000 + idx * 450}`,
        type: "beacon",
        host: node.label,
        user: node.metadata?.privilege === "system" ? "SYSTEM *" : (node.metadata?.user || "operator"),
        pid: node.metadata?.pid || 1000 + idx * 450,
        lastSeen: "1s",
        row: (idx % 2 === 0 ? 1 : 2) as 1 | 2,
        logs: [
          { type: "info", text: `[*] Initialized telemetry listener for campaign: ${campaignName || campaignId || "ARES"}` },
          { type: "success", text: `[+] Synced session on host: ${node.label} (${node.metadata?.ip || "in-scope"})` }
        ]
      }));
    }
    return DEFAULT_SESSIONS;
  });

  const [activeSessionId, setActiveSessionId] = useState<string>(() => sessions[0]?.id || "session-active-4844");
  const [commandInput, setCommandInput] = useState("");
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Sync sessions when campaign or activeNodes change
  useEffect(() => {
    if (activeNodes.length > 0) {
      const derived: BeaconSession[] = activeNodes.slice(0, 6).map((node, idx) => ({
        id: `node-${node.id}`,
        name: `Beacon ${node.label}@${node.metadata?.pid || 1000 + idx * 450}`,
        type: "beacon",
        host: node.label,
        user: node.metadata?.privilege === "system" ? "SYSTEM *" : (node.metadata?.user || "operator"),
        pid: node.metadata?.pid || 1000 + idx * 450,
        lastSeen: "2s",
        row: (idx % 2 === 0 ? 1 : 2) as 1 | 2,
        logs: [
          { type: "info", text: `[*] Campaign Scope: ${campaignName || campaignId || "Default"}` },
          { type: "success", text: `[+] Active telemetry node: ${node.label}` },
          { type: "info", text: `[*] Transport: Named Pipe \\pipe\\browser // Protocol: AES-256` }
        ]
      }));
      setSessions(derived);
      setActiveSessionId(derived[0].id);
    }
  }, [campaignId, activeNodes.length]);

  // If user clicks a node in the graph, focus or open a tab for it
  useEffect(() => {
    if (!selectedNodeId || !selectedNodeLabel) return;
    setSessions((prev) => {
      const existing = prev.find((s) => s.id === `node-${selectedNodeId}` || s.host === selectedNodeLabel);
      if (existing) {
        setActiveSessionId(existing.id);
        return prev;
      }
      const newSession: BeaconSession = {
        id: `node-${selectedNodeId}`,
        name: `Beacon: ${selectedNodeLabel}`,
        type: "beacon",
        host: selectedNodeLabel,
        user: "SYSTEM *",
        pid: Math.floor(1000 + Math.random() * 8000),
        lastSeen: "1s",
        row: 2,
        logs: [
          { type: "success", text: `[+] established link to host: ${selectedNodeLabel}` },
          { type: "info", text: `[*] Pivot route synchronized for entity: ${selectedNodeId}` },
          { type: "cmd", text: `beacon> link ${selectedNodeLabel}` },
          { type: "success", text: `[+] Pivot link confirmed. Cryptographic auth: AES-256-GCM` }
        ]
      };
      setActiveSessionId(newSession.id);
      return [...prev, newSession];
    });
  }, [selectedNodeId, selectedNodeLabel]);

  // Scroll to bottom when logs update
  useEffect(() => {
    terminalBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [sessions, activeSessionId]);

  const activeSession = sessions.find((s) => s.id === activeSessionId) ?? sessions[0];

  function handleCloseTab(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    if (sessions.length <= 1) return;
    const remaining = sessions.filter((s) => s.id !== id);
    setSessions(remaining);
    if (activeSessionId === id) {
      setActiveSessionId(remaining[0].id);
    }
  }

  function handleExecuteCommand(cmd: string) {
    const trimmed = cmd.trim();
    if (!trimmed || !activeSession) return;

    let responseLog: { type: "success" | "info" | "warn"; text: string };
    const lower = trimmed.toLowerCase();

    if (lower === "whoami") {
      const userVal = activeSession.user || "operator";
      const hostVal = activeSession.host || "TARGET";
      const integrity = userVal.includes("*") || userVal.includes("SYSTEM") ? "High/System" : "Medium";
      responseLog = { type: "success", text: `${hostVal}\\${userVal} (Integrity: ${integrity})` };
    } else if (lower.includes("ppid")) {
      responseLog = { type: "info", text: `[*] Tasked beacon to spoof PPID (sent 16 bytes)` };
    } else if (lower.includes("ssh")) {
      responseLog = { type: "info", text: `[*] Tasked beacon to SSH: ${trimmed}` };
    } else if (lower.includes("hashdump") || lower.includes("creds")) {
      responseLog = { type: "success", text: `[+] Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::` };
    } else if (lower.includes("ps") || lower.includes("process")) {
      responseLog = { type: "info", text: `[+] Active process tree enumerated on ${activeSession.host}. Parent PID resolved.` };
    } else if (lower.includes("net view") || lower.includes("recon") || lower === "hosts") {
      const hostList = activeNodes.map((n) => `\\\\${n.label}`).join(", ") || `\\\\${activeSession.host}`;
      responseLog = { type: "info", text: `[*] Discovered Nodes in Scope: ${hostList}` };
    } else if (lower === "help") {
      responseLog = { type: "info", text: `[!] Beacon commands: ppid, ssh, ps, whoami, hashdump, net view, hosts, sleep, link, clear` };
    } else if (lower === "clear") {
      setSessions((prev) =>
        prev.map((s) => (s.id === activeSession.id ? { ...s, logs: [] } : s))
      );
      setCommandInput("");
      return;
    } else {
      responseLog = { type: "info", text: `[*] Tasked beacon on ${activeSession.host} to execute: ${trimmed} (sent 48 bytes)` };
    }

    setSessions((prev) =>
      prev.map((s) => {
        if (s.id !== activeSession.id) return s;
        return {
          ...s,
          logs: [
            ...s.logs,
            { type: "cmd", text: `beacon> ${trimmed}` },
            responseLog
          ]
        };
      })
    );
    setCommandInput("");
  }

  function onSubmitForm(e: FormEvent) {
    e.preventDefault();
    handleExecuteCommand(commandInput);
  }

  const row1Sessions = sessions.filter(s => s.row === 1);
  const row2Sessions = sessions.filter(s => s.row !== 1);

  return (
    <div className="cobalt-terminal-dock">
      {/* Authentic Multi-Row Java Swing Metal Tab Bar */}
      <div className="cobalt-tab-strip-wrapper">
        {/* Tab Row 1 */}
        {row1Sessions.length > 0 && (
          <div className="cobalt-tab-bar row-1">
            {row1Sessions.map((session) => (
              <div
                key={session.id}
                className={`cobalt-tab-item${session.id === activeSessionId ? " active" : ""}`}
                onClick={() => setActiveSessionId(session.id)}
              >
                <span>{session.name}</span>
                {sessions.length > 1 && (
                  <span
                    className="cobalt-tab-close"
                    onClick={(e) => handleCloseTab(e, session.id)}
                    title="Close session tab"
                  >
                    ×
                  </span>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Tab Row 2 */}
        <div className="cobalt-tab-bar row-2">
          {row2Sessions.map((session) => (
            <div
              key={session.id}
              className={`cobalt-tab-item${session.id === activeSessionId ? " active" : ""}`}
              onClick={() => setActiveSessionId(session.id)}
            >
              {session.id === activeSessionId && <span className="cobalt-tab-beacon-dot" />}
              <span>{session.name}</span>
              {sessions.length > 1 && (
                <span
                  className="cobalt-tab-close"
                  onClick={(e) => handleCloseTab(e, session.id)}
                  title="Close session tab"
                >
                  ×
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Terminal Console Output */}
      <div className="cobalt-terminal-body">
        {activeSession?.logs.map((log, idx) => {
          let textClass = "cobalt-log-line";
          if (log.type === "success") textClass += " cobalt-log-success";
          else if (log.type === "info") textClass += " cobalt-log-info";
          else if (log.type === "warn") textClass += " cobalt-log-warn";
          else if (log.type === "cmd") textClass += " cobalt-log-cmd";

          return (
            <div key={idx} className={textClass}>
              {log.text}
            </div>
          );
        })}
        <div ref={terminalBottomRef} />
      </div>

      {/* Authentic Cobalt Strike Status Bar (Directly Above Prompt) */}
      {activeSession && (
        <div className="cobalt-terminal-statusbar">
          <div className="cobalt-status-left">
            [{activeSession.host}] {activeSession.user}
          </div>
          <div className="cobalt-status-right">
            last: {activeSession.lastSeen}
          </div>
        </div>
      )}

      {/* Interactive Beacon Command Prompt */}
      <form className="cobalt-terminal-input-row" onSubmit={onSubmitForm}>
        <span className="cobalt-prompt-label">beacon&gt;</span>
        <input
          type="text"
          className="cobalt-terminal-input"
          value={commandInput}
          onChange={(e) => setCommandInput(e.target.value)}
          autoComplete="off"
          spellCheck="false"
        />
      </form>
    </div>
  );
}
