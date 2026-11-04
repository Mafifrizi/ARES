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

// No fabricated/demo sessions. Sessions are derived ONLY from real in-scope nodes
// (see the activeNodes-driven builders below). When there is no real session data,
// the dock shows an honest standby empty-state instead of invented beacon output.
const DEFAULT_SESSIONS: BeaconSession[] = [];

export function CobaltSessionDock({
  selectedNodeId,
  selectedNodeLabel,
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
  // Helper to determine OS and attributes for a session node
  function getNodeOsInfo(nodeLabel: string, metadata?: Record<string, any>) {
    const rawOs = String(metadata?.os || metadata?.os_info || "").toLowerCase();
    const isLinux = rawOs.includes("linux") || rawOs.includes("kali") || rawOs.includes("ubuntu") || rawOs.includes("debian") || nodeLabel.includes("192.168.56.105");
    return { isLinux, rawOs };
  }

  // Build a session from a REAL in-scope node only. No invented PIDs, transports, or
  // crypto claims: fields come from the node's own metadata, and absent values show "—".
  function buildSessionFromNode(
    node: { id: string; label: string; type?: string; metadata?: Record<string, any> },
    idx: number,
    campaignLabel?: string
  ): BeaconSession {
    const { isLinux } = getNodeOsInfo(node.label, node.metadata);
    const isSystem = node.metadata?.privilege === "system" || node.metadata?.privilege === "root";
    const user = isLinux
      ? (isSystem ? "root" : String(node.metadata?.user || "operator"))
      : (isSystem ? "SYSTEM" : String(node.metadata?.user || "operator"));
    const pid = node.metadata?.pid;
    return {
      id: `node-${node.id}`,
      name: pid ? `${node.label} · ${pid}` : node.label,
      type: "beacon",
      host: node.label,
      user,
      pid: pid ?? "—",
      lastSeen: String(node.metadata?.last_seen || "live"),
      row: (idx % 2 === 0 ? 1 : 2) as 1 | 2,
      logs: [
        { type: "info", text: `Session synced · campaign ${campaignLabel || "—"}` },
        { type: "success", text: `Host ${node.label}${node.metadata?.ip ? ` (${node.metadata.ip})` : ""} · ${user}` }
      ]
    };
  }

  const [sessions, setSessions] = useState<BeaconSession[]>(() => {
    if (activeNodes.length > 0) {
      return activeNodes.slice(0, 5).map((node, idx) => buildSessionFromNode(node, idx, campaignName || campaignId));
    }
    return DEFAULT_SESSIONS;
  });

  const [activeSessionId, setActiveSessionId] = useState<string>(() => sessions[0]?.id || "session-active-4844");
  const [commandInput, setCommandInput] = useState("");
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Sync sessions when campaign or activeNodes change
  useEffect(() => {
    if (activeNodes.length > 0) {
      const derived = activeNodes.slice(0, 6).map((node, idx) => buildSessionFromNode(node, idx, campaignName || campaignId));
      setSessions(derived);
      setActiveSessionId(derived[0].id);
    } else {
      setSessions([]);
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
      const matchedNode = activeNodes.find((n) => n.id === selectedNodeId || n.label === selectedNodeLabel)
        ?? { id: selectedNodeId, label: selectedNodeLabel };
      const newSession = buildSessionFromNode(matchedNode, prev.length, campaignName || campaignId);
      setActiveSessionId(newSession.id);
      return [...prev, newSession];
    });
  }, [selectedNodeId, selectedNodeLabel, activeNodes]);

  // Scroll to bottom when logs update
  useEffect(() => {
    terminalBottomRef.current?.scrollIntoView?.({ behavior: "smooth" });
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

  // Honest, read-only console. It never fabricates command output: there is no live
  // C2 channel wired to this UI, so commands either reflect real known data (session
  // identity, in-scope hosts) or return an honest "no live channel" notice. Nothing
  // here invents credentials, hashes, or byte counts.
  function handleExecuteCommand(cmd: string) {
    const trimmed = cmd.trim();
    if (!trimmed || !activeSession) return;

    let responseLog: { type: "success" | "info" | "warn"; text: string };
    const lower = trimmed.toLowerCase();

    if (lower === "clear") {
      setSessions((prev) =>
        prev.map((s) => (s.id === activeSession.id ? { ...s, logs: [] } : s))
      );
      setCommandInput("");
      return;
    } else if (lower === "whoami") {
      // Reflects only the session identity already known from real node metadata.
      responseLog = { type: "info", text: `${activeSession.host} · ${activeSession.user}` };
    } else if (lower === "hosts" || lower.includes("net view")) {
      // Real in-scope nodes only.
      const hostList = activeNodes.length
        ? activeNodes.map((n) => n.label).join(", ")
        : activeSession.host;
      responseLog = { type: "info", text: `In-scope hosts: ${hostList}` };
    } else if (lower === "help") {
      responseLog = { type: "info", text: "Read-only session view. Available: whoami, hosts, clear. Run modules from the Modules page to act on a target." };
    } else {
      // No fabrication: be explicit that there is no live command channel here.
      responseLog = { type: "warn", text: "No live command channel is connected. This console is read-only telemetry; use the Modules page to execute validation modules against in-scope targets." };
    }

    setSessions((prev) =>
      prev.map((s) => {
        if (s.id !== activeSession.id) return s;
        return {
          ...s,
          logs: [
            ...s.logs,
            { type: "cmd", text: `> ${trimmed}` },
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
      {/* Session tab strip — only when real sessions exist */}
      {sessions.length > 0 && (
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
      )}

      {/* Terminal Console Output */}
      <div className="cobalt-terminal-body">
        {activeSession ? (
          <>
            {activeSession.logs.map((log, idx) => {
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
          </>
        ) : (
          <div className="cobalt-terminal-empty">
            No active sessions · standby. Session telemetry appears here for in-scope hosts once a campaign has live nodes — run a validation module from the Modules page to populate it.
          </div>
        )}
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

      {/* Read-only session console (no live command channel) */}
      {activeSession && (
        <form className="cobalt-terminal-input-row" onSubmit={onSubmitForm}>
          <span className="cobalt-prompt-label">&gt;</span>
          <input
            type="text"
            className="cobalt-terminal-input"
            value={commandInput}
            onChange={(e) => setCommandInput(e.target.value)}
            autoComplete="off"
            spellCheck="false"
            placeholder="read-only · type 'help'"
          />
        </form>
      )}
    </div>
  );
}
