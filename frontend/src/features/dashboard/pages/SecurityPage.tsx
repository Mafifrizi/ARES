import {
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  ChevronDown,
  Copy,
  FileText,
  Loader2,
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { ApiKeyMeta } from "../../../api/types";
import { ConfirmModal } from "../../../components/ui/ConfirmModal";
import { StructuredJsonViewer } from "../../../components/common/StructuredJsonViewer";
import { useAuth } from "../../auth/authContext";
import { useTabParam } from "../dashboardUiState";
import {
  ApiKeyCopyStatus,
  DataPanel,
  EmptyState,
  GeneratedApiKey,
  Page,
  SectionHeader,
  StatusBadge,
  clearValidationMessage,
  setRequiredMessage,
} from "../dashboardComponents";

function formatRole(role?: string): string {
  const labels: Record<string, string> = {
    team_lead: "Team Lead",
    operator: "Operator",
    recon: "Recon",
    reporter: "Reporter"
  };
  if (!role) {
    return "";
  }
  return labels[role] ?? role.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function apiKeyVisibleIdentifier(key: ApiKeyMeta): string {
  const prefix = typeof key.key_prefix === "string" && key.key_prefix
    ? key.key_prefix
    : typeof key.prefix === "string" && key.prefix
      ? key.prefix
      : "";
  return prefix ? `Prefix: ${prefix}` : `ID: ${key.id.slice(0, 12)}`;
}

function apiKeyOwnerLabel(key: ApiKeyMeta): string {
  const owner = key.owner ?? key.owner_username ?? key.username ?? key.role;
  return typeof owner === "string" && owner.trim() ? owner : "";
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function SecurityAuditTable({ auditData, error }: { auditData?: unknown; error?: unknown }) {
  const [sortAsc, setSortAsc] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  const rows = useMemo((): Array<{ id: string; timestamp: string | number; actor: string; action: string; resource: string; status: string }> => {
    if (!auditData) return [];
    if (Array.isArray(auditData)) {
      return auditData.map((item, idx) => {
        const rawTs = (item as Record<string, unknown>).timestamp ?? (item as Record<string, unknown>).created_at;
        const ts: string | number = typeof rawTs === "string" || typeof rawTs === "number" ? rawTs : "";
        return {
          id: String((item as Record<string, unknown>).id ?? idx),
          timestamp: ts,
          actor: String((item as Record<string, unknown>).actor ?? (item as Record<string, unknown>).username ?? "system"),
          action: String((item as Record<string, unknown>).action ?? (item as Record<string, unknown>).event ?? "audit"),
          resource: String((item as Record<string, unknown>).resource ?? (item as Record<string, unknown>).target ?? (item as Record<string, unknown>).detail ?? "—"),
          status: String((item as Record<string, unknown>).status ?? "logged")
        };
      });
    }
    const obj = auditData as Record<string, unknown>;
    if (Array.isArray(obj.events)) {
      return (obj.events as Record<string, unknown>[]).map((item, idx) => {
        const rawTs = item.timestamp ?? item.created_at;
        const ts: string | number = typeof rawTs === "string" || typeof rawTs === "number" ? rawTs : "";
        return {
          id: String(item.id ?? idx),
          timestamp: ts,
          actor: String(item.actor ?? item.username ?? "system"),
          action: String(item.action ?? item.event ?? "audit"),
          resource: String(item.resource ?? item.target ?? item.detail ?? "—"),
          status: String(item.status ?? "logged")
        };
      });
    }
    if (Array.isArray(obj.logs)) {
      return (obj.logs as Record<string, unknown>[]).map((item, idx) => {
        const rawTs = item.timestamp ?? item.created_at;
        const ts: string | number = typeof rawTs === "string" || typeof rawTs === "number" ? rawTs : "";
        return {
          id: String(item.id ?? idx),
          timestamp: ts,
          actor: String(item.actor ?? item.username ?? "system"),
          action: String(item.action ?? item.event ?? "audit"),
          resource: String(item.resource ?? item.target ?? item.detail ?? "—"),
          status: String(item.status ?? "logged")
        };
      });
    }
    if (Array.isArray(obj.vulnerabilities)) {
      const scanTime = typeof obj.scan_timestamp === "number" ? new Date(obj.scan_timestamp * 1000).toISOString() : new Date().toISOString();
      const scanner = String(obj.scanner ?? "pip-audit");
      return (obj.vulnerabilities as Record<string, unknown>[]).map((v, idx) => ({
        id: String(v.vuln_id ?? idx),
        timestamp: scanTime,
        actor: scanner,
        action: String(v.vuln_id ?? "cve_detected"),
        resource: `${String(v.package ?? "")} ${String(v.version ?? "")}`,
        status: String(v.severity ?? "high")
      }));
    }
    return [];
  }, [auditData]);

  const sortedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const timeA = new Date(a.timestamp || 0).getTime() || 0;
      const timeB = new Date(b.timestamp || 0).getTime() || 0;
      return sortAsc ? timeA - timeB : timeB - timeA;
    });
  }, [rows, sortAsc]);

  if (error) {
    return <DataPanel title="Security Audit Error" data={error} />;
  }

  return (
    <section className="panel table-panel">
      <SectionHeader
        title="Security Audit Log"
        description="Immutable record of sensitive operations, security scans, and administrative activity."
        action={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSortAsc(!sortAsc)}
              className="btn btn-compact text-xs flex items-center gap-1.5"
              title="Toggle sort direction by timestamp"
            >
              <ArrowUpDown size={12} />
              <span>{sortAsc ? "Oldest First" : "Newest First"}</span>
            </button>
            <span className="badge">{rows.length} event{rows.length === 1 ? "" : "s"}</span>
          </div>
        }
      />
      {sortedRows.length > 0 ? (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th
                  className="cursor-pointer select-none hover:text-zinc-100"
                  onClick={() => setSortAsc(!sortAsc)}
                  title="Click to sort by timestamp"
                >
                  <div className="flex items-center gap-1">
                    <span>Timestamp</span>
                    <ArrowUpDown size={12} className="text-zinc-400" />
                  </div>
                </th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sortedRows.map((row) => (
                <tr key={row.id}>
                  <td className="font-mono text-xs text-zinc-300 whitespace-nowrap">
                    {row.timestamp ? formatDateTime(String(row.timestamp)) : "—"}
                  </td>
                  <td>
                    <span className="font-mono text-xs font-semibold text-zinc-200">{row.actor}</span>
                  </td>
                  <td>
                    <span className="badge font-mono text-[11px]">{row.action}</span>
                  </td>
                  <td>
                    <span className="font-mono text-xs text-zinc-300">{row.resource}</span>
                  </td>
                  <td>
                    <StatusBadge status={row.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="p-4">
          <EmptyState text="No security audit events recorded yet." />
        </div>
      )}

      {Boolean(auditData) && (
        <div className="p-4 border-t border-zinc-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-400">Underlying telemetry payload:</span>
            <button
              type="button"
              onClick={() => setShowRaw(!showRaw)}
              className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
            >
              <FileText size={12} />
              <span>{showRaw ? "Hide Raw Audit JSON" : "View Raw Audit JSON"}</span>
              <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
            </button>
          </div>
          {showRaw && (
            <div className="mt-3">
              <StructuredJsonViewer data={auditData} title="Raw Audit Payload" maxHeightClass="max-h-72" />
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function SecurityUsersTable({ usersData, error }: { usersData?: unknown; error?: unknown }) {
  const [showRaw, setShowRaw] = useState(false);
  const usersList = Array.isArray(usersData) ? (usersData as Record<string, unknown>[]) : [];

  if (error) {
    return <DataPanel title="Users Error" data={error} />;
  }

  return (
    <section className="panel table-panel">
      <SectionHeader
        title="Platform Users"
        description="Registered accounts and role-based access control."
        action={<span className="badge">{usersList.length} user{usersList.length === 1 ? "" : "s"}</span>}
      />
      {usersList.length > 0 ? (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Last Active</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {usersList.map((u, index) => {
                const username = String(u.username ?? `user-${index}`);
                const role = String(u.role ?? "viewer");
                const isActive = u.is_active === true || u.is_active === 1;
                const lastLogin = u.last_login ? formatDateTime(String(u.last_login)) : "Never";
                const roleTone = role === "team_lead" ? "badge badge-high" : role === "operator" ? "badge badge-low" : "badge";
                return (
                  <tr key={String(u.id ?? username)}>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="w-6 h-6 rounded-full bg-zinc-800 text-zinc-300 font-bold text-xs flex items-center justify-center">
                          {username.slice(0, 1).toUpperCase()}
                        </span>
                        <span className="font-semibold text-zinc-100 text-sm">{username}</span>
                      </div>
                    </td>
                    <td>
                      <span className={roleTone}>{formatRole(role)}</span>
                    </td>
                    <td className="text-xs text-zinc-400 font-mono">
                      {lastLogin}
                    </td>
                    <td>
                      <span className={`badge ${isActive ? "badge-low" : "badge-high"}`}>
                        {isActive ? "Active" : "Disabled"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="p-4">
          <EmptyState text="No user records loaded yet." />
        </div>
      )}

      {Boolean(usersData) && (
        <div className="p-4 border-t border-zinc-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-400">Raw database user records:</span>
            <button
              type="button"
              onClick={() => setShowRaw(!showRaw)}
              className="btn btn-compact text-[11px] py-1 px-2.5 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5"
            >
              <FileText size={12} />
              <span>{showRaw ? "Hide Raw Users JSON" : "View Raw Users JSON"}</span>
              <ChevronDown size={12} className={`transition-transform duration-200 ${showRaw ? "rotate-180" : ""}`} />
            </button>
          </div>
          {showRaw && (
            <div className="mt-3">
              <StructuredJsonViewer data={usersData} title="Raw User Records" maxHeightClass="max-h-72" />
            </div>
          )}
        </div>
      )}
    </section>
  );
}

const VALID_TABS_SECURITY = ["Account", "API Keys", "Audit", "Users"] as const;
type SecurityTab = typeof VALID_TABS_SECURITY[number];

export function SecurityPage() {
  const { user } = useAuth();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.apiKeys });
  const audit = useQuery({ queryKey: ["security-audit"], queryFn: api.securityAudit, enabled: user?.role === "team_lead" });
  const users = useQuery({ queryKey: ["security-users"], queryFn: api.users, enabled: user?.role === "team_lead" });
  const queryClient = useQueryClient();
  const secretKeyInputRef = useRef<HTMLInputElement | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmTouched, setConfirmTouched] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [scopes, setScopes] = useState("read");
  const [creatingApiKey, setCreatingApiKey] = useState(false);
  const [generatedApiKey, setGeneratedApiKey] = useState<GeneratedApiKey | null>(null);
  const [apiKeyError, setApiKeyError] = useState<unknown>(null);
  const [copyStatus, setCopyStatus] = useState<ApiKeyCopyStatus>("idle");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [rawTab, setActiveTab] = useTabParam("Account");
  const activeTab = (VALID_TABS_SECURITY as readonly string[]).includes(rawTab)
    ? (rawTab as SecurityTab)
    : "Account";
  const change = useMutation({
    mutationFn: () => api.changePassword({ current_password: currentPassword, new_password: newPassword }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setConfirmTouched(false);
    }
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteApiKey(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    }
  });

  useEffect(() => {
    if (generatedApiKey) {
      secretKeyInputRef.current?.focus();
    }
  }, [generatedApiKey]);

  async function handleCreateApiKey(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    setApiKeyError(null);
    setGeneratedApiKey(null);
    setCopyStatus("idle");
    setCreatingApiKey(true);
    try {
      const response = await api.createApiKey({ name: keyName, scopes });
      if (!response.key) {
        throw new Error("API key created, but the secret was not returned by the API.");
      }
      setGeneratedApiKey({
        id: response.id,
        key: response.key,
        note: response.note,
        prefix: response.prefix ?? response.key_prefix
      });
      setKeyName("");
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (error) {
      setApiKeyError(error);
    } finally {
      setCreatingApiKey(false);
    }
  }

  async function copyGeneratedKey(): Promise<void> {
    if (!generatedApiKey?.key) return;

    let copied = false;
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(generatedApiKey.key);
        copied = true;
      } catch {
        copied = false;
      }
    }

    if (!copied && secretKeyInputRef.current) {
      secretKeyInputRef.current.focus();
      secretKeyInputRef.current.select();
      try {
        copied = document.execCommand("copy");
      } catch {
        copied = false;
      }
    }

    setCopyStatus(copied ? "copied" : "manual");
  }

  function closeGeneratedKeyModal(): void {
    setGeneratedApiKey(null);
    setCopyStatus("idle");
  }

  return (
    <Page
      title="Security"
      actions={<span className="status-pill">{formatRole(user?.role)}</span>}
      tabs={["Account", "API Keys", "Audit", "Users"]}
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "Account" && (
        <section className="panel p-4">
          <SectionHeader title="Account" />
          <div className="profile-row mb-3">
            <span className="profile-avatar-light">{user?.username?.slice(0, 1).toUpperCase() ?? "A"}</span>
            <div>
              <div className="font-semibold text-zinc-100">{user?.username}</div>
              <div className="text-xs text-zinc-400">{formatRole(user?.role)}</div>
            </div>
          </div>
          <form className="grid gap-2" onSubmit={(event) => {
            event.preventDefault();
            if (!event.currentTarget.reportValidity()) return;
            if (newPassword !== confirmPassword) return;
            change.mutate();
          }}>
            <input className="field" required type="password" placeholder="Current password" value={currentPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setCurrentPassword(e.target.value); }} />
            <input className="field" required minLength={12} type="password" placeholder="New password" value={newPassword} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setNewPassword(e.target.value); }} />
            <div>
              <input
                className={`field ${confirmTouched && confirmPassword !== "" && newPassword !== confirmPassword ? "border-rose-500/70 focus:border-rose-500" : ""}`}
                required
                minLength={12}
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onInvalid={setRequiredMessage}
                onBlur={() => setConfirmTouched(true)}
                onChange={(e) => {
                  clearValidationMessage(e);
                  setConfirmTouched(true);
                  setConfirmPassword(e.target.value);
                }}
              />
              {confirmTouched && confirmPassword !== "" && newPassword !== confirmPassword && (
                <p className="mt-1.5 flex items-center gap-1.5 text-xs text-rose-400" role="alert">
                  <AlertTriangle size={13} className="shrink-0 text-rose-400" />
                  Passwords do not match
                </p>
              )}
            </div>
            <button
              className="btn"
              disabled={
                change.isPending ||
                !currentPassword.trim() ||
                !newPassword ||
                !confirmPassword ||
                newPassword !== confirmPassword
              }
              type="submit"
            >
              {change.isPending && <Loader2 className="spin" size={16} />}
              Change Password
            </button>
          </form>
          <DataPanel title="Password Result" data={change.data ?? change.error} />
        </section>
      )}
      {activeTab === "API Keys" && (
        <section className="panel p-4">
          <SectionHeader
            title="API Keys"
            action={<span className="badge">{keys.data?.length ?? 0} active</span>}
            description="Metadata only; new secrets are shown once."
          />
          <form className="mb-3 grid gap-2 sm:grid-cols-[1fr_120px_auto]" onSubmit={(event) => void handleCreateApiKey(event)}>
            <input className="field" required placeholder="Name" value={keyName} onInvalid={setRequiredMessage} onChange={(e) => { clearValidationMessage(e); setKeyName(e.target.value); }} />
            <select className="field" value={scopes} onChange={(e) => setScopes(e.target.value)}>
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn" disabled={creatingApiKey} type="submit">
              {creatingApiKey && <Loader2 className="spin" size={16} />}
              Create
            </button>
          </form>
          {(keys.data ?? []).map((key) => (
            <div className="key-row" key={key.id}>
              <div className="min-w-0">
                <div className="font-semibold text-zinc-100">{key.name ?? "Unnamed API key"}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs font-semibold text-zinc-400">
                  <span className="font-mono">{apiKeyVisibleIdentifier(key)}</span>
                  {key.scopes ? <span className="badge">Scope: {key.scopes}</span> : null}
                  {apiKeyOwnerLabel(key) ? <span>Owner: {apiKeyOwnerLabel(key)}</span> : null}
                </div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-zinc-400">
                  {key.created_at ? <span>Created: {formatDateTime(key.created_at)}</span> : null}
                  {key.expires_at ? <span>Expires: {formatDateTime(key.expires_at)}</span> : <span>No expiry</span>}
                </div>
              </div>
              <button className="btn btn-danger" disabled={remove.isPending} onClick={() => setDeleteTarget(key.id)} type="button">Delete</button>
            </div>
          ))}
          {(keys.data ?? []).length === 0 && <EmptyState text="No API keys yet." />}
          <DataPanel title="API Key Error" data={apiKeyError ?? remove.error ?? keys.error} />
        </section>
      )}
      {activeTab === "Audit" && (
        <section className="grid gap-4">
          {user?.role === "team_lead" ? (
            <SecurityAuditTable auditData={audit.data} error={audit.error} />
          ) : (
            <EmptyState text="Audit data is available to team leads." />
          )}
        </section>
      )}
      {activeTab === "Users" && (
        <section className="grid gap-4">
          {user?.role === "team_lead" ? (
            <SecurityUsersTable usersData={users.data} error={users.error} />
          ) : (
            <EmptyState text="User management is available to team leads." />
          )}
        </section>
      )}
      {generatedApiKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
          <section
            aria-labelledby="api-key-dialog-title"
            aria-modal="true"
            className="panel w-full max-w-2xl p-5 shadow-2xl"
            role="dialog"
          >
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-zinc-100" id="api-key-dialog-title">Save your key</h2>
                <p className="mt-1 text-sm text-zinc-400">Copy this secret key now and store it somewhere safe.</p>
              </div>
              {generatedApiKey.prefix ? <span className="badge font-mono">{generatedApiKey.prefix}</span> : null}
            </div>
            <p className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm font-semibold text-amber-200">
              This secret key is shown only once. After you close this dialog, ARES will not show the full key again.
            </p>
            <div className="block">
              <label htmlFor="generated-api-key-secret" className="block text-sm font-semibold text-zinc-300 mb-1 cursor-pointer">
                Secret key
              </label>
              <div className="mt-2 grid gap-2 sm:grid-cols-[1fr_auto]">
                <input
                  id="generated-api-key-secret"
                  aria-label="Generated API key secret"
                  className="field font-mono text-sm"
                  onFocus={(event) => event.currentTarget.select()}
                  readOnly
                  ref={secretKeyInputRef}
                  value={generatedApiKey.key}
                />
                <button className="btn" onClick={() => void copyGeneratedKey()} type="button">
                  {copyStatus === "copied" ? <CheckCircle2 size={16} /> : <Copy size={16} />}
                  {copyStatus === "copied" ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
            {copyStatus === "manual" && (
              <p className="mt-2 rounded-md border border-zinc-700 bg-zinc-900 p-3 text-sm text-zinc-300">
                Clipboard access was blocked. The key field is selected; press Ctrl+C to copy it manually.
              </p>
            )}
            {generatedApiKey.note ? <p className="mt-3 text-sm text-zinc-400">{generatedApiKey.note}</p> : null}
            <div className="mt-5 flex justify-end">
              <button className="btn btn-primary" onClick={closeGeneratedKeyModal} type="button">Done</button>
            </div>
          </section>
        </div>
      )}
      <ConfirmModal
        open={deleteTarget !== null}
        title="Delete API Key"
        description="This action cannot be undone. All integrations using this key will immediately lose access."
        confirmLabel="Delete API Key"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={() => {
          if (deleteTarget) {
            remove.mutate(deleteTarget);
            setDeleteTarget(null);
          }
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </Page>
  );
}



export default SecurityPage;
