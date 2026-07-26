import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, it, vi } from "vitest";
import {
  bindDashboardPrincipal,
  clearDashboardSession,
  useDashboardSessionWriter,
  useSessionState
} from "./dashboardUiState";

interface StateCase {
  label: string;
  key: string;
  fallback: unknown;
  stored: unknown;
  updated: unknown;
}

const PERSISTENT_CASES: StateCase[] = [
  {
    label: "canonical principal marker",
    key: "ares.dashboard.principal",
    fallback: null,
    stored: { username: "alice", role: "operator" },
    updated: { username: "bob", role: "reporter" }
  },
  { label: "selected campaign", key: "ares.dashboard.selectedCampaignId", fallback: "", stored: "campaign-a", updated: "campaign-b" },
  { label: "live campaign", key: "ares.dashboard.live.campaignId", fallback: "", stored: "campaign-a", updated: "campaign-b" },
  { label: "campaign comparison", key: "ares.dashboard.campaigns.compareId", fallback: "", stored: "campaign-a", updated: "campaign-b" },
  { label: "selected module", key: "ares.dashboard.modules.selectedId", fallback: "", stored: "module-a", updated: "module-b" },
  { label: "campaign tab", key: "ares.dashboard.campaigns.tab", fallback: "List", stored: "Scope", updated: "Findings" },
  { label: "module tab", key: "ares.dashboard.modules.tab", fallback: "Catalog", stored: "Run Panel", updated: "Results" },
  { label: "report tab", key: "ares.dashboard.reports.tab", fallback: "Generate", stored: "Library", updated: "Generate" },
  { label: "template tab", key: "ares.dashboard.templates.tab", fallback: "Templates", stored: "Plan Builder", updated: "Templates" },
  { label: "strategy tab", key: "ares.dashboard.strategy.tab", fallback: "Objective", stored: "Active", updated: "Result" },
  { label: "security tab", key: "ares.dashboard.security.tab", fallback: "Account", stored: "API Keys", updated: "Audit" },
  { label: "EDR tab", key: "ares.dashboard.edr.tab", fallback: "Knowledge Base", stored: "Report Outcome", updated: "Knowledge Base" },
  { label: "live tab", key: "ares.dashboard.live.tab", fallback: "Stream", stored: "Buffer", updated: "Stream" },
  { label: "module category", key: "ares.dashboard.modules.category", fallback: "", stored: "network", updated: "recon" },
  { label: "module OPSEC", key: "ares.dashboard.modules.opsec", fallback: "", stored: "LOW", updated: "MEDIUM" },
  { label: "report format", key: "ares.dashboard.reports.format", fallback: "html", stored: "pdf", updated: "markdown" },
  { label: "strategy LLM backend", key: "ares.dashboard.strategy.llmBackend", fallback: "claude", stored: "local", updated: "openai" },
  { label: "template name selection", key: "ares.dashboard.templates.name", fallback: "", stored: "template-a", updated: "template-b" }
];

const VOLATILE_CASES: StateCase[] = [
  { label: "live events", key: "ares.dashboard.live.events", fallback: [], stored: [{ kind: "legacy" }], updated: [{ kind: "current" }] },
  { label: "campaign name", key: "ares.dashboard.campaigns.create.name", fallback: "", stored: "legacy-name", updated: "current-name" },
  { label: "campaign client", key: "ares.dashboard.campaigns.create.client", fallback: "Internal", stored: "legacy-client", updated: "current-client" },
  { label: "campaign targets", key: "ares.dashboard.campaigns.create.targets", fallback: "", stored: "legacy-target", updated: "current-target" },
  { label: "campaign scope", key: "ares.dashboard.campaigns.create.scope", fallback: "", stored: "legacy-scope", updated: "current-scope" },
  { label: "campaign noise profile", key: "ares.dashboard.campaigns.create.noiseProfile", fallback: "stealth", stored: "aggressive", updated: "normal" },
  { label: "module search", key: "ares.dashboard.modules.search", fallback: "", stored: "legacy-search", updated: "current-search" },
  { label: "module dry-run", key: "ares.dashboard.modules.dryRun", fallback: true, stored: false, updated: false },
  { label: "module confirmation", key: "ares.dashboard.modules.confirmed", fallback: false, stored: true, updated: true },
  { label: "module parameters", key: "ares.dashboard.modules.params", fallback: {}, stored: { field: "legacy" }, updated: { field: "current" } },
  { label: "module result", key: "ares.dashboard.modules.lastRun", fallback: null, stored: { status: "legacy" }, updated: { status: "current" } },
  { label: "report result", key: "ares.dashboard.reports.lastGenerate", fallback: null, stored: { status: "legacy" }, updated: { status: "current" } },
  { label: "template parameters", key: "ares.dashboard.templates.params", fallback: "{}", stored: "{\"field\":\"legacy\"}", updated: "{\"field\":\"current\"}" },
  { label: "template result", key: "ares.dashboard.templates.lastPlan", fallback: null, stored: { status: "legacy" }, updated: { status: "current" } },
  { label: "strategy goal", key: "ares.dashboard.strategy.goal", fallback: "domain_admin", stored: "legacy-goal", updated: "current-goal" },
  { label: "strategy authorization", key: "ares.dashboard.strategy.authorizations", fallback: "", stored: "legacy-note", updated: "current-note" },
  { label: "strategy result", key: "ares.dashboard.strategy.lastEngage", fallback: null, stored: { status: "legacy" }, updated: { status: "current" } },
  { label: "EDR technique", key: "ares.dashboard.edr.techniqueId", fallback: "", stored: "legacy-technique", updated: "current-technique" },
  { label: "EDR vendor", key: "ares.dashboard.edr.vendor", fallback: "", stored: "legacy-vendor", updated: "current-vendor" },
  { label: "EDR version", key: "ares.dashboard.edr.version", fallback: "", stored: "legacy-version", updated: "current-version" },
  { label: "EDR outcome", key: "ares.dashboard.edr.success", fallback: false, stored: true, updated: true },
  { label: "EDR notes", key: "ares.dashboard.edr.notes", fallback: "", stored: "legacy-note", updated: "current-note" },
  { label: "EDR result", key: "ares.dashboard.edr.lastReport", fallback: null, stored: { status: "legacy" }, updated: { status: "current" } }
];

const DIRECT_WRITER_CASES = [
  ["campaign tab", "ares.dashboard.campaigns.tab", "Scope"],
  ["selected module", "ares.dashboard.modules.selectedId", "module-a"],
  ["module tab", "ares.dashboard.modules.tab", "Run Panel"],
  ["report tab", "ares.dashboard.reports.tab", "Library"],
  ["template name", "ares.dashboard.templates.name", "template-a"],
  ["template tab", "ares.dashboard.templates.tab", "Plan Builder"]
] as const;

function requireFixed(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function resetTestSessionStorage(): void {
  const keys = Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index))
    .filter((key): key is string => key !== null);
  for (const key of keys) {
    sessionStorage.removeItem(key);
  }
}

describe("dashboard session persistence policy", () => {
  beforeEach(() => {
    resetTestSessionStorage();
    clearDashboardSession();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    resetTestSessionStorage();
    clearDashboardSession();
  });

  it.each(PERSISTENT_CASES)("persists and rehydrates approved $label", (testCase) => {
    sessionStorage.setItem(testCase.key, JSON.stringify(testCase.stored));

    const { result } = renderHook(() => useSessionState<unknown>(testCase.key, testCase.fallback));
    const rehydrated = sameValue(result.current[0], testCase.stored);
    requireFixed(rehydrated, "Approved dashboard state should rehydrate.");

    act(() => result.current[1](testCase.updated));
    const updatePersisted = sessionStorage.getItem(testCase.key) === JSON.stringify(testCase.updated);
    requireFixed(updatePersisted, "Approved dashboard state should persist.");
  });

  it.each(VOLATILE_CASES)("keeps mandatory volatile $label in memory only", (testCase) => {
    sessionStorage.setItem(testCase.key, JSON.stringify(testCase.stored));
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    try {
      const { result } = renderHook(() => useSessionState<unknown>(testCase.key, testCase.fallback));
      const legacyIgnored = sameValue(result.current[0], testCase.fallback);
      requireFixed(legacyIgnored, "Volatile dashboard state should start from its fallback.");

      act(() => result.current[1](testCase.updated));
      const memoryUpdated = sameValue(result.current[0], testCase.updated);
      const writesForKey = setItem.mock.calls.filter(([key]) => key === testCase.key).length;
      const legacyUntouched = sessionStorage.getItem(testCase.key) === JSON.stringify(testCase.stored);
      requireFixed(memoryUpdated, "Volatile dashboard state should update in memory.");
      requireFixed(writesForKey === 0, "Volatile dashboard state must not be written.");
      requireFixed(legacyUntouched, "Volatile state updates must not overwrite legacy storage.");
    } finally {
      setItem.mockRestore();
    }
  });

  it("restores the caller fallback when volatile state remounts", () => {
    const key = "ares.dashboard.modules.search";
    const first = renderHook(() => useSessionState(key, ""));
    act(() => first.result.current[1]("current-search"));
    const memoryUpdated = first.result.current[0] === "current-search";
    requireFixed(memoryUpdated, "Volatile state should remain usable during its mount.");
    first.unmount();

    const second = renderHook(() => useSessionState(key, ""));
    const fallbackRestored = second.result.current[0] === "";
    const storageAbsent = sessionStorage.getItem(key) === null;
    requireFixed(fallbackRestored, "A volatile remount should restore the caller fallback.");
    requireFixed(storageAbsent, "A volatile remount should not create storage.");
  });

  it("keeps module execution controls and data at safe reload defaults", () => {
    sessionStorage.setItem("ares.dashboard.modules.dryRun", JSON.stringify(false));
    sessionStorage.setItem("ares.dashboard.modules.confirmed", JSON.stringify(true));
    sessionStorage.setItem("ares.dashboard.modules.params", JSON.stringify({ field: "legacy" }));
    sessionStorage.setItem("ares.dashboard.modules.lastRun", JSON.stringify({ status: "legacy" }));

    const { result } = renderHook(() => {
      const [dryRun] = useSessionState("ares.dashboard.modules.dryRun", true);
      const [confirmed] = useSessionState("ares.dashboard.modules.confirmed", false);
      const [params] = useSessionState<Record<string, unknown>>("ares.dashboard.modules.params", {});
      const [lastRun] = useSessionState<unknown>("ares.dashboard.modules.lastRun", null);
      return { confirmed, dryRun, lastRun, params };
    });

    const safeDefaults = (
      result.current.dryRun === true
      && result.current.confirmed === false
      && sameValue(result.current.params, {})
      && result.current.lastRun === null
    );
    requireFixed(safeDefaults, "Module execution state should use safe reload defaults.");
  });

  it("does not rehydrate event, result, or strategy authorization payloads", () => {
    sessionStorage.setItem("ares.dashboard.live.events", JSON.stringify([{ kind: "legacy" }]));
    sessionStorage.setItem("ares.dashboard.reports.lastGenerate", JSON.stringify({ status: "legacy" }));
    sessionStorage.setItem("ares.dashboard.templates.lastPlan", JSON.stringify({ status: "legacy" }));
    sessionStorage.setItem("ares.dashboard.strategy.authorizations", JSON.stringify("legacy-note"));
    sessionStorage.setItem("ares.dashboard.strategy.lastEngage", JSON.stringify({ status: "legacy" }));
    sessionStorage.setItem("ares.dashboard.edr.lastReport", JSON.stringify({ status: "legacy" }));

    const { result } = renderHook(() => {
      const [events] = useSessionState<unknown[]>("ares.dashboard.live.events", []);
      const [report] = useSessionState<unknown>("ares.dashboard.reports.lastGenerate", null);
      const [plan] = useSessionState<unknown>("ares.dashboard.templates.lastPlan", null);
      const [authorization] = useSessionState("ares.dashboard.strategy.authorizations", "");
      const [strategy] = useSessionState<unknown>("ares.dashboard.strategy.lastEngage", null);
      const [edr] = useSessionState<unknown>("ares.dashboard.edr.lastReport", null);
      return { authorization, edr, events, plan, report, strategy };
    });

    const safeDefaults = (
      result.current.events.length === 0
      && result.current.report === null
      && result.current.plan === null
      && result.current.authorization === ""
      && result.current.strategy === null
      && result.current.edr === null
    );
    requireFixed(safeDefaults, "Payload and authorization state should not survive reload.");
  });

  it.each(DIRECT_WRITER_CASES)("accepts approved guarded search writer for %s", (_label, key, value) => {
    const { result } = renderHook(() => useDashboardSessionWriter());
    const accepted = result.current(key, value);
    const persisted = sessionStorage.getItem(key) === JSON.stringify(value);
    requireFixed(accepted, "Approved direct dashboard writer should be accepted.");
    requireFixed(persisted, "Approved direct dashboard writer should persist.");
  });

  it("rejects unknown dashboard and non-ARES keys", () => {
    const { result } = renderHook(() => useDashboardSessionWriter());
    const unknownRejected = result.current("ares.dashboard.future.setting", "blocked") === false;
    const outsideRejected = result.current("other.application", "blocked") === false;
    const unknownAbsent = sessionStorage.getItem("ares.dashboard.future.setting") === null;
    const outsideAbsent = sessionStorage.getItem("other.application") === null;
    requireFixed(unknownRejected && outsideRejected, "Unapproved dashboard writers should be rejected.");
    requireFixed(unknownAbsent && outsideAbsent, "Rejected dashboard writers must not create storage.");
  });

  it("purges unknown future state while retaining it as volatile React state", () => {
    const key = "ares.dashboard.future.setting";
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem(key, JSON.stringify("legacy"));
    const { result } = renderHook(() => useSessionState(key, "fallback"));
    act(() => result.current[1]("current"));
    const memoryUpdated = result.current[0] === "current";
    const legacyUnchanged = sessionStorage.getItem(key) === JSON.stringify("legacy");
    requireFixed(memoryUpdated, "Unknown dashboard state should remain usable in memory.");
    requireFixed(legacyUnchanged, "Unknown dashboard state must not be rewritten.");

    bindDashboardPrincipal({ username: "alice", role: "operator" });
    const legacyPurged = sessionStorage.getItem(key) === null;
    requireFixed(legacyPurged, "Unknown dashboard storage should be purged by default.");
  });

  it("preserves allowed same-principal preferences and purges legacy volatile state", () => {
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
    for (const testCase of VOLATILE_CASES) {
      sessionStorage.setItem(testCase.key, JSON.stringify(testCase.stored));
    }
    sessionStorage.setItem("ares.dashboard.future.setting", JSON.stringify("legacy"));
    sessionStorage.setItem("other.application", "keep");

    bindDashboardPrincipal({ username: "alice", role: "operator" });

    const preferencePreserved =
      sessionStorage.getItem("ares.dashboard.modules.category") === JSON.stringify("network");
    const volatilePurged = VOLATILE_CASES.every(
      (testCase) => sessionStorage.getItem(testCase.key) === null
    );
    const futurePurged = sessionStorage.getItem("ares.dashboard.future.setting") === null;
    const unrelatedPreserved = sessionStorage.getItem("other.application") === "keep";
    requireFixed(preferencePreserved, "Matching principal should retain approved preferences.");
    requireFixed(volatilePurged && futurePurged, "Matching principal should purge disallowed legacy state.");
    requireFixed(unrelatedPreserved, "Legacy purge should preserve unrelated session state.");
  });

  it.each([
    ["missing marker", null],
    ["malformed marker", "not-json"],
    ["different username", JSON.stringify({ username: "bob", role: "operator" })],
    ["different role", JSON.stringify({ username: "alice", role: "team_lead" })]
  ])("retains full account-boundary purge for %s", (_label, storedPrincipal) => {
    sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
    sessionStorage.setItem("ares.dashboard.modules.params", JSON.stringify({ field: "legacy" }));
    sessionStorage.setItem("other.application", "keep");
    if (storedPrincipal) {
      sessionStorage.setItem("ares.dashboard.principal", storedPrincipal);
    }

    bindDashboardPrincipal({ username: "alice", role: "operator" });

    const allowedRemoved = sessionStorage.getItem("ares.dashboard.modules.category") === null;
    const disallowedRemoved = sessionStorage.getItem("ares.dashboard.modules.params") === null;
    const principalUpdated =
      sessionStorage.getItem("ares.dashboard.principal")
      === JSON.stringify({ username: "alice", role: "operator" });
    const unrelatedPreserved = sessionStorage.getItem("other.application") === "keep";
    requireFixed(allowedRemoved && disallowedRemoved, "Account-boundary purge should remove all dashboard state.");
    requireFixed(principalUpdated, "Canonical principal should replace an invalid marker.");
    requireFixed(unrelatedPreserved, "Account-boundary purge should preserve unrelated session state.");
  });

  it("purges disallowed legacy state idempotently", () => {
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem("ares.dashboard.reports.format", JSON.stringify("pdf"));
    sessionStorage.setItem("ares.dashboard.reports.lastGenerate", JSON.stringify({ status: "legacy" }));

    bindDashboardPrincipal({ username: "alice", role: "operator" });
    bindDashboardPrincipal({ username: "alice", role: "operator" });

    const preferencePreserved =
      sessionStorage.getItem("ares.dashboard.reports.format") === JSON.stringify("pdf");
    const legacyPurged = sessionStorage.getItem("ares.dashboard.reports.lastGenerate") === null;
    requireFixed(preferencePreserved, "Idempotent purge should retain approved preferences.");
    requireFixed(legacyPurged, "Idempotent purge should keep legacy state absent.");
  });

  it("removes every dashboard key during a full account cleanup", () => {
    sessionStorage.setItem("ares.dashboard.selectedCampaignId", JSON.stringify("campaign-a"));
    sessionStorage.setItem("ares.dashboard.future.setting", JSON.stringify("legacy"));
    sessionStorage.setItem("ares.refreshToken", "refresh");
    sessionStorage.setItem("other.application", "keep");

    clearDashboardSession();

    const selectedRemoved = sessionStorage.getItem("ares.dashboard.selectedCampaignId") === null;
    const futureRemoved = sessionStorage.getItem("ares.dashboard.future.setting") === null;
    const refreshPreserved = sessionStorage.getItem("ares.refreshToken") === "refresh";
    const unrelatedPreserved = sessionStorage.getItem("other.application") === "keep";
    requireFixed(selectedRemoved && futureRemoved, "Full cleanup should remove every dashboard key.");
    requireFixed(refreshPreserved, "Dashboard-only cleanup should preserve the refresh token.");
    requireFixed(unrelatedPreserved, "Full cleanup should preserve unrelated session state.");
  });

  it("blocks an old epoch writer after full cleanup and permits a new mount", () => {
    const key = "ares.dashboard.modules.tab";
    const stale = renderHook(() => useDashboardSessionWriter());
    const initialAccepted = stale.result.current(key, "Run Panel");
    requireFixed(initialAccepted, "Initial mounted writer should be accepted.");

    clearDashboardSession();

    const staleRejected = stale.result.current(key, "Results") === false;
    const staleAbsent = sessionStorage.getItem(key) === null;
    requireFixed(staleRejected && staleAbsent, "Old epoch writer should remain blocked.");

    const current = renderHook(() => useDashboardSessionWriter());
    const currentAccepted = current.result.current(key, "Catalog");
    const currentPersisted = sessionStorage.getItem(key) === JSON.stringify("Catalog");
    requireFixed(currentAccepted && currentPersisted, "New epoch writer should persist normally.");
  });

  it("fails closed when an allowed storage write throws", () => {
    const { result } = renderHook(() => useDashboardSessionWriter());
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("unavailable", "SecurityError");
    });
    try {
      const rejected = result.current("ares.dashboard.modules.tab", "Run Panel") === false;
      requireFixed(rejected, "Failed storage write should be rejected.");
    } finally {
      setItem.mockRestore();
    }
    const storageAbsent = sessionStorage.getItem("ares.dashboard.modules.tab") === null;
    requireFixed(storageAbsent, "Failed storage write should remain absent.");
  });

  it("logically blocks an allowed key whose full-cleanup removal fails", () => {
    const key = "ares.dashboard.modules.tab";
    sessionStorage.setItem(key, JSON.stringify("Run Panel"));
    const originalRemoveItem = Storage.prototype.removeItem;
    const removeItem = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (
      this: Storage,
      keyToRemove: string
    ) {
      if (keyToRemove === key) {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalRemoveItem.call(this, keyToRemove);
    });
    try {
      clearDashboardSession();
    } finally {
      removeItem.mockRestore();
    }

    const neutralized = sessionStorage.getItem(key) === "";
    requireFixed(neutralized, "Failed cleanup should neutralize the stored key.");
    const { result } = renderHook(() => useSessionState(key, "Catalog"));
    const fallbackUsed = result.current[0] === "Catalog";
    requireFixed(fallbackUsed, "Blocked key should not rehydrate old account state.");
  });

  it("logically blocks a disallowed legacy key whose purge removal fails", () => {
    const key = "ares.dashboard.modules.params";
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem(key, JSON.stringify({ field: "legacy" }));
    const originalRemoveItem = Storage.prototype.removeItem;
    const removeItem = vi.spyOn(Storage.prototype, "removeItem").mockImplementation(function (
      this: Storage,
      keyToRemove: string
    ) {
      if (keyToRemove === key) {
        throw new DOMException("unavailable", "SecurityError");
      }
      return originalRemoveItem.call(this, keyToRemove);
    });
    try {
      bindDashboardPrincipal({ username: "alice", role: "operator" });
    } finally {
      removeItem.mockRestore();
    }

    const neutralized = sessionStorage.getItem(key) === "";
    requireFixed(neutralized, "Failed legacy purge should neutralize the stored key.");
    const { result } = renderHook(() => useSessionState<Record<string, unknown>>(key, {}));
    const fallbackUsed = sameValue(result.current[0], {});
    requireFixed(fallbackUsed, "Failed legacy purge should remain logically blocked.");
  });

  it("fails closed when legacy storage enumeration throws", () => {
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem("ares.dashboard.modules.category", JSON.stringify("network"));
    sessionStorage.setItem("ares.dashboard.modules.params", JSON.stringify({ field: "legacy" }));
    const key = vi.spyOn(Storage.prototype, "key").mockImplementation(() => {
      throw new DOMException("unavailable", "SecurityError");
    });
    try {
      bindDashboardPrincipal({ username: "alice", role: "operator" });
    } finally {
      key.mockRestore();
    }

    const { result } = renderHook(() => useSessionState("ares.dashboard.modules.category", ""));
    const fallbackUsed = result.current[0] === "";
    requireFixed(fallbackUsed, "Enumeration failure should block legacy dashboard reads.");
  });
});
