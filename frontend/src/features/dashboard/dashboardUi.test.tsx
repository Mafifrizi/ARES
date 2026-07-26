import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  bindDashboardPrincipal,
  clearDashboardSession,
  useDashboardSessionWriter,
  useSessionState
} from "./dashboardUiState";

function requireFixed(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function resetTestSessionStorage(): void {
  const keys = Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index))
    .filter((key): key is string => key !== null);
  for (const key of keys) {
    sessionStorage.removeItem(key);
  }
}

describe("dashboard session state", () => {
  beforeEach(() => {
    resetTestSessionStorage();
  });

  it("rehydrates and persists a campaign selection without changing the storage key", () => {
    const key = "ares.dashboard.selectedCampaignId";
    sessionStorage.setItem(key, JSON.stringify("campaign-before"));

    const { result } = renderHook(() => useSessionState(key, ""));
    expect(result.current[0]).toBe("campaign-before");

    act(() => result.current[1]("campaign-after"));
    const selectionPersisted = sessionStorage.getItem(key) === JSON.stringify("campaign-after");
    requireFixed(selectionPersisted, "Campaign selection should be persisted.");
  });

  it("removes every current and future dashboard key while preserving other session data", () => {
    sessionStorage.setItem("ares.dashboard.selectedCampaignId", "one");
    sessionStorage.setItem("ares.dashboard.future.setting", "two");
    sessionStorage.setItem("ares.refreshToken", "refresh");
    sessionStorage.setItem("other.application", "keep");

    clearDashboardSession();

    const selectedCampaignRemoved =
      sessionStorage.getItem("ares.dashboard.selectedCampaignId") === null;
    const futureSettingRemoved = sessionStorage.getItem("ares.dashboard.future.setting") === null;
    requireFixed(selectedCampaignRemoved, "Known dashboard state should be removed.");
    requireFixed(futureSettingRemoved, "Future dashboard state should be removed.");
    const refreshTokenPreserved = sessionStorage.getItem("ares.refreshToken") === "refresh";
    requireFixed(refreshTokenPreserved, "expected non-dashboard session key preservation");
    const unrelatedStatePreserved = sessionStorage.getItem("other.application") === "keep";
    requireFixed(unrelatedStatePreserved, "Unrelated session state should be preserved.");
  });

  it("prevents a mounted stale hook from recreating state after cleanup", () => {
    const key = "ares.dashboard.live.events";
    const { result } = renderHook(() => useSessionState<unknown[]>(key, []));

    act(() => {
      result.current[1]([{ type: "before-cleanup" }]);
    });
    const initialStatePersisted = sessionStorage.getItem(key) !== null;
    requireFixed(initialStatePersisted, "Mounted dashboard state should be persisted.");

    act(() => {
      clearDashboardSession();
      result.current[1]([{ type: "stale-write" }]);
    });
    const staleStateAbsent = sessionStorage.getItem(key) === null;
    requireFixed(staleStateAbsent, "Stale dashboard state should remain absent.");
  });

  it("allows a newly mounted hook to persist after cleanup", () => {
    clearDashboardSession();
    const key = "ares.dashboard.modules.search";
    const { result } = renderHook(() => useSessionState(key, ""));

    act(() => result.current[1]("current"));
    const currentStatePersisted = sessionStorage.getItem(key) === JSON.stringify("current");
    requireFixed(currentStatePersisted, "Newly mounted dashboard state should be persisted.");
  });

  it("rejects a retained component writer after cleanup and permits a newly mounted writer", () => {
    const key = "ares.dashboard.modules.tab";
    const stale = renderHook(() => useDashboardSessionWriter());
    expect(stale.result.current(key, "before")).toBe(true);

    clearDashboardSession();

    expect(stale.result.current(key, "stale")).toBe(false);
    const staleWriteAbsent = sessionStorage.getItem(key) === null;
    requireFixed(staleWriteAbsent, "Retained writer should not persist stale state.");

    const current = renderHook(() => useDashboardSessionWriter());
    expect(current.result.current(key, "after")).toBe(true);
    const currentWritePersisted = sessionStorage.getItem(key) === JSON.stringify("after");
    requireFixed(currentWritePersisted, "Current dashboard writer should persist state.");
  });

  it("rejects non-ARES keys and fails closed when storage writes fail", () => {
    const { result } = renderHook(() => useDashboardSessionWriter());
    expect(result.current("other.application", "blocked")).toBe(false);

    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("unavailable", "SecurityError");
    });
    try {
      expect(result.current("ares.dashboard.modules.tab", "blocked")).toBe(false);
    } finally {
      setItem.mockRestore();
    }
    const unrelatedWriteAbsent = sessionStorage.getItem("other.application") === null;
    const failedDashboardWriteAbsent =
      sessionStorage.getItem("ares.dashboard.modules.tab") === null;
    requireFixed(unrelatedWriteAbsent, "Non-dashboard write should remain absent.");
    requireFixed(failedDashboardWriteAbsent, "Failed dashboard write should remain absent.");
  });

  it("does not rehydrate a key whose removal failed during cleanup", () => {
    const key = "ares.dashboard.cleanup.failed";
    sessionStorage.setItem(key, JSON.stringify("previous-account"));
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

    const failedRemovalNeutralized = sessionStorage.getItem(key) === "";
    requireFixed(failedRemovalNeutralized, "Failed removal should leave a neutralized value.");
    const { result } = renderHook(() => useSessionState(key, "current-account"));
    expect(result.current[0]).toBe("current-account");
  });

  it("preserves dashboard preferences for the same canonical principal", () => {
    const preferenceKey = "ares.dashboard.modules.dryRun";
    bindDashboardPrincipal({ username: "alice", role: "operator" });
    sessionStorage.setItem(preferenceKey, JSON.stringify(true));

    bindDashboardPrincipal({ username: "alice", role: "operator" });

    const preferencePreserved = sessionStorage.getItem(preferenceKey) === JSON.stringify(true);
    requireFixed(preferencePreserved, "Matching principal should preserve dashboard preference.");
  });

  it.each([
    ["missing marker", null],
    ["malformed marker", "not-json"],
    ["different username", JSON.stringify({ username: "bob", role: "operator" })],
    ["different role", JSON.stringify({ username: "alice", role: "team_lead" })]
  ])("purges dashboard state for %s", (_label, storedPrincipal) => {
    const preferenceKey = "ares.dashboard.modules.dryRun";
    sessionStorage.setItem(preferenceKey, JSON.stringify(true));
    if (storedPrincipal) {
      sessionStorage.setItem("ares.dashboard.principal", storedPrincipal);
    }

    bindDashboardPrincipal({ username: "alice", role: "operator" });

    const preferenceRemoved = sessionStorage.getItem(preferenceKey) === null;
    const principalUpdated =
      sessionStorage.getItem("ares.dashboard.principal")
      === JSON.stringify({ username: "alice", role: "operator" });
    requireFixed(preferenceRemoved, "Mismatched principal should remove dashboard preference.");
    requireFixed(principalUpdated, "Canonical dashboard principal should be persisted.");
  });
});
