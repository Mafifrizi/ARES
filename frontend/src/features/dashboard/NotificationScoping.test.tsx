import { beforeEach, describe, expect, it } from "vitest";

import { getStoredNotificationIds, setStoredNotificationIds } from "./DashboardPages";
import { clearDashboardSession } from "./dashboardUiState";

// AUDIT run-1 H20: notification read/deleted state must be scoped to the current
// operator, never written to an unscoped key, never read via an unscoped
// fallback, and purged from localStorage on logout.
describe("Dashboard notification state is per-operator (H20)", () => {
  const KEY = "ares.dashboard.notifications.deleted";

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("writes only the per-operator key and isolates operators", () => {
    setStoredNotificationIds(KEY, "alice", ["telemetry:a"]);

    expect(localStorage.getItem(`${KEY}.alice`)).not.toBeNull();
    // The unscoped key must never be written (that is what leaked across operators).
    expect(localStorage.getItem(KEY)).toBeNull();

    // Another operator on the same browser sees nothing.
    expect(getStoredNotificationIds(KEY, "bob")).toEqual([]);
    // The owning operator still sees their own state.
    expect(getStoredNotificationIds(KEY, "alice")).toEqual(["telemetry:a"]);
  });

  it("does not fall back to a legacy unscoped blob", () => {
    localStorage.setItem(KEY, JSON.stringify(["leaked-from-previous-operator"]));
    expect(getStoredNotificationIds(KEY, "alice")).toEqual([]);
  });

  it("returns nothing when there is no operator scope", () => {
    localStorage.setItem(KEY, JSON.stringify(["x"]));
    expect(getStoredNotificationIds(KEY, undefined)).toEqual([]);
    setStoredNotificationIds(KEY, undefined, ["y"]);
    expect(localStorage.getItem(KEY)).toBe(JSON.stringify(["x"])); // unchanged, not overwritten
  });

  it("purges notification localStorage on logout", () => {
    setStoredNotificationIds(KEY, "alice", ["telemetry:a"]);
    localStorage.setItem("ares.dashboard.notifications.read.alice", "[]");

    clearDashboardSession();

    expect(localStorage.getItem(`${KEY}.alice`)).toBeNull();
    expect(localStorage.getItem("ares.dashboard.notifications.read.alice")).toBeNull();
  });
});
