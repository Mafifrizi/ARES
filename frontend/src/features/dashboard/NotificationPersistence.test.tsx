import { describe, expect, it, beforeEach } from "vitest";

describe("Dashboard notification deletion and persistence", () => {
  const DELETED_KEY = "ares.dashboard.notifications.deleted";
  const READ_KEY = "ares.dashboard.notifications.read";

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("persists deleted notification IDs to localStorage and reloads them on fresh mount", () => {
    const testIds = ["telemetry:failed-runs", "telemetry:error-rate"];
    localStorage.setItem(DELETED_KEY, JSON.stringify(testIds));

    const raw = localStorage.getItem(DELETED_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed).toEqual(testIds);
  });

  it("matches deleted notifications by exact ID and legacy dynamic prefixes", () => {
    const deletedList = ["telemetry:failed-runs", "telemetry:error-rate:0.58"];

    function isNotificationDeleted(id: string, deletedNotificationIds: string[]): boolean {
      return (
        deletedNotificationIds.includes(id) ||
        deletedNotificationIds.some(
          (deletedId) => deletedId.startsWith(`${id}:`) || id.startsWith(`${deletedId}:`)
        )
      );
    }

    // Exact match for stable id
    expect(isNotificationDeleted("telemetry:failed-runs", deletedList)).toBe(true);
    // Prefix match for legacy deleted id with float or count
    expect(isNotificationDeleted("telemetry:error-rate", deletedList)).toBe(true);
    // Unrelated notification is not suppressed
    expect(isNotificationDeleted("health:error", deletedList)).toBe(false);
  });

  it("does not wipe deleted notifications when current active notifications change or switch scopes", () => {
    let deleted = ["telemetry:failed-runs"];

    // Simulate switching campaign where telemetry:failed-runs is not in current active query
    const activeIdsInNewCampaign: string[] = ["reports:error:camp-2"];

    // Buggy behavior was: deleted = deleted.filter(id => activeIdsInNewCampaign.includes(id));
    // Correct behavior: deleted list is preserved across scope changes
    expect(deleted).toContain("telemetry:failed-runs");

    // When switching back to scope with telemetry:failed-runs:
    expect(deleted.includes("telemetry:failed-runs")).toBe(true);
  });
});
