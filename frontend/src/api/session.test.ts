import { beforeEach, describe, expect, it, vi } from "vitest";

const KEY_A = "A".repeat(43);
const KEY_B = "B".repeat(43);

function installLocks(): void {
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: { request: vi.fn(async (_name: string, operation: () => unknown) => operation()) }
  });
}

describe("cookie-backed session state", () => {
  beforeEach(async () => {
    sessionStorage.clear();
    localStorage.clear();
    installLocks();
    vi.resetModules();
  });

  it("deletes the legacy refresh token synchronously on module load", async () => {
    sessionStorage.setItem("ares.refreshToken", "legacy-value");
    await import("./session");
    expect(sessionStorage.getItem("ares.refreshToken")).toBeNull();
  });

  it("fails closed when legacy refresh storage cannot be cleared", async () => {
    const failure = vi.spyOn(Storage.prototype, "removeItem").mockImplementationOnce(() => {
      throw new Error("fixed-storage-failure");
    });
    const session = await import("./session");
    expect(session.browserCoordinationAvailable()).toBe(false);
    failure.mockRestore();
  });

  it("keeps access tokens in module memory only", async () => {
    const session = await import("./session");
    session.setAccessToken("memory-only");
    expect(session.getAccessToken()).toBe("memory-only");
    expect(JSON.stringify(sessionStorage)).not.toContain("memory-only");
    expect(JSON.stringify(localStorage)).not.toContain("memory-only");
  });

  it("requires Web Locks and writable localStorage", async () => {
    const session = await import("./session");
    expect(session.browserCoordinationAvailable()).toBe(true);
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    expect(session.browserCoordinationAvailable()).toBe(false);
  });

  it("publishes only versioned non-secret coordination metadata", async () => {
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    expect(session.installSessionIfCurrent(snapshot, "access", KEY_A, 1)).toBe(true);
    expect(session.readCoordinationRecord()).toEqual({
      version: 2,
      key: KEY_A,
      generation: 1,
      tombstone: false
    });
    expect(localStorage.getItem("ares.sessionCoordination.v2")).not.toContain("access");
  });

  it.each([
    null,
    {},
    { version: 1, key: KEY_A, generation: 0, tombstone: false },
    { version: 2, key: "short", generation: 0, tombstone: false },
    { version: 2, key: KEY_A, generation: -1, tombstone: false },
    { version: 2, key: KEY_A, generation: 0, tombstone: "false" }
  ])("rejects malformed coordination records", async (value) => {
    const session = await import("./session");
    expect(session.parseCoordinationRecord(value)).toBeNull();
  });

  it("normal generation advancement preserves an access token", async () => {
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    session.installSessionIfCurrent(snapshot, "access-a", KEY_A, 1);
    window.dispatchEvent(new StorageEvent("storage", {
      key: "ares.sessionCoordination.v2",
      newValue: JSON.stringify({ version: 2, key: KEY_A, generation: 2, tombstone: false })
    }));
    expect(session.getAccessToken()).toBe("access-a");
    expect(session.captureSession().refreshGeneration).toBe(2);
  });

  it("a matching tombstone clears in-memory access", async () => {
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    session.installSessionIfCurrent(snapshot, "access-a", KEY_A, 1);
    window.dispatchEvent(new StorageEvent("storage", {
      key: "ares.sessionCoordination.v2",
      newValue: JSON.stringify({ version: 2, key: KEY_A, generation: 1, tombstone: true })
    }));
    expect(session.getAccessToken()).toBeNull();
  });

  it("a different-family message cannot alter local authority", async () => {
    const session = await import("./session");
    const snapshot = session.beginIdentityTransition();
    session.installSessionIfCurrent(snapshot, "access-a", KEY_A, 1);
    window.dispatchEvent(new StorageEvent("storage", {
      key: "ares.sessionCoordination.v2",
      newValue: JSON.stringify({ version: 2, key: KEY_B, generation: 2, tombstone: true })
    }));
    expect(session.getAccessToken()).toBe("access-a");
  });

  it("stale revisions cannot install a late response", async () => {
    const session = await import("./session");
    const stale = session.captureSession();
    session.clearTokens();
    expect(session.installSessionIfCurrent(stale, "late", KEY_A, 1)).toBe(false);
    expect(session.getAccessToken()).toBeNull();
  });

  it("identity transitions publish a tombstone for the old family", async () => {
    const session = await import("./session");
    const first = session.beginIdentityTransition();
    session.installSessionIfCurrent(first, "access", KEY_A, 3);
    session.beginIdentityTransition();
    expect(session.readCoordinationRecord()?.tombstone).toBe(true);
  });

  it("unavailable state is fixed and contains no credential", async () => {
    const session = await import("./session");
    const snapshot = session.captureSession();
    expect(session.markSessionUnavailable(snapshot)).toBe(true);
    expect(session.isSessionUnavailable()).toBe(true);
    expect(session.getAccessToken()).toBeNull();
  });
});
