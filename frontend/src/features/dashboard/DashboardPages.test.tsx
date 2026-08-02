import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, beginIdentityTransition, clearTokens, setAccessToken } from "../../api/client";
import { installTokenPairIfCurrent } from "../../api/session";
import { CampaignEventSocketController } from "./DashboardPages";

interface Deferred<T> {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function requireFixed(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const ticketA = "A".repeat(43);
const ticketB = "B".repeat(43);

class ReducedWebSocket {
  static constructorCount = 0;
  static closeCount = 0;
  static legacyCredentialObserved = false;
  static canonicalTicketObserved = false;
  static freshTicketObserved = false;

  onclose: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(url: string | URL) {
    const candidate = String(url);
    ReducedWebSocket.constructorCount += 1;
    ReducedWebSocket.legacyCredentialObserved =
      ReducedWebSocket.legacyCredentialObserved
      || candidate.includes("token=")
      || candidate.includes("api_key=");
    ReducedWebSocket.canonicalTicketObserved =
      ReducedWebSocket.canonicalTicketObserved
      || candidate.endsWith(`?ticket=${ticketA}`)
      || candidate.endsWith(`?ticket=${ticketB}`);
    ReducedWebSocket.freshTicketObserved =
      ReducedWebSocket.freshTicketObserved
      || candidate.endsWith(`?ticket=${ticketB}`);
  }

  close(): void {
    ReducedWebSocket.closeCount += 1;
  }

  static reset(): void {
    ReducedWebSocket.constructorCount = 0;
    ReducedWebSocket.closeCount = 0;
    ReducedWebSocket.legacyCredentialObserved = false;
    ReducedWebSocket.canonicalTicketObserved = false;
    ReducedWebSocket.freshTicketObserved = false;
  }
}

function installSession(label = "a"): void {
  const snapshot = beginIdentityTransition();
  const installed = installTokenPairIfCurrent(
    snapshot,
    `access-${label}`,
    `refresh-${label}`
  );
  requireFixed(installed, "expected test session installation");
}

function storageExcludesTickets(): boolean {
  const values: string[] = [];
  for (const storage of [localStorage, sessionStorage]) {
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (key !== null) {
        values.push(storage.getItem(key) ?? "");
      }
    }
  }
  return values.every((value) => !value.includes(ticketA) && !value.includes(ticketB));
}

describe("campaign WebSocket ticket barrier", () => {
  beforeEach(() => {
    clearTokens();
    localStorage.clear();
    sessionStorage.clear();
    installSession();
    ReducedWebSocket.reset();
    vi.stubGlobal("WebSocket", ReducedWebSocket);
  });

  afterEach(() => {
    cleanup();
    clearTokens();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("awaits issuance before constructing a ticket-only WebSocket", async () => {
    const barrier = deferred<{ ticket: string; expires_in: 30 }>();
    vi.spyOn(api, "websocketTicket").mockReturnValue(barrier.promise);
    const disconnected = vi.fn();
    const events = vi.fn();

    render(<CampaignEventSocketController
      campaignId="campaign-a"
      enabled
      onDisconnected={disconnected}
      onEvent={events}
    />);
    expect(ReducedWebSocket.constructorCount).toBe(0);

    await act(async () => {
      barrier.resolve({ ticket: ticketA, expires_in: 30 });
      await barrier.promise;
    });
    await waitFor(() => expect(ReducedWebSocket.constructorCount).toBe(1));
    requireFixed(
      ReducedWebSocket.canonicalTicketObserved
      && !ReducedWebSocket.legacyCredentialObserved
      && storageExcludesTickets(),
      "expected transient ticket-only WebSocket construction",
    );
    expect(disconnected).not.toHaveBeenCalled();
    expect(events).not.toHaveBeenCalled();
  });

  it("discards a ticket response after logout or another-account login", async () => {
    const logoutBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const loginBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    vi.spyOn(api, "websocketTicket")
      .mockReturnValueOnce(logoutBarrier.promise)
      .mockReturnValueOnce(loginBarrier.promise);

    const first = render(<CampaignEventSocketController
      campaignId="campaign-a"
      enabled
      onDisconnected={vi.fn()}
      onEvent={vi.fn()}
    />);
    clearTokens();
    await act(async () => {
      logoutBarrier.resolve({ ticket: ticketA, expires_in: 30 });
      await logoutBarrier.promise;
    });
    first.unmount();

    installSession("a-again");
    const second = render(<CampaignEventSocketController
      campaignId="campaign-a"
      enabled
      onDisconnected={vi.fn()}
      onEvent={vi.fn()}
    />);
    installSession("b");
    await act(async () => {
      loginBarrier.resolve({ ticket: ticketA, expires_in: 30 });
      await loginBarrier.promise;
    });
    second.unmount();

    expect(ReducedWebSocket.constructorCount).toBe(0);
  });

  it("discards superseded campaign and unmounted responses", async () => {
    const firstBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const secondBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const unmountBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    vi.spyOn(api, "websocketTicket")
      .mockReturnValueOnce(firstBarrier.promise)
      .mockReturnValueOnce(secondBarrier.promise)
      .mockReturnValueOnce(unmountBarrier.promise);
    const options = {
      campaignId: "campaign-a",
      enabled: true,
      onDisconnected: vi.fn(),
      onEvent: vi.fn()
    };
    const hook = render(<CampaignEventSocketController {...options} />);
    hook.rerender(<CampaignEventSocketController
      {...options}
      campaignId="campaign-b"
    />);
    await act(async () => {
      firstBarrier.resolve({ ticket: ticketA, expires_in: 30 });
      await firstBarrier.promise;
    });
    expect(ReducedWebSocket.constructorCount).toBe(0);
    await act(async () => {
      secondBarrier.resolve({ ticket: ticketB, expires_in: 30 });
      await secondBarrier.promise;
    });
    await waitFor(() => expect(ReducedWebSocket.constructorCount).toBe(1));
    hook.unmount();

    const unmounted = render(<CampaignEventSocketController
      {...options}
      campaignId="campaign-c"
    />);
    unmounted.unmount();
    await act(async () => {
      unmountBarrier.resolve({ ticket: ticketA, expires_in: 30 });
      await unmountBarrier.promise;
    });
    expect(ReducedWebSocket.constructorCount).toBe(1);
    expect(ReducedWebSocket.closeCount).toBe(1);
  });

  it("allows same-session refresh while rejecting malformed issuance", async () => {
    const validBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const malformedBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    vi.spyOn(api, "websocketTicket")
      .mockReturnValueOnce(validBarrier.promise)
      .mockReturnValueOnce(malformedBarrier.promise);
    const disconnected = vi.fn();
    const valid = render(<CampaignEventSocketController
      campaignId="campaign-a"
      enabled
      onDisconnected={disconnected}
      onEvent={vi.fn()}
    />);
    setAccessToken("same-session-refreshed-access");
    await act(async () => {
      validBarrier.resolve({ ticket: ticketA, expires_in: 30 });
      await validBarrier.promise;
    });
    await waitFor(() => expect(ReducedWebSocket.constructorCount).toBe(1));
    valid.unmount();

    const malformed = render(<CampaignEventSocketController
      campaignId="campaign-a"
      enabled
      onDisconnected={disconnected}
      onEvent={vi.fn()}
    />);
    await act(async () => {
      malformedBarrier.resolve({ ticket: "invalid", expires_in: 30 });
      await malformedBarrier.promise;
    });
    await waitFor(() => expect(disconnected).toHaveBeenCalledTimes(1));
    malformed.unmount();
    expect(ReducedWebSocket.constructorCount).toBe(1);
  });

  it("requests a new ticket after a failed attempt", async () => {
    const failedBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const retryBarrier = deferred<{ ticket: string; expires_in: 30 }>();
    const ticketRequest = vi.spyOn(api, "websocketTicket")
      .mockReturnValueOnce(failedBarrier.promise)
      .mockReturnValueOnce(retryBarrier.promise);
    const disconnected = vi.fn();
    const options = {
      campaignId: "campaign-a",
      enabled: true,
      onDisconnected: disconnected,
      onEvent: vi.fn()
    };
    const hook = render(<CampaignEventSocketController {...options} />);
    await act(async () => {
      failedBarrier.reject(new Error("fixed test failure"));
      try {
        await failedBarrier.promise;
      } catch {
        // The hook owns the expected failure path.
      }
    });
    await waitFor(() => expect(disconnected).toHaveBeenCalledTimes(1));

    hook.rerender(<CampaignEventSocketController {...options} enabled={false} />);
    hook.rerender(<CampaignEventSocketController {...options} enabled />);
    await act(async () => {
      retryBarrier.resolve({ ticket: ticketB, expires_in: 30 });
      await retryBarrier.promise;
    });
    await waitFor(() => expect(ReducedWebSocket.constructorCount).toBe(1));
    requireFixed(
      ticketRequest.mock.calls.length === 2 && ReducedWebSocket.freshTicketObserved,
      "expected a fresh ticket on the superseding connection attempt",
    );
  });
});
