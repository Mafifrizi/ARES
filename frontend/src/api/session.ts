const REFRESH_TOKEN_KEY = "ares.refreshToken";
const COORDINATION_KEY = "ares.sessionCoordination";
const COORDINATION_CHANNEL = "ares.session-control";

let accessToken: string | null = null;
let sessionRevision = 0;
let refreshTokenSuppressed = false;
let coordinationKey: string | null = null;
let refreshGeneration: number | null = null;
const invalidationListeners = new Set<() => void>();

export interface SessionSnapshot {
  readonly revision: number;
  readonly accessToken: string | null;
  readonly refreshToken: string | null;
  readonly coordinationKey: string | null;
  readonly refreshGeneration: number | null;
}

interface CoordinationRecord {
  readonly key: string;
  readonly generation: number;
  readonly tombstone: boolean;
}

function publishCoordination(record: CoordinationRecord): void {
  try {
    localStorage.setItem(COORDINATION_KEY, JSON.stringify(record));
  } catch {
    // In-memory state remains fail-closed when cross-tab storage is unavailable.
  }
  try {
    const channel = new BroadcastChannel(COORDINATION_CHANNEL);
    channel.postMessage(record);
    channel.close();
  } catch {
    // Web Locks plus local state still protect the current tab.
  }
}

export function readCoordinationRecord(): CoordinationRecord | null {
  try {
    const value = JSON.parse(localStorage.getItem(COORDINATION_KEY) ?? "null") as unknown;
    if (
      typeof value !== "object"
      || value === null
      || !("key" in value)
      || !("generation" in value)
      || !("tombstone" in value)
      || typeof value.key !== "string"
      || typeof value.generation !== "number"
      || !Number.isSafeInteger(value.generation)
      || typeof value.tombstone !== "boolean"
    ) {
      return null;
    }
    return value as CoordinationRecord;
  } catch {
    return null;
  }
}

function persistRefreshToken(token: string | null): boolean {
  try {
    if (token) {
      sessionStorage.setItem(REFRESH_TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(REFRESH_TOKEN_KEY);
    }
    refreshTokenSuppressed = false;
    return true;
  } catch {
    if (token) {
      try {
        sessionStorage.removeItem(REFRESH_TOKEN_KEY);
      } catch {
        try {
          sessionStorage.setItem(REFRESH_TOKEN_KEY, "");
        } catch {
          // In-memory suppression remains authoritative while storage is unavailable.
        }
      }
    } else {
      try {
        sessionStorage.setItem(REFRESH_TOKEN_KEY, "");
      } catch {
        // In-memory suppression remains authoritative while storage is unavailable.
      }
    }
    refreshTokenSuppressed = true;
    return false;
  }
}

function writeTokenPair(
  nextAccessToken: string | null,
  nextRefreshToken: string | null,
  nextCoordinationKey: string | null = null,
  nextGeneration: number | null = null
): boolean {
  if (nextRefreshToken === null) {
    accessToken = null;
    if (coordinationKey !== null && refreshGeneration !== null) {
      publishCoordination({
        key: coordinationKey,
        generation: refreshGeneration,
        tombstone: true
      });
    }
    coordinationKey = null;
    refreshGeneration = null;
    persistRefreshToken(null);
    return true;
  }
  if (!persistRefreshToken(nextRefreshToken)) {
    accessToken = null;
    return false;
  }
  accessToken = nextAccessToken;
  coordinationKey = nextCoordinationKey;
  refreshGeneration = nextGeneration;
  if (coordinationKey !== null && refreshGeneration !== null) {
    publishCoordination({
      key: coordinationKey,
      generation: refreshGeneration,
      tombstone: false
    });
  }
  return true;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setRefreshToken(token: string | null): void {
  persistRefreshToken(token);
}

export function getRefreshToken(): string | null {
  if (refreshTokenSuppressed) {
    return null;
  }
  try {
    return sessionStorage.getItem(REFRESH_TOKEN_KEY) || null;
  } catch {
    refreshTokenSuppressed = true;
    return null;
  }
}

export function captureSession(): SessionSnapshot {
  return {
    revision: sessionRevision,
    accessToken,
    refreshToken: getRefreshToken(),
    coordinationKey,
    refreshGeneration
  };
}

export function isSessionCurrent(snapshot: Pick<SessionSnapshot, "revision">): boolean {
  return snapshot.revision === sessionRevision;
}

export function beginIdentityTransition(): SessionSnapshot {
  sessionRevision += 1;
  writeTokenPair(null, null);
  return captureSession();
}

export function installTokenPairIfCurrent(
  snapshot: Pick<SessionSnapshot, "revision">,
  nextAccessToken: string,
  nextRefreshToken: string,
  nextCoordinationKey: string | null = null,
  nextGeneration: number | null = null
): boolean {
  if (!isSessionCurrent(snapshot)) {
    return false;
  }
  return writeTokenPair(
    nextAccessToken,
    nextRefreshToken,
    nextCoordinationKey,
    nextGeneration
  );
}

export function replaceTokenPairIfCurrent(
  snapshot: SessionSnapshot,
  nextAccessToken: string,
  nextRefreshToken: string,
  nextCoordinationKey: string | null = snapshot.coordinationKey,
  nextGeneration: number | null = snapshot.refreshGeneration
): boolean {
  if (
    !isSessionCurrent(snapshot)
    || getRefreshToken() !== snapshot.refreshToken
  ) {
    return false;
  }
  return writeTokenPair(
    nextAccessToken,
    nextRefreshToken,
    nextCoordinationKey,
    nextGeneration
  );
}

export function clearTokens(): void {
  sessionRevision += 1;
  writeTokenPair(null, null);
}

export function invalidateSession(snapshot?: Pick<SessionSnapshot, "revision">): boolean {
  if (snapshot && !isSessionCurrent(snapshot)) {
    return false;
  }
  sessionRevision += 1;
  writeTokenPair(null, null);
  for (const listener of [...invalidationListeners]) {
    try {
      listener();
    } catch {
      // One subscriber must not prevent the remaining local cleanup subscribers.
    }
  }
  return true;
}

export function subscribeToSessionInvalidation(listener: () => void): () => void {
  invalidationListeners.add(listener);
  return () => {
    invalidationListeners.delete(listener);
  };
}

function applyPeerInvalidation(value: unknown): void {
  if (
    typeof value !== "object"
    || value === null
    || !("key" in value)
    || !("generation" in value)
    || !("tombstone" in value)
    || value.key !== coordinationKey
    || typeof value.generation !== "number"
    || !Number.isSafeInteger(value.generation)
    || typeof value.tombstone !== "boolean"
    || refreshGeneration === null
    || (!value.tombstone && value.generation <= refreshGeneration)
  ) {
    return;
  }
  sessionRevision += 1;
  accessToken = null;
  coordinationKey = null;
  refreshGeneration = null;
  persistRefreshToken(null);
  for (const listener of [...invalidationListeners]) {
    try {
      listener();
    } catch {
      // A peer invalidation must settle every remaining subscriber.
    }
  }
}

try {
  const peerChannel = new BroadcastChannel(COORDINATION_CHANNEL);
  peerChannel.onmessage = (event: MessageEvent<unknown>) => {
    applyPeerInvalidation(event.data);
  };
} catch {
  // Lack of a safe channel is handled by the refresh fail-closed path.
}
