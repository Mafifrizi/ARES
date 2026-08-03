const LEGACY_REFRESH_TOKEN_KEY = "ares.refreshToken";
const COORDINATION_KEY = "ares.sessionCoordination.v2";
const COORDINATION_CHANNEL = "ares.session-control-v2";
const COORDINATION_VERSION = 2;
const MAX_GENERATION = 1_000_000_000;

// Rollout hygiene is synchronous and precedes every possible network operation.
let legacyStorageCleared = true;
try {
  sessionStorage.removeItem(LEGACY_REFRESH_TOKEN_KEY);
} catch {
  legacyStorageCleared = false;
}

let accessToken: string | null = null;
let sessionRevision = 0;
let coordinationKey: string | null = null;
let refreshGeneration: number | null = null;
let unavailable = false;
const invalidationListeners = new Set<() => void>();

export interface SessionSnapshot {
  readonly revision: number;
  readonly accessToken: string | null;
  readonly coordinationKey: string | null;
  readonly refreshGeneration: number | null;
}

export interface CoordinationRecord {
  readonly version: 2;
  readonly key: string;
  readonly generation: number;
  readonly tombstone: boolean;
}

function isCoordinationKey(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function parseCoordinationRecord(value: unknown): CoordinationRecord | null {
  if (
    typeof value !== "object"
    || value === null
    || !("version" in value)
    || !("key" in value)
    || !("generation" in value)
    || !("tombstone" in value)
    || value.version !== COORDINATION_VERSION
    || !isCoordinationKey(value.key)
    || typeof value.generation !== "number"
    || !Number.isSafeInteger(value.generation)
    || value.generation < 0
    || value.generation > MAX_GENERATION
    || typeof value.tombstone !== "boolean"
  ) {
    return null;
  }
  return value as CoordinationRecord;
}

function notifyInvalidation(): void {
  for (const listener of [...invalidationListeners]) {
    try {
      listener();
    } catch {
      // One local subscriber cannot prevent the remaining cleanup subscribers.
    }
  }
}

export function browserCoordinationAvailable(): boolean {
  if (
    !legacyStorageCleared
    || !navigator.locks
    || typeof navigator.locks.request !== "function"
  ) {
    return false;
  }
  try {
    const probe = "ares.sessionCoordination.probe";
    localStorage.setItem(probe, "2");
    const writable = localStorage.getItem(probe) === "2";
    localStorage.removeItem(probe);
    return writable;
  } catch {
    return false;
  }
}

export function publishCoordination(record: CoordinationRecord): boolean {
  if (parseCoordinationRecord(record) === null) {
    return false;
  }
  try {
    localStorage.setItem(COORDINATION_KEY, JSON.stringify(record));
    if (localStorage.getItem(COORDINATION_KEY) !== JSON.stringify(record)) {
      return false;
    }
  } catch {
    return false;
  }
  try {
    const channel = new BroadcastChannel(COORDINATION_CHANNEL);
    channel.postMessage(record);
    channel.close();
  } catch {
    // Strictly validated localStorage events are the required fallback.
  }
  return true;
}

export function readCoordinationRecord(): CoordinationRecord | null {
  try {
    const raw = localStorage.getItem(COORDINATION_KEY);
    if (raw === null) {
      return null;
    }
    return parseCoordinationRecord(JSON.parse(raw) as unknown);
  } catch {
    return null;
  }
}

function writeLocalSession(
  nextAccessToken: string | null,
  nextCoordinationKey: string | null,
  nextGeneration: number | null,
  options: { publish: boolean }
): boolean {
  accessToken = nextAccessToken;
  coordinationKey = nextCoordinationKey;
  refreshGeneration = nextGeneration;
  unavailable = false;
  if (!options.publish || nextCoordinationKey === null || nextGeneration === null) {
    return true;
  }
  return publishCoordination({
    version: COORDINATION_VERSION,
    key: nextCoordinationKey,
    generation: nextGeneration,
    tombstone: false
  });
}

function publishTombstone(): boolean {
  if (coordinationKey === null || refreshGeneration === null) {
    return true;
  }
  return publishCoordination({
    version: COORDINATION_VERSION,
    key: coordinationKey,
    generation: refreshGeneration,
    tombstone: true
  });
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function captureSession(): SessionSnapshot {
  return {
    revision: sessionRevision,
    accessToken,
    coordinationKey,
    refreshGeneration
  };
}

export function isSessionCurrent(snapshot: Pick<SessionSnapshot, "revision">): boolean {
  return snapshot.revision === sessionRevision;
}

export function beginIdentityTransition(): SessionSnapshot {
  publishTombstone();
  sessionRevision += 1;
  writeLocalSession(null, null, null, { publish: false });
  return captureSession();
}

export function installSessionIfCurrent(
  snapshot: Pick<SessionSnapshot, "revision">,
  nextAccessToken: string,
  nextCoordinationKey: string,
  nextGeneration: number
): boolean {
  if (
    !isSessionCurrent(snapshot)
    || !nextAccessToken
    || !isCoordinationKey(nextCoordinationKey)
    || !Number.isSafeInteger(nextGeneration)
    || nextGeneration < 0
    || nextGeneration > MAX_GENERATION
  ) {
    return false;
  }
  if (!writeLocalSession(
    nextAccessToken,
    nextCoordinationKey,
    nextGeneration,
    { publish: true }
  )) {
    accessToken = null;
    coordinationKey = null;
    refreshGeneration = null;
    return false;
  }
  return true;
}

// Compatibility signature for the protected dashboard test surface. The legacy
// refresh argument is deliberately discarded and can never enter browser state.
export function installTokenPairIfCurrent(
  snapshot: Pick<SessionSnapshot, "revision">,
  nextAccessToken: string,
  _legacyRefreshToken: string,
  nextCoordinationKey: string | null = null,
  nextGeneration: number | null = null
): boolean {
  if (nextCoordinationKey === null || nextGeneration === null) {
    if (!isSessionCurrent(snapshot) || !nextAccessToken) {
      return false;
    }
    accessToken = nextAccessToken;
    return true;
  }
  return installSessionIfCurrent(
    snapshot,
    nextAccessToken,
    nextCoordinationKey,
    nextGeneration
  );
}

export function replaceSessionIfCurrent(
  snapshot: Pick<SessionSnapshot, "revision">,
  nextAccessToken: string,
  nextCoordinationKey: string,
  nextGeneration: number
): boolean {
  return installSessionIfCurrent(
    snapshot,
    nextAccessToken,
    nextCoordinationKey,
    nextGeneration
  );
}

export function clearTokens(): void {
  publishTombstone();
  sessionRevision += 1;
  writeLocalSession(null, null, null, { publish: false });
}

export function markSessionUnavailable(
  snapshot?: Pick<SessionSnapshot, "revision">
): boolean {
  if (snapshot && !isSessionCurrent(snapshot)) {
    return false;
  }
  publishTombstone();
  sessionRevision += 1;
  accessToken = null;
  coordinationKey = null;
  refreshGeneration = null;
  unavailable = true;
  notifyInvalidation();
  return true;
}

export function isSessionUnavailable(): boolean {
  return unavailable;
}

export function invalidateSession(snapshot?: Pick<SessionSnapshot, "revision">): boolean {
  if (snapshot && !isSessionCurrent(snapshot)) {
    return false;
  }
  publishTombstone();
  sessionRevision += 1;
  writeLocalSession(null, null, null, { publish: false });
  notifyInvalidation();
  return true;
}

export function subscribeToSessionInvalidation(listener: () => void): () => void {
  invalidationListeners.add(listener);
  return () => {
    invalidationListeners.delete(listener);
  };
}

function applyPeerRecord(value: unknown): void {
  const record = parseCoordinationRecord(value);
  if (record === null || coordinationKey === null || record.key !== coordinationKey) {
    return;
  }
  if (record.tombstone) {
    sessionRevision += 1;
    writeLocalSession(null, null, null, { publish: false });
    notifyInvalidation();
    return;
  }
  if (refreshGeneration !== null && record.generation > refreshGeneration) {
    refreshGeneration = record.generation;
  }
}

try {
  const peerChannel = new BroadcastChannel(COORDINATION_CHANNEL);
  peerChannel.onmessage = (event: MessageEvent<unknown>) => {
    applyPeerRecord(event.data);
  };
} catch {
  // Validated storage events remain the notification fallback.
}

try {
  window.addEventListener("storage", (event: StorageEvent) => {
    if (event.key !== COORDINATION_KEY || event.newValue === null) {
      return;
    }
    try {
      applyPeerRecord(JSON.parse(event.newValue) as unknown);
    } catch {
      // Invalid records never alter local authority.
    }
  });
} catch {
  // Browser coordination availability is checked before session operations.
}

export const REFRESH_COOKIE_LOCK = "ares-refresh-cookie-v2";
