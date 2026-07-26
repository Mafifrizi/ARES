const REFRESH_TOKEN_KEY = "ares.refreshToken";

let accessToken: string | null = null;
let sessionRevision = 0;
let refreshTokenSuppressed = false;
const invalidationListeners = new Set<() => void>();

export interface SessionSnapshot {
  readonly revision: number;
  readonly accessToken: string | null;
  readonly refreshToken: string | null;
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

function writeTokenPair(nextAccessToken: string | null, nextRefreshToken: string | null): boolean {
  if (nextRefreshToken === null) {
    accessToken = null;
    persistRefreshToken(null);
    return true;
  }
  if (!persistRefreshToken(nextRefreshToken)) {
    accessToken = null;
    return false;
  }
  accessToken = nextAccessToken;
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
    refreshToken: getRefreshToken()
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
  nextRefreshToken: string
): boolean {
  if (!isSessionCurrent(snapshot)) {
    return false;
  }
  return writeTokenPair(nextAccessToken, nextRefreshToken);
}

export function replaceTokenPairIfCurrent(
  snapshot: SessionSnapshot,
  nextAccessToken: string,
  nextRefreshToken: string
): boolean {
  if (
    !isSessionCurrent(snapshot)
    || getRefreshToken() !== snapshot.refreshToken
  ) {
    return false;
  }
  return writeTokenPair(nextAccessToken, nextRefreshToken);
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
