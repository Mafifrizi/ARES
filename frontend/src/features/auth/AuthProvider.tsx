import { useQueryClient } from "@tanstack/react-query";
import { Fragment, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  captureSession,
  clearTokens,
  getRefreshToken,
  invalidateSession,
  isSessionCurrent,
  login as loginRequest,
  logout as logoutRequest,
  logoutAll as logoutAllRequest,
  refreshAccessToken,
  subscribeToSessionInvalidation
} from "../../api/client";
import type { UserProfile } from "../../api/types";
import { bindDashboardPrincipal, clearDashboardSession } from "../dashboard/dashboardUiState";
import { AuthContext, type AuthState } from "./authContext";

function LoadingSession() {
  return (
    <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
      <div className="panel p-5 text-center">
        <h1 className="text-xl font-bold">ARES</h1>
        <p className="mt-1 text-sm text-slate-600">Loading session</p>
      </div>
    </div>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(Boolean(getRefreshToken()));
  const [accountBoundary, setAccountBoundary] = useState(0);
  const providerLifecycle = useRef({ generation: 0, mounted: false });
  const queryClient = useQueryClient();

  const resetLocalSession = useCallback((tokensAlreadyCleared = false) => {
    if (!tokensAlreadyCleared) {
      clearTokens();
    }
    setUser(null);
    setAccountBoundary((current) => current + 1);
    try {
      queryClient.clear();
    } finally {
      clearDashboardSession();
    }
  }, [queryClient]);

  const ownsProviderLifecycle = useCallback((generation: number) => {
    const current = providerLifecycle.current;
    return current.mounted && current.generation === generation;
  }, []);

  useEffect(() => {
    const generation = providerLifecycle.current.generation + 1;
    providerLifecycle.current = { generation, mounted: true };
    return () => {
      if (providerLifecycle.current.generation === generation) {
        providerLifecycle.current = { generation: generation + 1, mounted: false };
      }
    };
  }, []);

  useEffect(
    () => subscribeToSessionInvalidation(() => resetLocalSession(true)),
    [resetLocalSession]
  );

  useEffect(() => {
    let active = true;
    if (!getRefreshToken()) {
      resetLocalSession();
      setLoading(false);
      return;
    }
    (async () => {
      const startupSession = captureSession();
      try {
        if (!(await refreshAccessToken(startupSession))) {
          if (active && isSessionCurrent(startupSession)) {
            invalidateSession(startupSession);
          }
          return;
        }
        if (!active || !isSessionCurrent(startupSession)) {
          return;
        }
        const profileSession = captureSession();
        const profile = await api.me();
        if (active && isSessionCurrent(profileSession)) {
          bindDashboardPrincipal(profile);
          setUser(profile);
        }
      } catch {
        if (active) {
          invalidateSession(startupSession);
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    })();
    return () => {
      active = false;
    };
  }, [resetLocalSession]);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      login: async (username, password) => {
        const loginLifecycle = providerLifecycle.current.generation;
        if (!ownsProviderLifecycle(loginLifecycle)) {
          throw new Error("Session changed");
        }
        resetLocalSession();
        if (!ownsProviderLifecycle(loginLifecycle)) {
          throw new Error("Session changed");
        }
        const loginPromise = loginRequest(username, password);
        const loginSession = captureSession();
        const assertLoginOwnership = () => {
          if (!ownsProviderLifecycle(loginLifecycle) || !isSessionCurrent(loginSession)) {
            throw new Error("Session changed");
          }
        };
        try {
          await loginPromise;
          assertLoginOwnership();
          const profile = await api.me();
          assertLoginOwnership();
          bindDashboardPrincipal(profile);
          assertLoginOwnership();
          setUser(profile);
        } catch (error) {
          invalidateSession(loginSession);
          throw error;
        }
      },
      logout: async () => {
        const logoutSession = captureSession();
        try {
          await logoutRequest();
        } catch {
          // Remote revocation is best effort; local logout must always complete.
        } finally {
          invalidateSession(logoutSession);
        }
      },
      logoutAll: async () => {
        const logoutSession = captureSession();
        try {
          await logoutAllRequest();
        } catch {
          // Local invalidation is mandatory even if remote revocation is unavailable.
        } finally {
          invalidateSession(logoutSession);
        }
      }
    }),
    [loading, ownsProviderLifecycle, resetLocalSession, user]
  );

  return (
    <AuthContext.Provider value={value}>
      {loading ? <LoadingSession /> : <Fragment key={accountBoundary}>{children}</Fragment>}
    </AuthContext.Provider>
  );
}
