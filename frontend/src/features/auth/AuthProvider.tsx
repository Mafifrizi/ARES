import { useQueryClient } from "@tanstack/react-query";
import { ReactNode, useEffect, useMemo, useState } from "react";
import {
  api,
  clearTokens,
  getRefreshToken,
  login as loginRequest,
  logout as logoutRequest,
  refreshAccessToken
} from "../../api/client";
import type { UserProfile } from "../../api/types";
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
  const queryClient = useQueryClient();

  useEffect(() => {
    let active = true;
    if (!getRefreshToken()) {
      setLoading(false);
      return;
    }
    (async () => {
      try {
        if (!(await refreshAccessToken())) {
          if (active) {
            setUser(null);
          }
          return;
        }
        const profile = await api.me();
        if (active) {
          setUser(profile);
        }
      } catch {
        clearTokens();
        if (active) {
          setUser(null);
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
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      login: async (username, password) => {
        await loginRequest(username, password);
        const profile = await api.me();
        setUser(profile);
      },
      logout: async () => {
        await logoutRequest();
        setUser(null);
        queryClient.clear();
      }
    }),
    [loading, queryClient, user]
  );

  return <AuthContext.Provider value={value}>{loading ? <LoadingSession /> : children}</AuthContext.Provider>;
}
