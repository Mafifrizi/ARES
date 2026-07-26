import { createContext, Dispatch, SetStateAction, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { UserProfile } from "../../api/types";

const DASHBOARD_SESSION_PREFIX = "ares.dashboard.";
const DASHBOARD_PRINCIPAL_KEY = `${DASHBOARD_SESSION_PREFIX}principal`;

let dashboardStorageEpoch = 0;
let blockAllDashboardReads = false;
const blockedDashboardKeys = new Set<string>();
const currentEpochDashboardKeys = new Set<string>();

export interface DashboardUiState {
  selectedCampaignId: string;
  setSelectedCampaignId: Dispatch<SetStateAction<string>>;
  liveCampaignId: string;
  setLiveCampaignId: Dispatch<SetStateAction<string>>;
  liveConnected: boolean;
  setLiveConnected: Dispatch<SetStateAction<boolean>>;
  liveEvents: unknown[];
  clearLiveEvents: () => void;
}

export const DashboardUiContext = createContext<DashboardUiState | null>(null);

export function useDashboardUi(): DashboardUiState {
  const value = useContext(DashboardUiContext);
  if (!value) {
    throw new Error("DashboardUiContext missing");
  }
  return value;
}

function readSessionState<T>(key: string, initialValue: T): T {
  if (
    !key.startsWith(DASHBOARD_SESSION_PREFIX)
    || blockedDashboardKeys.has(key)
    || (blockAllDashboardReads && !currentEpochDashboardKeys.has(key))
  ) {
    return initialValue;
  }
  try {
    const stored = window.sessionStorage.getItem(key);
    return stored ? JSON.parse(stored) as T : initialValue;
  } catch {
    return initialValue;
  }
}

export function clearDashboardSession(): void {
  dashboardStorageEpoch += 1;
  currentEpochDashboardKeys.clear();
  let keys: string[] = [];
  try {
    keys = Array.from({ length: window.sessionStorage.length }, (_, index) => window.sessionStorage.key(index))
      .filter((key): key is string => key !== null);
  } catch {
    blockAllDashboardReads = true;
    blockedDashboardKeys.clear();
    return;
  }
  blockAllDashboardReads = false;
  for (const key of keys) {
    if (key.startsWith(DASHBOARD_SESSION_PREFIX)) {
      try {
        window.sessionStorage.removeItem(key);
        blockedDashboardKeys.delete(key);
      } catch {
        try {
          window.sessionStorage.setItem(key, "");
        } catch {
          // The blocked-key guard remains authoritative while storage is unavailable.
        }
        blockedDashboardKeys.add(key);
      }
    }
  }
}

function writeDashboardSessionAtEpoch(epoch: number, key: string, value: unknown): boolean {
  if (epoch !== dashboardStorageEpoch || !key.startsWith(DASHBOARD_SESSION_PREFIX)) {
    return false;
  }
  try {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      window.sessionStorage.removeItem(key);
    } else {
      window.sessionStorage.setItem(key, serialized);
    }
    blockedDashboardKeys.delete(key);
    currentEpochDashboardKeys.add(key);
    return true;
  } catch {
    return false;
  }
}

export function useDashboardSessionWriter(): (key: string, value: unknown) => boolean {
  const mountedEpoch = useRef(dashboardStorageEpoch);
  return useCallback(
    (key: string, value: unknown) => writeDashboardSessionAtEpoch(mountedEpoch.current, key, value),
    []
  );
}

export function bindDashboardPrincipal(user: Pick<UserProfile, "username" | "role">): void {
  const principal = { username: user.username, role: user.role };
  let matches = false;
  try {
    const stored = window.sessionStorage.getItem(DASHBOARD_PRINCIPAL_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as unknown;
      matches = Boolean(
        parsed
        && typeof parsed === "object"
        && !Array.isArray(parsed)
        && "username" in parsed
        && "role" in parsed
        && parsed.username === principal.username
        && parsed.role === principal.role
      );
    }
  } catch {
    matches = false;
  }
  if (!matches) {
    clearDashboardSession();
  }
  writeDashboardSessionAtEpoch(dashboardStorageEpoch, DASHBOARD_PRINCIPAL_KEY, principal);
}

export function useSessionState<T>(key: string, initialValue: T): readonly [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readSessionState(key, initialValue));
  const writeDashboardSession = useDashboardSessionWriter();

  useEffect(() => {
    writeDashboardSession(key, value);
  }, [key, value, writeDashboardSession]);

  return [value, setValue] as const;
}
