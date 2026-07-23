import { createContext, Dispatch, SetStateAction, useContext, useEffect, useState } from "react";

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
  try {
    const stored = window.sessionStorage.getItem(key);
    return stored ? JSON.parse(stored) as T : initialValue;
  } catch {
    return initialValue;
  }
}

export function useSessionState<T>(key: string, initialValue: T): readonly [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readSessionState(key, initialValue));

  useEffect(() => {
    try {
      const serialized = JSON.stringify(value);
      if (serialized === undefined) {
        window.sessionStorage.removeItem(key);
      } else {
        window.sessionStorage.setItem(key, serialized);
      }
    } catch {
      // Session persistence is a UX aid; storage failures should never block the dashboard.
    }
  }, [key, value]);

  return [value, setValue] as const;
}
