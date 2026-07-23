import { ReactNode } from "react";
import { DashboardUiContext, type DashboardUiState } from "./dashboardUiState";

export function DashboardUiProvider({ children, value }: { children: ReactNode; value: DashboardUiState }) {
  return <DashboardUiContext.Provider value={value}>{children}</DashboardUiContext.Provider>;
}
