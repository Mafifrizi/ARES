import { Loader2 } from "lucide-react";
import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import {
  CampaignsPage,
  DashboardShell,
  EdrPage,
  LivePage,
  ModulesPage,
  OverviewPage,
  ReportsPage,
  SecurityPage,
  StrategyPage,
  TemplatesPage
} from "./DashboardPages";
import { LoginPage } from "../auth/LoginPage";
import { useDashboardUi } from "./dashboardUiState";

const GraphPage = lazy(() => import("../graph/GraphPage"));

function DashboardRoutes() {
  const { selectedCampaignId, setSelectedCampaignId } = useDashboardUi();

  return (
    <Routes>
      <Route path="/" element={<OverviewPage />} />
      <Route path="/playbooks" element={<Navigate to="/modules" replace />} />
      <Route path="/campaigns" element={<CampaignsPage />} />
      <Route path="/modules" element={<ModulesPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route
        path="/graph"
        element={(
          <Suspense fallback={<div className="panel p-4 loading-row"><Loader2 className="spin" size={18} /> Loading graph renderer…</div>}>
            <GraphPage campaignId={selectedCampaignId} onCampaignIdChange={setSelectedCampaignId} />
          </Suspense>
        )}
      />
      <Route path="/templates" element={<TemplatesPage />} />
      <Route path="/strategy" element={<StrategyPage />} />
      <Route path="/security" element={<SecurityPage />} />
      <Route path="/edr" element={<EdrPage />} />
      <Route path="/live" element={<LivePage />} />
    </Routes>
  );
}

export function DashboardRouter() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/*" element={<DashboardShell><DashboardRoutes /></DashboardShell>} />
    </Routes>
  );
}
