import { Loader2 } from "lucide-react";
import { lazy, Suspense, useEffect } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { DashboardShell } from "./DashboardPages";
import { LoginPage } from "../auth/LoginPage";
import { useDashboardUi } from "./dashboardUiState";

const OverviewPage = lazy(() => import("./pages/OverviewPage"));
const CampaignsPage = lazy(() => import("./pages/CampaignsPage"));
const ModulesPage = lazy(() => import("./pages/ModulesPage"));
const ReportsPage = lazy(() => import("./pages/ReportsPage"));
const GraphPage = lazy(() => import("../graph/GraphPage"));
const TemplatesPage = lazy(() => import("./pages/TemplatesPage"));
const StrategyPage = lazy(() => import("./pages/StrategyPage"));
const SecurityPage = lazy(() => import("./pages/SecurityPage"));
const EdrPage = lazy(() => import("./pages/EdrPage"));
const LivePage = lazy(() => import("./pages/LivePage"));

function PageFallback({ label }: { label?: string }) {
  return (
    <div className="panel p-4 loading-row" role="status" aria-live="polite">
      <Loader2 className="spin" size={18} />
      <span>Loading {label || "view"}…</span>
    </div>
  );
}

function DashboardRoutes() {
  const { selectedCampaignId, setSelectedCampaignId } = useDashboardUi();
  const navigate = useNavigate();

  useEffect(() => {
    (window as unknown as { __navigate?: typeof navigate }).__navigate = navigate;
  }, [navigate]);

  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/playbooks" element={<Navigate to="/modules" replace />} />
        <Route path="/campaigns" element={<CampaignsPage />} />
        <Route path="/modules" element={<ModulesPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route
          path="/graph"
          element={(
            <GraphPage campaignId={selectedCampaignId} onCampaignIdChange={setSelectedCampaignId} />
          )}
        />
        <Route path="/templates" element={<TemplatesPage />} />
        <Route path="/strategy" element={<StrategyPage />} />
        <Route path="/security" element={<SecurityPage />} />
        <Route path="/edr" element={<EdrPage />} />
        <Route path="/live" element={<LivePage />} />
      </Routes>
    </Suspense>
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
