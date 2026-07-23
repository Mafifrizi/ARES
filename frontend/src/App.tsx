import { AuthProvider } from "./features/auth/AuthProvider";
import { DashboardRouter } from "./features/dashboard/DashboardRouter";

export default function App() {
  return (
    <AuthProvider>
      <DashboardRouter />
    </AuthProvider>
  );
}
