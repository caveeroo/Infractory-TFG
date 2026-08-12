import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { AppShell, EnvironmentLayout } from "./components";
import {
  ActivityPage, AdoptHostPage, ConnectionsPage, CreateEnvironmentPage, DestroyPage,
  EnvironmentActivityPage, EnvironmentOverviewPage, EnvironmentSettingsPage,
  EnvironmentWorkloadsPage, EnvironmentsPage, NodesPage, NotFoundPage,
  OperationPage, PlanPage, SettingsPage, WorkloadDetailPage, WorkloadImportPage,
  WorkloadsPage
} from "./pages";

function RouteFocus() {
  const { pathname } = useLocation();
  useEffect(() => {
    const main = document.getElementById("main-content");
    main?.focus({ preventScroll: true });
  }, [pathname]);
  return null;
}

export function App() {
  return <>
    <RouteFocus />
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/environments" replace />} />
        <Route path="environments" element={<EnvironmentsPage />} />
        <Route path="environments/new" element={<CreateEnvironmentPage />} />
        <Route path="environments/:environmentId/plan" element={<PlanPage />} />
        <Route path="environments/:environmentId/operation" element={<OperationPage />} />
        <Route path="environments/:environmentId/destroy" element={<DestroyPage />} />
        <Route path="environments/:environmentId/adopt" element={<AdoptHostPage />} />
        <Route path="environments/:environmentId" element={<EnvironmentLayout />}>
          <Route index element={<EnvironmentOverviewPage />} />
          <Route path="nodes" element={<NodesPage />} />
          <Route path="workloads" element={<EnvironmentWorkloadsPage />} />
          <Route path="activity" element={<EnvironmentActivityPage />} />
          <Route path="settings" element={<EnvironmentSettingsPage />} />
        </Route>
        <Route path="workloads" element={<WorkloadsPage />} />
        <Route path="workloads/import" element={<WorkloadImportPage />} />
        <Route path="workloads/:workloadId" element={<WorkloadDetailPage />} />
        <Route path="connections" element={<ConnectionsPage />} />
        <Route path="activity" element={<ActivityPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  </>;
}
