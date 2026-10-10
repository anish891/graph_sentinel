import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { Spinner } from "../components/ui";
import { AuthProvider, useAuth } from "../hooks/useAuth";
import { ApiError } from "../lib/api";
import { AlertsPage } from "../pages/AlertsPage";
import { ApprovalsPage } from "../pages/ApprovalsPage";
import { AuditPage } from "../pages/AuditPage";
import { DashboardPage } from "../pages/DashboardPage";
import { GraphExplorerPage } from "../pages/GraphExplorerPage";
import { HistoryPage } from "../pages/HistoryPage";
import { InvestigationPage, NewInvestigationPage } from "../pages/InvestigationPage";
import { LoginPage } from "../pages/LoginPage";
import { SettingsPage } from "../pages/SettingsPage";
import { Layout } from "./Layout";

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        refetchOnWindowFocus: false,
        // Never retry client errors (401/403/404/422); retry transient failures twice.
        retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
      },
    },
  });
}

function Gate() {
  const { me, loading } = useAuth();
  if (loading) return <Spinner label="Checking session" />;
  if (!me) return <LoginPage />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="investigate" element={<NewInvestigationPage />} />
        <Route path="investigations" element={<HistoryPage />} />
        <Route path="investigations/:id" element={<InvestigationPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="graph" element={<GraphExplorerPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App({ client = makeQueryClient() }: { client?: QueryClient }) {
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <AuthProvider>
          <Gate />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
