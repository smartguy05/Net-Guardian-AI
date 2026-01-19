import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './stores/auth';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import DevicesPage from './pages/DevicesPage';
import DeviceDetailPage from './pages/DeviceDetailPage';
import EventsPage from './pages/EventsPage';
import AlertsPage from './pages/AlertsPage';
import AnomaliesPage from './pages/AnomaliesPage';
import SourcesPage from './pages/SourcesPage';
import UsersPage from './pages/UsersPage';
import ChatPage from './pages/ChatPage';
import QuarantinePage from './pages/QuarantinePage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function App() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  return (
    <Routes>
      <Route
        path="/login"
        element={
          isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/:id" element={<DeviceDetailPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="anomalies" element={<AnomaliesPage />} />
        <Route path="chat" element={<ChatPage />} />
        <Route path="quarantine" element={<QuarantinePage />} />
        <Route path="sources" element={<SourcesPage />} />
        <Route path="users" element={<UsersPage />} />
      </Route>
    </Routes>
  );
}

export default App;
