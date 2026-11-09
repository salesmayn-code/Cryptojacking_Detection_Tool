import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';

// Components
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import AdminDashboard from './components/dashboard/AdminDashboard';
import UserDashboard from './components/dashboard/UserDashboard';
import SystemMonitoring from './components/monitoring/SystemMonitoring';
import AlertsPage from './components/alerts/AlertsPage';
import ReportsPage from './components/reports/ReportsPage';
import ProfilePage from './components/profile/ProfilePage';
import MainLayout from './components/layout/MainLayout';
import AuditLogsPage from './components/dashboard/AuditLogsPage';

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="app-boot-shell" role="status" aria-live="polite">
        <div className="spinner" aria-hidden="true"></div>
        <span>Verifying operator session...</span>
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

// Public Route - redirect to dashboard if already logged in
const PublicRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="app-boot-shell" role="status" aria-live="polite">
        <div className="spinner" aria-hidden="true"></div>
        <span>Initializing CryptoDetect...</span>
      </div>
    );
  }

  return isAuthenticated ? <Navigate to="/dashboard" replace /> : children;
};

// Dashboard Router - shows admin or user dashboard based on role
const DashboardRouter = () => {
  const { isAdmin } = useAuth();
  return isAdmin ? <AdminDashboard /> : <UserDashboard />;
};

function App() {
  return (
    <AuthProvider>
      <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          {/* Public Routes - redirect to dashboard if logged in */}
          <Route path="/login" element={
            <PublicRoute><Login /></PublicRoute>
          } />
          <Route path="/register" element={
            <PublicRoute><Register /></PublicRoute>
          } />

          {/* Protected Routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <MainLayout title="Dashboard">
                  <DashboardRouter />
                </MainLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/system/:systemId"
            element={
              <ProtectedRoute>
                <MainLayout title="Live Metrics">
                  <SystemMonitoring />
                </MainLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <MainLayout title="Profile">
                  <ProfilePage />
                </MainLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <MainLayout title="Alerts">
                  <AlertsPage />
                </MainLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <MainLayout title="Reports">
                  <ReportsPage />
                </MainLayout>
              </ProtectedRoute>
            }
          />

          <Route
            path="/admin/audit-logs"
            element={
              <ProtectedRoute>
                <MainLayout title="Audit Logs">
                  <AuditLogsPage />
                </MainLayout>
              </ProtectedRoute>
            }
          />

          {/* Default redirect -> login */}
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
