import React, { Component, Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SystemProvider, ThemeProvider, ToastProvider } from './context/UiContext';
import AppShell from './components/AppShell';
import Login from './pages/Login';
import Register from './pages/Register';
import OAuthSuccess from './pages/OAuthSuccess';

// Each page is its own small bundle, loaded on first visit: the first screen
// appears faster and heavy pages (charts) never slow down the others.
const Dashboard = lazy(() => import('./pages/Dashboard'));
const ScanMessage = lazy(() => import('./pages/ScanMessage'));
const ScanUrl = lazy(() => import('./pages/ScanUrl'));
const ScanImage = lazy(() => import('./pages/ScanImage'));
const ScanAudio = lazy(() => import('./pages/ScanAudio'));
const ScanVideo = lazy(() => import('./pages/ScanVideo'));
const ScanLogs = lazy(() => import('./pages/ScanLogs'));
const ScanHistory = lazy(() => import('./pages/ScanHistory'));
const Admin = lazy(() => import('./pages/Admin'));
const GmailInbox = lazy(() => import('./pages/GmailInbox'));
const NetworkIDS = lazy(() => import('./pages/NetworkIDS'));
const MLModels = lazy(() => import('./pages/MLModels'));

function PageSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading">
      <div className="cg-skeleton" style={{ height: 150, marginBottom: 20, borderRadius: 14 }} />
      <div className="cg-skeleton" style={{ height: 320, borderRadius: 14 }} />
    </div>
  );
}

// A bug in one page shows a friendly message instead of a blank screen.
class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error('[ui]', error, info); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="cg-panel" style={{ maxWidth: 560, margin: '40px auto' }}>
        <div className="cg-panel-title">Something went wrong on this page</div>
        <p className="cg-muted" style={{ fontSize: 14 }}>The rest of CyberGuard is still working. Reload the page to try again.</p>
        <button className="cg-btn-primary" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}

function PrivateLayout({ adminOnly }) {
  const { user, loading } = useAuth();
  if (loading) return <div style={{ padding: 40 }} className="cg-muted">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (adminOnly && user.role !== 'admin') return <Navigate to="/" replace />;
  return (
    <AppShell>
      <ErrorBoundary>
        <Suspense fallback={<PageSkeleton />}><Outlet /></Suspense>
      </ErrorBoundary>
    </AppShell>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/oauth-success" element={<OAuthSuccess />} />
      <Route element={<PrivateLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/message" element={<ScanMessage />} />
        <Route path="/scan/url" element={<ScanUrl />} />
        <Route path="/scan/image" element={<ScanImage />} />
        <Route path="/scan/audio" element={<ScanAudio />} />
        <Route path="/scan/video" element={<ScanVideo />} />
        <Route path="/scan/logs" element={<ScanLogs />} />
        <Route path="/gmail" element={<GmailInbox />} />
        <Route path="/nids" element={<NetworkIDS />} />
        <Route path="/ml" element={<MLModels />} />
        <Route path="/history" element={<ScanHistory />} />
      </Route>
      <Route element={<PrivateLayout adminOnly />}>
        <Route path="/admin" element={<Admin />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AuthProvider>
          <SystemProvider>
            <ToastProvider>
              <AppRoutes />
            </ToastProvider>
          </SystemProvider>
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
}
