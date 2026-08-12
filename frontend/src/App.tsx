import { useEffect, useMemo, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { ThemeProvider } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import { IconButton, Tooltip } from '@mui/material'
import Brightness4Icon from '@mui/icons-material/Brightness4'
import Brightness7Icon from '@mui/icons-material/Brightness7'
import { useAuth } from './lib/auth-context'
import { registerLoginRedirect } from './lib/session'
import { darkTheme, lightTheme } from './lib/theme'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import CertificatesPage from './pages/CertificatesPage'
import CertificateDetailPage from './pages/CertificateDetailPage'
import IssueWizardPage from './pages/IssueWizardPage'
import ImportPage from './pages/ImportPage'
import ServersPage from './pages/ServersPage'
import ServerDetailPage from './pages/ServerDetailPage'
import DeploymentsPage from './pages/DeploymentsPage'
import DiscoveryPage from './pages/DiscoveryPage'
import HooksPage from './pages/HooksPage'
import NotificationsPage from './pages/NotificationsPage'
import AuditPage from './pages/AuditPage'
import UsersPage from './pages/UsersPage'
import SettingsPage from './pages/SettingsPage'
import CompliancePage from './pages/CompliancePage'
import ReportsPage from './pages/ReportsPage'
import AiAssistantPage from './pages/AiAssistantPage'

function ThemeToggle({ dark, onToggle }: { dark: boolean; onToggle: () => void }) {
  return (
    <Tooltip title={dark ? 'Switch to light mode' : 'Switch to dark mode'}>
      <IconButton onClick={onToggle} color="inherit">
        {dark ? <Brightness7Icon /> : <Brightness4Icon />}
      </IconButton>
    </Tooltip>
  )
}

function SessionRedirectRegistrar() {
  const navigate = useNavigate()
  const { resetSession } = useAuth()
  useEffect(() => {
    // Auth failures (expired token, unrecoverable session) navigate in-app —
    // never a full page reload (which can wipe sandboxed-iframe storage).
    registerLoginRedirect(() => {
      resetSession()
      navigate('/login', { replace: true })
    })
  }, [navigate, resetSession])
  return null
}

function GuardedRoutes() {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center text-slate-500">
        Loading platform…
      </div>
    )
  }

  if (!user) {
    if (location.pathname !== '/login') return <Navigate to="/login" replace />
    return <LoginPage />
  }

  if (location.pathname === '/login') return <Navigate to="/" replace />

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/certificates" element={<CertificatesPage />} />
        <Route path="/certificates/:id" element={<CertificateDetailPage />} />
        <Route path="/issue" element={<IssueWizardPage />} />
        <Route path="/import" element={<ImportPage />} />
        <Route path="/servers" element={<ServersPage />} />
        <Route path="/servers/:id" element={<ServerDetailPage />} />
        <Route path="/deployments" element={<DeploymentsPage />} />
        <Route path="/discovery" element={<DiscoveryPage />} />
        <Route path="/hooks" element={<HooksPage />} />
        <Route path="/notifications" element={<NotificationsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/ai" element={<AiAssistantPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default function App() {
  const [dark, setDark] = useState(() => localStorage.getItem('certmgr_theme') !== 'light')
  const theme = useMemo(() => (dark ? darkTheme : lightTheme), [dark])

  const toggle = () => {
    setDark((d) => {
      localStorage.setItem('certmgr_theme', d ? 'light' : 'dark')
      return !d
    })
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <SessionRedirectRegistrar />
        <GuardedRoutes />
      </BrowserRouter>
      <div style={{ position: 'fixed', top: 12, right: 12, zIndex: 2000 }}>
        <ThemeToggle dark={dark} onToggle={toggle} />
      </div>
    </ThemeProvider>
  )
}
