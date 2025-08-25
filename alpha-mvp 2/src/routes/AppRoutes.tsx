import { Route, Routes, Navigate } from 'react-router-dom'
import LandingLayout from '@/layouts/LandingLayout'
import AppLayout from '@/layouts/AppLayout'
import LandingPage from '@/pages/Landing/LandingPage'
import DashboardPage from '@/pages/Dashboard/DashboardPage'
import AlertsPage from '@/pages/Alerts/AlertsPage'

export default function AppRoutes() {
  return (
    <Routes>
      {/* Public landing */}
      <Route element={<LandingLayout />}>
        <Route path="/" element={<LandingPage />} />
      </Route>

      {/* App area with sidebar */}
      <Route path="/app" element={<AppLayout />}>
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
      </Route>

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
