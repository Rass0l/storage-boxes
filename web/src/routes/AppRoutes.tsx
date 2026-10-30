import { Route, Routes, Navigate } from 'react-router-dom'
import { DashboardPage } from '../pages/DashboardPage'
import { LoginPage } from '../pages/LoginPage'
import { BoxesPage } from '../pages/BoxesPage'
import { SharesPage } from '../pages/SharesPage'
import { AuditPage } from '../pages/AuditPage'
import { SettingsPage } from '../pages/SettingsPage'
import { ProtectedRoute } from './ProtectedRoute'

function NotFoundPage() {
  return <Navigate to='/' replace />
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path='/' element={<Navigate to='/dashboard' replace />} />
      <Route path='/login' element={<LoginPage />} />
      <Route path='/dashboard' element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
      <Route path='/boxes' element={<ProtectedRoute><BoxesPage /></ProtectedRoute>} />
      <Route path='/shares' element={<ProtectedRoute><SharesPage /></ProtectedRoute>} />
      <Route path='/audit' element={<ProtectedRoute><AuditPage /></ProtectedRoute>} />
      <Route path='/settings' element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
      <Route path='*' element={<NotFoundPage />} />
    </Routes>
  )
}
