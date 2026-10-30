import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useSession } from '../features/auth/useSession'

export function ProtectedRoute({ children, redirectTo = '/login' }: { children: ReactNode; redirectTo?: string }) {
  const session = useSession()
  const location = useLocation()

  if (session.loading) {
    return (
      <div className='page-stack' aria-busy='true' aria-live='polite'>
        <div className='card'>
          <div className='skeleton' style={{ height: '1rem', width: '40%' }} />
          <div className='skeleton' style={{ height: '0.75rem', width: '70%', marginTop: '0.6rem' }} />
          <div className='skeleton' style={{ height: '0.75rem', width: '55%', marginTop: '0.4rem' }} />
        </div>
      </div>
    )
  }

  if (!session.isAuthenticated) {
    return <Navigate to={redirectTo} replace state={{ from: location.pathname }} />
  }

  return <>{children}</>
}
