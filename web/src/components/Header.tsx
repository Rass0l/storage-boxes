import { Link, useNavigate } from 'react-router-dom'
import { HealthBadge } from './HealthBadge'
import { useSession } from '../features/auth/useSession'

export function Header() {
  const navigate = useNavigate()
  const session = useSession()
  const isAdmin = Boolean(session.user?.roles?.includes('admin'))

  async function handleLogout() {
    await session.logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className='app-header'>
      <Link to='/' className='brand-link'>
        <span className='brand-title'>Storage Boxes</span>
        <span className='brand-subtitle'>Encrypted storage and controlled sharing</span>
      </Link>
      <div className='header-actions'>
        <HealthBadge />
        {session.isAuthenticated && session.user ? (
          <>
            <span className={'user-chip' + (isAdmin ? ' is-admin' : '')}>
              <span className='role-dot' aria-hidden='true' />
              {session.user.email}
              {isAdmin && <span aria-label='admin role'> • admin</span>}
            </span>
            <button type='button' className='secondary-button' onClick={handleLogout}>
              Logout
            </button>
          </>
        ) : (
          <Link to='/login' className='primary-link-button'>Sign in</Link>
        )}
      </div>
    </header>
  )
}
