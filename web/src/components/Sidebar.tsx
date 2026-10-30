import { NavLink } from 'react-router-dom'
import { useSession } from '../features/auth/useSession'

type Item = { to: string; label: string }

const navItems: Item[] = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/boxes', label: 'Boxes' },
  { to: '/shares', label: 'Shares' },
  { to: '/audit', label: 'Audit' },
  { to: '/settings', label: 'Settings' },
]

export function Sidebar() {
  const session = useSession()
  return (
    <nav className='sidebar' aria-label='Primary'>
      <div className='sidebar-title'>Workspace</div>
      <ul className='nav-list'>
        {navItems.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                ['nav-link', isActive ? 'active' : ''].filter(Boolean).join(' ')
              }
            >
              <span>{item.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <div className='sidebar-footer'>
        {session.isAuthenticated
          ? `Signed in as ${session.user?.email ?? 'user'}`
          : 'Sign in to manage your files'}
      </div>
    </nav>
  )
}
