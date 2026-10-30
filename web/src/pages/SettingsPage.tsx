import { useNavigate } from 'react-router-dom'
import { useSession } from '../features/auth/useSession'
import { useToast } from '../components/Toast'

export function SettingsPage() {
  const session = useSession()
  const toast = useToast()
  const navigate = useNavigate()
  const user = session.user

  async function doLogout() {
    await session.logout()
    toast.show({ kind: 'info', title: 'Signed out' })
    navigate('/login', { replace: true })
  }

  return (
    <div className='page-stack'>
      <div>
        <h1 className='page-title'>Settings</h1>
        <p className='page-subtitle'>Account and session controls.</p>
      </div>

      <section className='card'>
        <div className='card-header'><h2>Profile</h2></div>
        <dl className='form-grid' style={{ gridTemplateColumns: '140px 1fr' }}>
          <dt style={{ color: 'var(--text-dim)' }}>Email</dt>
          <dd style={{ margin: 0 }}>{user?.email ?? '—'}</dd>
          <dt style={{ color: 'var(--text-dim)' }}>Display name</dt>
          <dd style={{ margin: 0 }}>{user?.display_name || <span style={{ color: 'var(--text-dim)' }}>not set</span>}</dd>
          <dt style={{ color: 'var(--text-dim)' }}>Roles</dt>
          <dd style={{ margin: 0 }}>{user?.roles?.join(', ') || <span style={{ color: 'var(--text-dim)' }}>none</span>}</dd>
        </dl>
      </section>

      <section className='card'>
        <div className='card-header'><h2>Session</h2></div>
        <p className='page-subtitle' style={{ marginBottom: '0.4rem' }}>
          You are signed in on this browser. Sign out to end your session.
        </p>
        <div className='button-row'>
          <button type='button' className='danger-button' onClick={doLogout}>Sign out</button>
        </div>
      </section>

    </div>
  )
}
