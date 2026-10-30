import { FormEvent, useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useSession } from '../features/auth/useSession'
import { useToast } from '../components/Toast'

export function LoginPage() {
  const session = useSession()
  const toast = useToast()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (session.isAuthenticated) {
    return <Navigate to='/dashboard' replace />
  }

  const from = (location.state as { from?: string } | undefined)?.from ?? '/dashboard'

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    if (!email.trim() || !password) {
      setError('Email and password are required.')
      return
    }
    setBusy(true)
    const res = await session.login(email.trim(), password)
    setBusy(false)
    if (!res.ok) {
      const msg = res.error ?? 'Login failed.'
      setError(msg)
      toast.show({ kind: 'error', title: 'Sign-in failed', message: msg })
      return
    }
    toast.show({ kind: 'success', title: 'Welcome back' })
    navigate(from, { replace: true })
  }

  return (
    <div className='login-page'>
      <section className='card login-card'>
        <h1 className='page-title'>Sign in</h1>
        <p className='page-subtitle'>Access your files and manage sharing.</p>
        <form className='form-grid' onSubmit={handleSubmit} aria-label='Sign in'>
          <label>
            <span>Email</span>
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type='email'
              autoComplete='username'
              placeholder='you@example.com'
            />
          </label>
          <label>
            <span>Password</span>
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type='password'
              autoComplete='current-password'
              placeholder='••••••••'
            />
          </label>
          {error && <div className='form-error' role='alert'>{error}</div>}
          <div className='button-row'>
            <button type='submit' className='primary-button' disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
            <Link to='/' className='secondary-link-button'>Cancel</Link>
          </div>
        </form>
        <div className='login-meta'>
          Need an account or help signing in? Contact your administrator.
        </div>
      </section>
    </div>
  )
}
