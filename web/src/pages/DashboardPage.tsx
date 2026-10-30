import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiGet } from '../lib/api/client'
import { useSession } from '../features/auth/useSession'

type Box = {
  id: string
  name: string
  status: string
  size_bytes: number
  created_at: string
}

export function DashboardPage() {
  const session = useSession()
  const [boxes, setBoxes] = useState<Box[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      const res = await apiGet<{ items: Box[] }>('/api/v1/boxes')
      if (cancelled) return
      if (res.error) setError(res.error.message)
      else setBoxes(res.data?.items ?? [])
    }
    void load()
    return () => { cancelled = true }
  }, [])

  const totalSize = boxes?.reduce((n, b) => n + b.size_bytes, 0) ?? 0

  return (
    <div className='page-stack'>
      <div>
        <h1 className='page-title'>Welcome back{session.user?.display_name ? `, ${session.user.display_name}` : ''}.</h1>
        <p className='page-subtitle'>Keep your files organized and choose who can access them.</p>
      </div>

      <div className='card-grid'>
        <div className='stat-card'>
          <span className='label'>Signed in as</span>
          <span className='value' style={{ fontSize: '1.1rem' }}>{session.user?.email ?? '—'}</span>
          <span className='sub'>{session.user?.roles?.join(', ') || 'no roles'}</span>
        </div>
        <div className='stat-card'>
          <span className='label'>Your boxes</span>
          <span className='value' data-testid='stat-box-count'>
            {boxes === null
              ? <span className='skeleton' style={{ display: 'inline-block', width: '2ch', height: '1.5rem' }} />
              : boxes.length}
          </span>
          <span className='sub'>
            {boxes === null ? 'loading…' : `${formatBytes(totalSize)} quota allocated`}
          </span>
        </div>
        <div className='stat-card'>
          <span className='label'>Session</span>
          <span className='value' style={{ fontSize: '1.1rem' }}>active</span>
          <span className='sub'>Signed in and ready</span>
        </div>
      </div>

      <section className='card'>
        <div className='card-header'>
          <h2>Quick actions</h2>
          <Link to='/boxes' className='secondary-link-button'>All boxes →</Link>
        </div>
        <div className='button-row'>
          <Link to='/boxes' className='primary-link-button'>Create or open a box</Link>
          <Link to='/settings' className='secondary-link-button'>Account settings</Link>
        </div>
      </section>

      {error && (
        <section className='card'>
          <div className='form-error'>Couldn't load boxes: {error}</div>
        </section>
      )}
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`
}
