import { useEffect, useState } from 'react'

type Health = 'unknown' | 'ok' | 'down'

export function HealthBadge() {
  const [health, setHealth] = useState<Health>('unknown')

  useEffect(() => {
    let cancelled = false
    async function ping() {
      try {
        const res = await fetch('/healthz')
        if (cancelled) return
        setHealth(res.ok ? 'ok' : 'down')
      } catch {
        if (!cancelled) setHealth('down')
      }
    }
    void ping()
    const t = window.setInterval(ping, 15000)
    return () => { cancelled = true; window.clearInterval(t) }
  }, [])

  const label = health === 'ok' ? 'Connected' : health === 'down' ? 'Connection unavailable' : 'Connecting…'
  return (
    <span className={`health-badge is-${health}`} role='status' aria-label={label}>
      <span className='dot' aria-hidden='true' />
      {label}
    </span>
  )
}
