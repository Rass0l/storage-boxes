import { useEffect, useMemo, useState } from 'react'
import { apiGet } from '../lib/api/client'

type AuditEvent = {
  id: string
  event_type: string
  subject_type: string
  subject_id: string
  actor_id?: string
  occurred_at?: string
  metadata?: Record<string, unknown>
}

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null)
  const [error, setError] = useState('')
  const [filters, setFilters] = useState({ event_type: '', subject_type: '', actor_id: '' })

  async function load() {
    setError('')
    const q = new URLSearchParams()
    Object.entries(filters).forEach(([k, v]) => { if (v) q.set(k, v) })
    q.set('limit', '100')
    const res = await apiGet<{ items: AuditEvent[] }>(`/api/v1/audit/events?${q.toString()}`)
    if (res.error) setError(res.error.message)
    else setEvents(res.data?.items ?? [])
  }

  useEffect(() => { void load() }, [])

  const types = useMemo(() => Array.from(new Set((events ?? []).map(e => e.event_type))).sort(), [events])

  return (
    <div className='page-stack'>
      <div>
        <h1 className='page-title'>Audit</h1>
        <p className='page-subtitle'>Review account activity, file access, and sharing decisions.</p>
      </div>
      <section className='card'>
        <div className='card-header'><h2>Filters</h2></div>
        <form className='form-grid' onSubmit={(e) => { e.preventDefault(); void load() }}>
          <label>Event type
            <select value={filters.event_type} onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}>
              <option value=''>(any)</option>
              {types.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label>Subject type
            <select value={filters.subject_type} onChange={(e) => setFilters({ ...filters, subject_type: e.target.value })}>
              <option value=''>(any)</option>
              <option value='user'>user</option>
              <option value='box'>box</option>
              <option value='file'>file</option>
              <option value='share'>share</option>
              <option value='share_recipient'>share_recipient</option>
              <option value='share_claim'>share_claim</option>
              <option value='share_access_request'>share_access_request</option>
            </select>
          </label>
          <label>Actor ID<input value={filters.actor_id} onChange={(e) => setFilters({ ...filters, actor_id: e.target.value })} /></label>
          <button type='submit'>Apply</button>
        </form>
      </section>
      <section className='card'>
        <div className='card-header'><h2>Recent events</h2></div>
        {events === null && <div className='empty'>Loading…</div>}
        {error && <div className='form-error'>{error}</div>}
        {events !== null && events.length === 0 && !error && (
          <div className='empty'>No events match these filters.</div>
        )}
        {events !== null && events.length > 0 && (
          <table className='grid'>
            <thead><tr><th>When</th><th>Type</th><th>Subject</th><th>Actor</th><th>Metadata</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td>{e.occurred_at ? new Date(e.occurred_at).toLocaleString() : '—'}</td>
                  <td>{e.event_type}</td>
                  <td>{e.subject_type}/{e.subject_id}</td>
                  <td>{e.actor_id ?? '—'}</td>
                  <td><code>{e.metadata ? JSON.stringify(e.metadata) : ''}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
