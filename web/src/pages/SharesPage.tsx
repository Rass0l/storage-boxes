import { useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPatch, apiPost } from '../lib/api/client'

type Share = {
  id: string
  box_id: string
  file_entry_id: string
  status: string
  expires_at: string
  max_downloads: number
  download_count: number
  created_at: string
  revoked_at?: string
  purge_requested_at?: string
  // Server-computed IsDeliverable(now). Use this instead of checking
  // `status === 'active'` — a soft-deleted box stamps purge_requested
  // on shares without flipping status right away.
  deliverable: boolean
  access_mode?: string
  require_otp?: boolean
  domain_allowlist?: string[]
}

type Recipient = {
  id: string
  share_id: string
  email: string
  email_normalized: string
  verified_at?: string
  revoked_at?: string
  failed_attempts: number
  created_at: string
}

type RecipientInvite = Recipient & { passcode: string }

type CreateResponse = Share & {
  token: string
  url: string
  recipients?: RecipientInvite[]
}

type AccessEvent = {
  id: string
  remote_ip?: string
  user_agent?: string
  referer?: string
  succeeded: boolean
  accessed_at: string
  risk_score: number
  country_code?: string
}

export function SharesPage() {
  const [shares, setShares] = useState<Share[] | null>(null)
  const [error, setError] = useState('')
  const [lastToken, setLastToken] = useState<string | null>(null)
  const [lastRecipients, setLastRecipients] = useState<RecipientInvite[] | null>(null)
  const [openShareId, setOpenShareId] = useState<string | null>(null)
  const [accessEvents, setAccessEvents] = useState<AccessEvent[] | null>(null)
  const [editing, setEditing] = useState<Share | null>(null)
  const [recipientsOf, setRecipientsOf] = useState<Share | null>(null)
  const [accessRequestsOf, setAccessRequestsOf] = useState<Share | null>(null)

  async function load() {
    const res = await apiGet<{ items: Share[] }>('/api/v1/shares')
    if (res.error) setError(res.error.message)
    else setShares(res.data?.items ?? [])
  }

  useEffect(() => { void load() }, [])

  async function revoke(id: string) {
    setError('')
    const res = await apiDelete<void>(`/api/v1/shares/${id}`)
    if (res.error) setError(res.error.message)
    else void load()
  }

  async function openAccess(id: string) {
    setOpenShareId(id)
    setAccessEvents(null)
    const res = await apiGet<{ items: AccessEvent[] }>(`/api/v1/shares/${id}/access`)
    setAccessEvents(res.data?.items ?? [])
  }

  return (
    <div className='page-stack'>
      <div>
        <h1 className='page-title'>Shares</h1>
        <p className='page-subtitle'>Share files with expiring links or verified recipients.</p>
      </div>
      {lastToken && (
        <section className='card'>
          <div className='card-header'><h2>Share link created</h2></div>
          <p>Copy this link now. It will not be shown again:</p>
          <code className='token-display'>{lastToken}</code>
          <button onClick={() => { void navigator.clipboard?.writeText(lastToken); }}>Copy</button>
          <button onClick={() => { setLastToken(null); setLastRecipients(null) }}>Dismiss</button>
          {lastRecipients && lastRecipients.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <p><strong>Per-recipient passcodes (shown once):</strong></p>
              <p className='sub'>Send each recipient their passcode through a trusted channel, separate from the share link.</p>
              <table className='grid'>
                <thead><tr><th>Email</th><th>Passcode</th></tr></thead>
                <tbody>
                  {lastRecipients.map((r) => (
                    <tr key={r.id}><td>{r.email}</td><td><code>{r.passcode}</code></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
      {error && <div className='form-error'>{error}</div>}
      <CreateShareCard onCreated={(res) => {
        setLastToken(res.url || `/s/${res.token}`)
        setLastRecipients(res.recipients ?? null)
        void load()
      }} />
      <section className='card'>
        <div className='card-header'><h2>Active & recent share links</h2></div>
        {shares === null && <div className='empty'>Loading…</div>}
        {shares !== null && shares.length === 0 && <div className='empty'>No shares yet. Create a link to share a file.</div>}
        {shares !== null && shares.length > 0 && (
          <ul className='box-list'>
            {shares.map((s) => (
              <li key={s.id} className='box-row' data-status={s.status} data-deliverable={s.deliverable}>
                <div className='box-meta'>
                  <span className='name'>{s.id}</span>
                  <span className='sub'>box {s.box_id} · file {s.file_entry_id}</span>
                  <span className='sub'>
                    {displayState(s)} · expires {new Date(s.expires_at).toLocaleString()} · {s.download_count}/{s.max_downloads} downloads
                  </span>
                  <span className='sub'>{accessModeSummary(s)}</span>
                </div>
                <div className='box-actions'>
                  <button onClick={() => void openAccess(s.id)}>Access log</button>
                  {s.access_mode === 'restricted' && <button onClick={() => setRecipientsOf(s)}>Recipients</button>}
                  {s.access_mode === 'restricted' && <button onClick={() => setAccessRequestsOf(s)}>Access requests</button>}
                  {/* Only offer edit/revoke when the server says the share is deliverable.
                      A pending-purge share (e.g. from a box soft-delete)
                      will read status=active but deliverable=false. */}
                  {s.deliverable && <button onClick={() => setEditing(s)}>Edit settings</button>}
                  {s.deliverable && <button onClick={() => void revoke(s.id)}>Revoke</button>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
      {editing && (
        <EditShareCard
          share={editing}
          onCancel={() => setEditing(null)}
          onSaved={() => { setEditing(null); void load() }}
          onError={setError}
        />
      )}
      {recipientsOf && (
        <RecipientsPanel share={recipientsOf} onClose={() => setRecipientsOf(null)} onError={setError} />
      )}
      {accessRequestsOf && (
        <AccessRequestsPanel share={accessRequestsOf} onClose={() => setAccessRequestsOf(null)} onError={setError} />
      )}
      {openShareId && (
        <section className='card'>
          <div className='card-header'>
            <h2>Access log — {openShareId}</h2>
            <button onClick={() => { setOpenShareId(null); setAccessEvents(null) }}>Close</button>
          </div>
          {accessEvents === null && <div className='empty'>Loading…</div>}
          {accessEvents !== null && accessEvents.length === 0 && <div className='empty'>No accesses recorded yet.</div>}
          {accessEvents && accessEvents.length > 0 && (
            <table className='grid'>
              <thead><tr><th>When</th><th>IP</th><th>UA</th><th>Risk</th><th>OK</th></tr></thead>
              <tbody>
                {accessEvents.map((e) => (
                  <tr key={e.id}>
                    <td>{new Date(e.accessed_at).toLocaleString()}</td>
                    <td>{e.remote_ip || '—'}</td>
                    <td>{e.user_agent || '—'}</td>
                    <td>{e.risk_score}</td>
                    <td>{e.succeeded ? '✓' : '✗'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </div>
  )
}

// displayState collapses status + purge_requested_at into the string
// the operator actually needs to see. A share with status=active but
// purge_requested_at set is no longer deliverable — surface that.
function displayState(s: Share): string {
  if (s.status !== 'active') return s.status
  if (s.purge_requested_at) return 'active · pending purge'
  if (!s.deliverable) return 'active · not serving'
  return 'active'
}

// accessModeSummary surfaces the share's delivery policy at a glance so
// the operator can tell a bearer link from a verified, recipient-scoped
// share without opening the Recipients panel.
function accessModeSummary(s: Share): string {
  if (s.access_mode !== 'restricted') return 'public link (bearer)'
  const parts = ['restricted · verification required']
  if (s.require_otp) parts.push('OTP')
  if (s.domain_allowlist && s.domain_allowlist.length > 0) {
    parts.push(`domains: ${s.domain_allowlist.join(', ')}`)
  }
  return parts.join(' · ')
}

function EditShareCard({ share, onCancel, onSaved, onError }: {
  share: Share
  onCancel: () => void
  onSaved: () => void
  onError: (msg: string) => void
}) {
  // Default values: seconds remaining from now, current cap.
  const remaining = Math.max(60, Math.floor((new Date(share.expires_at).getTime() - Date.now()) / 1000))
  const [expirySeconds, setExpirySeconds] = useState(remaining)
  const [maxDownloads, setMaxDownloads] = useState(share.max_downloads)
  const [busy, setBusy] = useState(false)

  async function save(evt: React.FormEvent) {
    evt.preventDefault()
    setBusy(true)
    const body: Record<string, unknown> = {}
    if (expirySeconds > 0 && expirySeconds !== remaining) body.expiry_seconds = expirySeconds
    if (maxDownloads !== share.max_downloads) body.max_downloads = maxDownloads
    const res = await apiPatch<Share>(`/api/v1/shares/${share.id}`, body)
    setBusy(false)
    if (res.error) onError(res.error.message)
    else onSaved()
  }

  return (
    <section className='card'>
      <div className='card-header'>
        <h2>Edit share {share.id}</h2>
        <button onClick={onCancel}>Cancel</button>
      </div>
      <form className='form-grid' onSubmit={save}>
        <label>Expiry (seconds from now)
          <input type='number' min='60' value={expirySeconds} onChange={(e) => setExpirySeconds(Number(e.target.value))} />
        </label>
        <label>Max downloads (must be ≥ current count {share.download_count})
          <input type='number' min={share.download_count} value={maxDownloads} onChange={(e) => setMaxDownloads(Number(e.target.value))} />
        </label>
        <button disabled={busy} type='submit'>{busy ? 'Saving…' : 'Save'}</button>
      </form>
    </section>
  )
}

function CreateShareCard({ onCreated }: { onCreated: (res: CreateResponse) => void }) {
  const [boxId, setBoxId] = useState('')
  const [fileId, setFileId] = useState('')
  const [unlock, setUnlock] = useState('')
  const [expirySeconds, setExpirySeconds] = useState(86400)
  const [maxDownloads, setMaxDownloads] = useState(5)
  const [mode, setMode] = useState<'public' | 'restricted'>('public')
  const [recipients, setRecipients] = useState('')
  const [domains, setDomains] = useState('')
  const [requireOtp, setRequireOtp] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(evt: React.FormEvent) {
    evt.preventDefault()
    setErr('')
    setBusy(true)
    const body: Record<string, unknown> = {
      box_id: boxId, file_entry_id: fileId, expiry_seconds: expirySeconds, max_downloads: maxDownloads,
    }
    if (mode === 'restricted') {
      body.access_mode = 'restricted'
      body.recipient_emails = recipients.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
      const doms = domains.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
      if (doms.length > 0) body.domain_allowlist = doms
      if (requireOtp) body.require_otp = true
    }
    const res = await apiPost<CreateResponse>('/api/v1/shares', body, unlock)
    setBusy(false)
    if (res.error) setErr(res.error.message)
    else if (res.data) onCreated(res.data)
  }

  return (
    <section className='card'>
      <div className='card-header'><h2>Create share link</h2></div>
      <div style={{ marginBottom: '0.75rem' }}>
        <label style={{ marginRight: '1rem' }}>
          <input type='radio' checked={mode === 'public'} onChange={() => setMode('public')} /> Public link
        </label>
        <label>
          <input type='radio' checked={mode === 'restricted'} onChange={() => setMode('restricted')} /> Restricted (recipients)
        </label>
      </div>
      <form className='form-grid' onSubmit={submit}>
        <label>Box ID<input required value={boxId} onChange={(e) => setBoxId(e.target.value)} /></label>
        <label>File Entry ID<input required value={fileId} onChange={(e) => setFileId(e.target.value)} /></label>
        <label>Unlock session ID<input required value={unlock} onChange={(e) => setUnlock(e.target.value)} /></label>
        <label>Expiry (seconds)<input type='number' min='60' value={expirySeconds} onChange={(e) => setExpirySeconds(Number(e.target.value))} /></label>
        <label>Max downloads<input type='number' min='1' value={maxDownloads} onChange={(e) => setMaxDownloads(Number(e.target.value))} /></label>
        {mode === 'restricted' && (
          <>
            <label>Recipient emails (comma, space, or semicolon separated)
              <textarea rows={2} value={recipients} onChange={(e) => setRecipients(e.target.value)} required={mode === 'restricted'} />
            </label>
            <label>Domain allowlist (optional)
              <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder='example.com, .partner.com' />
            </label>
            <label>
              <input type='checkbox' checked={requireOtp} onChange={(e) => setRequireOtp(e.target.checked)} /> Require OTP after passcode
            </label>
          </>
        )}
        <button disabled={busy} type='submit'>{busy ? 'Creating…' : 'Create'}</button>
        {err && <div className='form-error'>{err}</div>}
      </form>
    </section>
  )
}

type ActivityEvent = {
  kind: 'challenge' | 'access' | 'lifecycle'
  id: string
  share_id: string
  recipient_id?: string
  occurred_at: string
  succeeded: boolean
  reason?: string
  challenge_kind?: string
  lifecycle_event?: string
  actor_id?: string
  remote_ip?: string
  user_agent?: string
  country_code?: string
  risk_score: number
}

function RecipientsPanel({ share, onClose, onError }: {
  share: Share
  onClose: () => void
  onError: (msg: string) => void
}) {
  const [items, setItems] = useState<Recipient[] | null>(null)
  const [newEmails, setNewEmails] = useState('')
  const [lastInvites, setLastInvites] = useState<RecipientInvite[] | null>(null)
  const [lastRotated, setLastRotated] = useState<{ id: string; passcode: string } | null>(null)
  const [activityFor, setActivityFor] = useState<Recipient | null>(null)
  const [showClaims, setShowClaims] = useState(false)

  async function refresh() {
    const res = await apiGet<{ items: Recipient[] }>(`/api/v1/shares/${share.id}/recipients`)
    if (res.error) onError(res.error.message)
    else setItems(res.data?.items ?? [])
  }
  useEffect(() => { void refresh() }, [share.id])

  async function add(evt: React.FormEvent) {
    evt.preventDefault()
    const emails = newEmails.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
    if (emails.length === 0) return
    const res = await apiPost<{ items: RecipientInvite[] }>(`/api/v1/shares/${share.id}/recipients`, { emails })
    if (res.error) onError(res.error.message)
    else {
      setLastInvites(res.data?.items ?? [])
      setNewEmails('')
      void refresh()
    }
  }

  async function rotate(rid: string) {
    const res = await apiPost<{ passcode: string }>(`/api/v1/shares/${share.id}/recipients/${rid}/rotate`, {})
    if (res.error) onError(res.error.message)
    else {
      setLastRotated({ id: rid, passcode: res.data?.passcode ?? '' })
      void refresh()
    }
  }

  async function revoke(rid: string) {
    const res = await apiDelete<void>(`/api/v1/shares/${share.id}/recipients/${rid}`)
    if (res.error) onError(res.error.message)
    else void refresh()
  }

  return (
    <section className='card'>
      <div className='card-header'>
        <h2>Recipients — {share.id}</h2>
        <div>
          <button onClick={() => setShowClaims((v) => !v)}>{showClaims ? 'Hide claims' : 'Active claims'}</button>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
      {lastInvites && lastInvites.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <p><strong>New passcodes (shown once):</strong></p>
          <table className='grid'>
            <thead><tr><th>Email</th><th>Passcode</th></tr></thead>
            <tbody>
              {lastInvites.map((r) => (<tr key={r.id}><td>{r.email}</td><td><code>{r.passcode}</code></td></tr>))}
            </tbody>
          </table>
          <button onClick={() => setLastInvites(null)}>Dismiss</button>
        </div>
      )}
      {lastRotated && (
        <div style={{ marginBottom: '1rem' }}>
          <p>Rotated passcode for <code>{lastRotated.id}</code>: <code>{lastRotated.passcode}</code></p>
          <button onClick={() => setLastRotated(null)}>Dismiss</button>
        </div>
      )}
      {items === null && <div className='empty'>Loading…</div>}
      {items !== null && items.length === 0 && <div className='empty'>No recipients yet.</div>}
      {items && items.length > 0 && (
        <table className='grid'>
          <thead><tr><th>Email</th><th>Verified</th><th>Revoked</th><th>Failed</th><th></th></tr></thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id} data-revoked={!!r.revoked_at}>
                <td>{r.email}</td>
                <td>{r.verified_at ? new Date(r.verified_at).toLocaleString() : '—'}</td>
                <td>{r.revoked_at ? new Date(r.revoked_at).toLocaleString() : '—'}</td>
                <td>{r.failed_attempts}</td>
                <td>
                  <button onClick={() => setActivityFor(r)}>Activity</button>
                  {!r.revoked_at && <button onClick={() => void rotate(r.id)}>Rotate</button>}
                  {!r.revoked_at && <button onClick={() => void revoke(r.id)}>Revoke</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={add} style={{ marginTop: '1rem' }}>
        <label>Add recipients (comma/space/semicolon separated)
          <input value={newEmails} onChange={(e) => setNewEmails(e.target.value)} placeholder='new@example.com' />
        </label>
        <button type='submit'>Add</button>
      </form>
      {showClaims && (
        <ClaimsPanel share={share} recipients={items ?? []} onError={onError} />
      )}
      {activityFor && (
        <RecipientActivity
          share={share}
          recipient={activityFor}
          onClose={() => setActivityFor(null)}
          onError={onError}
        />
      )}
    </section>
  )
}

// RecipientActivity renders a per-recipient timeline of verification
// attempts (share_challenges) so the operator can see who accessed
// what, when, from where, and distinguish denied / verified / expired
// / revoked / cleanup events. The data feed matches the audit trail —
// any challenge row here has a corresponding shares.challenge_* audit
// event visible on the Audit page.
function RecipientActivity({ share, recipient, onClose, onError }: {
  share: Share
  recipient: Recipient
  onClose: () => void
  onError: (msg: string) => void
}) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null)
  useEffect(() => {
    (async () => {
      const res = await apiGet<{ items: ActivityEvent[] }>(
        `/api/v1/shares/${share.id}/recipients/${recipient.id}/activity?limit=200`,
      )
      if (res.error) onError(res.error.message)
      else setEvents(res.data?.items ?? [])
    })()
  }, [share.id, recipient.id])
  return (
    <div className='card' style={{ marginTop: '1rem', border: '1px solid #ccc', padding: '0.75rem' }}>
      <div className='card-header'>
        <h3>Activity — {recipient.email}</h3>
        <button onClick={onClose}>Close</button>
      </div>
      {events === null && <div className='empty'>Loading…</div>}
      {events !== null && events.length === 0 && <div className='empty'>No activity yet.</div>}
      {events && events.length > 0 && (
        <table className='grid'>
          <thead><tr><th>When</th><th>Event</th><th>Status</th><th>Reason</th><th>IP</th><th>Country</th><th>Risk</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.kind + ':' + e.id} data-kind={e.kind} data-succeeded={e.succeeded}>
                <td>{new Date(e.occurred_at).toLocaleString()}</td>
                <td>{activityLabel(e)}</td>
                <td>{activityStatus(e)}</td>
                <td>{e.reason || '—'}</td>
                <td>{e.remote_ip || '—'}</td>
                <td>{e.country_code || '—'}</td>
                <td>{e.risk_score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

type AccessRequest = {
  id: string
  share_id: string
  requester_email: string
  requester_domain: string
  message?: string
  status: string
  recipient_id?: string
  // recipient_state is the CURRENT state of the linked recipient
  // ('active' | 'revoked' | 'missing'); status is the historical decision.
  recipient_state?: string
  decided_by?: string
  decided_at?: string
  decision_reason?: string
  expires_at?: string
  remote_ip?: string
  country_code?: string
  risk_score: number
  created_at: string
}

// accessRequestState renders the historical decision plus current access
// truth, so an approved request whose recipient was later revoked reads as
// "approved · access revoked" rather than implying the requester still has in.
function accessRequestState(ar: AccessRequest): string {
  if (ar.status === 'approved' && ar.recipient_state && ar.recipient_state !== 'active') {
    return `approved · access ${ar.recipient_state === 'revoked' ? 'revoked' : 'gone'}`
  }
  return ar.status
}

type AccessRequestApproveResponse = {
  request: AccessRequest
  recipient: Recipient
  passcode?: string
  reactivated: boolean
}

// AccessRequestsPanel lets the owner inspect and decide owner-approved
// recipient access requests. Approving adds/reactivates the requester as a
// recipient under the share's existing policy and returns a one-shot
// passcode — the requester must STILL verify normally; approval is not a
// shortcut. Denying keeps delivery blocked. The status filter surfaces
// pending, approved, denied, expired, and superseded requests.
function AccessRequestsPanel({ share, onClose, onError }: {
  share: Share
  onClose: () => void
  onError: (msg: string) => void
}) {
  const [items, setItems] = useState<AccessRequest[] | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const [lastApproval, setLastApproval] = useState<AccessRequestApproveResponse | null>(null)

  async function refresh() {
    const q = statusFilter ? `?status=${statusFilter}` : ''
    const res = await apiGet<{ items: AccessRequest[] }>(`/api/v1/shares/${share.id}/access-requests${q}`)
    if (res.error) onError(res.error.message)
    else setItems(res.data?.items ?? [])
  }
  useEffect(() => { void refresh() }, [share.id, statusFilter])

  async function approve(arid: string) {
    const res = await apiPost<AccessRequestApproveResponse>(`/api/v1/shares/${share.id}/access-requests/${arid}/approve`, {})
    if (res.error) onError(res.error.message)
    else {
      if (res.data) setLastApproval(res.data)
      void refresh()
    }
  }

  async function deny(arid: string) {
    const res = await apiPost<void>(`/api/v1/shares/${share.id}/access-requests/${arid}/deny`, {})
    if (res.error) onError(res.error.message)
    else void refresh()
  }

  return (
    <section className='card'>
      <div className='card-header'>
        <h2>Access requests — {share.id}</h2>
        <div>
          <label style={{ marginRight: '0.5rem' }}>Status
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value=''>all</option>
              <option value='pending'>pending</option>
              <option value='approved'>approved</option>
              <option value='denied'>denied</option>
              <option value='expired'>expired</option>
              <option value='superseded'>superseded</option>
            </select>
          </label>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
      {lastApproval && (
        <div style={{ marginBottom: '1rem' }}>
          <p><strong>Approved {lastApproval.recipient.email}{lastApproval.reactivated ? ' (reactivated)' : ''}.</strong></p>
          {lastApproval.passcode
            ? <p className='sub'>Send this passcode to the recipient separately from the share link: <code>{lastApproval.passcode}</code>. It is shown only once and is required to verify and download.</p>
            : <p className='sub'>This recipient already has access and can use their existing passcode.</p>}
          <button onClick={() => setLastApproval(null)}>Dismiss</button>
        </div>
      )}
      {items === null && <div className='empty'>Loading…</div>}
      {items !== null && items.length === 0 && <div className='empty'>No access requests.</div>}
      {items && items.length > 0 && (
        <table className='grid'>
          <thead><tr><th>Email</th><th>Status</th><th>Requested</th><th>Message</th><th>Reason</th><th></th></tr></thead>
          <tbody>
            {items.map((ar) => (
              <tr key={ar.id} data-status={ar.status} data-recipient-state={ar.recipient_state}>
                <td>{ar.requester_email}</td>
                <td>{accessRequestState(ar)}</td>
                <td>{new Date(ar.created_at).toLocaleString()}</td>
                <td>{ar.message || '—'}</td>
                <td>{ar.decision_reason || '—'}</td>
                <td>{ar.status === 'pending'
                  ? <>
                      <button onClick={() => void approve(ar.id)}>Approve</button>
                      <button onClick={() => void deny(ar.id)}>Deny</button>
                    </>
                  : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

type Claim = {
  id: string
  share_id: string
  recipient_id: string
  issued_at: string
  expires_at: string
  revoked_at?: string
  otp_pending: boolean
  remote_ip?: string
  user_agent?: string
}

// ClaimsPanel lists the per-recipient verified sessions (claims) on a
// restricted share and lets the creator revoke an individual claim
// without rotating the passcode or revoking the whole recipient. A
// revoked claim's cookie stops working immediately; subsequent download
// attempts land in the access log as denials with reason=claim_revoked.
function ClaimsPanel({ share, recipients, onError }: {
  share: Share
  recipients: Recipient[]
  onError: (msg: string) => void
}) {
  const [claims, setClaims] = useState<Claim[] | null>(null)
  const emailFor = (rid: string) => recipients.find((r) => r.id === rid)?.email ?? rid

  async function refresh() {
    const res = await apiGet<{ items: Claim[] }>(`/api/v1/shares/${share.id}/claims`)
    if (res.error) onError(res.error.message)
    else setClaims(res.data?.items ?? [])
  }
  useEffect(() => { void refresh() }, [share.id])

  async function revokeClaim(cid: string) {
    const res = await apiDelete<void>(`/api/v1/shares/${share.id}/claims/${cid}`)
    if (res.error) onError(res.error.message)
    else void refresh()
  }

  function claimState(c: Claim): string {
    if (c.revoked_at) return 'revoked'
    if (c.otp_pending) return 'awaiting OTP'
    if (new Date(c.expires_at).getTime() <= Date.now()) return 'expired'
    return 'active'
  }

  return (
    <div className='card' style={{ marginTop: '1rem', border: '1px solid #ccc', padding: '0.75rem' }}>
      <div className='card-header'><h3>Active claims</h3></div>
      {claims === null && <div className='empty'>Loading…</div>}
      {claims !== null && claims.length === 0 && <div className='empty'>No claims issued yet.</div>}
      {claims && claims.length > 0 && (
        <table className='grid'>
          <thead><tr><th>Recipient</th><th>Issued</th><th>Expires</th><th>State</th><th></th></tr></thead>
          <tbody>
            {claims.map((c) => {
              const state = claimState(c)
              return (
                <tr key={c.id} data-claim-state={state}>
                  <td>{emailFor(c.recipient_id)}</td>
                  <td>{new Date(c.issued_at).toLocaleString()}</td>
                  <td>{new Date(c.expires_at).toLocaleString()}</td>
                  <td>{state}</td>
                  <td>{state === 'active' || state === 'awaiting OTP'
                    ? <button onClick={() => void revokeClaim(c.id)}>Revoke claim</button>
                    : '—'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

// activityLabel / activityStatus translate the wire `kind` +
// per-kind sub-field into short strings the operator can scan. The
// table reads like a single lifecycle — "verify/passcode", "download",
// "recipient: revoked" — rather than exposing audit event type
// constants.
function activityLabel(e: ActivityEvent): string {
  if (e.kind === 'challenge') {
    return `verify / ${e.challenge_kind || 'challenge'}`
  }
  if (e.kind === 'lifecycle') {
    return lifecycleLabel(e.lifecycle_event)
  }
  return 'download'
}

function activityStatus(e: ActivityEvent): string {
  if (e.kind === 'challenge') return e.succeeded ? 'verified' : 'denied'
  if (e.kind === 'lifecycle') return e.succeeded ? 'applied' : 'revoked'
  return e.succeeded ? 'delivered' : 'denied'
}

// lifecycleLabel maps an audit event type to a human-scannable label.
// Anything we don't explicitly recognize falls back to the raw type
// so new lifecycle events still render (just less prettily) while a
// patch is being written.
function lifecycleLabel(ev?: string): string {
  switch (ev) {
    case 'shares.recipient_added':     return 'recipient: invited'
    case 'shares.recipient_reactivated': return 'recipient: reactivated'
    case 'shares.recipient_revoked':   return 'recipient: revoked'
    case 'shares.passcode_rotated':    return 'recipient: passcode rotated'
    case 'shares.claim_issued':        return 'claim: issued'
    case 'shares.claim_revoked':       return 'claim: revoked'
    case 'shares.claim_expired':       return 'claim: expired'
    default:                           return ev ?? 'lifecycle'
  }
}
