import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  apiDelete,
  apiDownloadBlob,
  apiGet,
  apiPost,
  apiUploadBytes,
} from '../lib/api/client'
import { useToast } from '../components/Toast'

type Box = {
  id: string
  name: string
  owner_user_id: string
  size_bytes: number
  status: string
  created_at: string
}

type FileTreeItem = {
  id: string
  name: string
  logical_path: string
  content_type?: string
  kind: 'file' | 'folder'
  size_bytes?: number
}

type UnlockState = { sessionId: string; expiresAt: string }

export function BoxesPage() {
  const toast = useToast()
  const [boxes, setBoxes] = useState<Box[] | null>(null)
  const [listError, setListError] = useState('')
  const [selected, setSelected] = useState<Box | null>(null)
  const [unlock, setUnlock] = useState<UnlockState | null>(null)

  const refreshBoxes = useCallback(async () => {
    const res = await apiGet<{ items: Box[] }>('/api/v1/boxes')
    if (res.error) {
      setListError(res.error.message)
      setBoxes([])
      return
    }
    setListError('')
    setBoxes(res.data?.items ?? [])
  }, [])

  useEffect(() => { void refreshBoxes() }, [refreshBoxes])

  async function handleDelete(b: Box) {
    if (!window.confirm(`Delete box "${b.name}"? All contents are unrecoverable.`)) return
    const res = await apiDelete(`/api/v1/boxes/${b.id}`)
    if (res.error) {
      toast.show({ kind: 'error', title: 'Could not delete', message: res.error.message })
      return
    }
    toast.show({ kind: 'success', title: 'Box deleted', message: b.name })
    if (selected?.id === b.id) { setSelected(null); setUnlock(null) }
    await refreshBoxes()
  }

  return (
    <div className='page-stack'>
      <div>
        <h1 className='page-title'>Boxes</h1>
        <p className='page-subtitle'>Encrypted containers you own. Unlock one to work with its contents.</p>
      </div>

      <div className='boxes-layout'>
        <div className='page-stack' style={{ gap: '1rem' }}>
          <section className='card'>
            <div className='card-header'><h2>Create a box</h2></div>
            <BoxCreateForm onCreated={async (created) => {
              toast.show({ kind: 'success', title: 'Box created', message: created.name })
              await refreshBoxes()
              setSelected(created)
              setUnlock(null)
            }} />
          </section>

          <section className='card'>
            <div className='card-header'>
              <h2>Your boxes</h2>
              <button type='button' className='ghost-button' onClick={refreshBoxes}>Refresh</button>
            </div>
            {boxes === null && <BoxListSkeleton />}
            {boxes !== null && listError && <div className='form-error'>{listError}</div>}
            {boxes !== null && !listError && boxes.length === 0 && (
              <div className='empty'>
                <strong>No boxes yet</strong>
                Create your first encrypted box using the form above.
              </div>
            )}
            {boxes !== null && boxes.length > 0 && (
              <ul className='box-list' role='list'>
                {boxes.map((b) => (
                  <li
                    key={b.id}
                    className={'box-row' + (selected?.id === b.id ? ' selected' : '')}
                    onClick={() => { setSelected(b); setUnlock(null) }}
                    data-testid={`box-row-${b.name}`}
                  >
                    <div className='box-meta'>
                      <span className='name'>{b.name}</span>
                      <span className='sub'>{formatBytes(b.size_bytes)} · created {new Date(b.created_at).toLocaleDateString()}</span>
                    </div>
                    <div className='button-row' style={{ gap: '0.35rem' }} onClick={(e) => e.stopPropagation()}>
                      <span className={'state-pill ' + (unlock && selected?.id === b.id ? 'is-unlocked' : 'is-locked')}>
                        {unlock && selected?.id === b.id ? 'unlocked' : 'locked'}
                      </span>
                      <button type='button' className='danger-button' onClick={() => handleDelete(b)} aria-label={`Delete ${b.name}`}>Delete</button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <div>
          {!selected && (
            <div className='card'>
              <div className='empty'>
                <strong>Select a box</strong>
                Pick a box from the list to unlock and browse its contents.
              </div>
            </div>
          )}
          {selected && !unlock && (
            <section className='card'>
              <div className='card-header'>
                <h2>Unlock “{selected.name}”</h2>
                <button type='button' className='ghost-button' onClick={() => setSelected(null)}>Close</button>
              </div>
              <BoxUnlockPanel
                box={selected}
                onUnlocked={(u) => {
                  toast.show({ kind: 'success', title: 'Box unlocked', message: `Session expires ${new Date(u.expiresAt).toLocaleTimeString()}` })
                  setUnlock(u)
                }}
                onError={(m) => toast.show({ kind: 'error', title: 'Unlock failed', message: m })}
              />
            </section>
          )}
          {selected && unlock && (
            <section className='card'>
              <div className='card-header'>
                <h2>{selected.name}</h2>
                <div className='button-row'>
                  <span className='state-pill is-unlocked'>unlocked</span>
                  <button
                    type='button'
                    className='secondary-button'
                    onClick={async () => {
                      await apiDelete(`/api/v1/boxes/${selected.id}/sessions/${unlock.sessionId}`)
                      setUnlock(null)
                      toast.show({ kind: 'info', title: 'Box locked' })
                    }}
                  >Lock</button>
                </div>
              </div>
              <BoxExplorer box={selected} unlockSession={unlock.sessionId} />
            </section>
          )}
        </div>
      </div>
    </div>
  )
}

/* ---------------------------------------------------------------------- */

function BoxListSkeleton() {
  return (
    <ul className='box-list' aria-hidden>
      {[0, 1, 2].map((i) => (
        <li key={i} className='box-row'>
          <div className='box-meta' style={{ flex: 1 }}>
            <div className='skeleton' style={{ width: '50%', height: '0.9rem' }} />
            <div className='skeleton' style={{ width: '35%', height: '0.7rem', marginTop: '0.35rem' }} />
          </div>
        </li>
      ))}
    </ul>
  )
}

function BoxCreateForm({ onCreated }: { onCreated: (b: Box) => void | Promise<void> }) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [size, setSize] = useState('1073741824')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(ev: FormEvent) {
    ev.preventDefault()
    setErr('')
    if (!name.trim()) return setErr('Name is required.')
    if (password.length < 8) return setErr('Password must be at least 8 characters.')
    setBusy(true)
    const res = await apiPost<Box>('/api/v1/boxes', {
      name: name.trim(),
      size_bytes: Number(size) || 1073741824,
      password,
    })
    setBusy(false)
    if (res.error || !res.data) {
      setErr(res.error?.message ?? 'unexpected response')
      toast.show({ kind: 'error', title: 'Create failed', message: res.error?.message })
      return
    }
    setName(''); setPassword('')
    await onCreated(res.data)
  }

  return (
    <form className='form-grid' onSubmit={submit}>
      <label>
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder='e.g. finance-2026' />
      </label>
      <label>
        <span>Quota (bytes)</span>
        <input value={size} onChange={(e) => setSize(e.target.value)} inputMode='numeric' />
      </label>
      <label>
        <span>Box password (min 8 chars)</span>
        <input type='password' value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {err && <div className='form-error' role='alert'>{err}</div>}
      <div className='button-row'>
        <button type='submit' className='primary-button' disabled={busy}>
          {busy ? 'Creating…' : 'Create box'}
        </button>
      </div>
    </form>
  )
}

function BoxUnlockPanel({
  box, onUnlocked, onError,
}: {
  box: Box
  onUnlocked: (u: UnlockState) => void
  onError: (msg: string) => void
}) {
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(ev: FormEvent) {
    ev.preventDefault()
    setErr('')
    setBusy(true)
    const res = await apiPost<{ session_id: string; expires_at: string }>(
      `/api/v1/boxes/${box.id}/sessions`, { password })
    setBusy(false)
    if (res.error || !res.data) {
      const msg = res.error?.message ?? 'unlock failed'
      setErr(msg); onError(msg); return
    }
    onUnlocked({ sessionId: res.data.session_id, expiresAt: res.data.expires_at })
    setPassword('')
  }

  return (
    <form className='form-grid' onSubmit={submit}>
      <label>
        <span>Password</span>
        <input type='password' value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
      </label>
      {err && <div className='form-error' role='alert'>{err}</div>}
      <div className='button-row'>
        <button type='submit' className='primary-button' disabled={busy}>
          {busy ? 'Unlocking…' : 'Unlock'}
        </button>
      </div>
    </form>
  )
}

/* ---------------------------------------------------------------------- */

function BoxExplorer({ box, unlockSession }: { box: Box; unlockSession: string }) {
  const toast = useToast()
  const [items, setItems] = useState<FileTreeItem[] | null>(null)
  const [cwd, setCwd] = useState('/') // always ends with '/'
  const fileInput = useRef<HTMLInputElement>(null)

  const refresh = useCallback(async () => {
    const res = await apiGet<{ items: FileTreeItem[] }>(`/api/v1/boxes/${box.id}/files`, unlockSession)
    if (res.error) {
      toast.show({ kind: 'error', title: 'Could not list files', message: res.error.message })
      setItems([])
      return
    }
    setItems(res.data?.items ?? [])
  }, [box.id, unlockSession, toast])

  useEffect(() => { void refresh() }, [refresh])

  const visible = useMemo(() => filterByCwd(items ?? [], cwd), [items, cwd])

  async function handleUpload(ev: React.ChangeEvent<HTMLInputElement>) {
    const f = ev.target.files?.[0]
    if (!f) return
    const buf = await f.arrayBuffer()
    const logical = cwd + f.name
    const res = await apiUploadBytes(
      `/api/v1/boxes/${box.id}/files?path=${encodeURIComponent(logical)}`,
      buf, f.type || 'application/octet-stream', unlockSession,
    )
    if (res.error) { toast.show({ kind: 'error', title: 'Upload failed', message: res.error.message }); return }
    toast.show({ kind: 'success', title: 'Uploaded', message: f.name })
    if (fileInput.current) fileInput.current.value = ''
    await refresh()
  }

  async function createFolder() {
    const name = window.prompt('Folder name (inside current folder):')
    if (!name) return
    const logical = cwd + name.replace(/^\/+/, '')
    const res = await apiPost(`/api/v1/boxes/${box.id}/folders`,
      { logical_path: logical }, unlockSession)
    if (res.error) { toast.show({ kind: 'error', title: 'Folder failed', message: res.error.message }); return }
    toast.show({ kind: 'success', title: 'Folder created', message: logical })
    await refresh()
  }

  async function deleteEntry(item: FileTreeItem) {
    if (!window.confirm(`Delete ${item.logical_path}?`)) return
    const res = await apiDelete(
      `/api/v1/boxes/${box.id}/files?path=${encodeURIComponent(item.logical_path)}`,
      unlockSession,
    )
    if (res.error) { toast.show({ kind: 'error', title: 'Delete failed', message: res.error.message }); return }
    toast.show({ kind: 'success', title: 'Deleted', message: item.logical_path })
    await refresh()
  }

  async function renameEntry(item: FileTreeItem) {
    const dest = window.prompt('New path:', item.logical_path)
    if (!dest || dest === item.logical_path) return
    const res = await apiPost(`/api/v1/boxes/${box.id}/files/move`,
      { from_path: item.logical_path, to_path: dest }, unlockSession)
    if (res.error) { toast.show({ kind: 'error', title: 'Move failed', message: res.error.message }); return }
    toast.show({ kind: 'success', title: 'Moved', message: `${item.logical_path} → ${dest}` })
    await refresh()
  }

  async function downloadFile(item: FileTreeItem) {
    const res = await apiDownloadBlob(`/api/v1/boxes/${box.id}/files/${item.id}/content`, unlockSession)
    if (res.error || !res.blob) {
      toast.show({ kind: 'error', title: 'Download failed', message: res.error?.message ?? 'unknown' })
      return
    }
    const url = URL.createObjectURL(res.blob)
    const a = document.createElement('a')
    a.href = url; a.download = item.name; a.click()
    URL.revokeObjectURL(url)
  }

  const parts = cwd.split('/').filter(Boolean) // e.g. ['work', 'docs']

  return (
    <div>
      <div className='breadcrumb' aria-label='Breadcrumb'>
        <button type='button' onClick={() => setCwd('/')}>/</button>
        {parts.map((p, i) => (
          <span key={i}>
            <span className='sep'>/</span>
            <button type='button' onClick={() => setCwd('/' + parts.slice(0, i + 1).join('/') + '/')}>{p}</button>
          </span>
        ))}
      </div>

      <div className='button-row' style={{ marginBottom: '0.8rem' }}>
        <label className='primary-button' style={{ cursor: 'pointer' }}>
          Upload file
          <input ref={fileInput} type='file' style={{ display: 'none' }} onChange={handleUpload} data-testid='file-input' />
        </label>
        <button type='button' className='secondary-button' onClick={createFolder}>New folder</button>
      </div>

      {items === null && <div className='empty'>Loading…</div>}
      {items !== null && visible.length === 0 && (
        <div className='empty'>
          <strong>Empty folder</strong>
          Upload a file or create a subfolder to get started.
        </div>
      )}
      {items !== null && visible.length > 0 && (
        <table className='file-table'>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th className='size'>Size</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {visible.map((it) => (
              <tr key={it.id} className={it.kind === 'folder' ? 'folder-row' : ''}>
                <td onClick={it.kind === 'folder' ? () => setCwd(it.logical_path.replace(/\/+$/, '') + '/') : undefined}>
                  {it.kind === 'folder' ? '📁 ' : '📄 '}{it.name}
                </td>
                <td><span className='kind'>{it.kind}</span></td>
                <td className='size'>{it.size_bytes ? formatBytes(it.size_bytes) : ''}</td>
                <td>
                  <div className='actions'>
                    {it.kind === 'file' && (
                      <button type='button' className='secondary-button' onClick={() => downloadFile(it)}>Download</button>
                    )}
                    <button type='button' className='secondary-button' onClick={() => renameEntry(it)}>Rename</button>
                    <button type='button' className='danger-button' onClick={() => deleteEntry(it)} aria-label={`Delete ${it.logical_path}`}>Delete</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function filterByCwd(items: FileTreeItem[], cwd: string): FileTreeItem[] {
  const prefix = cwd
  return items
    .filter((it) => {
      if (!it.logical_path.startsWith(prefix)) return false
      const rest = it.logical_path.slice(prefix.length).replace(/\/+$/, '')
      return rest !== '' && !rest.includes('/')
    })
    .sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1
      return a.name.localeCompare(b.name)
    })
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`
}
