import { apiGet, apiPost } from '../api/client'

export type SessionUser = {
  id: string
  email: string
  display_name?: string
  roles: string[]
}

export type SessionState = {
  status: 'unknown' | 'anonymous' | 'authenticated'
  user?: SessionUser
  checkedAt?: string
}

type Listener = (s: SessionState) => void

let current: SessionState = { status: 'unknown' }
const listeners = new Set<Listener>()

function setState(next: SessionState) {
  current = next
  for (const l of listeners) l(current)
}

export function getSessionState(): SessionState {
  return current
}

export function subscribeSession(l: Listener): () => void {
  listeners.add(l)
  l(current)
  return () => { listeners.delete(l) }
}

export function clearSessionState() {
  setState({ status: 'anonymous', checkedAt: new Date().toISOString() })
}

export async function refreshSession(): Promise<SessionState> {
  const res = await apiGet<{ user: SessionUser }>('/api/v1/auth/me')
  if (res.data?.user) {
    setState({ status: 'authenticated', user: res.data.user, checkedAt: new Date().toISOString() })
  } else {
    setState({ status: 'anonymous', checkedAt: new Date().toISOString() })
  }
  return current
}

export async function loginWithCredentials(email: string, password: string): Promise<{ ok: boolean; error?: string }> {
  const res = await apiPost<{ user: SessionUser }>('/api/v1/auth/login', { email, password })
  if (res.error) return { ok: false, error: res.error.message }
  if (res.data?.user) {
    setState({ status: 'authenticated', user: res.data.user, checkedAt: new Date().toISOString() })
    return { ok: true }
  }
  return { ok: false, error: 'unexpected_response' }
}

export async function logout(): Promise<void> {
  await apiPost('/api/v1/auth/logout')
  clearSessionState()
}
