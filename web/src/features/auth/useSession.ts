import { useEffect, useMemo, useState } from 'react'
import {
  clearSessionState,
  getSessionState,
  loginWithCredentials,
  logout as doLogout,
  refreshSession,
  subscribeSession,
  type SessionState,
  type SessionUser,
} from '../../lib/state/session'

let hydrated = false

export function useSession() {
  const [state, setState] = useState<SessionState>(getSessionState())

  useEffect(() => {
    const unsub = subscribeSession(setState)
    if (!hydrated) {
      hydrated = true
      void refreshSession()
    }
    return () => unsub()
  }, [])

  return useMemo(() => ({
    state,
    loading: state.status === 'unknown',
    isAuthenticated: state.status === 'authenticated',
    user: state.user as SessionUser | undefined,
    async login(email: string, password: string) {
      return loginWithCredentials(email, password)
    },
    async logout() {
      await doLogout()
    },
    clear() {
      clearSessionState()
    },
    async refresh() {
      await refreshSession()
    },
  }), [state])
}
