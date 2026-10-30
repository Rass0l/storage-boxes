import React from 'react'
import ReactDOM from 'react-dom/client'
import { App } from './App'
import { installInterceptors } from './lib/api/interceptors'
import { clearSessionState } from './lib/state/session'
import './styles.css'

installInterceptors({
  onUnauthorized() {
    clearSessionState()
    // Only hard-redirect away from protected routes. If we're already on a
    // public page (/login, /) the React router will handle the transition
    // and a hard replace would cause a probe-loop on /auth/me.
    const p = window.location.pathname
    if (p !== '/login' && p !== '/') {
      window.location.replace('/login')
    }
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
