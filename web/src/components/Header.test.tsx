import { describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Header } from './Header'
import { renderAt } from '../test/render'
import { authedMe, mockFetch, seedUser } from '../test/fixtures'
import { refreshSession } from '../lib/state/session'

describe('Header', () => {
  it('renders the signed-in user chip and triggers logout', async () => {
    let logouts = 0
    mockFetch({
      'GET /healthz': () => ({ status: 200, body: { status: 'ok' } }),
      'GET /api/v1/auth/me': () => authedMe(),
      'POST /api/v1/auth/logout': () => { logouts++; return { status: 204 } },
    })
    await refreshSession()
    renderAt('/dashboard', <Header />)

    expect(screen.getByText(seedUser.email)).toBeInTheDocument()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /logout/i }))
    await waitFor(() => expect(logouts).toBe(1))
    // After logout the chip is gone and the sign-in link appears.
    await waitFor(() => expect(screen.queryByText(seedUser.email)).toBeNull())
    expect(screen.getByRole('link', { name: /sign in/i })).toBeInTheDocument()
  })
})
