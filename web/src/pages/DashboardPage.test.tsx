import { describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { DashboardPage } from './DashboardPage'
import { renderAt } from '../test/render'
import { authedMe, mockFetch } from '../test/fixtures'
import { refreshSession } from '../lib/state/session'

describe('DashboardPage', () => {
  it('shows the signed-in user and a live box count', async () => {
    mockFetch({
      'GET /api/v1/auth/me': () => authedMe(),
      'GET /api/v1/boxes': () => ({
        status: 200,
        body: {
          items: [
            { id: 'box_1', name: 'alpha', owner_user_id: 'usr_test', size_bytes: 2048, status: 'active', created_at: new Date().toISOString() },
            { id: 'box_2', name: 'beta',  owner_user_id: 'usr_test', size_bytes: 4096, status: 'active', created_at: new Date().toISOString() },
          ],
        },
      }),
    })
    // Pre-hydrate the session so useSession reports authenticated on first render.
    await refreshSession()

    renderAt('/dashboard', <DashboardPage />)

    expect(screen.getByText('admin@example.local')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByTestId('stat-box-count')).toHaveTextContent('2')
    })
  })
})
