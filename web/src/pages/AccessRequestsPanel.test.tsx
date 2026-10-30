import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SharesPage } from './SharesPage'
import { renderAt } from '../test/render'
import { mockFetch } from '../test/fixtures'

// A restricted share fixture so the "Access requests" button renders.
const restrictedShare = {
  id: 'shr_r', box_id: 'box_1', file_entry_id: 'file_1',
  status: 'active', expires_at: '2030-05-01T00:00:00Z',
  max_downloads: 5, download_count: 0, created_at: '2026-04-17T12:00:00Z',
  deliverable: true, access_mode: 'restricted',
}

describe('AccessRequestsPanel', () => {
  it('lists pending requests and shows the one-shot passcode on approve', async () => {
    let approved = false
    mockFetch({
      'GET /api/v1/shares': () => ({ status: 200, body: { items: [restrictedShare] } }),
      'GET /api/v1/shares/shr_r/access-requests': () => ({
        status: 200,
        body: {
          items: approved
            ? [{ id: 'ar_1', share_id: 'shr_r', requester_email: 'guest@example.com', requester_domain: 'example.com', status: 'approved', decision_reason: 'owner_approved', risk_score: 0, created_at: '2026-04-17T12:30:00Z' }]
            : [{ id: 'ar_1', share_id: 'shr_r', requester_email: 'guest@example.com', requester_domain: 'example.com', status: 'pending', message: 'please', risk_score: 0, created_at: '2026-04-17T12:30:00Z' }],
        },
      }),
      'POST /api/v1/shares/shr_r/access-requests/ar_1/approve': () => {
        approved = true
        return {
          status: 200,
          body: {
            request: { id: 'ar_1', share_id: 'shr_r', requester_email: 'guest@example.com', requester_domain: 'example.com', status: 'approved', risk_score: 0, created_at: '2026-04-17T12:30:00Z' },
            recipient: { id: 'rcp_new', share_id: 'shr_r', email: 'guest@example.com', email_normalized: 'guest@example.com', failed_attempts: 0, created_at: '2026-04-17T13:00:00Z' },
            passcode: 'NEWPASS9',
            reactivated: false,
          },
        }
      },
    })

    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_r')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /access requests/i }))

    const card = (await screen.findByRole('heading', { name: /Access requests — shr_r/ })).closest('.card') as HTMLElement
    await waitFor(() => expect(within(card).getByRole('cell', { name: 'guest@example.com' })).toBeInTheDocument())
    expect(within(card).getByRole('cell', { name: 'pending' })).toBeInTheDocument()

    await userEvent.click(within(card).getByRole('button', { name: /approve/i }))
    // The one-shot passcode must surface exactly once.
    await waitFor(() => expect(within(card).getByText('NEWPASS9')).toBeInTheDocument())
    // The row now reflects the approved status after refresh.
    await waitFor(() => expect(within(card).getByRole('cell', { name: 'approved' })).toBeInTheDocument())
  })

  it('shows an approved request whose recipient was revoked as access revoked', async () => {
    mockFetch({
      'GET /api/v1/shares': () => ({ status: 200, body: { items: [restrictedShare] } }),
      'GET /api/v1/shares/shr_r/access-requests': () => ({
        status: 200,
        body: {
          items: [{
            id: 'ar_x', share_id: 'shr_r', requester_email: 'guest@example.com', requester_domain: 'example.com',
            status: 'approved', recipient_id: 'rcp_1', recipient_state: 'revoked',
            decision_reason: 'owner_approved', risk_score: 0, created_at: '2026-04-17T12:30:00Z',
          }],
        },
      }),
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_r')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /access requests/i }))
    const card = (await screen.findByRole('heading', { name: /Access requests — shr_r/ })).closest('.card') as HTMLElement
    // The historical decision is shown, annotated with current access truth.
    await waitFor(() => expect(within(card).getByText(/approved · access revoked/i)).toBeInTheDocument())
  })

  it('denies a pending request', async () => {
    let denied = false
    mockFetch({
      'GET /api/v1/shares': () => ({ status: 200, body: { items: [restrictedShare] } }),
      'GET /api/v1/shares/shr_r/access-requests': () => ({
        status: 200,
        body: {
          items: denied
            ? [{ id: 'ar_2', share_id: 'shr_r', requester_email: 'mallory@example.com', requester_domain: 'example.com', status: 'denied', decision_reason: 'owner_denied', risk_score: 0, created_at: '2026-04-17T12:30:00Z' }]
            : [{ id: 'ar_2', share_id: 'shr_r', requester_email: 'mallory@example.com', requester_domain: 'example.com', status: 'pending', risk_score: 0, created_at: '2026-04-17T12:30:00Z' }],
        },
      }),
      'POST /api/v1/shares/shr_r/access-requests/ar_2/deny': () => { denied = true; return { status: 204 } },
    })

    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_r')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /access requests/i }))
    const card = (await screen.findByRole('heading', { name: /Access requests — shr_r/ })).closest('.card') as HTMLElement
    await waitFor(() => expect(within(card).getByRole('cell', { name: 'mallory@example.com' })).toBeInTheDocument())
    await userEvent.click(within(card).getByRole('button', { name: /deny/i }))
    await waitFor(() => expect(within(card).getByRole('cell', { name: 'denied' })).toBeInTheDocument())
  })
})
