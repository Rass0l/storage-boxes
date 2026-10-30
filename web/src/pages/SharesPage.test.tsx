import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SharesPage } from './SharesPage'
import { renderAt } from '../test/render'
import { mockFetch } from '../test/fixtures'

describe('SharesPage', () => {
  it('renders shares returned by the API', async () => {
    mockFetch({
      'GET /api/v1/shares': () => ({
        status: 200,
        body: {
          items: [{
            id: 'shr_1', box_id: 'box_1', file_entry_id: 'file_1',
            status: 'active', expires_at: '2026-05-01T00:00:00Z',
            max_downloads: 3, download_count: 0, created_at: '2026-04-17T12:00:00Z',
            deliverable: true,
          }],
        },
      }),
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_1')).toBeInTheDocument())
    expect(screen.getByText(/0\/3 downloads/)).toBeInTheDocument()
  })

  it('surfaces server error when listing fails', async () => {
    mockFetch({
      'GET /api/v1/shares': () => ({
        status: 500, body: { error: { code: 'list_failed', message: 'boom' } },
      }),
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText(/boom/i)).toBeInTheDocument())
  })

  it('renders pending-purge state when deliverable=false', async () => {
    // Share with status=active but purge_requested_at set and
    // deliverable=false. This is the state a share enters the moment
    // its parent box is soft-deleted, before the worker tick flips
    // status to revoked/purged. UI must surface the distinction so
    // operators aren't misled into thinking the link still serves.
    mockFetch({
      'GET /api/v1/shares': () => ({
        status: 200,
        body: {
          items: [{
            id: 'shr_pending', box_id: 'box_1', file_entry_id: 'file_1',
            status: 'active', expires_at: '2026-05-01T00:00:00Z',
            max_downloads: 3, download_count: 0, created_at: '2026-04-17T12:00:00Z',
            purge_requested_at: '2026-04-17T12:30:00Z',
            deliverable: false,
          }],
        },
      }),
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_pending')).toBeInTheDocument())
    expect(screen.getByText(/active · pending purge/i)).toBeInTheDocument()
    // Revoke / edit buttons must be hidden for a non-deliverable
    // share — the worker is already driving it to terminal.
    expect(screen.queryByRole('button', { name: /revoke/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /edit settings/i })).toBeNull()
  })

  it('creates a restricted share and shows per-recipient passcodes once', async () => {
    let createdBody: any = null
    mockFetch({
      'GET /api/v1/shares': () => ({ status: 200, body: { items: [] } }),
      'POST /api/v1/shares': (init) => {
        createdBody = JSON.parse(String(init.body))
        return {
          status: 201,
          body: {
            id: 'shr_r1', box_id: 'box_1', file_entry_id: 'file_1',
            status: 'active', expires_at: '2026-05-01T00:00:00Z',
            max_downloads: 5, download_count: 0, created_at: '2026-04-17T12:00:00Z',
            deliverable: true, access_mode: 'restricted',
            token: 'tok_1', url: '/s/tok_1',
            recipients: [
              { id: 'rcp_1', share_id: 'shr_r1', email: 'a@example.com', email_normalized: 'a@example.com', failed_attempts: 0, created_at: '2026-04-17T12:00:00Z', passcode: 'ABCD1234' },
            ],
          },
        }
      },
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByRole('button', { name: /create/i })).toBeInTheDocument())
    // Switch to restricted.
    await userEvent.click(screen.getByLabelText(/restricted \(recipients\)/i))
    await userEvent.type(screen.getByLabelText(/box id/i), 'box_1')
    await userEvent.type(screen.getByLabelText(/file entry id/i), 'file_1')
    await userEvent.type(screen.getByLabelText(/unlock session/i), 'uls_1')
    await userEvent.type(screen.getByLabelText(/recipient emails/i), 'a@example.com')
    await userEvent.click(screen.getByRole('button', { name: /create/i }))
    await waitFor(() => expect(screen.getByText(/per-recipient passcodes/i)).toBeInTheDocument())
    expect(screen.getByText('ABCD1234')).toBeInTheDocument()
    expect(createdBody.access_mode).toBe('restricted')
    expect(createdBody.recipient_emails).toEqual(['a@example.com'])
  })

  it('summarizes restricted-share policy and manages claims (list + revoke)', async () => {
    let claimRevoked = false
    mockFetch({
      'GET /api/v1/shares': () => ({
        status: 200,
        body: {
          items: [{
            id: 'shr_r', box_id: 'box_1', file_entry_id: 'file_1',
            status: 'active', expires_at: '2030-05-01T00:00:00Z',
            max_downloads: 5, download_count: 0, created_at: '2026-04-17T12:00:00Z',
            deliverable: true, access_mode: 'restricted', require_otp: true,
            domain_allowlist: ['example.com'],
          }],
        },
      }),
      'GET /api/v1/shares/shr_r/recipients': () => ({
        status: 200,
        body: { items: [
          { id: 'rcp_1', share_id: 'shr_r', email: 'a@example.com', email_normalized: 'a@example.com', verified_at: '2026-04-17T12:05:00Z', failed_attempts: 0, created_at: '2026-04-17T12:00:00Z' },
        ] },
      }),
      'GET /api/v1/shares/shr_r/claims': () => ({
        status: 200,
        body: { items: claimRevoked ? [
          { id: 'clm_1', share_id: 'shr_r', recipient_id: 'rcp_1', issued_at: '2026-04-17T12:05:00Z', expires_at: '2030-05-01T00:00:00Z', revoked_at: '2026-04-17T13:00:00Z', otp_pending: false },
        ] : [
          { id: 'clm_1', share_id: 'shr_r', recipient_id: 'rcp_1', issued_at: '2026-04-17T12:05:00Z', expires_at: '2030-05-01T00:00:00Z', otp_pending: false },
        ] },
      }),
      'DELETE /api/v1/shares/shr_r/claims/clm_1': () => { claimRevoked = true; return { status: 204 } },
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_r')).toBeInTheDocument())
    // Policy is summarized at a glance (restricted + OTP + domain rule).
    expect(screen.getByText(/restricted · verification required.*OTP.*domains: example\.com/)).toBeInTheDocument()
    // Open recipients, then the claims sub-panel.
    await userEvent.click(screen.getByRole('button', { name: /recipients/i }))
    await waitFor(() => expect(screen.getByText(/Recipients — shr_r/)).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /active claims/i }))
    // Scope assertions to the claims sub-panel (the recipient email also
    // appears in the recipients table above it).
    const claimsCard = (await screen.findByRole('heading', { name: 'Active claims' })).closest('.card') as HTMLElement
    // The claim renders attributed to the recipient email, state=active.
    await waitFor(() => expect(within(claimsCard).getByRole('cell', { name: 'a@example.com' })).toBeInTheDocument())
    expect(within(claimsCard).getByRole('cell', { name: 'active' })).toBeInTheDocument()
    // Revoke it; the panel reloads and the claim now reads revoked.
    await userEvent.click(within(claimsCard).getByRole('button', { name: /revoke claim/i }))
    await waitFor(() => expect(within(claimsCard).getByRole('cell', { name: 'revoked' })).toBeInTheDocument())
    expect(within(claimsCard).queryByRole('button', { name: /revoke claim/i })).toBeNull()
  })

  it('revokes a share and refreshes the list', async () => {
    let deleted = false
    mockFetch({
      'GET /api/v1/shares': () => deleted
        ? { status: 200, body: { items: [] } }
        : { status: 200, body: {
            items: [{
              id: 'shr_1', box_id: 'box_1', file_entry_id: 'file_1',
              status: 'active', expires_at: '2026-05-01T00:00:00Z',
              max_downloads: 3, download_count: 0, created_at: '2026-04-17T12:00:00Z',
              deliverable: true,
            }],
          } },
      'DELETE /api/v1/shares/shr_1': () => { deleted = true; return { status: 204 } },
    })
    renderAt('/shares', <SharesPage />)
    await waitFor(() => expect(screen.getByText('shr_1')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /revoke/i }))
    await waitFor(() => expect(screen.queryByText('shr_1')).not.toBeInTheDocument())
  })
})
