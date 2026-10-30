import { describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuditPage } from './AuditPage'
import { renderAt } from '../test/render'
import { mockFetch } from '../test/fixtures'

describe('AuditPage', () => {
  it('lists audit events', async () => {
    mockFetch({
      'GET /api/v1/audit/events': () => ({
        status: 200,
        body: {
          items: [
            { id: 'a1', event_type: 'shares.created', subject_type: 'share', subject_id: 'shr_x', actor_id: 'usr_1', occurred_at: '2026-04-17T12:00:00Z', metadata: { box_id: 'b1' } },
            { id: 'a2', event_type: 'identity.login_succeeded', subject_type: 'user', subject_id: 'usr_1', occurred_at: '2026-04-17T11:00:00Z', metadata: {} },
          ],
        },
      }),
    })
    renderAt('/audit', <AuditPage />)
    // Assert against the data-table cell specifically: each event_type
    // also appears as a filter <option>, so a bare getByText is
    // ambiguous. Targeting the cell proves the row actually rendered.
    await waitFor(() => expect(screen.getByRole('cell', { name: 'shares.created' })).toBeInTheDocument())
    expect(screen.getByRole('cell', { name: 'identity.login_succeeded' })).toBeInTheDocument()
  })

  it('reloads with subject_type filter applied', async () => {
    const seen: string[] = []
    mockFetch({
      'GET /api/v1/audit/events': (init) => {
        // fetch URL search is inaccessible via init; record method instead
        // to at least prove the reload occurred.
        seen.push(String(init.method ?? 'GET'))
        return { status: 200, body: { items: [] } }
      },
    })
    renderAt('/audit', <AuditPage />)
    await waitFor(() => expect(seen.length).toBeGreaterThanOrEqual(1))
    await userEvent.selectOptions(screen.getByLabelText(/subject type/i), 'share')
    await userEvent.click(screen.getByRole('button', { name: /apply/i }))
    await waitFor(() => expect(seen.length).toBeGreaterThanOrEqual(2))
  })
})
