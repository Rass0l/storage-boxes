import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BoxesPage } from './BoxesPage'
import { renderAt } from '../test/render'
import { authedMe, mockFetch, seedUser } from '../test/fixtures'
import { refreshSession } from '../lib/state/session'

function box(name: string, id = 'box_' + name) {
  return {
    id, name, owner_user_id: seedUser.id, size_bytes: 1024,
    status: 'active', created_at: new Date().toISOString(),
  }
}

describe('BoxesPage', () => {
  it('renders empty state, then lets the user create a box via the real form', async () => {
    let boxes: ReturnType<typeof box>[] = []
    mockFetch({
      'GET /api/v1/auth/me': () => authedMe(),
      'GET /api/v1/boxes': () => ({ status: 200, body: { items: boxes } }),
      'POST /api/v1/boxes': () => {
        const created = box('alpha')
        boxes = [created]
        return { status: 201, body: created }
      },
    })
    await refreshSession()

    renderAt('/boxes', <BoxesPage />)

    expect(await screen.findByText(/No boxes yet/i)).toBeInTheDocument()

    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/Name/i), 'alpha')
    await user.clear(screen.getByLabelText(/Box password/i))
    await user.type(screen.getByLabelText(/Box password/i), 'boxpass1')
    await user.click(screen.getByRole('button', { name: /create box/i }))

    // List refreshes and shows the new box.
    await screen.findByTestId('box-row-alpha')
  })

  it('unlocks a selected box and lists its files', async () => {
    const alpha = box('alpha')
    mockFetch({
      'GET /api/v1/auth/me': () => authedMe(),
      'GET /api/v1/boxes': () => ({ status: 200, body: { items: [alpha] } }),
      'POST /api/v1/boxes/box_alpha/sessions': () => ({
        status: 200,
        body: { session_id: 'ul_test', expires_at: new Date(Date.now() + 600_000).toISOString() },
      }),
      'GET /api/v1/boxes/box_alpha/files': () => ({
        status: 200,
        body: {
          items: [
            { id: 'f_1', name: 'README.md', logical_path: '/README.md', kind: 'file', size_bytes: 120 },
            { id: 'f_2', name: 'work',      logical_path: '/work',      kind: 'folder' },
          ],
        },
      }),
    })
    await refreshSession()
    renderAt('/boxes', <BoxesPage />)

    const user = userEvent.setup()
    // Click the alpha row.
    await user.click(await screen.findByTestId('box-row-alpha'))
    // Unlock panel is visible. Fill and submit.
    const unlockPanel = screen.getByRole('heading', { name: /Unlock/i }).closest('section')!
    await user.type(within(unlockPanel).getByLabelText(/password/i), 'boxpass1')
    await user.click(within(unlockPanel).getByRole('button', { name: /unlock/i }))

    // File table renders both entries.
    const table = await screen.findByRole('table')
    expect(within(table).getByText(/README\.md/)).toBeInTheDocument()
    expect(within(table).getByText(/work/i)).toBeInTheDocument()
  })

  it('navigates into a folder via breadcrumb and back to root', async () => {
    const alpha = box('alpha')
    mockFetch({
      'GET /api/v1/auth/me': () => authedMe(),
      'GET /api/v1/boxes': () => ({ status: 200, body: { items: [alpha] } }),
      'POST /api/v1/boxes/box_alpha/sessions': () => ({
        status: 200,
        body: { session_id: 'ul_test', expires_at: new Date(Date.now() + 600_000).toISOString() },
      }),
      'GET /api/v1/boxes/box_alpha/files': () => ({
        status: 200,
        body: {
          items: [
            { id: 'fo_work',  name: 'work',  logical_path: '/work',           kind: 'folder' },
            { id: 'fi_child', name: 'c.txt', logical_path: '/work/c.txt',     kind: 'file', size_bytes: 5 },
            { id: 'fi_root',  name: 'r.txt', logical_path: '/r.txt',          kind: 'file', size_bytes: 5 },
          ],
        },
      }),
    })
    await refreshSession()
    renderAt('/boxes', <BoxesPage />)

    const user = userEvent.setup()
    await user.click(await screen.findByTestId('box-row-alpha'))
    const unlockPanel = screen.getByRole('heading', { name: /Unlock/i }).closest('section')!
    await user.type(within(unlockPanel).getByLabelText(/password/i), 'boxpass1')
    await user.click(within(unlockPanel).getByRole('button', { name: /unlock/i }))

    // At root: we should see r.txt and work, but NOT c.txt.
    const table = await screen.findByRole('table')
    await waitFor(() => expect(within(table).queryByText(/r\.txt/)).toBeInTheDocument())
    const workCell = within(table).getByText((_, el) => !!el && el.tagName === 'TD' && /work/i.test(el.textContent ?? ''))
    expect(workCell).toBeInTheDocument()
    expect(within(table).queryByText(/c\.txt/)).toBeNull()

    // Click the 'work' folder cell to enter it.
    await user.click(workCell)
    await waitFor(() => {
      const t = screen.getByRole('table')
      expect(within(t).queryByText(/c\.txt/)).toBeInTheDocument()
    })
    // r.txt no longer visible inside /work.
    expect(within(screen.getByRole('table')).queryByText(/r\.txt/)).toBeNull()

    // Breadcrumb "/" returns to root.
    const crumbs = screen.getByLabelText('Breadcrumb')
    await user.click(within(crumbs).getByRole('button', { name: '/' }))
    await waitFor(() => {
      const t = screen.getByRole('table')
      expect(within(t).queryByText(/r\.txt/)).toBeInTheDocument()
    })
  })
})
