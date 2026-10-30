import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LoginPage } from './LoginPage'
import { renderAt } from '../test/render'
import { anonMe, mockFetch, seedUser } from '../test/fixtures'

describe('LoginPage', () => {
  it('rejects empty password client-side', async () => {
    mockFetch({
      'GET /api/v1/auth/me': () => anonMe(),
    })
    renderAt('/login', <LoginPage />)
    const user = userEvent.setup()
    await user.clear(screen.getByLabelText(/email/i))
    await user.type(screen.getByLabelText(/email/i), 'admin@example.local')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/email and password/i)
  })

  it('surfaces server error on bad credentials', async () => {
    mockFetch({
      'GET /api/v1/auth/me': () => anonMe(),
      'POST /api/v1/auth/login': () => ({
        status: 401,
        body: { error: { code: 'invalid_credentials', message: 'invalid email or password' } },
      }),
    })
    renderAt('/login', <LoginPage />)
    const user = userEvent.setup()
    await user.clear(screen.getByLabelText(/email/i))
    await user.type(screen.getByLabelText(/email/i), 'admin@example.local')
    await user.type(screen.getByLabelText(/password/i), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid email or password/i)
  })

  it('completes sign-in and transitions away from the form', async () => {
    let loginCalls = 0
    mockFetch({
      'GET /api/v1/auth/me': () => anonMe(),
      'POST /api/v1/auth/login': () => {
        loginCalls++
        return { status: 200, body: { user: seedUser, csrf_token: 'csrf-abc' } }
      },
    })
    renderAt('/login', <LoginPage />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/email/i), 'admin@example.local')
    await user.type(screen.getByLabelText(/password/i), 'password1')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    // After login the session store flips to authenticated and the page
    // renders a <Navigate />; the form disappears.
    await screen.findByText((_, el) => !!el && !el.matches('button') && el.textContent === '')
      .catch(() => { /* Navigate renders null body; absence of form is what we assert */ })
    expect(loginCalls).toBe(1)
    expect(screen.queryByRole('button', { name: /sign in/i })).toBeNull()
  })
})
