import { vi } from 'vitest'

type Route = (init: RequestInit) => { status: number; body?: unknown; headers?: Record<string, string> } | Promise<{ status: number; body?: unknown; headers?: Record<string, string> }>

export type FetchTable = Record<string, Route | Record<string, Route>>

/**
 * mockFetch installs a vi.fn for global.fetch that dispatches to a routing
 * table keyed by "METHOD PATH". Unknown URLs fall through to 404.
 *
 *   mockFetch({
 *     'GET /api/v1/auth/me': () => ({ status: 200, body: { user: {...} } }),
 *     'POST /api/v1/auth/login': () => ({ status: 200, body: {...} }),
 *   })
 */
export function mockFetch(table: Record<string, Route>) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : (input as Request).url
    const method = (init?.method ?? 'GET').toUpperCase()
    // Match on path only (strip origin if present).
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    const key = `${method} ${path.split('?')[0]}`
    const route = table[key] ?? table[`${method} ${path}`]
    if (!route) {
      return new Response(JSON.stringify({ error: { code: 'not_found', message: 'no route for ' + key } }),
        { status: 404, headers: { 'Content-Type': 'application/json' } })
    }
    const result = await route(init ?? {})
    const body = result.body === undefined ? '' : typeof result.body === 'string' ? result.body : JSON.stringify(result.body)
    return new Response(body, {
      status: result.status,
      headers: { 'Content-Type': 'application/json', ...(result.headers ?? {}) },
    })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

export const seedUser = {
  id: 'usr_test',
  email: 'admin@example.local',
  display_name: 'Administrator',
  roles: ['admin'],
}

export function authedMe() {
  return { status: 200, body: { user: seedUser } }
}

export function anonMe() {
  return { status: 401, body: { error: { code: 'no_session', message: 'not authenticated' } } }
}
