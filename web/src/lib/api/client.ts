import { getInstalledInterceptors } from './interceptors'

export type APIResponse<T> = {
  data?: T
  error?: { code: string; message: string; meta?: Record<string, unknown> }
}

function readCookie(name: string): string | null {
  const prefix = name + '='
  for (const raw of document.cookie.split(';')) {
    const c = raw.trim()
    if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length))
  }
  return null
}

function buildHeaders(method: string, extra?: HeadersInit, hasJSONBody = true, unlockSession?: string | null): Headers {
  const headers = new Headers(extra ?? {})
  if (hasJSONBody && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const csrf = readCookie('sb_csrf')
  const writeMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
  if (csrf && writeMethods.includes(method.toUpperCase())) {
    headers.set('X-CSRF-Token', csrf)
  }
  if (unlockSession) headers.set('X-Unlock-Session', unlockSession)
  return headers
}

async function safeJSON(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return {}
  try { return JSON.parse(text) } catch { return {} }
}

async function apiRequest<T>(path: string, init: RequestInit & { unlockSession?: string | null; jsonBody?: boolean }): Promise<APIResponse<T>> {
  try {
    const headers = buildHeaders(init.method ?? 'GET', init.headers, init.jsonBody !== false, init.unlockSession ?? null)
    const res = await fetch(path, { credentials: 'include', ...init, headers })
    const interceptors = getInstalledInterceptors()
    if (res.status === 401) interceptors.onUnauthorized?.()
    if (res.status === 429) interceptors.onRateLimited?.(res.headers.get('Retry-After'))
    if (!res.ok) {
      const payload = await safeJSON(res) as { error?: { code?: string; message?: string; meta?: Record<string, unknown> } }
      return { error: { code: payload.error?.code ?? 'http_error', message: payload.error?.message ?? `HTTP ${res.status}`, meta: payload.error?.meta } }
    }
    if (res.status === 204) return { data: undefined as unknown as T }
    return { data: (await safeJSON(res)) as T }
  } catch (e) {
    return { error: { code: 'network_error', message: e instanceof Error ? e.message : 'request failed' } }
  }
}

export function apiGet<T>(path: string, unlockSession?: string | null) {
  return apiRequest<T>(path, { method: 'GET', jsonBody: false, unlockSession })
}
export function apiPost<T>(path: string, body?: unknown, unlockSession?: string | null) {
  return apiRequest<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined, unlockSession })
}
export function apiPut<T>(path: string, body?: unknown, unlockSession?: string | null) {
  return apiRequest<T>(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined, unlockSession })
}
export function apiPatch<T>(path: string, body?: unknown, unlockSession?: string | null) {
  return apiRequest<T>(path, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined, unlockSession })
}
export function apiDelete<T>(path: string, unlockSession?: string | null) {
  return apiRequest<T>(path, { method: 'DELETE', jsonBody: false, unlockSession })
}

export async function apiUploadBytes<T>(path: string, bytes: ArrayBuffer | Blob, contentType: string, unlockSession?: string | null): Promise<APIResponse<T>> {
  const headers = buildHeaders('PUT', { 'Content-Type': contentType }, false, unlockSession ?? null)
  try {
    const res = await fetch(path, { method: 'PUT', credentials: 'include', body: bytes, headers })
    if (!res.ok) {
      const payload = await safeJSON(res) as { error?: { code?: string; message?: string } }
      return { error: { code: payload.error?.code ?? 'http_error', message: payload.error?.message ?? `HTTP ${res.status}` } }
    }
    return { data: await safeJSON(res) as T }
  } catch (e) {
    return { error: { code: 'network_error', message: e instanceof Error ? e.message : 'failed' } }
  }
}

export async function apiDownloadBlob(path: string, unlockSession?: string | null): Promise<{ blob?: Blob; error?: { code: string; message: string } }> {
  const headers = buildHeaders('GET', undefined, false, unlockSession ?? null)
  try {
    const res = await fetch(path, { method: 'GET', credentials: 'include', headers })
    if (!res.ok) {
      const payload = await safeJSON(res) as { error?: { code?: string; message?: string } }
      return { error: { code: payload.error?.code ?? 'http_error', message: payload.error?.message ?? `HTTP ${res.status}` } }
    }
    return { blob: await res.blob() }
  } catch (e) {
    return { error: { code: 'network_error', message: e instanceof Error ? e.message : 'failed' } }
  }
}
