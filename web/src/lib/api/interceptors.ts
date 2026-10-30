export type APIInterceptorOptions = {
  onUnauthorized?: () => void
  onRateLimited?: (retryAfter?: string | null) => void
}

let activeOptions: APIInterceptorOptions = {}

export function installInterceptors(options: APIInterceptorOptions = {}) {
  activeOptions = options
  return {
    normalizeStatus(status: number, retryAfter?: string | null) {
      if (status === 401) {
        activeOptions.onUnauthorized?.()
      }
      if (status === 429) {
        activeOptions.onRateLimited?.(retryAfter ?? null)
      }
    },
  }
}

export function getInstalledInterceptors() {
  return activeOptions
}
