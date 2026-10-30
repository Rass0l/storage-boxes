import '@testing-library/jest-dom/vitest'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

// Reset the module-scoped session store between tests so one test's login
// doesn't bleed into the next.
afterEach(async () => {
  cleanup()
  const sessionModule = await import('../lib/state/session')
  sessionModule.clearSessionState()
  vi.restoreAllMocks()
})
