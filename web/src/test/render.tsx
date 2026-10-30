import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { ToastProvider } from '../components/Toast'

export function renderAt(path: string, node: ReactElement) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={path} element={node} />
          <Route path='*' element={node} />
        </Routes>
      </MemoryRouter>
    </ToastProvider>,
  )
}
