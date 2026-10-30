import { BrowserRouter } from 'react-router-dom'
import { AppLayout } from './layouts/AppLayout'
import { AppRoutes } from './routes/AppRoutes'
import { ToastProvider } from './components/Toast'

export function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <AppLayout>
          <AppRoutes />
        </AppLayout>
      </BrowserRouter>
    </ToastProvider>
  )
}
