import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'

type ToastKind = 'info' | 'success' | 'error'
export type Toast = { id: number; kind: ToastKind; title: string; message?: string }

type ToastContextValue = {
  show(input: { kind?: ToastKind; title: string; message?: string; timeoutMs?: number }): void
  dismiss(id: number): void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const show = useCallback((input: { kind?: ToastKind; title: string; message?: string; timeoutMs?: number }) => {
    const id = nextId.current++
    const toast: Toast = { id, kind: input.kind ?? 'info', title: input.title, message: input.message }
    setToasts((prev) => [...prev, toast])
    const timeout = input.timeoutMs ?? 4500
    if (timeout > 0) {
      window.setTimeout(() => dismiss(id), timeout)
    }
  }, [dismiss])

  const ctx = useMemo(() => ({ show, dismiss }), [show, dismiss])

  return (
    <ToastContext.Provider value={ctx}>
      {children}
      <div className='toast-stack' role='status' aria-live='polite'>
        {toasts.map((t) => (
          <div key={t.id} className={`toast is-${t.kind}`}>
            <div className='toast-body'>
              <div className='toast-title'>{t.title}</div>
              {t.message && <div className='toast-message'>{t.message}</div>}
            </div>
            <button type='button' aria-label='Dismiss notification' onClick={() => dismiss(t.id)}>×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    // Tests can render components without a provider; fall back to a silent
    // no-op rather than crashing.
    return {
      show: () => { /* no-op */ },
      dismiss: () => { /* no-op */ },
    }
  }
  return ctx
}
