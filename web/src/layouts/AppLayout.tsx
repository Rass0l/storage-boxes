import type { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { Sidebar } from '../components/Sidebar'
import { Header } from '../components/Header'

export function AppLayout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const isLogin = location.pathname === '/login'

  return (
    <div className='app-shell'>
      <Header />
      <div className={'app-body' + (isLogin ? ' app-body--auth' : '')}>
        {!isLogin && <Sidebar />}
        <main className='app-main'>{children}</main>
      </div>
    </div>
  )
}
