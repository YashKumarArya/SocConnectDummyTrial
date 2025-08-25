import { Outlet } from 'react-router-dom'
import { Header } from '@/components/common/Header'
import Footer from '@/components/common/Footer'

export default function LandingLayout() {
  return (
    <div className="min-h-screen flex flex-col bg-[linear-gradient(to_bottom,_#0a0a0a,_#032e30)]">
      <Header />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer />
    </div>
  )
}
