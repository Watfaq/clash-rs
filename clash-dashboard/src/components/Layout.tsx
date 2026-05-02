import { NavLink, Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getVersion } from '../lib/api';
import {
  LayoutDashboard, Activity, Filter, Terminal,
  Server, SlidersHorizontal, GitBranch, Shield,
} from 'lucide-react';
import logoUrl from '../assets/logo.png';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/flows', label: 'Flows', icon: GitBranch },
  { to: '/connections', label: 'Connections', icon: Activity },
  { to: '/proxies', label: 'Proxies', icon: Shield },
  { to: '/rules', label: 'Rules', icon: Filter },
  { to: '/dns', label: 'DNS', icon: Server },
  { to: '/logs', label: 'Logs', icon: Terminal },
  { to: '/settings', label: 'Settings', icon: SlidersHorizontal },
];

export function Layout() {
  const { data: version, error } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    refetchInterval: 10000,
    retry: 0,
  });
  const isConnected = !!version && !error;

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* Top nav bar — Apple liquid glass */}
      <header className="liquid-glass flex-shrink-0 sticky top-0 z-50" style={{ height: 52 }}>
        {/* Inner content constrained to same max-width as pages */}
        <div className="h-full max-w-5xl mx-auto px-4 flex items-center gap-3">
          {/* Logo — real clash-rs icon from public/favicon.svg */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <img src={logoUrl} alt="clash-rs" className="w-7 h-7 rounded-lg" />
            <span className="font-semibold text-[15px] hidden sm:inline" style={{ color: '#1d1d1f' }}>
              clash-rs
            </span>
          </div>

          {/* Nav */}
          <nav className="flex items-center gap-0.5 flex-1 overflow-x-auto">
            {navItems.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                aria-label={label}
                title={label}
                className={({ isActive }) =>
                  `flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[13px] font-medium whitespace-nowrap transition-all flex-shrink-0 ${
                    isActive
                      ? 'nav-pill-glass text-[#0071e3]'
                      : 'text-[#6e6e73] hover:text-[#1d1d1f] hover:bg-black/[0.05]'
                  }`
                }
              >
                <Icon size={14} />
                <span className="hidden sm:inline">{label}</span>
              </NavLink>
            ))}
          </nav>

          {/* Connection status */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <div className="relative w-2 h-2 flex-shrink-0">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-[#34c759]' : 'bg-[#ff3b30]'}`} />
              {isConnected && (
                <div
                  className="absolute inset-0 w-2 h-2 rounded-full bg-[#34c759] animate-ping"
                  style={{ opacity: 0.6 }}
                />
              )}
            </div>
            <span className="text-[13px] font-medium hidden sm:inline" style={{ color: '#6e6e73' }}>
              {isConnected ? `v${version?.version}` : 'Offline'}
            </span>
          </div>
        </div>
      </header>

      {/* Page content — centred, max-width capped */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-5xl mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
