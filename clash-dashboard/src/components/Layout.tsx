import { NavLink, Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getVersion } from '../lib/api';
import {
  LayoutDashboard, Globe, Activity, Filter, Terminal,
  Settings2, Server, SlidersHorizontal,
} from 'lucide-react';

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/proxies', label: 'Proxies', icon: Globe },
  { to: '/connections', label: 'Connections', icon: Activity },
  { to: '/rules', label: 'Rules', icon: Filter },
  { to: '/logs', label: 'Logs', icon: Terminal },
  { to: '/config', label: 'Config', icon: Settings2 },
  { to: '/dns', label: 'DNS', icon: Server },
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
      {/* Top nav bar — Apple frosted glass */}
      <header
        className="liquid-glass flex-shrink-0 sticky top-0 z-50 flex items-center px-4 gap-3"
        style={{ height: 52 }}
      >
        {/* Logo */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <div
            className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: 'linear-gradient(135deg, #0071e3 0%, #0051a8 100%)' }}
          >
            <span className="text-white font-bold text-sm">C</span>
          </div>
          <span className="font-semibold text-[15px]" style={{ color: '#1d1d1f' }}>
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
            <div
              className={`w-2 h-2 rounded-full ${isConnected ? 'bg-[#34c759]' : 'bg-[#ff3b30]'}`}
            />
            {isConnected && (
              <div
                className="absolute inset-0 w-2 h-2 rounded-full bg-[#34c759] animate-ping"
                style={{ opacity: 0.6 }}
              />
            )}
          </div>
          <span className="text-[13px] font-medium" style={{ color: '#6e6e73' }}>
            {isConnected ? `v${version?.version}` : 'Offline'}
          </span>
        </div>
      </header>

      {/* Page content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
