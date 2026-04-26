import { NavLink, Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getVersion } from '../lib/api';

const navItems = [
  { to: '/', label: 'Overview', end: true },
  { to: '/proxies', label: 'Proxies' },
  { to: '/connections', label: 'Connections' },
  { to: '/rules', label: 'Rules' },
  { to: '/logs', label: 'Logs' },
  { to: '/config', label: 'Config' },
  { to: '/dns', label: 'DNS' },
  { to: '/settings', label: 'Settings' },
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
      {/* Top nav bar */}
      <header className="h-14 bg-white border-b border-slate-200 shadow-sm sticky top-0 z-10 flex items-center px-6 gap-6 flex-shrink-0">
        {/* Logo */}
        <div className="flex items-center gap-2.5 flex-shrink-0">
          <div className="bg-blue-600 rounded-xl w-8 h-8 flex items-center justify-center">
            <span className="text-white font-bold text-sm">C</span>
          </div>
          <span className="font-semibold text-slate-900 text-sm">clash-rs</span>
        </div>

        {/* Divider */}
        <div className="w-px h-5 bg-slate-200" />

        {/* Nav */}
        <nav className="flex items-center gap-1 flex-1 overflow-x-auto">
          {navItems.map(({ to, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `px-3 py-2 text-sm rounded-lg whitespace-nowrap transition-colors flex-shrink-0 ${
                  isActive
                    ? 'text-blue-600 font-medium bg-blue-50'
                    : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Connection status badge */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-red-500'}`} />
          <span className="text-xs font-medium text-slate-600">
            {isConnected ? `v${version?.version}` : 'Offline'}
          </span>
        </div>
      </header>

      {/* Page content */}
      <main className="flex-1 overflow-auto bg-slate-50">
        <Outlet />
      </main>
    </div>
  );
}
