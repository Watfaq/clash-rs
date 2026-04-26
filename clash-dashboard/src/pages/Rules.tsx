import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getRules } from '../lib/api';
import { Search } from 'lucide-react';

function getRuleTypeBadge(type: string): string {
  if (type.startsWith('DOMAIN')) return 'bg-blue-50 text-blue-700';
  if (type.startsWith('IP-CIDR') || type.startsWith('IP')) return 'bg-emerald-50 text-emerald-700';
  if (type === 'GEOIP') return 'bg-amber-50 text-amber-700';
  if (type === 'MATCH' || type === 'FINAL') return 'bg-slate-100 text-slate-600';
  if (type === 'RULE-SET') return 'bg-blue-50 text-blue-700';
  if (type === 'PROCESS-NAME' || type === 'PROCESS-PATH') return 'bg-slate-100 text-slate-600';
  return 'bg-slate-100 text-slate-500';
}

export function Rules() {
  const [search, setSearch] = useState('');
  const { data, isLoading } = useQuery({ queryKey: ['rules'], queryFn: getRules });

  const rules = data?.rules ?? [];
  const filtered = rules.filter(
    (r) =>
      r.type.toLowerCase().includes(search.toLowerCase()) ||
      r.payload.toLowerCase().includes(search.toLowerCase()) ||
      r.proxy.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-900">Rules</h1>
        <span className="text-sm text-slate-400">{filtered.length} / {rules.length}</span>
      </div>

      <div className="relative">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          placeholder="Filter rules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
        />
      </div>

      {isLoading ? (
        <div className="text-sm text-slate-400">Loading rules...</div>
      ) : (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100">
                <th className="text-right px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-12">#</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Payload</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Proxy</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule, i) => (
                <tr
                  key={i}
                  className="border-b border-slate-50 hover:bg-slate-50 transition-colors"
                >
                  <td className="px-4 py-2.5 text-xs text-slate-300 text-right font-mono">{i + 1}</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-xs rounded-full px-2 py-0.5 font-medium ${getRuleTypeBadge(rule.type)}`}>
                      {rule.type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-slate-700 max-w-xs truncate font-mono text-xs">{rule.payload || '—'}</td>
                  <td className="px-4 py-2.5 text-blue-600 font-medium text-xs">{rule.proxy}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-10 text-center text-sm text-slate-400">
                    No rules match your search
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
