import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getRules } from '../lib/api';
import { Search } from 'lucide-react';

function getRuleTypeBadgeStyle(type: string): { background: string; color: string } {
  switch (type) {
    case 'Domain':           return { background: 'rgba(0,113,227,0.12)',   color: '#0071e3' };
    case 'DomainSuffix':     return { background: 'rgba(0,149,255,0.12)',   color: '#0095ff' };
    case 'DomainKeyword':    return { background: 'rgba(10,132,255,0.12)',  color: '#0a84ff' };
    case 'DomainRegex':      return { background: 'rgba(50,173,230,0.12)',  color: '#32ade6' };
    case 'IPCIDR':           return { background: 'rgba(52,199,89,0.12)',   color: '#34c759' };
    case 'IPCIDR6':          return { background: 'rgba(48,209,88,0.12)',   color: '#30d158' };
    case 'IpAsn':            return { background: 'rgba(37,162,68,0.12)',   color: '#25a244' };
    case 'GeoIP':            return { background: 'rgba(255,149,0,0.12)',   color: '#ff9500' };
    case 'GeoSite':          return { background: 'rgba(244,160,21,0.12)',  color: '#f4a015' };
    case 'RuleSet':          return { background: 'rgba(175,82,222,0.12)',  color: '#af52de' };
    case 'ProcessName':      return { background: 'rgba(255,69,58,0.12)',   color: '#ff453a' };
    case 'ProcessPath':      return { background: 'rgba(255,99,82,0.12)',   color: '#ff6352' };
    case 'Port':             return { background: 'rgba(162,132,94,0.12)',  color: '#a2845e' };
    case 'Network':          return { background: 'rgba(100,100,100,0.12)', color: '#636366' };
    case 'AND':              return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'OR':               return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'NOT':              return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'Match':
    case 'Final':            return { background: 'rgba(142,142,147,0.12)', color: '#636366' };
    default:                 return { background: 'rgba(0,0,0,0.06)',        color: '#8e8e93' };
  }
}

export function Rules() {
  const [search, setSearch] = useState('');
  const { data, isLoading, isError } = useQuery({ queryKey: ['rules'], queryFn: getRules });

  const rules = data?.rules ?? [];
  const filtered = rules.filter(
    (r) =>
      r.type.toLowerCase().includes(search.toLowerCase()) ||
      (r.payload ?? '').toLowerCase().includes(search.toLowerCase()) ||
      r.proxy.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Rules</h1>
        <span className="text-[13px]" style={{ color: '#8e8e93' }}>{filtered.length} / {rules.length}</span>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#8e8e93' }} />
        <input
          type="text"
          placeholder="Filter rules…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[15px] focus:outline-none transition-shadow"
          style={{
            background: 'rgba(255,255,255,0.8)',
            border: '1px solid rgba(0,0,0,0.08)',
            color: '#1d1d1f',
          }}
        />
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading rules…</div>
      ) : isError ? (
        <div className="liquid-glass-card rounded-xl p-6 text-center text-[15px]" style={{ color: '#ff3b30' }}>
          Failed to load rules. Check your connection and API secret.
        </div>
      ) : (
        <div
          className="liquid-glass-card rounded-xl overflow-hidden"
          style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
        >
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-[15px]" style={{ color: '#8e8e93' }}>
              No rules match your search
            </div>
          ) : (
            filtered.map((rule, i) => {
              const typeStyle = getRuleTypeBadgeStyle(rule.type);
              return (
              <div
                key={i}
                className="flex items-center gap-3 px-4"
                style={{
                  minHeight: 48,
                  borderBottom: i < filtered.length - 1 ? '1px solid rgba(0,0,0,0.05)' : 'none',
                }}
              >
                <span
                  className="font-mono text-[11px] flex-shrink-0 w-8 text-right"
                  style={{ color: '#c7c7cc' }}
                >
                  {i + 1}
                </span>
                <span
                  className="text-[11px] font-semibold tracking-wider px-2 py-0.5 rounded-full flex-shrink-0"
                  style={{ background: typeStyle.color + '22', color: typeStyle.color }}
                >
                  {rule.type}
                </span>
                <span
                  className="flex-1 font-mono text-[13px] truncate"
                  style={{ color: '#1d1d1f' }}
                >
                  {rule.payload || '—'}
                </span>
                <span
                  className="text-[13px] font-medium flex-shrink-0"
                  style={{ color: '#1d1d1f' }}
                >
                  {rule.proxy}
                </span>
              </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
