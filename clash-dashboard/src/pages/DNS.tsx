import { useState } from 'react';
import { queryDNS } from '../lib/api';
import { Search } from 'lucide-react';
import type { DNSQueryResult } from '../lib/api';

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'];

const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 6: 'SOA',
};

function getTypeBadgeStyle(typeNum: number): { background: string; color: string } {
  const type = DNS_TYPE_NAMES[typeNum] ?? '';
  if (type === 'A') return { background: 'rgba(52,199,89,0.1)', color: '#34c759' };
  if (type === 'AAAA') return { background: 'rgba(0,113,227,0.1)', color: '#0071e3' };
  if (type === 'CNAME') return { background: 'rgba(255,149,0,0.1)', color: '#ff9500' };
  return { background: 'rgba(0,0,0,0.06)', color: '#6e6e73' };
}

export function DNS() {
  const [hostname, setHostname] = useState('');
  const [type, setType] = useState('A');
  const [result, setResult] = useState<DNSQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleQuery() {
    const normalizedHostname = hostname.trim();
    if (!normalizedHostname || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await queryDNS(normalizedHostname, type);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>DNS Lookup</h1>

      {/* Query form */}
      <div className="flex gap-2">
        <div className="flex-1 relative">
          <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#8e8e93' }} />
          <input
            type="text"
            placeholder="Hostname (e.g. example.com)"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                void handleQuery();
              }
            }}
            className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[15px] focus:outline-none transition-shadow"
            style={{
              background: 'rgba(255,255,255,0.8)',
              border: '1px solid rgba(0,0,0,0.08)',
              color: '#1d1d1f',
            }}
          />
        </div>
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="px-3 py-2.5 rounded-xl text-[15px] focus:outline-none"
          style={{
            background: 'white',
            border: '1px solid rgba(0,0,0,0.08)',
            color: '#1d1d1f',
          }}
        >
          {DNS_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <button
          onClick={handleQuery}
          disabled={loading || !hostname.trim()}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-[15px] font-medium transition-colors disabled:opacity-50"
          style={{ background: '#0071e3', color: 'white' }}
        >
          {loading ? 'Querying…' : 'Query'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div
          className="rounded-xl p-4"
          style={{ background: 'rgba(255,59,48,0.08)', border: '1px solid rgba(255,59,48,0.2)' }}
        >
          <div className="text-[13px] font-semibold mb-0.5" style={{ color: '#ff3b30' }}>Query failed</div>
          <div className="text-[13px]" style={{ color: '#ff3b30' }}>{error}</div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {result.Answer && result.Answer.length > 0 ? (
            <div>
              <div
                className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1"
                style={{ color: '#6e6e73' }}
              >
                Answer
              </div>
              <div
                className="liquid-glass-card rounded-xl overflow-hidden"
                style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
              >
                {result.Answer.map((a, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 px-4"
                    style={{
                      minHeight: 52,
                      borderBottom: i < result.Answer!.length - 1 ? '1px solid rgba(0,0,0,0.06)' : 'none',
                    }}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-[13px] truncate" style={{ color: '#1d1d1f' }}>{a.name}</div>
                      <div className="font-mono text-[11px]" style={{ color: '#8e8e93' }}>{a.TTL}s TTL</div>
                    </div>
                    <span
                      className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                      style={getTypeBadgeStyle(a.type)}
                    >
                      {DNS_TYPE_NAMES[a.type] ?? String(a.type)}
                    </span>
                    <div className="font-mono text-[13px] text-right" style={{ color: '#34c759' }}>{a.data}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div
              className="rounded-xl p-4 text-[13px]"
              style={{
                background: 'rgba(255,149,0,0.08)',
                border: '1px solid rgba(255,149,0,0.2)',
                color: '#ff9500',
              }}
            >
              No answer records returned.
            </div>
          )}

          <div
            className="rounded-xl p-3 text-[11px] font-mono"
            style={{
              background: 'white',
              border: '1px solid rgba(0,0,0,0.06)',
              color: '#8e8e93',
              boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
            }}
          >
            Status: {result.Status} · TC: {String(result.TC)} · RD: {String(result.RD)} · RA: {String(result.RA)} · AD: {String(result.AD)}
          </div>
        </div>
      )}
    </div>
  );
}
