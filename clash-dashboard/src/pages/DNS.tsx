import { useState } from 'react';
import { queryDNS } from '../lib/api';
import { Search } from 'lucide-react';
import type { DNSQueryResult } from '../lib/api';

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'];

const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 6: 'SOA',
};

function getTypeBadge(typeNum: number): string {
  const type = DNS_TYPE_NAMES[typeNum] ?? '';
  if (type === 'A') return 'bg-emerald-50 text-emerald-700';
  if (type === 'AAAA') return 'bg-blue-50 text-blue-700';
  if (type === 'CNAME') return 'bg-amber-50 text-amber-700';
  if (type === 'MX') return 'bg-slate-100 text-slate-600';
  return 'bg-slate-100 text-slate-600';
}

export function DNS() {
  const [hostname, setHostname] = useState('');
  const [type, setType] = useState('A');
  const [result, setResult] = useState<DNSQueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleQuery() {
    if (!hostname.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await queryDNS(hostname, type);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <h1 className="text-xl font-semibold text-slate-900">DNS Lookup</h1>

      {/* Query form */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Hostname (e.g. example.com)"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleQuery()}
          className="flex-1 px-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
        >
          {DNS_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <button
          onClick={handleQuery}
          disabled={loading || !hostname.trim()}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50"
        >
          <Search size={14} />
          {loading ? 'Querying...' : 'Query'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          <div className="font-medium mb-0.5">Query failed</div>
          <div className="text-red-600">{error}</div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {result.Answer && result.Answer.length > 0 ? (
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="px-5 py-3 border-b border-slate-100 bg-slate-50">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Answer</span>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100">
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">Name</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">TTL</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">Data</th>
                  </tr>
                </thead>
                <tbody>
                  {result.Answer.map((a, i) => (
                    <tr key={i} className="border-b border-slate-50 hover:bg-slate-50">
                      <td className="px-4 py-2.5 text-slate-700 font-mono text-xs">{a.name}</td>
                      <td className="px-4 py-2.5">
                        <span className={`text-xs rounded-full px-2 py-0.5 font-medium ${getTypeBadge(a.type)}`}>
                          {DNS_TYPE_NAMES[a.type] ?? String(a.type)}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-slate-400 font-mono text-xs">{a.TTL}s</td>
                      <td className="px-4 py-2.5 text-emerald-700 font-mono text-xs">{a.data}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-700">
              No answer records returned.
            </div>
          )}

          <div className="bg-white border border-slate-200 rounded-xl p-3 text-xs text-slate-400 font-mono">
            Status: {result.Status} · TC: {String(result.TC)} · RD: {String(result.RD)} · RA: {String(result.RA)} · AD: {String(result.AD)}
          </div>
        </div>
      )}
    </div>
  );
}
