import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { closeAllConnections, closeConnection, getWsUrl } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { X, Trash2, Search, ArrowUp, ArrowDown, Activity } from 'lucide-react';
import type { ConnectionsData, Connection } from '../lib/api';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`;
  return `${(bytes / 1024 / 1024).toFixed(2)}M`;
}

function formatDuration(start: string): string {
  const diff = Math.floor((Date.now() - new Date(start).getTime()) / 1000);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
}

function IconBadge({ bg, children }: { bg: string; children: React.ReactNode }) {
  return (
    <div
      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
      style={{ background: bg }}
    >
      {children}
    </div>
  );
}

export function Connections() {
  const [search, setSearch] = useState('');
  const wsUrl = getWsUrl('/ws/connections');
  const { lastMessage } = useWebSocket<ConnectionsData>(wsUrl);

  const connections = lastMessage?.connections ?? [];
  const downloadTotal = lastMessage?.downloadTotal ?? 0;
  const uploadTotal = lastMessage?.uploadTotal ?? 0;

  const filtered = connections.filter((conn: Connection) => {
    const q = search.toLowerCase();
    return (
      !q ||
      (conn.metadata.host || '').toLowerCase().includes(q) ||
      conn.rule.toLowerCase().includes(q) ||
      conn.chains?.join(' ').toLowerCase().includes(q) ||
      (conn.metadata.asn || '').toLowerCase().includes(q)
    );
  });

  const closeAllMutation = useMutation({ mutationFn: closeAllConnections });
  const closeOneMutation = useMutation({ mutationFn: closeConnection });

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Connections</h1>
        <button
          onClick={() => closeAllMutation.mutate()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors"
          style={{ background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }}
        >
          <Trash2 size={13} />
          Close All
        </button>
      </div>

      {/* Summary InsetGroup card */}
      <div
        className="text-[11px] font-semibold uppercase tracking-[0.06em] px-1"
        style={{ color: '#6e6e73' }}
      >
        Summary
      </div>
      <div className="liquid-glass-card rounded-xl overflow-hidden" style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        {[
          {
            icon: <Activity size={14} className="text-white" />,
            bg: '#0071e3',
            label: 'Active Connections',
            value: String(connections.length),
          },
          {
            icon: <ArrowUp size={14} className="text-white" />,
            bg: '#34c759',
            label: 'Total Upload',
            value: formatBytes(uploadTotal),
          },
          {
            icon: <ArrowDown size={14} className="text-white" />,
            bg: '#ff9500',
            label: 'Total Download',
            value: formatBytes(downloadTotal),
          },
        ].map((row, idx, arr) => (
          <div
            key={row.label}
            className="flex items-center gap-3 px-4"
            style={{
              minHeight: 52,
              borderBottom: idx < arr.length - 1 ? '1px solid rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <IconBadge bg={row.bg}>{row.icon}</IconBadge>
            <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{row.label}</span>
            <span className="text-[15px] font-mono" style={{ color: '#6e6e73' }}>{row.value}</span>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#8e8e93' }} />
        <input
          type="text"
          aria-label="Filter connections by host, rule, or chain"
          placeholder="Filter by host, rule, chain…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[15px] focus:outline-none transition-shadow"
          style={{
            background: 'rgba(255,255,255,0.8)',
            backdropFilter: 'blur(8px)',
            border: '1px solid rgba(0,0,0,0.08)',
            color: '#1d1d1f',
          }}
        />
      </div>

      {/* Connections list */}
      <div className="liquid-glass-card rounded-xl overflow-hidden overflow-x-auto" style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        <table className="table-fixed w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-52" style={{ color: '#6e6e73' }}>Host</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-32" style={{ color: '#6e6e73' }}>ASN</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-24" style={{ color: '#6e6e73' }}>Network</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-32" style={{ color: '#6e6e73' }}>Rule</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-36" style={{ color: '#6e6e73' }}>Chain</th>
              <th className="text-right px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-20" style={{ color: '#6e6e73' }}>Upload</th>
              <th className="text-right px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-20" style={{ color: '#6e6e73' }}>Download</th>
              <th className="text-right px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-24" style={{ color: '#6e6e73' }}>Duration</th>
              <th className="px-4 py-3 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-10 text-[15px]" style={{ color: '#8e8e93' }}>
                  No active connections
                </td>
              </tr>
            ) : (
              filtered.map((conn: Connection) => (
                <tr
                  key={conn.id}
                  className="group transition-colors"
                  style={{ borderBottom: '1px solid rgba(0,0,0,0.04)' }}
                >
                  <td className="px-4 py-3">
                    <div className="text-[15px] font-medium truncate" style={{ color: '#1d1d1f' }}>
                      {conn.metadata.host || conn.metadata.destinationIP}
                      {conn.metadata.destinationPort && `:${conn.metadata.destinationPort}`}
                    </div>
                    {conn.metadata.process && (
                      <div className="text-[11px] truncate" style={{ color: '#8e8e93' }}>{conn.metadata.process}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[12px] truncate" style={{ color: '#0071e3' }}>
                    {conn.metadata.asn || '—'}
                  </td>
                  <td className="px-4 py-3 font-mono whitespace-nowrap text-[13px]" style={{ color: '#8e8e93' }}>
                    {conn.metadata.network}/{conn.metadata.type}
                  </td>
                  <td className="px-4 py-3 text-[13px] truncate" style={{ color: '#6e6e73' }}>
                    {conn.rule}{conn.rulePayload && ` (${conn.rulePayload})`}
                  </td>
                  <td className="px-4 py-3 text-[13px] truncate" style={{ color: '#8e8e93' }}>
                    {conn.chains?.join(' → ')}
                  </td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#0071e3' }}>{formatBytes(conn.upload)}</td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#34c759' }}>{formatBytes(conn.download)}</td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#8e8e93' }}>{formatDuration(conn.start)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => closeOneMutation.mutate(conn.id)}
                      aria-label={`Close connection to ${conn.metadata.host || conn.id}`}
                      className="p-1 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
                      style={{ color: '#ff3b30' }}
                    >
                      <X size={13} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
