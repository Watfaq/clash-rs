import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { closeAllConnections, closeConnection, getWsUrl } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { X, Trash2, Search } from 'lucide-react';
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
      conn.chains?.join(' ').toLowerCase().includes(q)
    );
  });

  const closeAllMutation = useMutation({ mutationFn: closeAllConnections });
  const closeOneMutation = useMutation({ mutationFn: closeConnection });

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-slate-900">Connections</h1>
          <span className="bg-slate-100 text-slate-600 text-xs rounded-full px-2 py-0.5 font-medium">
            {connections.length} active
          </span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex gap-3 text-xs text-slate-500 font-mono">
            <span>↑ {formatBytes(uploadTotal)}</span>
            <span>↓ {formatBytes(downloadTotal)}</span>
          </div>
          <button
            onClick={() => closeAllMutation.mutate()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-red-50 text-red-600 hover:bg-red-100 transition-colors font-medium"
          >
            <Trash2 size={13} />
            Close All
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          placeholder="Filter by host, rule, chain..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
        />
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden overflow-x-auto">
        <table className="table-fixed w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-52">Host</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-24">Network</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-32">Rule</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-36">Chain</th>
              <th className="text-right px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-20">Upload</th>
              <th className="text-right px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-20">Download</th>
              <th className="text-right px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider w-24">Duration</th>
              <th className="px-4 py-3 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="text-center py-10 text-sm text-slate-400">
                  No active connections
                </td>
              </tr>
            ) : (
              filtered.map((conn: Connection) => (
                <tr
                  key={conn.id}
                  className="border-b border-slate-50 hover:bg-slate-50 transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="text-sm text-slate-800 truncate font-medium">
                      {conn.metadata.host || conn.metadata.destinationIP}
                      {conn.metadata.destinationPort && `:${conn.metadata.destinationPort}`}
                    </div>
                    {conn.metadata.process && (
                      <div className="text-xs text-slate-400 truncate">{conn.metadata.process}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-500 font-mono whitespace-nowrap">
                    {conn.metadata.network}/{conn.metadata.type}
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-600 truncate">
                    {conn.rule}{conn.rulePayload && ` (${conn.rulePayload})`}
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-500 truncate">
                    {conn.chains?.join(' → ')}
                  </td>
                  <td className="px-4 py-3 text-right text-sm font-mono text-blue-600">{formatBytes(conn.upload)}</td>
                  <td className="px-4 py-3 text-right text-sm font-mono text-emerald-600">{formatBytes(conn.download)}</td>
                  <td className="px-4 py-3 text-right text-sm font-mono text-slate-500">{formatDuration(conn.start)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => closeOneMutation.mutate(conn.id)}
                      className="p-1 rounded hover:bg-slate-100 text-slate-300 hover:text-red-500 transition-colors"
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
