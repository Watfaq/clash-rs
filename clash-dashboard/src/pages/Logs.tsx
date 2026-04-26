import { useState, useEffect, useRef } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { getWsUrl } from '../lib/api';
import type { LogEntry } from '../lib/api';

const LEVELS = ['all', 'debug', 'info', 'warning', 'error'] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_PILL: Record<string, string> = {
  debug: 'bg-slate-100 text-slate-600',
  info: 'bg-blue-50 text-blue-700',
  warning: 'bg-amber-50 text-amber-700',
  error: 'bg-red-50 text-red-700',
};

const LEVEL_ACTIVE: Record<string, string> = {
  all: 'bg-slate-800 text-white',
  debug: 'bg-slate-800 text-white',
  info: 'bg-blue-600 text-white',
  warning: 'bg-amber-500 text-white',
  error: 'bg-red-500 text-white',
};

interface TimestampedLog extends LogEntry {
  id: number;
  ts: string;
}

let logId = 0;

export function Logs() {
  const [level, setLevel] = useState<Level>('all');
  const [logs, setLogs] = useState<TimestampedLog[]>([]);
  const [paused, setPaused] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  const wsUrl = getWsUrl('/ws/logs');
  const { lastMessage } = useWebSocket<LogEntry>(wsUrl);

  useEffect(() => {
    if (!lastMessage) return;
    setLogs((prev) => {
      const next = [
        ...prev,
        { ...lastMessage, id: ++logId, ts: new Date().toLocaleTimeString() },
      ].slice(-500);
      return next;
    });
  }, [lastMessage]);

  useEffect(() => {
    if (!paused) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, paused]);

  const filtered = level === 'all' ? logs : logs.filter((l) => l.type === level);

  return (
    <div className="p-6 flex flex-col h-full space-y-4" style={{ height: 'calc(100vh - 56px)' }}>
      {/* Toolbar */}
      <div className="flex items-center justify-between flex-shrink-0">
        <h1 className="text-xl font-semibold text-slate-900">Logs</h1>
        <div className="flex items-center gap-2">
          {LEVELS.map((l) => (
            <button
              key={l}
              onClick={() => setLevel(l)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                level === l
                  ? LEVEL_ACTIVE[l] ?? 'bg-slate-800 text-white'
                  : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'
              }`}
            >
              {l}
            </button>
          ))}
          <div className="w-px h-4 bg-slate-200 mx-1" />
          <button
            onClick={() => setPaused((p) => !p)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              paused
                ? 'bg-amber-50 text-amber-700 hover:bg-amber-100'
                : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'
            }`}
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={() => setLogs([])}
            className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-500 hover:text-red-600 hover:bg-red-50 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Log area */}
      <div
        className="flex-1 overflow-y-auto bg-white rounded-2xl border border-slate-200 shadow-sm p-4 min-h-0"
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
      >
        {filtered.length === 0 ? (
          <div className="text-sm text-slate-400 text-center py-10">Waiting for logs...</div>
        ) : (
          <div className="space-y-0.5">
            {filtered.map((log) => (
              <div key={log.id} className="flex items-baseline gap-3 py-0.5">
                <span className="font-mono text-xs text-slate-300 flex-shrink-0 w-20">{log.ts}</span>
                <span className={`text-xs rounded-full px-2 py-0.5 flex-shrink-0 font-medium ${LEVEL_PILL[log.type] ?? 'bg-slate-100 text-slate-600'}`}>
                  {log.type.toUpperCase()}
                </span>
                <span className="font-mono text-xs text-slate-600 break-all">{log.payload}</span>
              </div>
            ))}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
