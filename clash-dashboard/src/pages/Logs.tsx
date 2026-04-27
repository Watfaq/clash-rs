import { useState, useEffect, useRef } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { getWsUrl } from '../lib/api';
import type { LogEntry } from '../lib/api';

const LEVELS = ['all', 'debug', 'info', 'warning', 'error'] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_DOT_COLOR: Record<string, string> = {
  error: '#ff3b30',
  warning: '#ff9500',
  info: '#0071e3',
  debug: '#8e8e93',
};

const LEVEL_ACTIVE_STYLE: Record<string, { background: string; color: string }> = {
  all: { background: '#1c1c1e', color: 'white' },
  debug: { background: '#8e8e93', color: 'white' },
  info: { background: '#0071e3', color: 'white' },
  warning: { background: '#ff9500', color: 'white' },
  error: { background: '#ff3b30', color: 'white' },
};

interface TimestampedLog extends LogEntry {
  id: number;
  ts: string;
}

let logId = 0;

function WsStatus({ state }: { state: string }) {
  const isOpen = state === 'OPEN';
  const isConnecting = state === 'CONNECTING';
  return (
    <span className="flex items-center gap-1.5 text-[11px]" style={{ color: '#6e6e73' }}>
      <span
        className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isConnecting ? 'animate-pulse' : ''}`}
        style={{ background: isOpen ? '#34c759' : isConnecting ? '#ff9500' : '#ff3b30' }}
      />
      {isOpen ? 'Connected' : isConnecting ? 'Connecting…' : 'Disconnected'}
    </span>
  );
}

export function Logs() {
  const [level, setLevel] = useState<Level>('all');
  const [logs, setLogs] = useState<TimestampedLog[]>([]);
  const [userPaused, setUserPaused] = useState(false);
  const [hoverPaused, setHoverPaused] = useState(false);
  const effectivePaused = userPaused || hoverPaused;
  const bottomRef = useRef<HTMLDivElement>(null);

  const wsUrl = getWsUrl('/ws/logs');
  const { lastMessage, readyState } = useWebSocket<LogEntry>(wsUrl);

  useEffect(() => {
    if (!lastMessage) return;
    setLogs((prev) => [
      ...prev,
      { ...lastMessage, id: ++logId, ts: new Date().toLocaleTimeString() },
    ].slice(-500));
  }, [lastMessage]);

  useEffect(() => {
    if (!effectivePaused) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, effectivePaused]);

  const filtered = level === 'all' ? logs : logs.filter((l) => l.type === level);

  return (
    <div className="p-6 flex flex-col space-y-4" style={{ height: 'calc(100vh - 52px)' }}>
      {/* Toolbar */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-[#1d1d1f] dark:text-white">Logs</h1>
          <WsStatus state={readyState} />
        </div>
        <div className="flex items-center gap-2">
          {/* Level segmented control */}
          <div className="flex items-center p-1 rounded-full bg-black/[0.06] dark:bg-white/[0.1]">
            {LEVELS.map((l) => {
              const active = level === l;
              return (
                <button
                  key={l}
                  onClick={() => setLevel(l)}
                  className={`px-3 py-1.5 rounded-full text-[12px] font-medium capitalize transition-all ${active ? '' : 'text-[#6e6e73] dark:text-white/60'}`}
                  style={active ? LEVEL_ACTIVE_STYLE[l] : undefined}
                >
                  {l}
                </button>
              );
            })}
          </div>

          <div className="w-px h-4 mx-1 bg-black/[0.08] dark:bg-white/[0.12]" />

          <button
            onClick={() => setUserPaused((p) => !p)}
            className="px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors"
            style={userPaused
              ? { background: 'rgba(255,149,0,0.1)', color: '#ff9500' }
              : { background: 'rgba(0,0,0,0.05)', color: '#6e6e73' }}
          >
            {userPaused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={() => setLogs([])}
            className="px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors"
            style={{ background: 'rgba(0,0,0,0.05)', color: '#6e6e73' }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* Log area — always dark */}
      <div
        className="flex-1 overflow-y-auto rounded-2xl p-4 min-h-0"
        style={{ background: '#1c1c1e' }}
        onMouseEnter={() => setHoverPaused(true)}
        onMouseLeave={() => setHoverPaused(false)}
      >
        {filtered.length === 0 ? (
          <div className="text-[13px] text-center py-10" style={{ color: '#6e6e73' }}>
            {readyState === 'OPEN' ? 'Waiting for logs…' : readyState === 'CONNECTING' ? 'Connecting…' : 'Disconnected — check API settings'}
          </div>
        ) : (
          <div className="space-y-0.5">
            {filtered.map((log) => (
              <div key={log.id} className="flex items-baseline gap-3 py-0.5">
                <span className="font-mono text-[11px] flex-shrink-0 w-20" style={{ color: '#6e6e73' }}>
                  {log.ts}
                </span>
                <div
                  className="w-1.5 h-1.5 rounded-full flex-shrink-0 self-center"
                  style={{ background: LEVEL_DOT_COLOR[log.type] ?? '#8e8e93' }}
                />
                <span className="font-mono text-[13px] break-all" style={{ color: '#f5f5f7' }}>
                  {log.payload}
                </span>
              </div>
            ))}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
