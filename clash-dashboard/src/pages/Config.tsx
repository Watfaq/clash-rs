import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getConfigs, reloadConfigs } from '../lib/api';
import { RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';
import type { ClashConfig } from '../lib/api';

function BoolBadge({ v }: { v: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium rounded-full px-2 py-0.5 ${
      v ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-500'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${v ? 'bg-emerald-500' : 'bg-slate-400'}`} />
      {String(v)}
    </span>
  );
}

function ConfigRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center py-2.5 border-b border-slate-50 last:border-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm text-slate-900 font-mono">{value}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">{title}</h3>
      {children}
    </div>
  );
}

export function Config() {
  const [showRaw, setShowRaw] = useState(false);
  const { data, isLoading, refetch } = useQuery({ queryKey: ['configs'], queryFn: getConfigs });

  const reloadMutation = useMutation({
    mutationFn: () => reloadConfigs(''),
    onSuccess: () => refetch(),
  });

  const cfg = data as ClashConfig | undefined;

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-900">Configuration</h1>
        <button
          onClick={() => reloadMutation.mutate()}
          disabled={reloadMutation.isPending}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={reloadMutation.isPending ? 'animate-spin' : ''} />
          Reload Config
        </button>
      </div>

      {isLoading ? (
        <div className="text-sm text-slate-400">Loading config...</div>
      ) : cfg ? (
        <div className="space-y-4">
          <Section title="Network">
            <ConfigRow label="HTTP Port" value={cfg.port ?? '—'} />
            <ConfigRow label="SOCKS Port" value={cfg['socks-port'] ?? '—'} />
            <ConfigRow label="Mixed Port" value={cfg['mixed-port'] ?? '—'} />
            <ConfigRow label="Redir Port" value={cfg['redir-port'] ?? '—'} />
            <ConfigRow label="Allow LAN" value={<BoolBadge v={cfg['allow-lan']} />} />
            <ConfigRow label="Bind Address" value={cfg['bind-address'] ?? '—'} />
          </Section>

          <Section title="Mode">
            <ConfigRow label="Mode" value={cfg.mode ?? '—'} />
            <ConfigRow label="Log Level" value={cfg['log-level'] ?? '—'} />
            <ConfigRow label="IPv6" value={<BoolBadge v={cfg.ipv6} />} />
          </Section>

          {cfg.dns && (
            <Section title="DNS">
              <ConfigRow label="Enabled" value={<BoolBadge v={cfg.dns.enable} />} />
              <ConfigRow label="IPv6" value={<BoolBadge v={cfg.dns.ipv6} />} />
              <ConfigRow label="Enhanced Mode" value={cfg.dns['enhanced-mode'] ?? '—'} />
              <ConfigRow label="Nameservers" value={cfg.dns.nameserver?.length ?? 0} />
            </Section>
          )}

          {cfg.tun && (
            <Section title="TUN">
              <ConfigRow label="Enabled" value={<BoolBadge v={cfg.tun.enable} />} />
              <ConfigRow label="Stack" value={cfg.tun.stack ?? '—'} />
              <ConfigRow label="Auto Route" value={<BoolBadge v={cfg.tun['auto-route']} />} />
              <ConfigRow label="Auto Detect Interface" value={<BoolBadge v={cfg.tun['auto-detect-interface']} />} />
            </Section>
          )}

          {/* Raw JSON */}
          <button
            onClick={() => setShowRaw((v) => !v)}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-700 transition-colors"
          >
            {showRaw ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showRaw ? 'Hide' : 'Show'} Raw JSON
          </button>
          {showRaw && (
            <pre className="bg-white border border-slate-200 rounded-2xl p-5 text-xs text-slate-600 overflow-auto max-h-96 font-mono shadow-sm">
              {JSON.stringify(cfg, null, 2)}
            </pre>
          )}
        </div>
      ) : null}
    </div>
  );
}
