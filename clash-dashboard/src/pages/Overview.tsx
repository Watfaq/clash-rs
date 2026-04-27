import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getMemory, getConfigs, patchConfigs, reloadConfigs, getWsUrl } from '../lib/api';
import { useTraffic } from '../hooks/useTraffic';
import { TrafficChart } from '../components/TrafficChart';
import { ProxyGroups } from '../components/ProxyGroups';
import {
  ArrowUp, ArrowDown, Activity, HardDrive,
  Globe, Router, Sliders, Server, Wifi, FileText, Shield,
  RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import type { ConnectionsData, PatchableConfig, ClashConfig } from '../lib/api';

function formatSpeed(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB/s`;
}

function formatBytesTotal(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatMB(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

const MODES = ['direct', 'rule', 'global'] as const;

interface VividStatCardProps {
  label: string;
  value: string;
  subtext?: string;
  icon: React.ReactNode;
  gradient: string;
  shadow: string;
}

function VividStatCard({ label, value, subtext, icon, gradient, shadow }: VividStatCardProps) {
  return (
    <div
      className="vivid-shimmer rounded-2xl p-5 flex flex-col gap-3"
      style={{
        background: gradient,
        boxShadow: `${shadow}, inset 0 1.5px 0 rgba(255,255,255,0.25)`,
        filter: 'url(#liquid-glass-distort)',
      }}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-white/80">{label}</span>
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ background: 'rgba(255,255,255,0.2)' }}
        >
          {icon}
        </div>
      </div>
      <div>
        <div className="text-3xl font-bold tabular-nums text-white">{value}</div>
        {subtext && <div className="text-xs text-white/70 mt-1">{subtext}</div>}
      </div>
    </div>
  );
}

const MODE_COLORS: Record<string, string> = {
  direct: 'bg-emerald-500 text-white shadow-sm',
  rule: 'bg-[#0071e3] text-white shadow-sm',
  global: 'bg-violet-500 text-white shadow-sm',
};

function IconBadge({ bg, children }: { bg: string; children: React.ReactNode }) {
  return (
    <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: bg }}>
      {children}
    </div>
  );
}


const LOG_LEVELS = ['trace', 'debug', 'info', 'warning', 'error', 'silent'] as const;

function ToggleSwitch({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className="w-10 h-6 rounded-full transition-colors flex-shrink-0 relative"
      style={{ background: value ? '#34c759' : 'rgba(0,0,0,0.15)' }}
    >
      <span
        className="absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-all"
        style={{ left: value ? '50%' : '2px' }}
      />
    </button>
  );
}

function PortInput({ value, onCommit }: { value: number | undefined; onCommit: (v: number | null) => void }) {
  const [local, setLocal] = useState<string>(value != null && value !== 0 ? String(value) : '');
  useEffect(() => { setLocal(value != null && value !== 0 ? String(value) : ''); }, [value]);
  return (
    <input
      type="number" min="0" max="65535" value={local}
      onChange={(e) => setLocal(e.target.value)}
      onBlur={() => { const n = parseInt(local, 10); onCommit(!local || isNaN(n) ? null : n); }}
      onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur(); }}
      className="form-input w-24 text-right text-[13px] font-mono rounded-lg border-0 bg-black/[0.04] focus:ring-2 focus:ring-[#0071e3]/30 focus:bg-white py-1 px-2 transition-all"
      placeholder="disabled"
    />
  );
}

function TextInput({ value, onCommit }: { value: string | undefined; onCommit: (v: string) => void }) {
  const [local, setLocal] = useState<string>(value ?? '');
  useEffect(() => { setLocal(value ?? ''); }, [value]);
  return (
    <input
      type="text" value={local}
      onChange={(e) => setLocal(e.target.value)}
      onBlur={() => onCommit(local)}
      onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur(); }}
      className="form-input w-40 text-right text-[13px] font-mono rounded-lg border-0 bg-black/[0.04] focus:ring-2 focus:ring-[#0071e3]/30 focus:bg-white py-1 px-2 transition-all"
    />
  );
}

function SelectInput({ value, options, onChange }: { value: string | undefined; options: readonly string[]; onChange: (v: string) => void }) {
  return (
    <select
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value)}
      className="form-select text-[13px] font-mono rounded-lg border-0 bg-black/[0.04] focus:ring-2 focus:ring-[#0071e3]/30 py-1 px-2 capitalize transition-all"
    >
      {options.map((o) => <option key={o} value={o} className="capitalize">{o}</option>)}
    </select>
  );
}

function EditRow({ label, icon, iconBg, children }: { label: string; icon: React.ReactNode; iconBg: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-4" style={{ minHeight: 52, borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
      <IconBadge bg={iconBg}>{icon}</IconBadge>
      <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{label}</span>
      {children}
    </div>
  );
}

function EditSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1" style={{ color: '#6e6e73' }}>{title}</div>
      <div className="liquid-glass-card rounded-xl overflow-hidden">
        <div className="[&>*:last-child]:[border-bottom:none]">{children}</div>
      </div>
    </div>
  );
}

export function Overview() {
  const queryClient = useQueryClient();
  const { history, current } = useTraffic();
  const { data: memory } = useQuery({ queryKey: ['memory'], queryFn: getMemory, refetchInterval: 5000 });
  const { data: configs, isLoading: configsLoading } = useQuery({ queryKey: ['configs'], queryFn: getConfigs, refetchInterval: 10000 });

  const modeMutation = useMutation({
    mutationFn: (mode: string) => patchConfigs({ mode }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

  const patchMutation = useMutation({
    mutationFn: (patch: PatchableConfig) => patchConfigs(patch),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

  const reloadMutation = useMutation({
    mutationFn: () => reloadConfigs(''),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

  function patch(fields: PatchableConfig) { patchMutation.mutate(fields); }

  const wsUrl = getWsUrl('/ws/connections');
  const { lastMessage: connData } = useWebSocket<ConnectionsData>(wsUrl);
  const connCount = connData?.connections?.length ?? 0;
  const uploadTotal = connData?.uploadTotal ?? 0;
  const downloadTotal = connData?.downloadTotal ?? 0;

  const memValue = memory ? formatMB(memory.inuse) : '—';
  const memSubtext = memory
    ? memory.oslimit > 0
      ? `Limit: ${formatMB(memory.oslimit)}`
      : 'OS limit: N/A'
    : undefined;

  const cfg = configs as ClashConfig | undefined;
  const currentMode = cfg?.mode?.toLowerCase() ?? '';

  const [showRaw, setShowRaw] = useState(false);
  const [proxyExpanded, setProxyExpanded] = useState(true);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Overview</h1>
        <div className="flex items-center gap-2">
          {patchMutation.isPending && (
            <span className="text-[12px]" style={{ color: '#6e6e73' }}>Saving…</span>
          )}
          <button
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-colors disabled:opacity-50"
            style={{ background: '#0071e3', color: 'white' }}
          >
            <RefreshCw size={13} className={reloadMutation.isPending ? 'animate-spin' : ''} />
            Reload Config
          </button>
        </div>
      </div>

      {/* Vivid stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <VividStatCard
          label="Upload Speed"
          value={formatSpeed(current.up)}
          icon={<ArrowUp size={18} className="text-white" />}
          gradient="linear-gradient(135deg, #0071e3 0%, #0051a8 100%)"
          shadow="0 8px 24px rgba(0,113,227,0.35)"
        />
        <VividStatCard
          label="Download Speed"
          value={formatSpeed(current.down)}
          icon={<ArrowDown size={18} className="text-white" />}
          gradient="linear-gradient(135deg, #34c759 0%, #00a550 100%)"
          shadow="0 8px 24px rgba(52,199,89,0.35)"
        />
        <VividStatCard
          label="Connections"
          value={String(connCount)}
          subtext={`↑ ${formatBytesTotal(uploadTotal)}  ↓ ${formatBytesTotal(downloadTotal)}`}
          icon={<Activity size={18} className="text-white" />}
          gradient="linear-gradient(135deg, #ff9500 0%, #ff6b00 100%)"
          shadow="0 8px 24px rgba(255,149,0,0.35)"
        />
        <VividStatCard
          label="Memory"
          value={memValue}
          subtext={memSubtext}
          icon={<HardDrive size={18} className="text-white" />}
          gradient="linear-gradient(135deg, #af52de 0%, #7b2cbf 100%)"
          shadow="0 8px 24px rgba(175,82,222,0.35)"
        />
      </div>

      {/* Traffic chart — always dark */}
      <div className="rounded-2xl p-5" style={{ background: 'linear-gradient(135deg, #1e2a3a 0%, #0f1923 100%)' }}>
        <div className="flex items-center justify-between mb-4">
          <span className="text-[15px] font-semibold text-white">Network Traffic</span>
          <div className="flex items-center gap-5 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#60a5fa]" />
              <span className="text-white/70">Upload</span>
              <span className="font-mono font-medium text-[#60a5fa]">{formatSpeed(current.up)}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#34d399]" />
              <span className="text-white/70">Download</span>
              <span className="font-mono font-medium text-[#34d399]">{formatSpeed(current.down)}</span>
            </span>
          </div>
        </div>
        <TrafficChart timestamps={history.timestamps} up={history.up} down={history.down} />
      </div>

      {/* Mode switcher + expandable proxy groups */}
      {cfg && (
        <div className="liquid-glass-card rounded-2xl overflow-hidden">
          {/* Header row */}
          <div className="p-5 flex items-center justify-between">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-1" style={{ color: '#6e6e73' }}>
                Proxy Mode
              </div>
              <div className="text-[13px]" style={{ color: '#6e6e73' }}>Controls how traffic is routed</div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center p-1 rounded-full" style={{ background: 'rgba(0,0,0,0.06)' }}>
                {MODES.map((m) => {
                  const active = currentMode === m;
                  return (
                    <button
                      key={m}
                      onClick={() => modeMutation.mutate(m)}
                      disabled={modeMutation.isPending}
                      className={`px-5 py-1.5 rounded-full text-[13px] font-medium capitalize transition-all disabled:opacity-50 ${
                        active
                          ? (MODE_COLORS[m] ?? 'bg-white text-[#1d1d1f] shadow-sm')
                          : 'text-[#6e6e73] hover:text-[#1d1d1f]'
                      }`}
                    >
                      {m.charAt(0).toUpperCase() + m.slice(1)}
                    </button>
                  );
                })}
              </div>
              {currentMode !== 'direct' && (
                <button
                  onClick={() => setProxyExpanded((v) => !v)}
                  className="p-1.5 rounded-lg transition-colors"
                  style={{ background: 'rgba(0,0,0,0.05)', color: '#6e6e73' }}
                >
                  {proxyExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </button>
              )}
            </div>
          </div>
          {/* Expandable proxy groups */}
          {proxyExpanded && currentMode !== 'direct' && (
            <div className="border-t px-5 pb-5 pt-4 space-y-3" style={{ borderColor: 'rgba(0,0,0,0.06)' }}>
              <ProxyGroups mode={currentMode} />
            </div>
          )}
        </div>
      )}

      {/* Config form — editable */}
      {configsLoading && <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading config…</div>}
      {cfg && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Ports */}
            <EditSection title="Ports">
              <EditRow label="HTTP" icon={<Globe size={14} color="white" />} iconBg="#0071e3">
                <PortInput value={cfg.port} onCommit={(v) => patch({ port: v ?? 0 })} />
              </EditRow>
              <EditRow label="SOCKS" icon={<Router size={14} color="white" />} iconBg="#af52de">
                <PortInput value={cfg['socks-port']} onCommit={(v) => patch({ 'socks-port': v ?? 0 })} />
              </EditRow>
              <EditRow label="Mixed" icon={<Sliders size={14} color="white" />} iconBg="#5ac8fa">
                <PortInput value={cfg['mixed-port']} onCommit={(v) => patch({ 'mixed-port': v ?? 0 })} />
              </EditRow>
              <EditRow label="Redir" icon={<Server size={14} color="white" />} iconBg="#8e8e93">
                <PortInput value={cfg['redir-port']} onCommit={(v) => patch({ 'redir-port': v ?? 0 })} />
              </EditRow>
              <EditRow label="TProxy" icon={<Server size={14} color="white" />} iconBg="#6e6e73">
                <PortInput value={cfg['tproxy-port']} onCommit={(v) => patch({ 'tproxy-port': v ?? 0 })} />
              </EditRow>
            </EditSection>

            {/* Access */}
            <EditSection title="Access">
              <EditRow label="Allow LAN" icon={<Wifi size={14} color="white" />} iconBg="#34c759">
                <ToggleSwitch value={cfg['allow-lan'] ?? false} onChange={(v) => patch({ 'allow-lan': v })} />
              </EditRow>
              <EditRow label="Bind Address" icon={<Shield size={14} color="white" />} iconBg="#5ac8fa">
                <TextInput value={cfg['bind-address']} onCommit={(v) => patch({ 'bind-address': v })} />
              </EditRow>
              <EditRow label="IPv6" icon={<Globe size={14} color="white" />} iconBg="#0071e3">
                <ToggleSwitch value={cfg.ipv6 ?? false} onChange={(v) => patch({ ipv6: v })} />
              </EditRow>
            </EditSection>

            {/* Logging */}
            <EditSection title="Logging">
              <EditRow label="Log Level" icon={<FileText size={14} color="white" />} iconBg="#8e8e93">
                <SelectInput value={cfg['log-level']} options={LOG_LEVELS} onChange={(v) => patch({ 'log-level': v })} />
              </EditRow>
            </EditSection>
          </div>

          {/* Active Listeners */}
          {cfg.listeners && cfg.listeners.length > 0 && (
            <EditSection title="Active Listeners">
              {[...cfg.listeners]
                .sort((a, b) => {
                  if (a.active !== b.active) return a.active ? -1 : 1;
                  return a.name.localeCompare(b.name);
                })
                .map((l) => (
                <div key={l.name} className="flex items-center gap-3 px-4" style={{ minHeight: 52, borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
                  <IconBadge bg={l.active ? '#34c759' : '#8e8e93'}>
                    <Server size={14} color="white" />
                  </IconBadge>
                  <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{l.name}</span>
                  <span className="flex items-center gap-2">
                    <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(0,0,0,0.06)', color: '#6e6e73' }}>{l.type}</span>
                    <span className="font-mono text-[13px]">:{l.port}</span>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: l.active ? '#34c759' : '#8e8e93' }} />
                  </span>
                </div>
              ))}
            </EditSection>
          )}

          {/* Raw JSON */}
          <button
            onClick={() => setShowRaw((v) => !v)}
            className="flex items-center gap-2 text-[13px] transition-colors"
            style={{ color: '#6e6e73' }}
          >
            {showRaw ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showRaw ? 'Hide' : 'Show'} Raw JSON
          </button>
          {showRaw && (
            <pre className="liquid-glass-card rounded-xl p-5 text-[11px] overflow-auto max-h-96 font-mono" style={{ color: '#6e6e73' }}>
              {JSON.stringify(cfg, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
