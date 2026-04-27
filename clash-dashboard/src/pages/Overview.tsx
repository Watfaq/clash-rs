import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getMemory, getConfigs, updateConfigs, getWsUrl } from '../lib/api';
import { useTraffic } from '../hooks/useTraffic';
import { TrafficChart } from '../components/TrafficChart';
import {
  ArrowUp, ArrowDown, Activity, HardDrive,
  Globe, Router, Sliders, Server, Wifi, FileText,
} from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import type { ConnectionsData } from '../lib/api';

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

interface InfoRowProps {
  icon: React.ReactNode;
  iconBg: string;
  label: string;
  value: React.ReactNode;
}

function InfoRow({ icon, iconBg, label, value }: InfoRowProps) {
  return (
    <div className="flex items-center gap-3 px-4" style={{ minHeight: 44 }}>
      <IconBadge bg={iconBg}>{icon}</IconBadge>
      <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{label}</span>
      <span className="text-[13px] font-mono" style={{ color: '#6e6e73' }}>{value}</span>
    </div>
  );
}

function InfoSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1" style={{ color: '#6e6e73' }}>
        {title}
      </div>
      <div className="liquid-glass-card rounded-xl overflow-hidden">
        <div className="[&>*:not(:last-child)]:border-b [&>*:not(:last-child)]:[border-color:rgba(0,0,0,0.06)]">
          {children}
        </div>
      </div>
    </div>
  );
}

function PortValue({ port }: { port: number | undefined }) {
  if (!port || port === 0) return <span style={{ color: '#c7c7cc' }}>disabled</span>;
  return <span>:{port}</span>;
}

function BoolPill({ value }: { value: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2 py-0.5 rounded-full"
      style={{
        background: value ? 'rgba(52,199,89,0.12)' : 'rgba(0,0,0,0.06)',
        color: value ? '#34c759' : '#6e6e73',
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: value ? '#34c759' : '#8e8e93' }} />
      {value ? 'On' : 'Off'}
    </span>
  );
}

export function Overview() {
  const queryClient = useQueryClient();
  const { history, current } = useTraffic();
  const { data: memory } = useQuery({ queryKey: ['memory'], queryFn: getMemory, refetchInterval: 5000 });
  const { data: configs } = useQuery({ queryKey: ['configs'], queryFn: getConfigs, refetchInterval: 10000 });

  const modeMutation = useMutation({
    mutationFn: (mode: string) => updateConfigs({ mode }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

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

  const currentMode = configs?.mode?.toLowerCase() ?? '';

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Overview</h1>

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
      <div
        className="rounded-2xl p-5"
        style={{ background: 'linear-gradient(135deg, #1e2a3a 0%, #0f1923 100%)' }}
      >
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
        <TrafficChart
          timestamps={history.timestamps}
          up={history.up}
          down={history.down}
        />
      </div>

      {/* Mode switcher — SwiftUI segmented control */}
      {configs && (
        <div className="liquid-glass-card rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <div
                className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-1"
                style={{ color: '#6e6e73' }}
              >
                Proxy Mode
              </div>
              <div className="text-[13px]" style={{ color: '#6e6e73' }}>
                Controls how traffic is routed
              </div>
            </div>
            <div
              className="flex items-center p-1 rounded-full"
              style={{ background: 'rgba(0,0,0,0.06)' }}
            >
              {MODES.map((m) => {
                const active = currentMode === m;
                return (
                  <button
                    key={m}
                    onClick={() => modeMutation.mutate(m)}
                    className={`px-5 py-1.5 rounded-full text-[13px] font-medium capitalize transition-all ${
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
          </div>
        </div>
      )}

      {/* Network & System info — pulled from config */}
      {configs && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <InfoSection title="Network">
            <InfoRow
              icon={<Globe size={14} color="white" />}
              iconBg="#0071e3"
              label="HTTP Port"
              value={<PortValue port={configs.port} />}
            />
            <InfoRow
              icon={<Router size={14} color="white" />}
              iconBg="#af52de"
              label="SOCKS Port"
              value={<PortValue port={configs['socks-port']} />}
            />
            <InfoRow
              icon={<Sliders size={14} color="white" />}
              iconBg="#5ac8fa"
              label="Mixed Port"
              value={<PortValue port={configs['mixed-port']} />}
            />
            <InfoRow
              icon={<Server size={14} color="white" />}
              iconBg="#8e8e93"
              label="Redir Port"
              value={<PortValue port={configs['redir-port']} />}
            />
            <InfoRow
              icon={<Wifi size={14} color="white" />}
              iconBg="#34c759"
              label="Allow LAN"
              value={<BoolPill value={configs['allow-lan'] ?? false} />}
            />
            {configs['bind-address'] && (
              <InfoRow
                icon={<Server size={14} color="white" />}
                iconBg="#5ac8fa"
                label="Bind Address"
                value={configs['bind-address']}
              />
            )}
          </InfoSection>

          <InfoSection title="System">
            <InfoRow
              icon={<FileText size={14} color="white" />}
              iconBg="#8e8e93"
              label="Log Level"
              value={configs['log-level'] ?? '—'}
            />
            <InfoRow
              icon={<Globe size={14} color="white" />}
              iconBg="#0071e3"
              label="IPv6"
              value={<BoolPill value={configs.ipv6 ?? false} />}
            />
            <InfoRow
              icon={<Wifi size={14} color="white" />}
              iconBg="#34c759"
              label="Allow LAN"
              value={<BoolPill value={configs['allow-lan'] ?? false} />}
            />
            {configs['bind-address'] && (
              <InfoRow
                icon={<Server size={14} color="white" />}
                iconBg="#5ac8fa"
                label="Bind Address"
                value={configs['bind-address']}
              />
            )}
          </InfoSection>
        </div>
      )}
    </div>
  );
}
