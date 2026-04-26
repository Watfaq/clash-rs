import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getMemory, getConfigs, updateConfigs, getWsUrl } from '../lib/api';
import { useTraffic } from '../hooks/useTraffic';
import { TrafficChart } from '../components/TrafficChart';
import { ArrowUp, ArrowDown, Activity, HardDrive } from 'lucide-react';
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

interface StatCardProps {
  label: string;
  value: string;
  subtext?: string;
  icon: React.ReactNode;
  iconBg: string;
}

function StatCard({ label, value, subtext, icon, iconBg }: StatCardProps) {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5">
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${iconBg}`}>
          {icon}
        </div>
      </div>
      <div className="text-2xl font-bold text-slate-900 font-mono">{value}</div>
      {subtext && <div className="text-xs text-slate-400 mt-1">{subtext}</div>}
    </div>
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
      <h1 className="text-xl font-semibold text-slate-900">Overview</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Upload Speed"
          value={formatSpeed(current.up)}
          icon={<ArrowUp size={16} className="text-blue-600" />}
          iconBg="bg-blue-50"
        />
        <StatCard
          label="Download Speed"
          value={formatSpeed(current.down)}
          icon={<ArrowDown size={16} className="text-emerald-600" />}
          iconBg="bg-emerald-50"
        />
        <StatCard
          label="Connections"
          value={String(connCount)}
          subtext={`↑ ${formatBytesTotal(uploadTotal)}  ↓ ${formatBytesTotal(downloadTotal)}`}
          icon={<Activity size={16} className="text-amber-600" />}
          iconBg="bg-amber-50"
        />
        <StatCard
          label="Memory"
          value={memValue}
          subtext={memSubtext}
          icon={<HardDrive size={16} className="text-slate-500" />}
          iconBg="bg-slate-100"
        />
      </div>

      {/* Traffic chart */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-slate-700">Network Traffic (60s)</span>
          <div className="flex items-center gap-5 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-600" />
              <span className="text-slate-500">Upload</span>
              <span className="font-mono font-medium text-blue-600">{formatSpeed(current.up)}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-slate-500">Download</span>
              <span className="font-mono font-medium text-emerald-600">{formatSpeed(current.down)}</span>
            </span>
          </div>
        </div>
        <TrafficChart
          timestamps={history.timestamps}
          up={history.up}
          down={history.down}
        />
      </div>

      {/* Mode switcher */}
      {configs && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Proxy Mode</div>
              <div className="text-sm text-slate-600">Controls how traffic is routed</div>
            </div>
            <div className="flex items-center gap-1 bg-slate-100 rounded-xl p-1">
              {MODES.map((m) => {
                const active = currentMode === m;
                return (
                  <button
                    key={m}
                    onClick={() => modeMutation.mutate(m)}
                    className={`px-4 py-1.5 rounded-lg text-sm font-medium capitalize transition-all ${
                      active
                        ? 'bg-white shadow-sm text-slate-900'
                        : 'text-slate-500 hover:text-slate-700'
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
    </div>
  );
}
