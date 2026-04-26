import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getConfigs, reloadConfigs } from '../lib/api';
import {
  RefreshCw, ChevronDown, ChevronUp,
  Globe, Cpu, Sliders, Wifi, Settings, FileText, Router, Server, Shield,
} from 'lucide-react';
import type { ClashConfig } from '../lib/api';

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

function BoolBadge({ v }: { v: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full"
      style={
        v
          ? { background: 'rgba(52,199,89,0.12)', color: '#34c759' }
          : { background: 'rgba(0,0,0,0.06)', color: '#8e8e93' }
      }
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: v ? '#34c759' : '#8e8e93' }}
      />
      {String(v)}
    </span>
  );
}

interface ConfigRowProps {
  label: string;
  value: React.ReactNode;
  icon?: React.ReactNode;
  iconBg?: string;
}

function ConfigRow({ label, value, icon, iconBg }: ConfigRowProps) {
  return (
    <div
      className="flex items-center gap-3 px-4"
      style={{
        minHeight: 52,
        borderBottom: '1px solid rgba(0,0,0,0.06)',
      }}
    >
      {icon && iconBg && (
        <IconBadge bg={iconBg}>{icon}</IconBadge>
      )}
      <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{label}</span>
      <span className="text-[15px] font-mono" style={{ color: '#6e6e73' }}>{value}</span>
    </div>
  );
}

function Section({ title, children, footer }: { title: string; children: React.ReactNode; footer?: string }) {
  return (
    <div>
      <div
        className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1"
        style={{ color: '#6e6e73' }}
      >
        {title}
      </div>
      <div
        className="liquid-glass-card rounded-xl overflow-hidden"
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
      >
        {children}
        {/* Remove last border-bottom from last child */}
        <style>{`.last-row-fix > div:last-child { border-bottom: none !important; }`}</style>
      </div>
      {footer && (
        <div className="text-[12px] mt-2 px-1" style={{ color: '#6e6e73' }}>{footer}</div>
      )}
    </div>
  );
}

const iconWhite = { color: 'white' };

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
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Configuration</h1>
        <button
          onClick={() => reloadMutation.mutate()}
          disabled={reloadMutation.isPending}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-[15px] font-medium transition-colors disabled:opacity-50"
          style={{ background: '#0071e3', color: 'white' }}
        >
          <RefreshCw size={14} className={reloadMutation.isPending ? 'animate-spin' : ''} />
          Reload Config
        </button>
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading config…</div>
      ) : cfg ? (
        <div className="space-y-5">
          <Section title="Network">
            <div className="last-row-fix">
              <ConfigRow
                label="HTTP Port" value={cfg.port ?? '—'}
                icon={<Globe size={14} style={iconWhite} />} iconBg="#0071e3"
              />
              <ConfigRow
                label="SOCKS Port" value={cfg['socks-port'] ?? '—'}
                icon={<Router size={14} style={iconWhite} />} iconBg="#af52de"
              />
              <ConfigRow
                label="Mixed Port" value={cfg['mixed-port'] ?? '—'}
                icon={<Sliders size={14} style={iconWhite} />} iconBg="#5ac8fa"
              />
              <ConfigRow
                label="Redir Port" value={cfg['redir-port'] ?? '—'}
                icon={<Server size={14} style={iconWhite} />} iconBg="#8e8e93"
              />
              <ConfigRow
                label="Allow LAN" value={<BoolBadge v={cfg['allow-lan']} />}
                icon={<Wifi size={14} style={iconWhite} />} iconBg="#34c759"
              />
              <ConfigRow
                label="Bind Address" value={cfg['bind-address'] ?? '—'}
                icon={<Shield size={14} style={iconWhite} />} iconBg="#5ac8fa"
              />
            </div>
          </Section>

          <Section title="Mode">
            <div className="last-row-fix">
              <ConfigRow
                label="Mode" value={cfg.mode ?? '—'}
                icon={<Settings size={14} style={iconWhite} />} iconBg="#ff9500"
              />
              <ConfigRow
                label="Log Level" value={cfg['log-level'] ?? '—'}
                icon={<FileText size={14} style={iconWhite} />} iconBg="#8e8e93"
              />
              <ConfigRow
                label="IPv6" value={<BoolBadge v={cfg.ipv6} />}
                icon={<Globe size={14} style={iconWhite} />} iconBg="#0071e3"
              />
            </div>
          </Section>

          {cfg.dns && (
            <Section title="DNS">
              <div className="last-row-fix">
                <ConfigRow
                  label="Enabled" value={<BoolBadge v={cfg.dns.enable} />}
                  icon={<Server size={14} style={iconWhite} />} iconBg="#34c759"
                />
                <ConfigRow
                  label="IPv6" value={<BoolBadge v={cfg.dns.ipv6} />}
                  icon={<Globe size={14} style={iconWhite} />} iconBg="#0071e3"
                />
                <ConfigRow
                  label="Enhanced Mode" value={cfg.dns['enhanced-mode'] ?? '—'}
                  icon={<Cpu size={14} style={iconWhite} />} iconBg="#ff9500"
                />
                <ConfigRow
                  label="Nameservers" value={cfg.dns.nameserver?.length ?? 0}
                  icon={<Router size={14} style={iconWhite} />} iconBg="#5ac8fa"
                />
              </div>
            </Section>
          )}

          {cfg.tun && (
            <Section title="TUN">
              <div className="last-row-fix">
                <ConfigRow
                  label="Enabled" value={<BoolBadge v={cfg.tun.enable} />}
                  icon={<Shield size={14} style={iconWhite} />} iconBg="#af52de"
                />
                <ConfigRow
                  label="Stack" value={cfg.tun.stack ?? '—'}
                  icon={<Sliders size={14} style={iconWhite} />} iconBg="#af52de"
                />
                <ConfigRow
                  label="Auto Route" value={<BoolBadge v={cfg.tun['auto-route']} />}
                  icon={<Router size={14} style={iconWhite} />} iconBg="#af52de"
                />
                <ConfigRow
                  label="Auto Detect Interface" value={<BoolBadge v={cfg.tun['auto-detect-interface']} />}
                  icon={<Wifi size={14} style={iconWhite} />} iconBg="#af52de"
                />
              </div>
            </Section>
          )}

          {/* Raw JSON toggle */}
          <button
            onClick={() => setShowRaw((v) => !v)}
            className="flex items-center gap-2 text-[13px] transition-colors"
            style={{ color: '#6e6e73' }}
          >
            {showRaw ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showRaw ? 'Hide' : 'Show'} Raw JSON
          </button>
          {showRaw && (
            <pre
              className="liquid-glass-card rounded-xl p-5 text-[11px] overflow-auto max-h-96 font-mono"
              style={{
                color: '#6e6e73',
                boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
              }}
            >
              {JSON.stringify(cfg, null, 2)}
            </pre>
          )}
        </div>
      ) : null}
    </div>
  );
}
