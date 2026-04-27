import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getConfigs, patchConfigs, reloadConfigs } from '../lib/api';
import {
  RefreshCw, ChevronDown, ChevronUp,
  Globe, Sliders, Wifi, Settings, FileText, Router, Server, Shield,
} from 'lucide-react';
import type { ClashConfig, PatchableConfig } from '../lib/api';

const MODES = ['rule', 'global', 'direct'] as const;
const LOG_LEVELS = ['trace', 'debug', 'info', 'warning', 'error', 'silent'] as const;
const iconWhite = { color: 'white' };

function IconBadge({ bg, children }: { bg: string; children: React.ReactNode }) {
  return (
    <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: bg }}>
      {children}
    </div>
  );
}

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
  useEffect(() => {
    setLocal(value != null && value !== 0 ? String(value) : '');
  }, [value]);

  return (
    <input
      type="number"
      min="0"
      max="65535"
      value={local}
      onChange={(e) => setLocal(e.target.value)}
      onBlur={() => {
        const n = parseInt(local, 10);
        if (!local || isNaN(n)) { onCommit(null); }
        else { onCommit(n); }
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
      }}
      className="w-24 text-right text-[13px] font-mono px-2 py-1 rounded-lg border outline-none transition-colors"
      style={{ borderColor: 'rgba(0,0,0,0.1)', color: '#1d1d1f', background: 'rgba(0,0,0,0.03)' }}
      placeholder="disabled"
    />
  );
}

function TextInput({ value, onCommit }: { value: string | undefined; onCommit: (v: string) => void }) {
  const [local, setLocal] = useState<string>(value ?? '');
  useEffect(() => { setLocal(value ?? ''); }, [value]);

  return (
    <input
      type="text"
      value={local}
      onChange={(e) => setLocal(e.target.value)}
      onBlur={() => onCommit(local)}
      onKeyDown={(e) => {
        if (e.key === 'Enter') (e.target as HTMLInputElement).blur();
      }}
      className="w-40 text-right text-[13px] font-mono px-2 py-1 rounded-lg border outline-none transition-colors"
      style={{ borderColor: 'rgba(0,0,0,0.1)', color: '#1d1d1f', background: 'rgba(0,0,0,0.03)' }}
    />
  );
}

function SelectInput({ value, options, onChange }: { value: string | undefined; options: readonly string[]; onChange: (v: string) => void }) {
  return (
    <select
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value)}
      className="text-[13px] font-mono px-2 py-1 rounded-lg border outline-none transition-colors capitalize"
      style={{ borderColor: 'rgba(0,0,0,0.1)', color: '#1d1d1f', background: 'rgba(0,0,0,0.03)' }}
    >
      {options.map((o) => (
        <option key={o} value={o} className="capitalize">{o}</option>
      ))}
    </select>
  );
}

interface EditRowProps {
  label: string;
  icon: React.ReactNode;
  iconBg: string;
  children: React.ReactNode;
}

function EditRow({ label, icon, iconBg, children }: EditRowProps) {
  return (
    <div
      className="flex items-center gap-3 px-4"
      style={{ minHeight: 52, borderBottom: '1px solid rgba(0,0,0,0.06)' }}
    >
      <IconBadge bg={iconBg}>{icon}</IconBadge>
      <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{label}</span>
      {children}
    </div>
  );
}

function InfoRow({ label, value, icon, iconBg }: { label: string; value: React.ReactNode; icon: React.ReactNode; iconBg: string }) {
  return (
    <div
      className="flex items-center gap-3 px-4"
      style={{ minHeight: 52, borderBottom: '1px solid rgba(0,0,0,0.06)' }}
    >
      <IconBadge bg={iconBg}>{icon}</IconBadge>
      <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{label}</span>
      <span className="text-[13px] font-mono" style={{ color: '#6e6e73' }}>{value}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1" style={{ color: '#6e6e73' }}>
        {title}
      </div>
      <div
        className="liquid-glass-card rounded-xl overflow-hidden"
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
      >
        <style>{`.cfg-section > div:last-child { border-bottom: none !important; }`}</style>
        <div className="cfg-section">{children}</div>
      </div>
    </div>
  );
}

export function Config() {
  const [showRaw, setShowRaw] = useState(false);
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['configs'], queryFn: getConfigs });

  const patchMutation = useMutation({
    mutationFn: (patch: PatchableConfig) => patchConfigs(patch),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

  const reloadMutation = useMutation({
    mutationFn: (path: string) => reloadConfigs(path),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['configs'] }),
  });

  function patch(fields: PatchableConfig) {
    patchMutation.mutate(fields);
  }

  const cfg = data as ClashConfig | undefined;
  const isPending = patchMutation.isPending;

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Configuration</h1>
        <div className="flex items-center gap-2">
          {isPending && <span className="text-[12px]" style={{ color: '#6e6e73' }}>Saving…</span>}
          <button
            onClick={() => reloadMutation.mutate('')}
            disabled={reloadMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-[13px] font-medium transition-colors disabled:opacity-50"
            style={{ background: '#0071e3', color: 'white' }}
          >
            <RefreshCw size={13} className={reloadMutation.isPending ? 'animate-spin' : ''} />
            Reload
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading config…</div>
      ) : cfg ? (
        <div className="space-y-5">
          <Section title="Mode & Logging">
            <EditRow label="Mode" icon={<Settings size={14} style={iconWhite} />} iconBg="#ff9500">
              <SelectInput
                value={cfg.mode}
                options={MODES}
                onChange={(v) => patch({ mode: v })}
              />
            </EditRow>
            <EditRow label="Log Level" icon={<FileText size={14} style={iconWhite} />} iconBg="#8e8e93">
              <SelectInput
                value={cfg['log-level']}
                options={LOG_LEVELS}
                onChange={(v) => patch({ 'log-level': v })}
              />
            </EditRow>
            <EditRow label="IPv6" icon={<Globe size={14} style={iconWhite} />} iconBg="#0071e3">
              <ToggleSwitch value={cfg.ipv6 ?? false} onChange={(v) => patch({ ipv6: v })} />
            </EditRow>
          </Section>

          <Section title="Network">
            <EditRow label="HTTP Port" icon={<Globe size={14} style={iconWhite} />} iconBg="#0071e3">
              <PortInput value={cfg.port} onCommit={(v) => patch({ port: v ?? 0 })} />
            </EditRow>
            <EditRow label="SOCKS Port" icon={<Router size={14} style={iconWhite} />} iconBg="#af52de">
              <PortInput value={cfg['socks-port']} onCommit={(v) => patch({ 'socks-port': v ?? 0 })} />
            </EditRow>
            <EditRow label="Mixed Port" icon={<Sliders size={14} style={iconWhite} />} iconBg="#5ac8fa">
              <PortInput value={cfg['mixed-port']} onCommit={(v) => patch({ 'mixed-port': v ?? 0 })} />
            </EditRow>
            <EditRow label="Redir Port" icon={<Server size={14} style={iconWhite} />} iconBg="#8e8e93">
              <PortInput value={cfg['redir-port']} onCommit={(v) => patch({ 'redir-port': v ?? 0 })} />
            </EditRow>
            <EditRow label="TProxy Port" icon={<Server size={14} style={iconWhite} />} iconBg="#6e6e73">
              <PortInput value={cfg['tproxy-port']} onCommit={(v) => patch({ 'tproxy-port': v ?? 0 })} />
            </EditRow>
            <EditRow label="Allow LAN" icon={<Wifi size={14} style={iconWhite} />} iconBg="#34c759">
              <ToggleSwitch value={cfg['allow-lan'] ?? false} onChange={(v) => patch({ 'allow-lan': v })} />
            </EditRow>
            <EditRow label="Bind Address" icon={<Shield size={14} style={iconWhite} />} iconBg="#5ac8fa">
              <TextInput value={cfg['bind-address']} onCommit={(v) => patch({ 'bind-address': v })} />
            </EditRow>
          </Section>

          {cfg.listeners && cfg.listeners.length > 0 && (
            <Section title="Active Listeners">
              {cfg.listeners.map((l) => (
                <InfoRow
                  key={l.name}
                  label={l.name}
                  value={
                    <span className="flex items-center gap-2">
                      <span
                        className="text-[11px] font-semibold px-2 py-0.5 rounded-full"
                        style={{ background: 'rgba(0,0,0,0.06)', color: '#6e6e73' }}
                      >
                        {l.type}
                      </span>
                      <span>:{l.port}</span>
                      <span
                        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                        style={{ background: l.active ? '#34c759' : '#8e8e93' }}
                      />
                    </span>
                  }
                  icon={<Server size={14} style={iconWhite} />}
                  iconBg={l.active ? '#34c759' : '#8e8e93'}
                />
              ))}
            </Section>
          )}

          {cfg['lan-ips'] && cfg['lan-ips'].length > 0 && (
            <Section title="LAN IPs">
              {cfg['lan-ips'].map((ip) => (
                <InfoRow
                  key={ip}
                  label={ip}
                  value=""
                  icon={<Globe size={14} style={iconWhite} />}
                  iconBg="#34c759"
                />
              ))}
            </Section>
          )}

          {cfg['dns-listen'] && (
            <Section title="DNS Listeners">
              {Object.entries(cfg['dns-listen']).filter(([, v]) => v).map(([proto, addr]) => (
                <InfoRow
                  key={proto}
                  label={proto.toUpperCase()}
                  value={String(addr)}
                  icon={<Server size={14} style={iconWhite} />}
                  iconBg="#5ac8fa"
                />
              ))}
            </Section>
          )}

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
              style={{ color: '#6e6e73', boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
            >
              {JSON.stringify(cfg, null, 2)}
            </pre>
          )}
        </div>
      ) : null}
    </div>
  );
}
