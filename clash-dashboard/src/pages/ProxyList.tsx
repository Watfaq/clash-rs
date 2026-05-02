import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getProxies, getProxyProviders, getProxyDelay, getProviderProxyDelay,
  updateProxyProvider,
} from '../lib/api';
import { Activity, RefreshCw } from 'lucide-react';
import type { Proxy, ProxyProvider } from '../lib/api';

const TEST_URL = 'http://www.gstatic.com/generate_204';
const TEST_TIMEOUT = 5000;

const GROUP_TYPES = ['Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay'];

function getLastDelay(history: Proxy['history']): number | undefined {
  if (!history || history.length === 0) return undefined;
  return history[history.length - 1]?.delay;
}

function getLatencyColor(delay: number | undefined): string {
  if (!delay || delay === 0) return '#8e8e93';
  if (delay < 200) return '#34c759';
  if (delay < 500) return '#ff9500';
  return '#ff3b30';
}

function getProxyTypeBadgeStyle(type: string): { background: string; color: string } {
  const t = type.toLowerCase();
  if (t === 'ss' || t === 'shadowsocks') return { background: 'rgba(175,82,222,0.1)', color: '#af52de' };
  if (t === 'vmess') return { background: 'rgba(0,113,227,0.1)', color: '#0071e3' };
  if (t === 'vless') return { background: 'rgba(50,173,230,0.1)', color: '#32ade6' };
  if (t === 'trojan') return { background: 'rgba(255,149,0,0.1)', color: '#ff9500' };
  if (t === 'socks5') return { background: 'rgba(52,199,89,0.1)', color: '#34c759' };
  if (t === 'http') return { background: 'rgba(255,69,58,0.1)', color: '#ff453a' };
  if (t === 'direct') return { background: 'rgba(52,199,89,0.1)', color: '#34c759' };
  if (t === 'reject') return { background: 'rgba(255,59,48,0.1)', color: '#ff3b30' };
  if (t === 'dns') return { background: 'rgba(100,100,100,0.1)', color: '#636366' };
  if (t === 'wireguard') return { background: 'rgba(88,86,214,0.1)', color: '#5856d6' };
  if (t === 'hysteria' || t === 'hysteria2') return { background: 'rgba(255,149,0,0.12)', color: '#ff9500' };
  if (t === 'tuic') return { background: 'rgba(0,149,255,0.1)', color: '#0095ff' };
  return { background: 'rgba(0,0,0,0.06)', color: '#6e6e73' };
}

interface ProxyCardProps {
  proxy: Proxy;
  latency?: number;
  onTest: () => void;
  testing?: boolean;
}

function ProxyCard({ proxy, latency, onTest, testing }: ProxyCardProps) {
  const delay = latency ?? getLastDelay(proxy.history);
  const latencyColor = getLatencyColor(delay);
  const typeStyle = getProxyTypeBadgeStyle(proxy.type);

  return (
    <div
      className="flex items-center gap-3 px-4 py-3 rounded-xl border"
      style={{ background: 'rgba(255,255,255,0.6)', borderColor: 'rgba(0,0,0,0.06)' }}
    >
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-medium truncate" style={{ color: '#1d1d1f' }}>
          {proxy.name}
        </div>
        <div className="flex items-center gap-1.5 mt-0.5">
          <span
            className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
            style={typeStyle}
          >
            {proxy.type}
          </span>
          <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: latencyColor }} />
          <span className="text-[11px] font-mono" style={{ color: latencyColor }}>
            {delay === undefined ? '—' : delay === 0 ? 'Timeout' : `${delay}ms`}
          </span>
        </div>
      </div>
      <button
        onClick={onTest}
        disabled={testing}
        title="Test latency"
        aria-label={`Test latency for ${proxy.name}`}
        className="flex-shrink-0 p-1.5 rounded-full disabled:opacity-40 transition-colors"
        style={{ background: 'rgba(52,199,89,0.1)', color: '#34c759' }}
      >
        <Activity size={12} className={testing ? 'animate-pulse' : ''} />
      </button>
    </div>
  );
}

interface ProviderSectionProps {
  provider: ProxyProvider;
  latencyMap: Record<string, number>;
  testingProxies: Set<string>;
  testingProviders: Set<string>;
  updatingProviders: Set<string>;
  onTestProxy: (providerName: string, proxy: Proxy) => void;
  onTestAll: (provider: ProxyProvider) => void;
  onUpdate: (provider: ProxyProvider) => void;
}

function ProviderSection({
  provider, latencyMap, testingProxies, testingProviders, updatingProviders,
  onTestProxy, onTestAll, onUpdate,
}: ProviderSectionProps) {
  const isTesting = testingProviders.has(provider.name);
  const isUpdating = updatingProviders.has(provider.name);
  const proxies = provider.proxies ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <h2 className="text-[17px] font-semibold" style={{ color: '#1d1d1f' }}>{provider.name}</h2>
          <span
            className="text-[11px] font-semibold px-2 py-0.5 rounded-full"
            style={{ background: 'rgba(0,0,0,0.06)', color: '#6e6e73' }}
          >
            {provider.vehicleType}
          </span>
          <span className="text-[11px]" style={{ color: '#8e8e93' }}>
            {proxies.length} {proxies.length === 1 ? 'proxy' : 'proxies'}
          </span>
          {provider.updatedAt && (
            <span className="text-[11px] hidden sm:inline" style={{ color: '#8e8e93' }}>
              · Updated {new Date(provider.updatedAt).toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onTestAll(provider)}
            disabled={isTesting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
            style={{ background: 'rgba(52,199,89,0.1)', color: '#34c759' }}
          >
            <Activity size={12} className={isTesting ? 'animate-pulse' : ''} />
            {isTesting ? 'Testing…' : 'Test All'}
          </button>
          <button
            onClick={() => onUpdate(provider)}
            disabled={isUpdating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
            style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
          >
            <RefreshCw size={12} className={isUpdating ? 'animate-spin' : ''} />
            {isUpdating ? 'Updating…' : 'Update'}
          </button>
        </div>
      </div>

      {proxies.length === 0 ? (
        <div className="text-[13px] italic" style={{ color: '#8e8e93' }}>No proxies in this provider.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
          {proxies.map((proxy) => (
            <ProxyCard
              key={proxy.name}
              proxy={proxy}
              latency={latencyMap[`${provider.name}::${proxy.name}`]}
              testing={testingProxies.has(`${provider.name}::${proxy.name}`)}
              onTest={() => onTestProxy(provider.name, proxy)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function ProxyList() {
  const queryClient = useQueryClient();
  const [latencyMap, setLatencyMap] = useState<Record<string, number>>({});
  const [testingProxies, setTestingProxies] = useState<Set<string>>(new Set());
  const [testingProviders, setTestingProviders] = useState<Set<string>>(new Set());
  const [updatingProviders, setUpdatingProviders] = useState<Set<string>>(new Set());

  const { data: proxiesData, isLoading: proxiesLoading, isError: proxiesError } = useQuery({
    queryKey: ['proxies'],
    queryFn: getProxies,
    refetchInterval: 30000,
  });

  const { data: providersData, isLoading: providersLoading, isError: providersError } = useQuery({
    queryKey: ['providers'],
    queryFn: getProxyProviders,
    refetchInterval: 60000,
  });

  const allProxies = proxiesData?.proxies ?? {};
  const staticProxies = Object.values(allProxies).filter(
    (p) => !GROUP_TYPES.includes(p.type)
  );

  const providers = Object.values(providersData?.providers ?? {})
    .filter((p) => p.name !== 'default' && p.vehicleType !== 'Compatible')
    .sort((a, b) => a.name.localeCompare(b.name));

  // Provider proxy names to exclude from static list (avoid duplicates)
  const providerProxyNames = new Set<string>(
    providers.flatMap((p) => (p.proxies ?? []).map((px) => px.name))
  );
  const configProxies = staticProxies.filter((p) => !providerProxyNames.has(p.name));

  async function testStaticProxy(proxy: Proxy) {
    const key = `static::${proxy.name}`;
    setTestingProxies((s) => new Set(s).add(key));
    try {
      const res = await getProxyDelay(proxy.name, TEST_URL, TEST_TIMEOUT);
      setLatencyMap((prev) => ({ ...prev, [key]: res.delay }));
    } catch {
      setLatencyMap((prev) => ({ ...prev, [key]: 0 }));
    } finally {
      setTestingProxies((s) => { const next = new Set(s); next.delete(key); return next; });
    }
  }

  async function testProviderProxy(providerName: string, proxy: Proxy) {
    const key = `${providerName}::${proxy.name}`;
    setTestingProxies((s) => new Set(s).add(key));
    try {
      const res = await getProviderProxyDelay(providerName, proxy.name, TEST_URL, TEST_TIMEOUT);
      setLatencyMap((prev) => ({ ...prev, [key]: res.delay }));
    } catch {
      setLatencyMap((prev) => ({ ...prev, [key]: 0 }));
    } finally {
      setTestingProxies((s) => { const next = new Set(s); next.delete(key); return next; });
    }
  }

  async function testAllInProvider(provider: ProxyProvider) {
    setTestingProviders((s) => new Set(s).add(provider.name));
    try {
      const proxies = provider.proxies ?? [];
      const BATCH = 5;
      for (let i = 0; i < proxies.length; i += BATCH) {
        await Promise.allSettled(
          proxies.slice(i, i + BATCH).map((proxy) => testProviderProxy(provider.name, proxy))
        );
      }
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setTestingProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  async function updateProvider(provider: ProxyProvider) {
    setUpdatingProviders((s) => new Set(s).add(provider.name));
    try {
      await updateProxyProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setUpdatingProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  const isLoading = proxiesLoading || providersLoading;
  const isError = proxiesError || providersError;

  return (
    <div className="p-6 space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Proxies</h1>
        <span className="text-[13px]" style={{ color: '#8e8e93' }}>
          {configProxies.length} static · {providers.length} provider{providers.length !== 1 ? 's' : ''}
        </span>
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading proxies…</div>
      ) : isError ? (
        <div className="text-[15px]" style={{ color: '#ff3b30' }}>Failed to load proxies. Check your API connection.</div>
      ) : (
        <>
          {/* Config Proxies */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <h2 className="text-[17px] font-semibold" style={{ color: '#1d1d1f' }}>Config Proxies</h2>
              <span className="text-[11px]" style={{ color: '#8e8e93' }}>
                {configProxies.length} {configProxies.length === 1 ? 'proxy' : 'proxies'}
              </span>
            </div>

            {configProxies.length === 0 ? (
              <div
                className="liquid-glass-card rounded-2xl p-8 flex flex-col items-center gap-2 text-center"
              >
                <div className="text-3xl">🔌</div>
                <div className="text-[15px] font-semibold" style={{ color: '#1d1d1f' }}>No Static Proxies</div>
                <div className="text-[13px]" style={{ color: '#6e6e73' }}>
                  Define proxies directly in your config file.
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                {configProxies.map((proxy) => (
                  <ProxyCard
                    key={proxy.name}
                    proxy={proxy}
                    latency={latencyMap[`static::${proxy.name}`]}
                    testing={testingProxies.has(`static::${proxy.name}`)}
                    onTest={() => testStaticProxy(proxy)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Provider sections */}
          {providers.length === 0 ? (
            <div
              className="liquid-glass-card rounded-2xl p-8 flex flex-col items-center gap-2 text-center"
            >
              <div className="text-3xl">📦</div>
              <div className="text-[15px] font-semibold" style={{ color: '#1d1d1f' }}>No Proxy Providers</div>
              <div className="text-[13px]" style={{ color: '#6e6e73' }}>
                Add proxy providers to your config to see them here.
              </div>
            </div>
          ) : (
            <>
              <div className="w-full h-px" style={{ background: 'rgba(0,0,0,0.06)' }} />
              <div className="space-y-8">
                {providers.map((provider) => (
                  <ProviderSection
                    key={provider.name}
                    provider={provider}
                    latencyMap={latencyMap}
                    testingProxies={testingProxies}
                    testingProviders={testingProviders}
                    updatingProviders={updatingProviders}
                    onTestProxy={testProviderProxy}
                    onTestAll={testAllInProvider}
                    onUpdate={updateProvider}
                  />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
