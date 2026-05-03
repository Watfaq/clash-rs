import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getProxies, getProxyProviders, getProxyDelay, getProviderProxyDelay,
  updateProxyProvider, healthcheckProvider,
} from '../lib/api';
import { Activity, RefreshCw, Zap } from 'lucide-react';
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
  return { background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' };
}

interface ProxyCardProps {
  proxy: Proxy;
  onTest: () => void;
  testing?: boolean;
}

function ProxyCard({ proxy, onTest, testing }: ProxyCardProps) {
  const delay = getLastDelay(proxy.history);
  const latencyColor = getLatencyColor(delay);
  const typeStyle = getProxyTypeBadgeStyle(proxy.type);

  return (
    <div
      className="flex items-center gap-3 px-4 py-3 rounded-xl border"
      style={{ background: 'var(--color-proxy-card-bg)', borderColor: 'var(--color-separator)' }}
    >
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-medium truncate" style={{ color: 'var(--color-text-primary)' }}>
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
  testingProxies: Set<string>;
  testingProviders: Set<string>;
  updatingProviders: Set<string>;
  onTestProxy: (providerName: string, proxy: Proxy) => void;
  onTestAll: (provider: ProxyProvider) => void;
  onUpdate: (provider: ProxyProvider) => void;
}

function ProviderSection({
  provider, testingProxies, testingProviders, updatingProviders,
  onTestProxy, onTestAll, onUpdate,
}: ProviderSectionProps) {
  const isTesting = testingProviders.has(provider.name);
  const isUpdating = updatingProviders.has(provider.name);
  const proxies = provider.proxies ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <h2 className="text-[17px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>{provider.name}</h2>
          <span
            className="text-[11px] font-semibold px-2 py-0.5 rounded-full"
            style={{ background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' }}
          >
            {provider.vehicleType}
          </span>
          <span className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
            {proxies.length} {proxies.length === 1 ? 'proxy' : 'proxies'}
          </span>
          {provider.updatedAt && (
            <span className="text-[11px] hidden sm:inline" style={{ color: 'var(--color-text-tertiary)' }}>
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
        <div className="text-[13px] italic" style={{ color: 'var(--color-text-tertiary)' }}>No proxies in this provider.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
          {proxies.map((proxy) => (
            <ProxyCard
              key={proxy.name}
              proxy={proxy}
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
  const [testingProxies, setTestingProxies] = useState<Set<string>>(new Set());
  const [testingProviders, setTestingProviders] = useState<Set<string>>(new Set());
  const [updatingProviders, setUpdatingProviders] = useState<Set<string>>(new Set());
  const [testingAll, setTestingAll] = useState(false);

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
      await getProxyDelay(proxy.name, TEST_URL, TEST_TIMEOUT);
      await queryClient.refetchQueries({ queryKey: ['proxies'] });
    } catch {
      // ignore, server will have recorded the timeout
    } finally {
      setTestingProxies((s) => { const next = new Set(s); next.delete(key); return next; });
    }
  }

  async function testProviderProxy(providerName: string, proxy: Proxy) {
    const key = `${providerName}::${proxy.name}`;
    setTestingProxies((s) => new Set(s).add(key));
    try {
      await getProviderProxyDelay(providerName, proxy.name, TEST_URL, TEST_TIMEOUT);
      await queryClient.refetchQueries({ queryKey: ['providers'] });
    } catch {
      // ignore
    } finally {
      setTestingProxies((s) => { const next = new Set(s); next.delete(key); return next; });
    }
  }

  async function testAllInProvider(provider: ProxyProvider) {
    setTestingProviders((s) => new Set(s).add(provider.name));
    try {
      await healthcheckProvider(provider.name);
      await queryClient.refetchQueries({ queryKey: ['providers'] });
    } catch {
      // ignore
    } finally {
      setTestingProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  async function testAllProxies() {
    setTestingAll(true);
    try {
      const proxyKeys = configProxies.map((p) => `static::${p.name}`);
      proxyKeys.forEach((k) => setTestingProxies((s) => new Set(s).add(k)));
      await Promise.all([
        Promise.allSettled(providers.map((p) => healthcheckProvider(p.name))),
        Promise.allSettled(configProxies.map((proxy) =>
          getProxyDelay(proxy.name, TEST_URL, TEST_TIMEOUT).catch(() => {})
        )),
      ]);
      proxyKeys.forEach((k) => setTestingProxies((s) => { const next = new Set(s); next.delete(k); return next; }));
      await Promise.all([
        queryClient.refetchQueries({ queryKey: ['proxies'] }),
        queryClient.refetchQueries({ queryKey: ['providers'] }),
      ]);
    } finally {
      setTestingAll(false);
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
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>Proxies</h1>
        <div className="flex items-center gap-3">
          <span className="text-[13px]" style={{ color: 'var(--color-text-tertiary)' }}>
            {configProxies.length} static · {providers.length} provider{providers.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={testAllProxies}
            disabled={testingAll}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-opacity"
            style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}
          >
            <Zap size={12} className={testingAll ? 'animate-pulse' : ''} />
            {testingAll ? 'Testing all…' : 'Test All'}
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: 'var(--color-text-secondary)' }}>Loading proxies…</div>
      ) : isError ? (
        <div className="text-[15px]" style={{ color: '#ff3b30' }}>Failed to load proxies. Check your API connection.</div>
      ) : (
        <>
          {/* Proxies */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <h2 className="text-[17px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Proxies</h2>
              <span className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                {configProxies.length} {configProxies.length === 1 ? 'proxy' : 'proxies'}
              </span>
            </div>

            {configProxies.length === 0 ? (
              <div
                className="liquid-glass-card rounded-2xl p-8 flex flex-col items-center gap-2 text-center"
              >
                <div className="text-3xl">🔌</div>
                <div className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>No Static Proxies</div>
                <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                  Define proxies directly in your config file.
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                {configProxies.map((proxy) => (
                  <ProxyCard
                    key={proxy.name}
                    proxy={proxy}
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
              <div className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>No Proxy Providers</div>
              <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                Add proxy providers to your config to see them here.
              </div>
            </div>
          ) : (
            <>
              <div className="w-full h-px" style={{ background: 'var(--color-separator)' }} />
              <div className="flex items-center gap-2">
                <h2 className="text-[17px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Proxy Providers</h2>
                <span className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                  {providers.length} {providers.length === 1 ? 'provider' : 'providers'}
                </span>
              </div>
              <div className="space-y-8">
                {providers.map((provider) => (
                  <ProviderSection
                    key={provider.name}
                    provider={provider}
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
