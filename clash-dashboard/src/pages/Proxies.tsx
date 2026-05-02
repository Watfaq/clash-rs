import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getProxies, selectProxy, getGroupDelay, getProxyProviders,
  updateProxyProvider, healthcheckProvider, getConfigs,
} from '../lib/api';
import { RefreshCw, ChevronDown, ChevronUp, Check, Activity } from 'lucide-react';
import type { Proxy, ProxyProvider } from '../lib/api';

const TEST_URL = 'http://www.gstatic.com/generate_204';
const TEST_TIMEOUT = 5000;

const GROUP_TYPES = ['Selector', 'URLTest', 'Fallback', 'LoadBalance'];

function getLatencyColor(delay: number | undefined): string {
  if (!delay || delay === 0) return '#8e8e93';
  if (delay < 200) return '#34c759';
  if (delay < 500) return '#ff9500';
  return '#ff3b30';
}

function getGroupAccentColor(type: string): string {
  if (type === 'Selector') return '#0071e3';
  if (type === 'URLTest') return '#34c759';
  if (type === 'Fallback') return '#ff9500';
  if (type === 'LoadBalance') return '#af52de';
  return '#8e8e93';
}

function getTypeBadgeStyle(type: string): { background: string; color: string } {
  if (type === 'Selector') return { background: 'rgba(0,113,227,0.1)', color: '#0071e3' };
  if (type === 'URLTest') return { background: 'rgba(52,199,89,0.1)', color: '#34c759' };
  if (type === 'Fallback') return { background: 'rgba(255,149,0,0.1)', color: '#ff9500' };
  if (type === 'LoadBalance') return { background: 'rgba(175,82,222,0.1)', color: '#af52de' };
  return { background: 'rgba(0,0,0,0.06)', color: '#6e6e73' };
}

function getLastDelay(history: Proxy['history']): number | undefined {
  if (!history || history.length === 0) return undefined;
  return history[history.length - 1]?.delay;
}

export function Proxies() {
  const queryClient = useQueryClient();
  const [testingGroups, setTestingGroups] = useState<Set<string>>(new Set());
  const [testingProviders, setTestingProviders] = useState<Set<string>>(new Set());
  const [updatingProviders, setUpdatingProviders] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set());

  const { data, isLoading } = useQuery({
    queryKey: ['proxies'],
    queryFn: getProxies,
    refetchInterval: 30000,
  });

  const { data: configsData } = useQuery({
    queryKey: ['configs'],
    queryFn: getConfigs,
    refetchInterval: 10000,
  });

  const mode = configsData?.mode?.toLowerCase() ?? 'rule';

  const { data: providersData } = useQuery({
    queryKey: ['providers'],
    queryFn: getProxyProviders,
    refetchInterval: 60000,
  });

  const selectMutation = useMutation({
    mutationFn: ({ group, proxy }: { group: string; proxy: string }) =>
      selectProxy(group, proxy),
    onMutate: async ({ group, proxy }) => {
      await queryClient.cancelQueries({ queryKey: ['proxies'] });
      const previous = queryClient.getQueryData<{ proxies: Record<string, Proxy> }>(['proxies']);
      queryClient.setQueryData<{ proxies: Record<string, Proxy> }>(['proxies'], (old) => {
        if (!old) return old;
        return {
          ...old,
          proxies: {
            ...old.proxies,
            [group]: { ...old.proxies[group], now: proxy },
          },
        };
      });
      return { previous };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.previous) queryClient.setQueryData(['proxies'], ctx.previous);
      queryClient.invalidateQueries({ queryKey: ['proxies'] });
    },
  });

  const proxies = data?.proxies ?? {};

  // Use GLOBAL.all as sort index — same approach as ChocLite
  const globalGroup = proxies['GLOBAL'];
  const sortIndex: string[] = globalGroup?.all ?? [];
  function sortByConfig<T extends { name: string }>(items: T[]): T[] {
    return [...items].sort((a, b) => {
      const ia = sortIndex.indexOf(a.name);
      const ib = sortIndex.indexOf(b.name);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.name.localeCompare(b.name);
    });
  }

  const allGroups = sortByConfig(
    Object.values(proxies).filter((p) => GROUP_TYPES.includes(p.type))
  );

  // Filter groups by mode
  const groups = mode === 'global'
    ? allGroups.filter((g) => g.name.toUpperCase() === 'GLOBAL')
    : mode === 'rule'
      ? allGroups.filter((g) => g.name.toUpperCase() !== 'GLOBAL')
      : []; // direct — no groups to show

  const providers = sortByConfig(
    Object.values(providersData?.providers ?? {})
      .filter((p) => p.name !== 'default' && p.vehicleType !== 'Compatible')
  );

  function toggleExpanded(name: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  function toggleProviderExpanded(name: string) {
    setExpandedProviders((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function testGroupDelay(group: Proxy) {
    if (!group.all) return;
    setTestingGroups((s) => new Set(s).add(group.name));
    setExpanded((prev) => new Set(prev).add(group.name));
    try {
      await getGroupDelay(group.name, TEST_URL, TEST_TIMEOUT);
      await queryClient.invalidateQueries({ queryKey: ['proxies'] });
    } catch {
      // leave existing latency values unchanged on error
    } finally {
      setTestingGroups((s) => {
        const next = new Set(s);
        next.delete(group.name);
        return next;
      });
    }
  }

  async function runHealthcheck(provider: ProxyProvider) {
    setTestingProviders((s) => new Set(s).add(provider.name));
    setExpandedProviders((prev) => new Set(prev).add(provider.name));
    try {
      await healthcheckProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setTestingProviders((s) => {
        const next = new Set(s);
        next.delete(provider.name);
        return next;
      });
    }
  }

  async function runUpdate(provider: ProxyProvider) {
    setUpdatingProviders((s) => new Set(s).add(provider.name));
    try {
      await updateProxyProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setUpdatingProviders((s) => {
        const next = new Set(s);
        next.delete(provider.name);
        return next;
      });
    }
  }

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading proxies...</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Proxies</h1>
        <span
          className="text-[11px] font-semibold px-2.5 py-1 rounded-full capitalize"
          style={{
            background: mode === 'rule' ? 'rgba(0,113,227,0.1)' : mode === 'global' ? 'rgba(52,199,89,0.1)' : 'rgba(0,0,0,0.06)',
            color: mode === 'rule' ? '#0071e3' : mode === 'global' ? '#34c759' : '#6e6e73',
          }}
        >
          {mode}
        </span>
      </div>

      {mode === 'direct' ? (
        <div className="liquid-glass-card rounded-2xl p-10 flex flex-col items-center gap-3 text-center">
          <div className="text-4xl">⚡️</div>
          <div className="text-[17px] font-semibold" style={{ color: '#1d1d1f' }}>Direct Mode</div>
          <div className="text-[13px] max-w-xs" style={{ color: '#6e6e73' }}>
            All traffic goes directly to its destination. No proxy groups to configure.
          </div>
        </div>
      ) : (
        <>
          <div className="space-y-3">
            {groups.map((group) => {
              const isTesting = testingGroups.has(group.name);
              const isExpanded = expanded.has(group.name);
              const isSelector = group.type === 'Selector';
              const accentColor = getGroupAccentColor(group.type);
              const typeBadge = getTypeBadgeStyle(group.type);

          return (
            <div
              key={group.name}
              className="liquid-glass-card rounded-xl overflow-hidden"
              style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
            >
              {/* Colored left accent + header */}
              <div className="flex">
                <div className="w-1 flex-shrink-0" style={{ background: accentColor }} />
                <div className="flex-1">
                  <div
                    className="px-4 py-3 flex items-center justify-between cursor-pointer transition-colors"
                    style={{ minHeight: 52 }}
                    role="button"
                    tabIndex={0}
                    aria-expanded={isExpanded}
                    onClick={() => toggleExpanded(group.name)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleExpanded(group.name);
                      }
                    }}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="font-semibold text-[15px] truncate" style={{ color: '#1d1d1f' }}>
                        {group.name}
                      </span>
                      <span
                        className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                        style={typeBadge}
                      >
                        {group.type}
                      </span>
                      {group.now && (
                        <span className="text-[13px] truncate" style={{ color: '#6e6e73' }}>
                          {group.now}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                      <button
                        onClick={(e) => { e.stopPropagation(); testGroupDelay(group); }}
                        disabled={isTesting}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors disabled:opacity-50"
                        style={{
                          background: 'rgba(0,0,0,0.05)',
                          color: '#6e6e73',
                        }}
                      >
                        <RefreshCw size={12} className={isTesting ? 'animate-spin' : ''} />
                        {isTesting ? 'Testing…' : 'Test'}
                      </button>
                      {isExpanded
                        ? <ChevronUp size={16} style={{ color: '#6e6e73' }} />
                        : <ChevronDown size={16} style={{ color: '#6e6e73' }} />
                      }
                    </div>
                  </div>

                  {/* Proxy grid */}
                  {isExpanded && (
                    <div
                      className="p-4 border-t"
                      style={{ borderColor: 'rgba(0,0,0,0.06)' }}
                    >
                      {!isSelector && (
                        <p className="text-[11px] mb-3 px-0.5" style={{ color: '#8e8e93' }}>
                          Auto-selected by latency — click to force override
                        </p>
                      )}
                      <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
                        {group.all?.map((proxyName) => {
                          const proxy = proxies[proxyName];
                          const history = proxy?.history ?? [];
                          const latency = getLastDelay(history);
                          const isSelected = group.now === proxyName;
                          const latencyColor = getLatencyColor(latency);

                          return (
                            <button
                              key={proxyName}
                              onClick={() => selectMutation.mutate({ group: group.name, proxy: proxyName })}
                              className="px-3 py-2.5 rounded-xl text-left border transition-all"
                              style={
                                isSelected
                                  ? { background: '#0071e3', borderColor: '#0071e3' }
                                  : { background: 'white', borderColor: 'rgba(0,0,0,0.06)' }
                              }
                            >
                              <div className="flex items-center gap-1.5 mb-1">
                                {isSelected && (
                                  <Check size={12} className="text-white flex-shrink-0" />
                                )}
                                <div
                                  className="text-[13px] font-medium truncate"
                                  style={{ color: isSelected ? 'white' : '#1d1d1f' }}
                                >
                                  {proxyName}
                                </div>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <div
                                  className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                  style={{ background: isSelected ? 'rgba(255,255,255,0.7)' : latencyColor }}
                                />
                                <span
                                  className="text-[11px] font-mono"
                                  style={{ color: isSelected ? 'rgba(255,255,255,0.8)' : latencyColor }}
                                >
                                  {latency === undefined ? '—' : latency === 0 ? 'Timeout' : `${latency}ms`}
                                </span>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
            );
          })}
          </div>

          {/* Providers — only in rule/global mode */}
          {providers.length > 0 && (
        <div className="space-y-3">
          <div
            className="text-[11px] font-semibold uppercase tracking-[0.06em] px-1"
            style={{ color: '#6e6e73' }}
          >
            Providers
          </div>
          {providers.map((provider) => {
            const isExpanded = expandedProviders.has(provider.name);
            const isTesting = testingProviders.has(provider.name);
            const isUpdating = updatingProviders.has(provider.name);

            return (
              <div
                key={provider.name}
                className="liquid-glass-card rounded-xl overflow-hidden"
                style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
              >
                <div className="flex">
                  <div className="w-1 flex-shrink-0" style={{ background: '#8e8e93' }} />
                  <div className="flex-1">
                    <div
                      className="px-4 py-3 flex items-center justify-between cursor-pointer transition-colors"
                      style={{ minHeight: 52 }}
                      role="button"
                      tabIndex={0}
                      aria-expanded={expandedProviders.has(provider.name)}
                      onClick={() => toggleProviderExpanded(provider.name)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleProviderExpanded(provider.name);
                        }
                      }}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="font-semibold text-[15px] truncate" style={{ color: '#1d1d1f' }}>
                          {provider.name}
                        </span>
                        <span
                          className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                          style={{ background: 'rgba(0,0,0,0.06)', color: '#6e6e73' }}
                        >
                          {provider.vehicleType}
                        </span>
                        <span
                          className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                          style={{ background: 'rgba(0,0,0,0.04)', color: '#8e8e93' }}
                        >
                          {provider.proxies?.length ?? 0} proxies
                        </span>
                        {provider.updatedAt && (
                          <span className="text-[11px] truncate" style={{ color: '#8e8e93' }}>
                            {new Date(provider.updatedAt).toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); runHealthcheck(provider); }}
                          disabled={isTesting}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors disabled:opacity-50"
                          style={{ background: 'rgba(0,0,0,0.05)', color: '#6e6e73' }}
                        >
                          <Activity size={12} className={isTesting ? 'animate-pulse' : ''} />
                          {isTesting ? 'Testing…' : 'Test'}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); runUpdate(provider); }}
                          disabled={isUpdating}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors disabled:opacity-50"
                          style={{ background: 'rgba(0,0,0,0.05)', color: '#6e6e73' }}
                        >
                          <RefreshCw size={12} className={isUpdating ? 'animate-spin' : ''} />
                          {isUpdating ? 'Updating…' : 'Update'}
                        </button>
                        {isExpanded
                          ? <ChevronUp size={16} style={{ color: '#6e6e73' }} />
                          : <ChevronDown size={16} style={{ color: '#6e6e73' }} />
                        }
                      </div>
                    </div>

                    {isExpanded && provider.proxies && provider.proxies.length > 0 && (
                      <div className="p-4 border-t" style={{ borderColor: 'rgba(0,0,0,0.06)' }}>
                        <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
                          {provider.proxies.map((proxy) => {
                            const latency = getLastDelay(proxy.history);
                            const latencyColor = getLatencyColor(latency);
                            return (
                              <div
                                key={proxy.name}
                                className="px-3 py-2.5 rounded-xl text-left border"
                                style={{ background: 'white', borderColor: 'rgba(0,0,0,0.06)' }}
                              >
                                <div
                                  className="text-[13px] font-medium truncate mb-1"
                                  style={{ color: '#1d1d1f' }}
                                >
                                  {proxy.name}
                                </div>
                                <div className="flex items-center gap-1.5">
                                  <div
                                    className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                    style={{ background: latencyColor }}
                                  />
                                  <span
                                    className="text-[11px] font-mono"
                                    style={{ color: latencyColor }}
                                  >
                                    {latency === undefined ? '—' : latency === 0 ? 'Timeout' : `${latency}ms`}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          </div>
        )}
        </>
      )}
    </div>
  );
}
