import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProxies, selectProxy, getProxyDelay, getProxyProviders, updateProxyProvider } from '../lib/api';
import { RefreshCw } from 'lucide-react';
import type { Proxy } from '../lib/api';

const TEST_URL = 'http://www.gstatic.com/generate_204';
const TEST_TIMEOUT = 5000;

const GROUP_TYPES = ['Selector', 'URLTest', 'Fallback', 'LoadBalance'];

function getLatencyDotClass(delay: number | undefined): string {
  if (!delay || delay === 0) return 'bg-slate-300';
  if (delay < 200) return 'bg-emerald-500';
  if (delay < 500) return 'bg-amber-500';
  return 'bg-red-500';
}

function getLatencyTextClass(delay: number | undefined): string {
  if (!delay || delay === 0) return 'text-slate-400';
  if (delay < 200) return 'text-emerald-600';
  if (delay < 500) return 'text-amber-600';
  return 'text-red-600';
}

function getLastDelay(history: Proxy['history']): number | undefined {
  if (!history || history.length === 0) return undefined;
  return history[history.length - 1]?.delay;
}

function getTypeBadgeClass(type: string): string {
  if (type === 'Selector') return 'bg-blue-50 text-blue-700';
  if (type === 'URLTest') return 'bg-emerald-50 text-emerald-700';
  if (type === 'Fallback') return 'bg-amber-50 text-amber-700';
  if (type === 'LoadBalance') return 'bg-slate-100 text-slate-600';
  return 'bg-slate-100 text-slate-600';
}

export function Proxies() {
  const queryClient = useQueryClient();
  const [testingGroups, setTestingGroups] = useState<Set<string>>(new Set());
  const [latencyMap, setLatencyMap] = useState<Record<string, number>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const { data, isLoading } = useQuery({
    queryKey: ['proxies'],
    queryFn: getProxies,
    refetchInterval: 30000,
  });

  const { data: providersData } = useQuery({
    queryKey: ['providers'],
    queryFn: getProxyProviders,
    refetchInterval: 60000,
  });

  const selectMutation = useMutation({
    mutationFn: ({ group, proxy }: { group: string; proxy: string }) =>
      selectProxy(group, proxy),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['proxies'] }),
  });

  const proxies = data?.proxies ?? {};
  const groups = Object.values(proxies).filter((p) => GROUP_TYPES.includes(p.type));
  const providers = Object.fromEntries(
    Object.entries(providersData?.providers ?? {}).filter(([name]) => name !== 'default')
  );

  function toggleExpanded(name: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function testGroupDelay(group: Proxy) {
    if (!group.all) return;
    setTestingGroups((s) => new Set(s).add(group.name));
    // Auto-expand when testing
    setExpanded((prev) => new Set(prev).add(group.name));
    try {
      await Promise.allSettled(
        group.all.map(async (name) => {
          try {
            const res = await getProxyDelay(name, TEST_URL, TEST_TIMEOUT);
            setLatencyMap((prev) => ({ ...prev, [name]: res.delay }));
          } catch {
            setLatencyMap((prev) => ({ ...prev, [name]: 0 }));
          }
        })
      );
      await queryClient.invalidateQueries({ queryKey: ['proxies'] });
    } finally {
      setTestingGroups((s) => {
        const next = new Set(s);
        next.delete(group.name);
        return next;
      });
    }
  }

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="text-sm text-slate-400">Loading proxies...</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold text-slate-900">Proxies</h1>

      <div className="space-y-3">
        {groups.map((group) => {
          const isTesting = testingGroups.has(group.name);
          const isExpanded = expanded.has(group.name);
          const isSelector = group.type === 'Selector';

          return (
            <div key={group.name} className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              {/* Card header */}
              <div
                className="px-5 py-4 flex items-center justify-between cursor-pointer hover:bg-slate-50 transition-colors"
                onClick={() => toggleExpanded(group.name)}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-semibold text-slate-900 truncate">{group.name}</span>
                  <span className={`text-xs rounded-full px-2 py-0.5 font-medium flex-shrink-0 ${getTypeBadgeClass(group.type)}`}>
                    {group.type}
                  </span>
                  {group.now && (
                    <span className="text-sm text-slate-500 truncate">
                      → <span className="text-slate-700 font-medium">{group.now}</span>
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                  <button
                    onClick={(e) => { e.stopPropagation(); testGroupDelay(group); }}
                    disabled={isTesting}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-500 hover:text-slate-700 hover:bg-slate-100 transition-colors disabled:opacity-50"
                  >
                    <RefreshCw size={12} className={isTesting ? 'animate-spin' : ''} />
                    {isTesting ? 'Testing...' : 'Test'}
                  </button>
                  <span className="text-slate-300 text-lg">{isExpanded ? '−' : '+'}</span>
                </div>
              </div>

              {/* Proxy grid */}
              {isExpanded && (
                <div className="border-t border-slate-100 p-4">
                  <div className="grid grid-cols-3 gap-2">
                    {group.all?.map((proxyName) => {
                      const proxy = proxies[proxyName];
                      const history = proxy?.history ?? [];
                      const latency = latencyMap[proxyName] ?? getLastDelay(history);
                      const isSelected = group.now === proxyName;

                      return (
                        <button
                          key={proxyName}
                          onClick={() => {
                            if (isSelector) {
                              selectMutation.mutate({ group: group.name, proxy: proxyName });
                            }
                          }}
                          className={`px-3 py-2.5 rounded-xl text-left border transition-all ${
                            isSelected
                              ? 'border-blue-500 bg-blue-50 shadow-sm'
                              : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'
                          } ${isSelector ? 'cursor-pointer' : 'cursor-default'}`}
                        >
                          <div className="text-sm font-medium text-slate-800 truncate">{proxyName}</div>
                          <div className="flex items-center gap-1.5 mt-1">
                            <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${getLatencyDotClass(latency)}`} />
                            <span className={`text-xs font-mono ${getLatencyTextClass(latency)}`}>
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
          );
        })}
      </div>

      {/* Providers */}
      {Object.keys(providers).length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Providers</h2>
          {Object.values(providers).map((provider) => (
            <div key={provider.name} className="bg-white rounded-2xl border border-slate-200 shadow-sm">
              <div className="px-5 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="font-semibold text-slate-900">{provider.name}</span>
                  <span className="bg-slate-100 text-slate-600 text-xs rounded-full px-2 py-0.5">
                    {provider.vehicleType}
                  </span>
                  <span className="bg-slate-100 text-slate-500 text-xs rounded-full px-2 py-0.5">
                    {provider.proxies?.length ?? 0} proxies
                  </span>
                </div>
                <button
                  onClick={() => updateProxyProvider(provider.name)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-500 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                >
                  <RefreshCw size={12} />
                  Update
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
