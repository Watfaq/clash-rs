import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getProxyProviders, getProxyDelay, updateProxyProvider, healthcheckProvider, getRuleProviders, updateRuleProvider, getRuleProviderRules, matchRuleProvider } from '../lib/api';
import { RefreshCw, Activity, ChevronDown, ChevronUp, Search } from 'lucide-react';
import type { ProxyProvider, Proxy, RuleProvider } from '../lib/api';

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

const TEST_URL = 'http://www.gstatic.com/generate_204';
const TEST_TIMEOUT = 5000;

export function Providers() {
  const queryClient = useQueryClient();
  const [testingProviders, setTestingProviders] = useState<Set<string>>(new Set());
  const [updatingProviders, setUpdatingProviders] = useState<Set<string>>(new Set());
  const [updatingRuleProviders, setUpdatingRuleProviders] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [expandedRuleProviders, setExpandedRuleProviders] = useState<Set<string>>(new Set());
  const [latencyMap, setLatencyMap] = useState<Record<string, number>>({});

  const { data, isLoading } = useQuery({
    queryKey: ['providers'],
    queryFn: getProxyProviders,
    refetchInterval: 60000,
  });

  const { data: ruleData, isLoading: ruleIsLoading } = useQuery({
    queryKey: ['rule-providers'],
    queryFn: getRuleProviders,
    refetchInterval: 60000,
  });

  const providers = Object.values(data?.providers ?? {})
    .filter((p) => p.name !== 'default' && p.vehicleType !== 'Compatible')
    .sort((a, b) => a.name.localeCompare(b.name));

  const ruleProviders = Object.values(ruleData?.providers ?? {})
    .filter((p) => p.vehicleType !== 'Compatible' && p.vehicleType !== 'Inline')
    .sort((a, b) => a.name.localeCompare(b.name));

  function toggleExpanded(name: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  }

  function toggleRuleProviderExpanded(name: string) {
    setExpandedRuleProviders((prev) => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  }

  async function runHealthcheck(provider: ProxyProvider) {
    setTestingProviders((s) => new Set(s).add(provider.name));
    setExpanded((prev) => new Set(prev).add(provider.name));
    try {
      if (provider.proxies) {
        await Promise.allSettled(
          provider.proxies.map(async (proxy) => {
            try {
              const res = await getProxyDelay(proxy.name, TEST_URL, TEST_TIMEOUT);
              setLatencyMap((prev) => ({ ...prev, [proxy.name]: res.delay }));
            } catch {
              setLatencyMap((prev) => ({ ...prev, [proxy.name]: 0 }));
            }
          })
        );
      }
      await healthcheckProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setTestingProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  async function runUpdate(provider: ProxyProvider) {
    setUpdatingProviders((s) => new Set(s).add(provider.name));
    try {
      await updateProxyProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['providers'] });
    } finally {
      setUpdatingProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  async function runRuleUpdate(provider: RuleProvider) {
    setUpdatingRuleProviders((s) => new Set(s).add(provider.name));
    try {
      await updateRuleProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['rule-providers'] });
    } finally {
      setUpdatingRuleProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  function getBehaviorStyle(behavior?: string): { background: string; color: string } {
    switch (behavior?.toLowerCase()) {
      case 'domain':    return { background: 'rgba(52,199,89,0.12)',  color: '#34c759' };
      case 'ipcidr':    return { background: 'rgba(0,113,227,0.12)',  color: '#0071e3' };
      case 'classical': return { background: 'rgba(255,149,0,0.12)', color: '#ff9500' };
      default:          return { background: 'rgba(0,0,0,0.06)',      color: '#6e6e73' };
    }
  }

  function RuleProviderRulesPanel({ name, behavior }: { name: string; behavior?: string }) {
    const [matchInput, setMatchInput] = useState('');
    const [matchTarget, setMatchTarget] = useState<string | null>(null);

    const { data, isLoading, isError } = useQuery({
      queryKey: ['rule-provider-rules', name],
      queryFn: () => getRuleProviderRules(name),
    });

    const { data: matchData, isLoading: matchLoading, isError: matchError } = useQuery({
      queryKey: ['rule-provider-match', name, matchTarget],
      queryFn: () => matchRuleProvider(name, matchTarget!),
      enabled: matchTarget !== null && matchTarget.trim().length > 0,
    });

    const rules = data?.rules ?? [];
    const behaviorLower = behavior?.toLowerCase();
    const canShowRules = behaviorLower === 'classical';

    function handleMatchSubmit(e: React.FormEvent) {
      e.preventDefault();
      if (matchInput.trim()) setMatchTarget(matchInput.trim());
    }

    return (
      <div className="space-y-3">
        {/* Match tester — shown for all behaviors */}
        <form onSubmit={handleMatchSubmit} className="flex gap-2 items-center">
          <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-xl border"
            style={{ background: 'rgba(0,0,0,0.03)', borderColor: 'rgba(0,0,0,0.08)' }}>
            <Search size={13} style={{ color: '#8e8e93', flexShrink: 0 }} />
            <input
              type="text"
              value={matchInput}
              onChange={(e) => setMatchInput(e.target.value)}
              placeholder={behaviorLower === 'ipcidr' ? 'Test IP (e.g. 8.8.8.8)' : 'Test domain or IP'}
              className="flex-1 bg-transparent outline-none text-[13px]"
              style={{ color: '#1d1d1f' }}
            />
          </div>
          <button
            type="submit"
            disabled={!matchInput.trim()}
            className="px-3 py-2 rounded-xl text-[12px] font-medium disabled:opacity-40 transition-colors"
            style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
          >
            Test
          </button>
          {matchTarget !== null && (
            <div className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-[12px] font-semibold flex-shrink-0"
              style={
                matchLoading ? { background: 'rgba(0,0,0,0.05)', color: '#8e8e93' }
                : matchError  ? { background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }
                : matchData?.match ? { background: 'rgba(52,199,89,0.12)', color: '#34c759' }
                : { background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }
              }
            >
              {matchLoading ? '…'
                : matchError ? '⚠ Error'
                : matchData?.match ? '✓ Match'
                : '✗ No match'}
            </div>
          )}
        </form>

        {/* Rule list — only for classical */}
        {canShowRules && (
          isLoading ? (
            <div className="text-[13px] py-1" style={{ color: '#8e8e93' }}>Loading rules…</div>
          ) : isError ? (
            <div className="text-[13px] py-1" style={{ color: '#ff3b30' }}>Failed to load rules.</div>
          ) : rules.length === 0 ? (
            <div className="text-[13px] py-1 italic" style={{ color: '#8e8e93' }}>No rules loaded</div>
          ) : (
            <div className="max-h-64 overflow-y-auto space-y-1 pr-1">
              {rules.map((rule, i) => {
                const [type, ...rest] = rule.split(',');
                const payload = rest.join(',');
                return (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-2 py-1 rounded-lg text-[12px]"
                    style={{ background: 'rgba(0,0,0,0.03)' }}
                  >
                    <span
                      className="font-mono font-semibold px-1.5 py-0.5 rounded flex-shrink-0"
                      style={{ background: 'rgba(255,149,0,0.12)', color: '#ff9500', fontSize: 10 }}
                    >
                      {type}
                    </span>
                    <span className="font-mono truncate" style={{ color: '#1d1d1f' }}>{payload}</span>
                  </div>
                );
              })}
              {rules.length >= 500 && (
                <div className="text-[11px] text-center pt-1" style={{ color: '#8e8e93' }}>
                  Showing first 500 rules
                </div>
              )}
            </div>
          )
        )}

        {/* Info message for non-classical */}
        {!canShowRules && (
          <div className="text-[12px] italic" style={{ color: '#8e8e93' }}>
            Rule entries are not enumerable for {behavior} providers — use the tester above.
          </div>
        )}
      </div>
    );
  }


  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Providers</h1>
        <span className="text-[13px]" style={{ color: '#8e8e93' }}>{providers.length} provider{providers.length !== 1 ? 's' : ''}</span>
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading providers…</div>
      ) : providers.length === 0 ? (
        <div className="liquid-glass-card rounded-2xl p-10 flex flex-col items-center gap-3 text-center">
          <div className="text-4xl">📦</div>
          <div className="text-[17px] font-semibold" style={{ color: '#1d1d1f' }}>No External Providers</div>
          <div className="text-[13px] max-w-xs" style={{ color: '#6e6e73' }}>
            Add proxy providers to your config to see them here.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {providers.map((provider) => {
            const isExpanded = expanded.has(provider.name);
            const isTesting = testingProviders.has(provider.name);
            const isUpdating = updatingProviders.has(provider.name);
            const proxyCount = provider.proxies?.length ?? 0;

            return (
              <div
                key={provider.name}
                className="liquid-glass-card rounded-xl overflow-hidden"
                style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
              >
                <div className="flex">
                  <div className="w-1 flex-shrink-0" style={{ background: '#8e8e93' }} />
                  <div className="flex-1">
                    {/* Header */}
                    <div
                      className="px-4 py-3 flex items-center justify-between cursor-pointer"
                      style={{ minHeight: 56 }}
                      onClick={() => toggleExpanded(provider.name)}
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
                          className="text-[11px] px-2 py-0.5 rounded-full flex-shrink-0"
                          style={{ background: 'rgba(0,0,0,0.04)', color: '#8e8e93' }}
                        >
                          {proxyCount} {proxyCount === 1 ? 'proxy' : 'proxies'}
                        </span>
                        {provider.updatedAt && (
                          <span className="text-[11px] truncate hidden sm:inline" style={{ color: '#8e8e93' }}>
                            Updated {new Date(provider.updatedAt).toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); runHealthcheck(provider); }}
                          disabled={isTesting}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
                          style={{ background: 'rgba(52,199,89,0.1)', color: '#34c759' }}
                        >
                          <Activity size={12} className={isTesting ? 'animate-pulse' : ''} />
                          {isTesting ? 'Testing…' : 'Test All'}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); runUpdate(provider); }}
                          disabled={isUpdating}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
                          style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
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

                    {/* Proxy grid */}
                    {isExpanded && provider.proxies && provider.proxies.length > 0 && (
                      <div className="p-4 border-t" style={{ borderColor: 'rgba(0,0,0,0.06)' }}>
                        <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-2">
                          {provider.proxies.map((proxy) => {
                            const latency = latencyMap[proxy.name] ?? getLastDelay(proxy.history);
                            const latencyColor = getLatencyColor(latency);
                            return (
                              <div
                                key={proxy.name}
                                className="px-3 py-2.5 rounded-xl border"
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
                                  <span className="text-[11px] font-mono" style={{ color: latencyColor }}>
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

      {/* Rule Providers Section */}
      <div className="flex items-center justify-between pt-4">
        <h2 className="text-xl font-semibold tracking-tight" style={{ color: '#1d1d1f' }}>Rule Providers</h2>
        <span className="text-[13px]" style={{ color: '#8e8e93' }}>{ruleProviders.length} provider{ruleProviders.length !== 1 ? 's' : ''}</span>
      </div>

      {ruleIsLoading ? (
        <div className="text-[15px]" style={{ color: '#6e6e73' }}>Loading rule providers…</div>
      ) : ruleProviders.length === 0 ? (
        <div className="liquid-glass-card rounded-2xl p-10 flex flex-col items-center gap-3 text-center">
          <div className="text-4xl">📋</div>
          <div className="text-[17px] font-semibold" style={{ color: '#1d1d1f' }}>No Rule Providers</div>
          <div className="text-[13px] max-w-xs" style={{ color: '#6e6e73' }}>
            Add rule providers to your config to see them here.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {ruleProviders.map((provider) => {
            const isUpdating = updatingRuleProviders.has(provider.name);
            const isExpanded = expandedRuleProviders.has(provider.name);
            const behaviorStyle = getBehaviorStyle(provider.behavior);

            return (
              <div
                key={provider.name}
                className="liquid-glass-card rounded-xl overflow-hidden"
                style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
              >
                <div className="flex">
                  <div className="w-1 flex-shrink-0" style={{ background: behaviorStyle.color }} />
                  <div className="flex-1">
                    {/* Header — clickable to expand */}
                    <div
                      className="px-4 py-3 flex items-center justify-between cursor-pointer"
                      style={{ minHeight: 56 }}
                      onClick={() => toggleRuleProviderExpanded(provider.name)}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                        <span className="font-semibold text-[15px] truncate" style={{ color: '#1d1d1f' }}>
                          {provider.name}
                        </span>
                        <span
                          className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                          style={{ background: 'rgba(0,0,0,0.06)', color: '#6e6e73' }}
                        >
                          {provider.vehicleType}
                        </span>
                        {provider.behavior && (
                          <span
                            className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                            style={behaviorStyle}
                          >
                            {provider.behavior}
                          </span>
                        )}
                        {provider.ruleCount !== undefined && (
                          <span
                            className="text-[11px] px-2 py-0.5 rounded-full flex-shrink-0"
                            style={{ background: 'rgba(0,0,0,0.04)', color: '#8e8e93' }}
                          >
                            {provider.ruleCount} rule{provider.ruleCount !== 1 ? 's' : ''}
                          </span>
                        )}
                        {provider.updatedAt && (
                          <span className="text-[11px] truncate hidden sm:inline" style={{ color: '#8e8e93' }}>
                            Updated {new Date(provider.updatedAt).toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); runRuleUpdate(provider); }}
                          disabled={isUpdating}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
                          style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
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

                    {/* Rules list */}
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t" style={{ borderColor: 'rgba(0,0,0,0.06)' }}>
                        <div className="pt-3">
                          <RuleProviderRulesPanel name={provider.name} behavior={provider.behavior} />
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
    </div>
  );
}
