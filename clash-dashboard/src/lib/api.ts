import { getApiUrl, getSecret } from './settings';

// Types
export interface Version {
  version: string;
  premium: boolean;
  meta: boolean;
}

export interface InboundEndpoint {
  name: string;
  type: string;
  port: number;
  active: boolean;
}

export interface DnsListenInfo {
  udp?: string;
  tcp?: string;
  doh?: string;
  dot?: string;
  doh3?: string;
}

export interface ClashConfig {
  port?: number;
  'socks-port'?: number;
  'redir-port'?: number;
  'tproxy-port'?: number;
  'mixed-port'?: number;
  'bind-address'?: string;
  mode?: string;
  'log-level'?: string;
  ipv6?: boolean;
  'allow-lan'?: boolean;
  listeners?: InboundEndpoint[];
  'lan-ips'?: string[];
  'dns-listen'?: DnsListenInfo;
}

/** Fields that can be patched via PATCH /configs */
export type PatchableConfig = Omit<ClashConfig, 'listeners' | 'lan-ips' | 'dns-listen'>;

export interface Proxy {
  name: string;
  type: string;
  udp: boolean;
  history: Array<{ time: string; delay: number }>;
  all?: string[];
  now?: string;
  alive?: boolean;
  extra?: Record<string, unknown>;
}

export interface Rule {
  type: string;
  payload: string;
  proxy: string;
  size?: number;
}

export interface Connection {
  id: string;
  metadata: {
    network: string;
    type: string;
    host: string;
    sourceIP: string;
    sourcePort: string;
    destinationPort: string;
    destinationIP?: string;
    inboundIP?: string;
    inboundPort?: string;
    inboundName?: string;
    inboundUser?: string;
    process?: string;
    processPath?: string;
    remoteDestination?: string;
    sniffHost?: string;
    asn?: string;
  };
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rulePayload: string;
}

export interface TrafficData {
  up: number;
  down: number;
}

export interface LogEntry {
  type: string;
  payload: string;
}

export interface MemoryData {
  inuse: number;
  oslimit: number;
}

export interface DNSQueryResult {
  Answer?: Array<{
    TTL: number;
    MXPreference: number;
    data: string;
    name: string;
    type: number;
  }>;
  Question: Array<{ name: string; type: number }>;
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
}

export interface ProxyProvider {
  name: string;
  type: string;
  vehicleType: string;
  updatedAt?: string;
  subscriptionInfo?: Record<string, unknown>;
  proxies: Proxy[];
}

export interface ConnectionsData {
  connections: Connection[];
  downloadTotal: number;
  uploadTotal: number;
  memory?: number;
}

// HTTP client
async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const baseUrl = getApiUrl();
  const secret = getSecret();
  const url = `${baseUrl}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  if (secret) {
    headers['Authorization'] = `Bearer ${secret}`;
  }

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    // Try to extract a message from the response body (plain text or JSON)
    let message = `${response.status} ${response.statusText}`;
    try {
      const ct = response.headers.get('content-type') ?? '';
      if (ct.includes('application/json')) {
        const body = await response.json() as { message?: string };
        if (body.message) message = body.message;
      } else {
        const text = await response.text();
        if (text.trim()) message = text.trim();
      }
    } catch { /* ignore */ }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const raw = await response.text();
  if (!raw.trim()) {
    return undefined as T;
  }
  return JSON.parse(raw) as T;
}

// Version
export const getVersion = () => request<Version>('/version');

// Config
export const getConfigs = () => request<ClashConfig>('/configs');
export const updateConfigs = (config: Partial<ClashConfig>) =>
  request<void>('/configs', { method: 'PUT', body: JSON.stringify(config) });
export const reloadConfigs = (path: string) =>
  request<void>('/configs', { method: 'PUT', body: JSON.stringify({ path }) });
export const patchConfigs = (patch: PatchableConfig) =>
  request<void>('/configs', { method: 'PATCH', body: JSON.stringify(patch) });

// Proxies
export const getProxies = () => request<{ proxies: Record<string, Proxy> }>('/proxies');
export const selectProxy = (groupName: string, proxyName: string) =>
  request<void>(`/proxies/${encodeURIComponent(groupName)}`, {
    method: 'PUT',
    body: JSON.stringify({ name: proxyName }),
  });
export const getProxyDelay = (name: string, url: string, timeout: number) =>
  request<{ delay: number }>(
    `/proxies/${encodeURIComponent(name)}/delay?url=${encodeURIComponent(url)}&timeout=${timeout}`
  );

// Groups
export const getGroup = (name: string) => request<Proxy>(`/group/${encodeURIComponent(name)}`);
export const getGroupDelay = (name: string, url: string, timeout: number) =>
  request<Record<string, number>>(
    `/group/${encodeURIComponent(name)}/delay?url=${encodeURIComponent(url)}&timeout=${timeout}`
  );

// Providers
export const getProxyProviders = () =>
  request<{ providers: Record<string, ProxyProvider> }>('/providers/proxies');
export const updateProxyProvider = (name: string) =>
  request<void>(`/providers/proxies/${encodeURIComponent(name)}`, { method: 'PUT' });
export const healthcheckProvider = (name: string) =>
  request<void>(`/providers/proxies/${encodeURIComponent(name)}/healthcheck`);
export const getProviderProxyDelay = (providerName: string, proxyName: string, url: string, timeout: number) =>
  request<{ delay: number }>(
    `/providers/proxies/${encodeURIComponent(providerName)}/proxies/${encodeURIComponent(proxyName)}/delay?url=${encodeURIComponent(url)}&timeout=${timeout}`
  );

// Rule Providers
export interface RuleProvider {
  name: string;
  type: string;
  vehicleType: string;
  updatedAt?: string;
  behavior?: string;
  format?: string;
  ruleCount?: number;
}

export const getRuleProviders = () =>
  request<{ providers: Record<string, RuleProvider> }>('/providers/rules');
export const updateRuleProvider = (name: string) =>
  request<void>(`/providers/rules/${encodeURIComponent(name)}`, { method: 'PUT' });
export const getRuleProviderRules = (name: string) =>
  request<{ rules: string[] }>(`/providers/rules/${encodeURIComponent(name)}/rules`);
export const matchRuleProvider = (name: string, target: string) =>
  request<{ match: boolean }>(`/providers/rules/${encodeURIComponent(name)}/match?target=${encodeURIComponent(target)}`);

// Rules
export const getRules = () => request<{ rules: Rule[] }>('/rules');

// Connections
export const getConnections = () => request<ConnectionsData>('/connections');
export const closeAllConnections = () => request<void>('/connections', { method: 'DELETE' });
export const closeConnection = (id: string) =>
  request<void>(`/connections/${encodeURIComponent(id)}`, { method: 'DELETE' });

// DNS
export const queryDNS = (name: string, type: string) =>
  request<DNSQueryResult>(`/dns/query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`);

// Memory
export const getMemory = () => request<MemoryData>('/memory');

// Restart
export const restart = () => request<void>('/restart', { method: 'POST' });

// WebSocket URL helper
export function getWsUrl(path: string): string {
  const baseUrl = getApiUrl();
  const secret = getSecret();
  const wsBase = baseUrl.replace(/^http/, 'ws');
  const url = new URL(`${wsBase}${path}`);
  if (secret) {
    url.searchParams.set('token', secret);
  }
  return url.toString();
}
