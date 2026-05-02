import { useMemo, useState } from 'react';
import { ResponsiveSankey } from '@nivo/sankey';
import { Activity, ArrowUp, ArrowDown, GitBranch, ChevronUp, ChevronDown } from 'lucide-react';
import { useFlows } from '../hooks/useFlows';
import type { FlowRecord } from '../hooks/useFlows';
import type { DefaultLink, DefaultNode, SankeyLinkDatum, SankeyNodeDatum } from '@nivo/sankey';

// ─── Formatting ────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)}MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)}GB`;
}

// ─── Protocol colours ───────────────────────────────────────────────────────────

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#0071e3',
  UDP: '#ff9500',
  QUIC: '#5ac8fa',
  HTTP: '#34c759',
  HTTPS: '#30d158',
};

function protocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol.toUpperCase()] ?? '#8e8e93';
}

// ─── Sankey types ───────────────────────────────────────────────────────────────

type FlowNode = DefaultNode;

interface FlowLink extends DefaultLink {
  protocol: string;
  uploadTotal: number;
  downloadTotal: number;
  connCount: number;
  rule: string;
}

// ─── Sankey data builder ────────────────────────────────────────────────────────

interface SankeyData {
  nodes: FlowNode[];
  links: FlowLink[];
}

function buildSankeyData(flows: FlowRecord[]): SankeyData {
  if (flows.length === 0) return { nodes: [], links: [] };

  const top15 = [...flows].sort((a, b) => b.bytesTotal - a.bytesTotal).slice(0, 15);

  const allSrcIps = new Set<string>();
  top15.forEach(f => f.srcIps.forEach(ip => allSrcIps.add(ip)));
  const groupSrcs = allSrcIps.size > 5;

  interface LinkAgg {
    bytes: number;
    upload: number;
    download: number;
    connCount: number;
    protocol: string;
    rule: string;
  }

  const linkAgg = new Map<string, Map<string, LinkAgg>>();

  for (const flow of top15) {
    const dstId = `dst:${flow.dstHost || `port-${flow.dstPort}`}`;
    const srcIps = flow.srcIps.length > 0 ? flow.srcIps : ['unknown'];
    const perIp = 1 / srcIps.length;

    for (const ip of srcIps) {
      const srcId = groupSrcs ? 'src:Local Network' : `src:${ip}`;
      if (!linkAgg.has(srcId)) linkAgg.set(srcId, new Map());
      const dstMap = linkAgg.get(srcId)!;
      const linkKey = `${dstId}|${flow.protocol.toUpperCase()}|${flow.dstPort}`;
      const existing = dstMap.get(linkKey);
      if (existing) {
        existing.bytes += flow.bytesTotal * perIp;
        existing.upload += flow.uploadTotal * perIp;
        existing.download += flow.downloadTotal * perIp;
        existing.connCount += flow.connCount * perIp;
      } else {
        dstMap.set(linkKey, {
          bytes: flow.bytesTotal * perIp,
          upload: flow.uploadTotal * perIp,
          download: flow.downloadTotal * perIp,
          connCount: flow.connCount * perIp,
          protocol: flow.protocol,
          rule: flow.rule,
        });
      }
    }
  }

  const nodeIds = new Set<string>();
  const links: FlowLink[] = [];

  for (const [srcId, dstMap] of linkAgg) {
    nodeIds.add(srcId);
    for (const [linkKey, agg] of dstMap) {
      const dstId = linkKey.split('|')[0];
      nodeIds.add(dstId);
      const color = protocolColor(agg.protocol);
      links.push({
        source: srcId,
        target: dstId,
        value: Math.max(1, Math.round(agg.bytes)),
        startColor: color,
        endColor: color,
        protocol: agg.protocol,
        uploadTotal: Math.round(agg.upload),
        downloadTotal: Math.round(agg.download),
        connCount: agg.connCount,
        rule: agg.rule,
      });
    }
  }

  const nodes: FlowNode[] = Array.from(nodeIds).map(id => ({ id }));
  return { nodes, links };
}

// ─── Sankey tooltip ─────────────────────────────────────────────────────────────

function LinkTooltip({ link }: { link: SankeyLinkDatum<FlowNode, FlowLink> }) {
  return (
    <div
      className="rounded-xl px-3 py-2 text-[13px] space-y-1"
      style={{
        background: 'rgba(255,255,255,0.97)',
        backdropFilter: 'blur(8px)',
        border: '1px solid rgba(0,0,0,0.08)',
        boxShadow: '0 4px 12px rgba(0,0,0,0.12)',
      }}
    >
      <div className="font-semibold text-[14px]" style={{ color: '#1d1d1f' }}>
        {link.source.id.replace(/^src:/, '')} → {link.target.id.replace(/^dst:/, '')}
      </div>
      <div className="flex gap-3" style={{ color: '#6e6e73' }}>
        <span>↑ {formatBytes(link.uploadTotal)}</span>
        <span>↓ {formatBytes(link.downloadTotal)}</span>
      </div>
      <div className="flex gap-3" style={{ color: '#6e6e73' }}>
        <span>Conns: {link.connCount}</span>
        <span style={{ color: protocolColor(link.protocol) }}>{link.protocol}</span>
      </div>
      <div className="text-[12px]" style={{ color: '#8e8e93' }}>Rule: {link.rule}</div>
    </div>
  );
}

// ─── Summary icon badge ─────────────────────────────────────────────────────────

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

// ─── Sort helpers ───────────────────────────────────────────────────────────────

type SortField = 'bytesTotal' | 'uploadTotal' | 'downloadTotal' | 'connCount';
type SortDir = 'asc' | 'desc';

function SortIcon({ field, active, dir }: { field: SortField; active: SortField; dir: SortDir }) {
  if (field !== active) return <ChevronUp size={11} style={{ opacity: 0.3 }} />;
  return dir === 'asc'
    ? <ChevronUp size={11} style={{ color: '#0071e3' }} />
    : <ChevronDown size={11} style={{ color: '#0071e3' }} />;
}

// ─── Main page ──────────────────────────────────────────────────────────────────

export function Flows() {
  const { flows } = useFlows();
  const [sortField, setSortField] = useState<SortField>('bytesTotal');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const totalBytes = useMemo(() => flows.reduce((s, f) => s + f.bytesTotal, 0), [flows]);
  const topDst = useMemo(
    () => flows.length > 0
      ? [...flows].sort((a, b) => b.bytesTotal - a.bytesTotal)[0].dstHost || '—'
      : '—',
    [flows],
  );

  const sankeyData = useMemo(() => buildSankeyData(flows), [flows]);
  const hasSankeyData = sankeyData.nodes.length >= 2 && sankeyData.links.length >= 1;

  const sortedFlows = useMemo(() => {
    const sorted = [...flows].sort((a, b) => {
      const diff = a[sortField] - b[sortField];
      return sortDir === 'asc' ? diff : -diff;
    });
    return sorted.slice(0, 50);
  }, [flows, sortField, sortDir]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  }

  const usedProtocols = useMemo(
    () => [...new Set(flows.map(f => f.protocol.toUpperCase()))],
    [flows],
  );

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <GitBranch size={20} style={{ color: '#0071e3' }} />
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Flows</h1>
      </div>

      {/* Summary cards */}
      <div
        className="text-[11px] font-semibold uppercase tracking-[0.06em] px-1"
        style={{ color: '#6e6e73' }}
      >
        Summary
      </div>
      <div
        className="liquid-glass-card rounded-xl overflow-hidden"
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
      >
        {[
          {
            icon: <Activity size={14} className="text-white" />,
            bg: '#0071e3',
            label: 'Unique Flows',
            value: String(flows.length),
          },
          {
            icon: <ArrowDown size={14} className="text-white" />,
            bg: '#34c759',
            label: 'Top Destination',
            value: topDst,
          },
          {
            icon: <ArrowUp size={14} className="text-white" />,
            bg: '#ff9500',
            label: 'Total Bytes',
            value: formatBytes(totalBytes),
          },
        ].map((row, idx, arr) => (
          <div
            key={row.label}
            className="flex items-center gap-3 px-4"
            style={{
              minHeight: 52,
              borderBottom: idx < arr.length - 1 ? '1px solid rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <IconBadge bg={row.bg}>{row.icon}</IconBadge>
            <span className="text-[15px] flex-1" style={{ color: '#1d1d1f' }}>{row.label}</span>
            <span className="text-[15px] font-mono truncate max-w-48" style={{ color: '#6e6e73' }}>{row.value}</span>
          </div>
        ))}
      </div>

      {/* Sankey diagram */}
      <div
        className="text-[11px] font-semibold uppercase tracking-[0.06em] px-1"
        style={{ color: '#6e6e73' }}
      >
        Flow Map (top 15 destinations)
      </div>

      {/* Protocol legend */}
      {usedProtocols.length > 0 && (
        <div className="flex items-center gap-3 px-1 flex-wrap">
          {usedProtocols.map(proto => (
            <div key={proto} className="flex items-center gap-1.5">
              <div
                className="w-2.5 h-2.5 rounded-sm"
                style={{ background: protocolColor(proto) }}
              />
              <span className="text-[12px]" style={{ color: '#6e6e73' }}>{proto}</span>
            </div>
          ))}
        </div>
      )}

      <div
        className="liquid-glass-card rounded-xl overflow-hidden"
        style={{ height: 420, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
      >
        {hasSankeyData ? (
          <ResponsiveSankey<FlowNode, FlowLink>
            data={sankeyData}
            margin={{ top: 20, right: 140, bottom: 20, left: 140 }}
            align="justify"
            colors={(node) =>
              node.id.startsWith('src:') ? '#5ac8fa' : '#0071e3'
            }
            nodeOpacity={0.85}
            nodeHoverOpacity={1}
            nodeThickness={14}
            nodeSpacing={20}
            nodeBorderWidth={0}
            nodeBorderRadius={4}
            linkOpacity={0.35}
            linkHoverOpacity={0.7}
            linkBlendMode="normal"
            enableLinkGradient={true}
            label={(node: Omit<SankeyNodeDatum<FlowNode, FlowLink>, 'color' | 'label'>) =>
              node.id.replace(/^(src:|dst:)/, '')
            }
            labelPosition="outside"
            labelPadding={12}
            labelTextColor={{ from: 'color', modifiers: [['darker', 1]] }}
            linkTooltip={LinkTooltip}
            animate={true}
            motionConfig="gentle"
          />
        ) : (
          <div className="h-full flex items-center justify-center">
            <span className="text-[15px]" style={{ color: '#8e8e93' }}>
              {flows.length === 0 ? 'Waiting for flow data…' : 'Not enough data to render diagram'}
            </span>
          </div>
        )}
      </div>

      {/* Flow table */}
      <div
        className="text-[11px] font-semibold uppercase tracking-[0.06em] px-1"
        style={{ color: '#6e6e73' }}
      >
        Flow Table (top 50)
      </div>
      <div
        className="liquid-glass-card rounded-xl overflow-hidden overflow-x-auto"
        style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
      >
        <table className="table-fixed w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-48" style={{ color: '#6e6e73' }}>Destination</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-16" style={{ color: '#6e6e73' }}>Port</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-20" style={{ color: '#6e6e73' }}>Protocol</th>
              <SortHeader field="connCount" label="Conns" current={sortField} dir={sortDir} onClick={toggleSort} width="w-20" />
              <SortHeader field="uploadTotal" label="↑ Upload" current={sortField} dir={sortDir} onClick={toggleSort} width="w-24" />
              <SortHeader field="downloadTotal" label="↓ Download" current={sortField} dir={sortDir} onClick={toggleSort} width="w-24" />
              <SortHeader field="bytesTotal" label="Total" current={sortField} dir={sortDir} onClick={toggleSort} width="w-24" />
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-28" style={{ color: '#6e6e73' }}>Rule</th>
              <th className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] w-40" style={{ color: '#6e6e73' }}>Proxy Chain</th>
            </tr>
          </thead>
          <tbody>
            {sortedFlows.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-10 text-[15px]" style={{ color: '#8e8e93' }}>
                  No flow data yet
                </td>
              </tr>
            ) : (
              sortedFlows.map((flow: FlowRecord, idx: number) => (
                <tr
                  key={`${flow.dstHost}-${flow.dstPort}-${flow.protocol}-${idx}`}
                  className="group transition-colors"
                  style={{ borderBottom: '1px solid rgba(0,0,0,0.04)' }}
                >
                  <td className="px-4 py-3">
                    <div className="text-[14px] font-medium truncate" style={{ color: '#1d1d1f' }}>
                      {flow.dstHost || '—'}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-[13px]" style={{ color: '#8e8e93' }}>
                    {flow.dstPort}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className="text-[12px] font-medium px-2 py-0.5 rounded-full"
                      style={{
                        background: `${protocolColor(flow.protocol)}18`,
                        color: protocolColor(flow.protocol),
                      }}
                    >
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#6e6e73' }}>
                    {flow.connCount}
                  </td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#0071e3' }}>
                    {formatBytes(flow.uploadTotal)}
                  </td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono" style={{ color: '#34c759' }}>
                    {formatBytes(flow.downloadTotal)}
                  </td>
                  <td className="px-4 py-3 text-right text-[13px] font-mono font-semibold" style={{ color: '#ff9500' }}>
                    {formatBytes(flow.bytesTotal)}
                  </td>
                  <td className="px-4 py-3 text-[12px] truncate" style={{ color: '#6e6e73' }}>
                    {flow.rule}
                  </td>
                  <td className="px-4 py-3 text-[12px] truncate" style={{ color: '#8e8e93' }}>
                    {flow.chains?.join(' → ')}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Sortable table header ──────────────────────────────────────────────────────

function SortHeader({
  field, label, current, dir, onClick, width,
}: {
  field: SortField;
  label: string;
  current: SortField;
  dir: SortDir;
  onClick: (f: SortField) => void;
  width: string;
}) {
  return (
    <th
      aria-sort={field === current ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`text-right px-4 py-3 text-[11px] font-semibold uppercase tracking-[0.06em] select-none ${width}`}
      style={{ color: field === current ? '#0071e3' : '#6e6e73' }}
    >
      <button
        type="button"
        className="w-full flex items-center justify-end gap-1 cursor-pointer"
        onClick={() => onClick(field)}
      >
        {label}
        <SortIcon field={field} active={current} dir={dir} />
      </button>
    </th>
  );
}
