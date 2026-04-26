import { useEffect, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';

interface TrafficChartProps {
  timestamps: number[];
  up: number[];
  down: number[];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB/s`;
}

function makeGradient(u: uPlot, color: string, alpha: string): CanvasGradient {
  const gradient = u.ctx.createLinearGradient(0, 0, 0, u.height);
  gradient.addColorStop(0, color + alpha);
  gradient.addColorStop(1, color + '00');
  return gradient;
}

export function TrafficChart({ timestamps, up, down }: TrafficChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<uPlot | null>(null);

  function buildChart(width: number) {
    if (!containerRef.current) return;
    chartRef.current?.destroy();

    const opts: uPlot.Options = {
      width,
      height: 160,
      series: [
        {},
        {
          label: 'Upload',
          stroke: '#2563eb',
          fill: (u: uPlot) => makeGradient(u, '#2563eb', '14'),
          width: 2,
          value: (_u: uPlot, v: number | null) => formatBytes(v ?? 0),
        },
        {
          label: 'Download',
          stroke: '#10b981',
          fill: (u: uPlot) => makeGradient(u, '#10b981', '14'),
          width: 2,
          value: (_u: uPlot, v: number | null) => formatBytes(v ?? 0),
        },
      ],
      axes: [
        {
          stroke: 'transparent',
          ticks: { show: false },
          grid: { show: false },
        },
        {
          stroke: '#94a3b8',
          ticks: { show: false },
          grid: { stroke: '#e2e8f0', width: 1 },
          values: (_u: uPlot, vals: (number | null)[]) => vals.map((v) => formatBytes(v ?? 0)),
          size: 80,
        },
      ],
      scales: { x: { time: true }, y: { auto: true } },
      cursor: { show: false },
      legend: { show: false },
      padding: [8, 0, 0, 0],
    };

    chartRef.current = new uPlot(opts, [timestamps, up, down], containerRef.current);
  }

  useEffect(() => {
    if (!containerRef.current) return;
    buildChart(containerRef.current.clientWidth);

    const observer = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width;
      if (width) buildChart(width);
    });
    observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (chartRef.current) {
      chartRef.current.setData([timestamps, up, down]);
    }
  }, [timestamps, up, down]);

  return <div ref={containerRef} className="w-full" />;
}
