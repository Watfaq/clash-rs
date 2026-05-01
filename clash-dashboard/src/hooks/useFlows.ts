import { useEffect, useState } from 'react';
import { useWebSocket } from './useWebSocket';
import { getWsUrl } from '../lib/api';

export interface FlowRecord {
  dstHost: string;
  dstPort: number;
  protocol: string;
  srcIps: string[];
  connCount: number;
  uploadTotal: number;
  downloadTotal: number;
  bytesTotal: number;
  rule: string;
  chains: string[];
  lastSeen: string;
}

interface UseFlowsReturn {
  flows: FlowRecord[];
  readyState: import('./useWebSocket').ReadyState;
}

export function useFlows(): UseFlowsReturn {
  const url = getWsUrl('/ws/flows?interval=5');
  const { lastMessage, readyState } = useWebSocket<FlowRecord[]>(url);

  const [flows, setFlows] = useState<FlowRecord[]>([]);

  useEffect(() => {
    if (!lastMessage) return;
    setFlows(lastMessage);
  }, [lastMessage]);

  return { flows, readyState };
}
