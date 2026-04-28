import { useEffect, useState } from 'react';
import { useWebSocket } from './useWebSocket';
import { getWsUrl } from '../lib/api';
import type { TrafficData } from '../lib/api';

const HISTORY_LENGTH = 60;

interface TrafficHistory {
  up: number[];
  down: number[];
  timestamps: number[];
}

interface UseTrafficReturn {
  history: TrafficHistory;
  current: TrafficData;
}

export function useTraffic(): UseTrafficReturn {
  const url = getWsUrl('/ws/traffic');
  const { lastMessage } = useWebSocket<TrafficData>(url);

  const [history, setHistory] = useState<TrafficHistory>({
    up: new Array(HISTORY_LENGTH).fill(0),
    down: new Array(HISTORY_LENGTH).fill(0),
    timestamps: Array.from({ length: HISTORY_LENGTH }, (_, i) => Date.now() / 1000 - (HISTORY_LENGTH - 1 - i)),
  });

  const [current, setCurrent] = useState<TrafficData>({ up: 0, down: 0 });

  useEffect(() => {
    if (!lastMessage) return;
    setCurrent(lastMessage);
    setHistory((prev) => {
      const now = Date.now() / 1000;
      return {
        up: [...prev.up.slice(1), lastMessage.up],
        down: [...prev.down.slice(1), lastMessage.down],
        timestamps: [...prev.timestamps.slice(1), now],
      };
    });
  }, [lastMessage]);

  return { history, current };
}
