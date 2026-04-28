import { useEffect, useRef, useState, useCallback } from 'react';

export type ReadyState = 'CONNECTING' | 'OPEN' | 'CLOSING' | 'CLOSED';

interface UseWebSocketReturn<T> {
  lastMessage: T | null;
  readyState: ReadyState;
}

export function useWebSocket<T = unknown>(url: string | null): UseWebSocketReturn<T> {
  const [lastMessage, setLastMessage] = useState<T | null>(null);
  const [readyState, setReadyState] = useState<ReadyState>('CLOSED');
  const wsRef = useRef<WebSocket | null>(null);
  const retryCount = useRef(0);
  const retryTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);
  const unmounted = useRef(false);

  const connect = useCallback(() => {
    if (!url) {
      wsRef.current?.close();
      wsRef.current = null;
      retryCount.current = 0;
      setReadyState('CLOSED');
      setLastMessage(null);
      return;
    }
    if (unmounted.current) return;

    setReadyState('CONNECTING');
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      if (unmounted.current) { ws.close(); return; }
      setReadyState('OPEN');
      retryCount.current = 0;
    };

    ws.onmessage = (event) => {
      if (unmounted.current) return;
      try {
        const data = JSON.parse(event.data) as T;
        setLastMessage(data);
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      if (unmounted.current) return;
      setReadyState('CLOSED');
      wsRef.current = null;

      const delay = Math.min(1000 * 2 ** retryCount.current, 30000);
      retryCount.current += 1;
      retryTimeout.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url]);

  useEffect(() => {
    unmounted.current = false;
    connect();

    return () => {
      unmounted.current = true;
      if (retryTimeout.current) clearTimeout(retryTimeout.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { lastMessage, readyState };
}
