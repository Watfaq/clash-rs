import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getVersion } from '../lib/api';
import { getApiUrl, getSecret, setApiUrl, setSecret } from '../lib/settings';
import { Save, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

function isDevMode(): boolean {
  const port = window.location.port;
  return port === '5173' || port === '5174' || port === '3000';
}

export function Settings() {
  const [apiUrl, setApiUrlState] = useState(getApiUrl);
  const [secret, setSecretState] = useState(getSecret);
  const [saved, setSaved] = useState(false);
  const saveTimersRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      saveTimersRef.current.forEach((id) => clearTimeout(id));
      saveTimersRef.current = [];
    };
  }, []);

  const { data, error, refetch } = useQuery({
    queryKey: ['version'],
    queryFn: getVersion,
    retry: 0,
    refetchInterval: 5000,
  });

  const isConnected = !!data && !error;
  const showDevPrompt = isDevMode() && !isConnected && !localStorage.getItem('clash-api-url');

  useEffect(() => {
    if (isDevMode() && !localStorage.getItem('clash-api-url')) {
      setApiUrlState('http://127.0.0.1:9090');
    }
  }, []);

  function handleSave() {
    setApiUrl(apiUrl);
    setSecret(secret);
    setSaved(true);
    saveTimersRef.current.push(window.setTimeout(() => setSaved(false), 2000));
    saveTimersRef.current.push(window.setTimeout(() => void refetch(), 100));
  }

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: 'transparent',
    border: 'none',
    outline: 'none',
    textAlign: 'right',
    fontSize: 15,
    color: '#1d1d1f',
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#1d1d1f' }}>Settings</h1>

      {/* Dev mode banner */}
      {showDevPrompt && (
        <div
          className="rounded-xl p-4 flex gap-3"
          style={{
            background: 'rgba(255,149,0,0.08)',
            border: '1px solid rgba(255,149,0,0.2)',
          }}
        >
          <AlertTriangle size={16} style={{ color: '#ff9500', flexShrink: 0, marginTop: 2 }} />
          <div className="space-y-1">
            <div className="text-[13px] font-semibold" style={{ color: '#1d1d1f' }}>Dev mode detected</div>
            <div className="text-[12px]" style={{ color: '#6e6e73' }}>
              Set the API URL below to point to your running clash-rs instance, then click Save &amp; Connect.
            </div>
          </div>
        </div>
      )}

      {/* Connection status — vivid gradient card */}
      <div
        className="rounded-2xl p-5 flex items-center gap-4"
        style={{
          background: isConnected
            ? 'linear-gradient(135deg, #34c759 0%, #00a550 100%)'
            : 'linear-gradient(135deg, #ff3b30 0%, #cc2f28 100%)',
          boxShadow: isConnected
            ? '0 8px 24px rgba(52,199,89,0.35), inset 0 1px 0 rgba(255,255,255,0.2)'
            : '0 8px 24px rgba(255,59,48,0.25), inset 0 1px 0 rgba(255,255,255,0.2)',
        }}
      >
        <div className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ background: 'rgba(255,255,255,0.2)' }}>
          {isConnected
            ? <CheckCircle size={20} className="text-white" />
            : <XCircle size={20} className="text-white" />
          }
        </div>
        <div>
          {isConnected ? (
            <>
              <div className="text-[15px] font-semibold text-white">Connected to clash-rs</div>
              <div className="text-[13px] font-mono text-white/80">v{data.version}</div>
            </>
          ) : (
            <>
              <div className="text-[15px] font-semibold text-white">Cannot reach API</div>
              <div className="text-[12px] font-mono text-white/70">{getApiUrl()}</div>
            </>
          )}
        </div>
      </div>

      {/* API URL InsetGroup */}
      <div>
        <div
          className="text-[11px] font-semibold uppercase tracking-[0.06em] mb-2 px-1"
          style={{ color: '#6e6e73' }}
        >
          API Connection
        </div>
        <div className="liquid-glass-card rounded-xl overflow-hidden" style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
          <div
            className="flex items-center gap-3 px-4"
            style={{ minHeight: 52, borderBottom: '1px solid rgba(0,0,0,0.06)' }}
          >
            <span className="text-[15px] flex-shrink-0" style={{ color: '#1d1d1f' }}>API URL</span>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrlState(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSave()}
              placeholder="http://127.0.0.1:9090"
              style={{ ...inputStyle, color: '#6e6e73' }}
            />
          </div>
          <div
            className="flex items-center gap-3 px-4"
            style={{ minHeight: 52 }}
          >
            <span className="text-[15px] flex-shrink-0" style={{ color: '#1d1d1f' }}>Secret</span>
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecretState(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSave()}
              placeholder="API secret (leave blank if none)"
              style={{ ...inputStyle, color: '#6e6e73' }}
            />
          </div>
        </div>
        <div className="text-[12px] mt-2 px-1" style={{ color: '#6e6e73' }}>
          When served from the clash-rs binary, defaults to the current origin.
        </div>
      </div>

      {/* Save button */}
      <button
        onClick={handleSave}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-[15px] font-semibold transition-colors"
        style={{ background: '#0071e3', color: 'white' }}
      >
        <Save size={16} />
        {saved ? '✓ Saved' : 'Save & Connect'}
      </button>
    </div>
  );
}
