import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getVersion } from '../lib/api';
import { getApiUrl, getSecret, setApiUrl, setSecret } from '../lib/settings';
import { Save, AlertTriangle } from 'lucide-react';

function isDevMode(): boolean {
  const port = window.location.port;
  return port === '5173' || port === '5174' || port === '3000';
}

export function Settings() {
  const [apiUrl, setApiUrlState] = useState(getApiUrl);
  const [secret, setSecretState] = useState(getSecret);
  const [saved, setSaved] = useState(false);

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
    setTimeout(() => setSaved(false), 2000);
    setTimeout(() => refetch(), 100);
  }

  return (
    <div className="p-6 space-y-6 max-w-md">
      <h1 className="text-xl font-semibold text-slate-900">Settings</h1>

      {/* Dev mode banner */}
      {showDevPrompt && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
          <AlertTriangle size={16} className="text-amber-500 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-amber-800 space-y-1">
            <div className="font-semibold">Dev mode detected</div>
            <div className="text-amber-700">
              Set the API URL below to point to your running clash-rs instance, then click Save & Connect.
            </div>
          </div>
        </div>
      )}

      {/* Connection status */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5 flex items-center gap-4">
        <div className={`w-3 h-3 rounded-full flex-shrink-0 transition-colors ${
          isConnected ? 'bg-emerald-500' : 'bg-red-500'
        }`} />
        <div>
          {isConnected ? (
            <>
              <div className="text-sm font-semibold text-slate-900">Connected to clash-rs</div>
              <div className="text-sm text-slate-400 font-mono">v{data.version}</div>
            </>
          ) : (
            <>
              <div className="text-sm font-semibold text-slate-900">Cannot reach API</div>
              <div className="text-xs text-slate-400 font-mono">{getApiUrl()}</div>
            </>
          )}
        </div>
      </div>

      {/* Form */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5 space-y-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium text-slate-600">API URL</label>
          <input
            type="text"
            value={apiUrl}
            onChange={(e) => setApiUrlState(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSave()}
            className="w-full px-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
            placeholder="http://127.0.0.1:9090"
          />
          <p className="text-xs text-slate-400">
            Base URL of the clash-rs API. When served from the binary, defaults to the current origin.
          </p>
        </div>

        <div className="space-y-1.5">
          <label className="text-sm font-medium text-slate-600">Secret</label>
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecretState(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSave()}
            className="w-full px-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-sm"
            placeholder="API secret (leave blank if none)"
          />
        </div>

        <button
          onClick={handleSave}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <Save size={14} />
          {saved ? '✓ Saved' : 'Save & Connect'}
        </button>
      </div>
    </div>
  );
}
