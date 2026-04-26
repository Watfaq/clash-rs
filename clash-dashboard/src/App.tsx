import { HashRouter as BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/Layout';
import { Overview } from './pages/Overview';
import { Proxies } from './pages/Proxies';
import { Connections } from './pages/Connections';
import { Rules } from './pages/Rules';
import { Logs } from './pages/Logs';
import { Config } from './pages/Config';
import { DNS } from './pages/DNS';
import { Settings } from './pages/Settings';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="proxies" element={<Proxies />} />
            <Route path="connections" element={<Connections />} />
            <Route path="rules" element={<Rules />} />
            <Route path="logs" element={<Logs />} />
            <Route path="config" element={<Config />} />
            <Route path="dns" element={<DNS />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
