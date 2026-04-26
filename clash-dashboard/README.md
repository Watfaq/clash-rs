# Clash RS Dashboard

A web dashboard for [clash-rs](https://github.com/watfaq/clash-rs) proxy software.

## Stack

- **Vite** + **React 19** + **TypeScript**
- **Tailwind CSS v4** for styling
- **shadcn/ui** for UI components
- **React Router v7** for client-side routing
- **TanStack Query v5** for REST data fetching
- **uPlot** for real-time traffic charts
- **lucide-react** for icons

## Development

```bash
npm install
npm run dev
```

The dashboard connects to the clash-rs API at `window.location.origin` by default. To develop against a local clash-rs instance:

1. Open Settings page in the dashboard
2. Set the API URL to your clash-rs address (e.g., `http://localhost:9090`)
3. Set the secret if configured

Or set `localStorage['clash-api-url']` before loading the page.

## Build

```bash
npm run build
```

Output goes to `dist/`. This is a static SPA — no server-side rendering.

## Embedding in the Binary

The dashboard is served by clash-rs when the `builtin-dashboard` feature flag is enabled. The built `dist/` folder is embedded into the binary at compile time and served under `/ui/`.

The app uses `base: './'` in Vite config to support being served from any path prefix.
