# Copilot Instructions — clash-rs

## Overview
Rust implementation of the Clash proxy protocol. Supports SS2022 (Shadowsocks 2022), trojan, VMess, and other protocols. Built on Tokio async runtime.

## Workflow Rules
- **Never commit directly to master** — always use a PR branch
- CI on PRs builds all target binaries as artifacts (downloadable without merging), even with `only-clippy-tests-on-pr: true`
- CI uses **nightly rustfmt** — import order is case-sensitive ASCII (uppercase before lowercase). Do not trust local stable rustfmt; check CI fmt output
- A push to master creates/updates the `latest` **pre-release** tag. To fetch it via API use `/releases/tags/latest`, NOT `/releases/latest` (which skips pre-releases)

## Testing a Branch Without Merging
Download the `x86_64-unknown-linux-gnu-binaries` artifact from the PR's CI run via the GitHub API and deploy it directly. No need to merge to get a testable binary.

## SS2022 Multi-user UDP
- Server response must be encrypted with the user's **uPSK** (per-user key), not the server iPSK
- `InboundShadowsocksDatagram` uses a per-client `HashMap<SocketAddr, UdpSocketControlData>` to track session context; `poll_next` upserts on receive, `poll_flush` looks up by `dst_addr`
- `server_session_id` is shared per socket; `packet_id` and `client_session_id`/`user` are per-client
- IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) from dual-stack SS2022 inbound must be canonicalized before socket creation to avoid EINVAL on bind
