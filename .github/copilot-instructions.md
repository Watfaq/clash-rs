# Copilot Instructions — clash-rs

## Overview
Rust implementation of the Clash proxy protocol. Supports SS2022 (Shadowsocks 2022), Trojan, VMess, VLESS, Hysteria2, TUIC, ShadowQUIC, AnyTLS, WireGuard, SSH, Tailscale, Tor, and more. Built on Tokio async runtime.

## Workspace Structure
Six crates: `clash-bin` (binary), `clash-lib` (core), `clash-doc`, `clash-ffi` (mobile FFI), `clash-dns`, `clash-netstack`. Rust 2024 edition, resolver = "3".

## Workflow Rules
- **Never commit directly to master** — always use a PR branch
- CI on PRs builds all target binaries as artifacts (downloadable without merging), even with `only-clippy-tests-on-pr: true`
- CI uses **nightly rustfmt** — import order is case-sensitive ASCII (uppercase before lowercase). Do not trust local stable rustfmt; check CI fmt output
- A push to master creates/updates the `latest` **pre-release** tag. To fetch it via API use `/releases/tags/latest`, NOT `/releases/latest` (which skips pre-releases)
- Always run `cargo +nightly fmt --all` and `cargo clippy -p clash-lib --all-features` (both must be clean) before committing

## Testing a Branch Without Merging
Download the `x86_64-unknown-linux-gnu-binaries` artifact from the PR's CI run via the GitHub API and deploy it directly. No need to merge to get a testable binary.

## Version Building
- **Master branch** (`GITHUB_REF=refs/heads/master`): version = `{cargo_version}-alpha+sha.{short_sha}` (e.g. `0.10.2-alpha+sha.abc1234`)
- **Tagged releases**: version = `{cargo_version}` only
- Commit SHA is also exposed separately as `CLASH_GIT_SHA_SHORT` env var, and the `/version` API returns a `commit` field (present only for master builds)

## API: Version Endpoint
`GET /version` returns `{"version": "...", "meta": false, "commit": "abc1234"}` — `commit` is only present on master/nightly builds.

## AnyTLS Protocol
- AnyTLS inbound: `clash-lib/src/proxy/anytls/inbound/`. Uses rustls-pemfile for cert loading, SHA256 for user map lookup, CancellationToken for relay coordination. No UDP listener (UoT v2 tunnels UDP over TCP).
- Tests using rustls directly must call `rustls::crypto::aws_lc_rs::default_provider().install_default()` before constructing TLS configs.

## SS2022 Multi-user UDP
- Server response must be encrypted with the user's **uPSK** (per-user key), not the server iPSK
- `InboundShadowsocksDatagram` uses a per-client `HashMap<SocketAddr, UdpSocketControlData>` to track session context; `poll_next` upserts on receive, `poll_flush` looks up by `dst_addr`
- `server_session_id` is shared per socket; `packet_id` and `client_session_id`/`user` are per-client
- IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) from dual-stack SS2022 inbound must be canonicalized before socket creation to avoid EINVAL on bind

## Outbound Manager
- Provider proxies are stored in `proxy_providers: HashMap<String, ThreadSafeProxyProvider>` separately from `registry` (static proxies+groups)
- `get_outbound()` only searches `registry` — this is by design, not a regression
- Common proxy response fields (name/type/udp/history/alive) are centralized in `OutboundManager::apply_common_proxy_fields`

## Testing Notes
- Run `cargo test -p clash-lib --all-features` for api_tests (requires `--all-features` for SS proxy config)
- `CLASH_RS_CI=true` enables CI-specific test behavior
