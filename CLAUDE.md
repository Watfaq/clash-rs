# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ClashRS is a custom protocol, rule-based network proxy software written in Rust. It's a high-performance proxy with support for multiple protocols (Shadowsocks, Trojan, Vmess, Wireguard, Tor, Tuic, Socks5), flexible routing rules, DNS anti-spoofing, and cross-platform support.

## Workspace Structure

This is a Rust workspace with six main crates:
- `clash-bin/` - Main binary executable
- `clash-lib/` - Core library containing all proxy logic
- `clash-doc/` - Documentation generation
- `clash-ffi/` - FFI bindings for mobile platforms
- `clash-dns/` - DNS resolution components
- `clash-netstack/` - Network stack implementation

## Common Commands

### Build
```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo build --features plus    # Build with all features including Tor
```

### Testing
```bash
cargo test --all --all-features                    # Run all tests
CLASH_RS_CI=true cargo test --all --all-features  # Run tests in CI mode
make test-no-docker                                # Run tests without Docker
```

### Documentation
```bash
make docs                      # Generate documentation
cargo doc -p clash_doc --no-deps  # Generate config docs only
```

### Running
```bash
./target/debug/clash-rs -c config.yaml  # Run with config file
./target/debug/clash-rs -t               # Test configuration
./target/debug/clash-rs -h               # Show help
./target/debug/clash-rs -l logfile.log   # Additionally log to file
```

### Development Setup
```bash
# Install pre-commit hooks for code quality
pipx install pre-commit
pre-commit install

# Install required dependencies
# - cmake (3.29 or newer)
# - libclang (LLVM)
# - nasm (Windows only)
# - protoc (for geodata proto generation)
```

## Architecture

### Core Components

**clash_lib/src/app/** - Main application modules:
- `api/` - REST API handlers for web dashboard
- `dispatcher/` - Traffic routing and connection management
- `dns/` - DNS resolution with anti-spoofing
- `inbound/` - Inbound connection handling
- `outbound/` - Outbound proxy connections
- `router/` - Rule-based routing logic

**clash_lib/src/proxy/** - Protocol implementations:
- `shadowsocks/`, `trojan/`, `vmess/`, `socks/` - Proxy protocols
- `group/` - Proxy group types (selector, fallback, load balance)
- `transport/` - Underlying transports (TLS, WebSocket, gRPC, H2)
- `tun/` - TUN device support for transparent proxy

**clash_lib/src/config/** - Configuration parsing and validation

### Key Design Patterns

- **Async/await**: Heavy use of Tokio for async networking
- **Trait-based**: Extensible proxy system using traits
- **Error handling**: Comprehensive error types with `thiserror`
- **Feature flags**: Conditional compilation for different protocols
- **Zero-copy**: Optimized data paths where possible
- **Workspace structure**: Uses Rust 2024 edition with resolver = "3"
- **Release optimization**: Configured for size optimization with LTO and strip

## Testing

Tests are located in `clash_lib/tests/` and include:
- `smoke_tests.rs` - Basic functionality tests
- `api_tests.rs` - API endpoint tests
- Integration tests with Docker containers for various proxy protocols

Set `CLASH_RS_CI=true` environment variable when running tests to enable CI-specific behavior.

## Platform-Specific Notes

- **iOS/macOS**: Use `scripts/build_apple.sh` to build XCFramework
- **Windows**: Requires `wintun.dll` in same directory as executable
- **Linux**: Enhanced with platform-specific UDP socket optimizations

## Feature Flags

Key features that can be enabled:
- `shadowsocks` - Shadowsocks protocol support
- `tuic` - TUIC protocol support
- `ssh` - SSH tunnel support
- `onion` - Tor support
- `shadowquic` - ShadowQUIC protocol support
- `tokio-console` - Tokio console debugging
- `bench` - Benchmarking tools

## Configuration

The project uses YAML configuration files. Sample configs are in `clash/tests/data/config/`.

Main configuration sections:
- `port` - HTTP/SOCKS proxy port
- `dns` - DNS server settings
- `rules` - Traffic routing rules
- `proxies` - Outbound proxy definitions
- `proxy-groups` - Proxy group configurations
