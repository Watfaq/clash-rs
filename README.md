<p align="center">
  <a href="https://ant.design">
    <img width="200" src="https://github.com/Watfaq/clash-rs/assets/543405/76122ef1-eac8-478a-8ba4-ca5e54f8e272">
  </a>
</p>

<h1 align="center">ClashRS</h1>

<div align="center">

A custom protocol, rule based network proxy software.

[![CI](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Watfaq/clash-rs/graph/badge.svg?token=ZQK5WB63KR)](https://codecov.io/gh/Watfaq/clash-rs)

</div>

## ✨ Features

- 🌈 Flexible traffic routing rules based off source/destination IP/Domain/GeoIP etc.
- 📦 Local anti spoofing DNS with support of UDP/TCP/DoH/DoT remote, and expose it as a local UDP/TCP/DoH/DoT server.
- 🛡 Run as an HTTP/Socks5 proxy, or utun device as a home network gateway.
- ⚙️ Shadowsocks/Trojan/Vmess/Wireguard(userspace)/Tor/Tuic/Socks5(TCP/UDP) outbound support with different underlying trasports(gRPC/TLS/H2/WebSocket/etc.).
- 🌍 Dynamic remote rule/proxy loader.
- 🎵 Tracing with Jaeger

## 🖥 Environment Support

- Linux
- macOS
- Windows
  - You need to copy the [wintun.dll](https://wintun.net/) file which matches your architecture to the same directory as your executable and run you program as administrator.
- iOS
  - [![ChocLite App Store](https://developer.apple.com/app-store/marketing/guidelines/images/badge-example-preferred_2x.png)](https://apps.apple.com/by/app/choclite/id6467517938)
  - TestFlight Access: [TestFlight](https://testflight.apple.com/join/cLy4Ub5C)
 
## 💰 Sponsors
- [Fast Access Cloud](https://fast-access.cloud/)


## 📦 Install

### Use With GUI

https://github.com/LibNyanpasu/clash-nyanpasu

### Download Prebuilt Binary

Can be found at https://github.com/Watfaq/clash-rs/releases

### Docker Image

https://github.com/Watfaq/clash-rs/pkgs/container/clash-rs

### Local Build

Dependencies

* cmake (3.29 or newer)
* libclang([LLVM](https://github.com/llvm/llvm-project/releases/tag/llvmorg-16.0.4))
* [nasm](https://www.nasm.us/pub/nasm/releasebuilds/2.16/win64/) (Windows)
* protoc(for geodata proto generation)
* pre-commit
  * [pre-commit](https://pre-commit.com/) for managing git hooks

```
$ pipx install pre-commit
$ pre-commit install

$ cargo build
```

## 🔨 Usage

### Example Config

sample.yaml:

```yaml
port: 7890
```

### Run
```shell
-> % ./target/debug/clash -c sample.yaml
```

### Help
```shell
-> % ./target/debug/clash-rs -h
Usage: clash-rs [OPTIONS]

Options:
  -d, --directory <DIRECTORY>
  -c, --config <FILE>          Specify configuration file [default: config.yaml] [short aliases: f]
  -t, --test-config            Test configuration and exit
  -v, --version                Print clash-rs version and exit [short aliases: V]
  -l, --log-file <LOG_FILE>    Additionally log to file
      --help-improve           Enable crash report to help improve clash
  -h, --help                   Print help
```

## FFI

### Compile for apple platforms

To create a framework for iOS and macOS platforms

```shell
git clone https://github.com/Watfaq/clash-rs.git
cd clash-rs
chmod +x scripts/build_apple.sh
./scripts/build_apple.sh
```

This command will generate a `clashrs.xcframework` file in the `build` directory.

## 🔗 Links

- [Documentation](https://watfaq.gitbook.io/clashrs-user-manual/)
- [Config Reference](https://watfaq.github.io/clash-rs/)
- [Roadmap](https://github.com/Watfaq/clash-rs/issues/59)


## 🤝 Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Telegram User Group](https://t.me/thisisnotclash)

## ❤️ Inspired By
- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [eycorsican/leaf](https://github.com/eycorsican/leaf)
