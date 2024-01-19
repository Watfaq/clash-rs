<p align="center">
  <a href="https://ant.design">
    <img width="200" src="https://github.com/Watfaq/clash-rs/assets/543405/76122ef1-eac8-478a-8ba4-ca5e54f8e272">
  </a>
</p>

<h1 align="center">ClashRS</h1>

<div align="center">

A custom protocol, rule based network proxy software.

[![CI](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml)

</div>

## ✨ Features

- 🌈 Flexible traffic routing rules based off source/destination IP/Domain/GeoIP etc.
- 📦 Local anti spoofing DNS with support of UDP/TCP/DoH/DoT remote.
- 🛡 Run as a HTTP/Socks5 proxy, or utun device as a home network gateway.
- ⚙️ Shadowsocks/Trojan/Vmess/Wireguard(userspace)/Tor outbound support with different underlying trasports(gRPC/TLS/H2/WebSocket/etc.).
- 🌍 Dynamic remote rule/proxy loader.
- 🎵 Tracing with Jaeger

## 🖥 Environment Support

- Linux
- macOS
- Windows
  - You need to copy the [wintun.dll](https://wintun.net/) file which matches your architecture to the same directory as your executable and run you program as administrator.
- iOS - [TestFlight](https://testflight.apple.com/join/cLy4Ub5C) 

## 📦 Install

### Download Prebuilt Binary

Can be found at https://github.com/Watfaq/clash-rs/releases

### Local Build

```
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
-> % ./target/debug/clash -h
Usage: clash [OPTIONS]

Options:
  -d, --directory <DIRECTORY>
  -c, --config <FILE>          [default: config.yaml]
  -t, --test
  -h, --help                   Print help
  -V, --version                Print version
```

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
