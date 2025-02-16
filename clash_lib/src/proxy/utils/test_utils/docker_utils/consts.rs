pub const LOCAL_ADDR: &str = "127.0.0.1";

pub const IMAGE_WG: &str = "lscr.io/linuxserver/wireguard:1.0.20210914-legacy";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SS_RUST: &str = "ghcr.io/shadowsocks/ssserver-rust:latest";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SHADOW_TLS: &str = "ghcr.io/ihciah/shadow-tls:latest";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_OBFS: &str = "gists/simple-obfs:latest";
pub const IMAGE_TROJAN_GO: &str = "p4gefau1t/trojan-go:latest";
pub const IMAGE_VMESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_XRAY: &str = "teddysun/xray:latest";
pub const IMAGE_SOCKS5: &str = "ghcr.io/wzshiming/socks5/socks5:v0.4.3";
#[cfg(feature = "ssh")]
pub const IMAGE_OPENSSH: &str = "docker.io/linuxserver/openssh-server:latest";
pub const IMAGE_HYSTERIA: &str = "tobyxdd/hysteria:latest";
