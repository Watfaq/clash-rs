pub const LOCAL_ADDR: &str = "127.0.0.1";
pub const EXAMPLE_REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
pub const EXAMLE_RESP_200: &[u8] = b"HTTP/1.1 200";

pub const IMAGE_WG: &str = "lscr.io/linuxserver/wireguard:latest";
pub const IMAGE_SS_RUST: &str = "ghcr.io/shadowsocks/ssserver-rust:latest";
pub const IMAGE_SHADOW_TLS: &str = "ghcr.io/ihciah/shadow-tls:latest";
pub const IMAGE_TROJAN_GO: &str = "p4gefau1t/trojan-go:latest";
pub const IMAGE_VMESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_XRAY: &str = "teddysun/xray:latest";
