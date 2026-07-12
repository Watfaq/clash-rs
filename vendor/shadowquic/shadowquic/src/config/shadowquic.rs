use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::deserialize_bps;
use crate::config::{
    AuthUser, CipherSuitePreference, CongestionControl, HasCipherSuitePreference, SocketOpt,
    default_alpn, default_blackhole_detection, default_brutal_ack_compensate,
    default_brutal_bandwidth, default_brutal_cwnd_gain, default_brutal_min_ack_rate,
    default_brutal_min_sample_count, default_brutal_min_window, default_congestion_control,
    default_gso, default_initial_mtu, default_keep_alive_interval, default_min_mtu,
    default_mtu_discovery, default_over_stream, default_zero_rtt,
};

pub fn default_rate_limit() -> u64 {
    u64::MAX
}

/// Configuration of shadowquic inbound
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1443"
/// users:
///   - username: "zhangsan"
///     password: "12345678"
/// jls-upstream:
///   addr: "echo.free.beeceptor.com:443" # domain/ip + port, domain must be the same as client.
///   rate-limit: 1000000 # Limiting forwarding rate in unit of bps. optional, default is disabled
/// server-name: "echo.free.beeceptor.com" # must be the same as client
/// alpn: ["h3"]
/// congestion-control: bbr
/// zero-rtt: true
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ShadowQuicServerCfg {
    /// Binding address. e.g. `0.0.0.0:443`, `[::1]:443`
    pub bind_addr: SocketAddr,
    /// Users for client authentication
    pub users: Vec<AuthUser>,
    /// Server name used to check client. Must be the same as client
    /// If empty, server name will be parsed from jls_upstream
    /// If not available, server name check will be skipped
    pub server_name: Option<String>,
    /// Jls upstream, camouflage server, must be address with port. e.g.: `codepn.io:443`,`google.com:443`,`127.0.0.1:443`
    pub jls_upstream: JlsUpstream,
    /// Alpn of tls. Default is `["h3"]`, must have common element with client
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// 0-RTT handshake.
    /// Set to true to enable zero rtt.
    /// Enabled by default
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    /// Congestion control, default to "bbr", supported: "bbr", "new-reno", "cubic"
    #[serde(default = "default_congestion_control")]
    pub congestion_control: CongestionControl,
    /// Initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    #[serde(default = "default_initial_mtu")]
    pub initial_mtu: u16,
    /// Minimum mtu, must be smaller than initial mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1290
    #[serde(default = "default_min_mtu")]
    pub min_mtu: u16,
    /// Enable QUIC Generic Segmentation Offload (GSO).
    /// Controls [`quinn::TransportConfig::enable_segmentation_offload`]. When supported, GSO reduces
    /// CPU usage for bulk sends; unsupported environments may see transient startup packet loss.
    /// Enabled by default
    #[serde(default = "default_gso")]
    pub gso: bool,
    /// Enable auto MTU discovery, default to true
    /// For stable udp network, it's better to disable it and set a proper initial mtu
    #[serde(default = "default_mtu_discovery")]
    pub mtu_discovery: bool,
    /// Enable MTU black-hole detection. When enabled, the current MTU is reset to `min_mtu` once
    /// a black hole is detected (standard PLPMTUD behavior). When disabled (default), the
    /// previously discovered MTU is kept after a black hole is detected.
    /// Controls quinn-jls `MtuDiscoveryConfig::blackhole_reset_mtu`.
    /// Only takes effect when `mtu_discovery` is enabled.
    ///
    /// In high packet loss network, it's better to disable black hole detection to avoid unnecessary mtu reset.
    #[serde(default = "default_blackhole_detection")]
    pub blackhole_detection: bool,
}

/// Jls upstream configuration
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct JlsUpstream {
    /// Jls upstream address, e.g. `codepn.io:443`, `google.com:443`, `127.0.0.1:443`
    pub addr: String,
    /// Maximum rate for JLS forwarding in unit of bps, default is disabled.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u64,
}

impl Default for JlsUpstream {
    fn default() -> Self {
        Self {
            addr: String::new(),
            rate_limit: u64::MAX,
        }
    }
}
impl Default for ShadowQuicServerCfg {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:443".parse().unwrap(),
            users: Default::default(),
            jls_upstream: Default::default(),
            alpn: Default::default(),
            zero_rtt: Default::default(),
            congestion_control: Default::default(),
            initial_mtu: default_initial_mtu(),
            min_mtu: default_min_mtu(),
            server_name: None,
            gso: default_gso(),
            mtu_discovery: default_mtu_discovery(),
            blackhole_detection: default_blackhole_detection(),
        }
    }
}

impl Default for ShadowQuicClientCfg {
    fn default() -> Self {
        Self {
            password: Default::default(),
            username: Default::default(),
            addr: Default::default(),
            server_name: Default::default(),
            alpn: Default::default(),
            initial_mtu: default_initial_mtu(),
            congestion_control: Default::default(),
            zero_rtt: Default::default(),
            over_stream: Default::default(),
            min_mtu: default_min_mtu(),
            keep_alive_interval: default_keep_alive_interval(),
            gso: default_gso(),
            mtu_discovery: default_mtu_discovery(),
            blackhole_detection: default_blackhole_detection(),
            cipher_suite_preference: None,
            socket_opt: Default::default(),
            protect_path: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct BrutalParams {
    #[serde(deserialize_with = "deserialize_bps")]
    pub bandwidth: u64,
    pub min_window: u64,
    pub cwnd_gain: f64,
    pub min_ack_rate: f64,
    pub min_sample_count: u64,
    pub ack_compensate: bool,
}

impl Default for BrutalParams {
    fn default() -> Self {
        Self {
            bandwidth: default_brutal_bandwidth(),
            min_window: default_brutal_min_window(),
            cwnd_gain: default_brutal_cwnd_gain(),
            min_ack_rate: default_brutal_min_ack_rate(),
            min_sample_count: default_brutal_min_sample_count(),
            ack_compensate: default_brutal_ack_compensate(),
        }
    }
}

/// Shadowquic outbound configuration
///   
/// example:
/// ```yaml
/// addr: "12.34.56.7:1089" # or "[12:ff::ff]:1089" for dualstack
/// password: "12345678"
/// username: "87654321"
/// server-name: "echo.free.beeceptor.com" # must be the same as jls_upstream in server
/// alpn: ["h3"]
/// initial-mtu: 1400
/// congestion-control: bbr
/// zero-rtt: true
/// over-stream: false  # true for udp over stream, false for udp over datagram
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ShadowQuicClientCfg {
    /// username, must be the same as the server
    pub username: String,
    /// password, must be the same as the server
    pub password: String,
    /// Shadowquic server address. example: `127.0.0.0.1:443`, `www.server.com:443`, `[ff::f1]:4443`
    pub addr: String,
    /// Server name, must be the same as the server jls_upstream
    /// domain name
    pub server_name: String,
    /// Alpn of tls, default is \["h3"\], must have common element with server
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    #[serde(default = "default_initial_mtu")]
    pub initial_mtu: u16,
    /// Congestion control, default to "bbr", supported: "bbr", "new-reno", "cubic"
    #[serde(default = "default_congestion_control")]
    pub congestion_control: CongestionControl,
    /// Set to true to enable zero rtt, default to true
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    /// Transfer udp over stream or over datagram.
    /// If true, use quic stream to send UDP, otherwise use quic datagram
    /// extension, similar to native UDP in TUIC
    ///
    /// ### Proxy HTTP3
    /// To proxy HTTP3 traffic, recommend to disable over-stream and blackhole-detection.
    ///
    /// Over-stream will retransmit lost packets conflicting shadowquic's inner congestion controller. This is famous [*TCP in TCP*(TCP meltdown)
    /// ](https://web.archive.org/web/20230228035749/http://sites.inka.de/%7EW1011/devel/tcp-tcp.html) problem.
    ///
    /// Over-stream also breaks HTTP3's mtu discovery leading to probe wrong MTU.
    #[serde(default = "default_over_stream")]
    pub over_stream: bool,
    #[serde(default = "default_min_mtu")]
    /// Minimum mtu, must be smaller than initial mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1290
    pub min_mtu: u16,
    /// Keep alive interval in milliseconds
    /// 0 means disable keep alive, should be smaller than 30_000(idle time).
    /// Disabled by default.
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: u32,

    /// Enable QUIC Generic Segmentation Offload (GSO).
    /// Controls [`quinn::TransportConfig::enable_segmentation_offload`]. When supported, GSO reduces
    /// CPU usage for bulk sends; unsupported environments may see transient startup packet loss.
    /// Enabled by default
    #[serde(default = "default_gso")]
    pub gso: bool,
    /// Enable auto MTU discovery, default to true
    /// For stable udp network, it's better to disable it and set a proper initial mtu
    #[serde(default = "default_mtu_discovery")]
    pub mtu_discovery: bool,
    /// Enable MTU black-hole detection. When enabled, the current MTU is reset to `min_mtu` once
    /// a black hole is detected (standard PLPMTUD behavior). When disabled (default), the
    /// previously discovered MTU is kept after a black hole is detected.
    /// Controls quinn-jls `MtuDiscoveryConfig::blackhole_reset_mtu`.
    /// Only takes effect when `mtu_discovery` is enabled.
    ///
    /// In high packet loss network, it's better to disable black hole detection to avoid unnecessary mtu reset.
    #[serde(default = "default_blackhole_detection")]
    pub blackhole_detection: bool,

    /// Optional TLS 1.3 cipher suite preference.
    /// If unset, use rustls/ring default preference order.
    #[serde(default)]
    pub cipher_suite_preference: Option<Vec<CipherSuitePreference>>,

    /// Android Only. the unix socket path for protecting android socket
    #[serde(default)]
    pub protect_path: Option<std::path::PathBuf>,

    /// Socket options like bind interface and fwmark
    #[serde(flatten)]
    pub socket_opt: SocketOpt,
}

impl HasCipherSuitePreference for ShadowQuicClientCfg {
    fn has_cipher_suite_preference(&self) -> bool {
        self.cipher_suite_preference
            .as_ref()
            .is_some_and(|preferences| !preferences.is_empty())
    }
}
