use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

use crate::config::{
    AuthUser, BrutalParams, CipherSuitePreference, CongestionControl, HasCipherSuitePreference,
    SocketOpt, default_alpn, default_congestion_control, default_gso, default_initial_mtu,
    default_keep_alive_interval, default_min_mtu, default_mtu_discovery, default_over_stream,
    default_zero_rtt,
};

pub(crate) fn default_multipath_num() -> u32 {
    12
}

/// Configuration of sunnyquic inbound
///
/// Example:
/// ```yaml
/// bind-addr: "0.0.0.0:1443"
/// users:
///   - username: "zhangsan"
///     password: "12345678"
/// server-name: "echo.free.beeceptor.com" # must be the same as client
/// alpn: ["h3"]
/// congestion-control: bbr
/// zero-rtt: true
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SunnyQuicServerCfg {
    /// Binding address. e.g. `0.0.0.0:443`, `[::1]:443`
    pub bind_addr: SocketAddr,
    /// Users for client authentication
    pub users: Vec<AuthUser>,
    /// Server name of the certificates
    pub server_name: String,
    /// Certificate path for tls
    pub cert_path: PathBuf,
    /// Private key path for tls
    pub key_path: PathBuf,
    /// Maximum number of paths for multipath quic, 0 for disabling multipath
    #[serde(default = "default_multipath_num")]
    pub max_path_num: u32,
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

    /// Brutal server configuration
    #[serde(default)]
    pub brutal: Option<BrutalParams>,
}

impl Default for SunnyQuicServerCfg {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:443".parse().unwrap(),
            users: Default::default(),
            alpn: Default::default(),
            zero_rtt: Default::default(),
            congestion_control: Default::default(),
            initial_mtu: default_initial_mtu(),
            min_mtu: default_min_mtu(),
            cert_path: PathBuf::from("./assets/certs/localhost.cert.pem"),
            key_path: PathBuf::from("./assets/certs/localhost.key.pem"),
            max_path_num: default_multipath_num(),
            server_name: "localhost".into(),
            mtu_discovery: default_mtu_discovery(),
            gso: default_gso(),
            brutal: None,
        }
    }
}

impl Default for SunnyQuicClientCfg {
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
            max_path_num: default_multipath_num(),
            extra_paths: Default::default(),
            cert_path: Default::default(),
            gso: default_gso(),
            mtu_discovery: default_mtu_discovery(),
            cipher_suite_preference: None,
            socket_opt: Default::default(),
            protect_path: Default::default(),
        }
    }
}

/// Sunnyquic outbound configuration
///
/// example:
/// ```yaml
/// addr: "12.34.56.7:1089" # or "[12:ff::ff]:1089" for dualstack
/// password: "12345678"
/// username: "87654321"
/// server-name: "echo.free.beeceptor.com"
/// alpn: ["h3"]
/// initial-mtu: 1400
/// congestion-control: bbr
/// zero-rtt: true
/// over-stream: false  # true for udp over stream, false for udp over datagram
/// ```
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SunnyQuicClientCfg {
    /// username, must be the same as the server
    pub username: String,
    /// password, must be the same as the server
    pub password: String,
    /// Shadowquic server address. example: `127.0.0.0.1:443`, `www.server.com:443`, `[ff::f1]:4443`
    pub addr: String,
    /// Additional paths for multipath quic
    /// IPV4 or IPv6 path are all fine.
    /// Right now only one path is used to sending data, the rest paths are backup paths.
    /// See https://github.com/n0-computer/quinn/issues/389 for more details.
    ///
    /// It's recommended to use IPV4 and IPV6 path together for dual stack network.
    /// ```yaml
    /// extra-paths:
    ///   - "[12:ff::ff]:1089"
    /// ```
    #[serde(default)]
    pub extra_paths: Vec<QuicPath>,
    /// Maximum number of paths for multipath quic, 0 for disabling multipath
    #[serde(default = "default_multipath_num")]
    pub max_path_num: u32,
    /// Server name, must be the same as the server jls_upstream
    /// domain name
    pub server_name: String,
    /// Alpn of tls, default is \["h3"\], must have common element with server
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Certificate path for tls
    pub cert_path: Option<PathBuf>,
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

    /// Optional TLS 1.3 cipher suite preference.
    /// If unset, use rustls/ring default preference order.
    #[serde(default)]
    pub cipher_suite_preference: Option<Vec<CipherSuitePreference>>,
    #[serde(flatten)]
    pub socket_opt: SocketOpt,

    /// Android Only. the unix socket path for protecting android socket
    #[serde(default)]
    pub protect_path: Option<std::path::PathBuf>,
}

impl HasCipherSuitePreference for SunnyQuicClientCfg {
    fn has_cipher_suite_preference(&self) -> bool {
        self.cipher_suite_preference
            .as_ref()
            .is_some_and(|preferences| !preferences.is_empty())
    }
}

type QuicPath = String;
