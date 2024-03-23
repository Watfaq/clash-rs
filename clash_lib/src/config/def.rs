use crate::Error;
use std::path::PathBuf;
use std::str::FromStr;
use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Serialize, Deserialize, Default, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[serde(alias = "Global")]
    Global,
    #[default]
    #[serde(alias = "Rule")]
    Rule,
    #[serde(alias = "Direct")]
    Direct,
}

impl Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Global => write!(f, "global"),
            RunMode::Rule => write!(f, "rule"),
            RunMode::Direct => write!(f, "direct"),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    #[serde(alias = "off")]
    Silent,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warning => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Silent => write!(f, "off"),
        }
    }
}

/// Example
/// ```yaml
/// ---
/// port: 8888
/// socks-port: 8889
/// mixed-port: 8899

/// tun:
///   enable: false
///   device-id: "dev://utun1989"

/// dns:
///   enable: true
///   listen: 127.0.0.1:53553
///   #   udp: 127.0.0.1:53553
///   #   tcp: 127.0.0.1:53553
///   #   dot: 127.0.0.1:53554
///   #   doh: 127.0.0.1:53555

///   # ipv6: false # when the false, response to AAAA questions will be empty

///   # These nameservers are used to resolve the DNS nameserver hostnames below.
///   # Specify IP addresses only
///   default-nameserver:
///     - 114.114.114.114
///     - 8.8.8.8
///   enhanced-mode: fake-ip
///   fake-ip-range: 198.18.0.2/16 # Fake IP addresses pool CIDR
///   # use-hosts: true # lookup hosts and return IP record

///   # Hostnames in this list will not be resolved with fake IPs
///   # i.e. questions to these domain names will always be answered with their
///   # real IP addresses
///   # fake-ip-filter:
///   #   - '*.lan'
///   #   - localhost.ptlogin2.qq.com

///   # Supports UDP, TCP, DoT, DoH. You can specify the port to connect to.
///   # All DNS questions are sent directly to the nameserver, without proxies
///   # involved. Clash answers the DNS question with the first result gathered.
///   nameserver:
///     - 114.114.114.114 # default value
///     - 1.1.1.1 # default value
///     - tls://1.1.1.1:853 # DNS over TLS
///     - https://1.1.1.1/dns-query # DNS over HTTPS
/// #    - dhcp://en0 # dns from dhcp

/// allow-lan: true
/// mode: rule
/// log-level: debug
/// external-controller: 127.0.0.1:9090
/// external-ui: "public"
/// # secret: "clash-rs"
/// experimental:
///   ignore-resolve-fail: true

/// profile:
///   store-selected: true
///   store-fake-ip: false

/// proxy-groups:
///   - name: "relay"
///     type: relay
///     proxies:
///       - "plain-vmess"
///       - "ws-vmess"
///       - "auto"
///       - "fallback-auto"
///       - "load-balance"
///       - "select"
///       - DIRECT

///   - name: "relay-one"
///     type: relay
///     use:
///       - "file-provider"

///   - name: "auto"
///     type: url-test
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300

///   - name: "fallback-auto"
///     type: fallback
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300

///   - name: "load-balance"
///     type: load-balance
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     strategy: round-robin
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300

///   - name: select
///     type: select
///     use:
///       - "file-provider"

///   - name: test 🌏
///     type: select
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT

/// proxies:
///   - name: plain-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 16823
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///   - name: ws-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 16824
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     network: ws
///     ws-opts:
///       path: /api/v3/download.getFile
///       headers:
///         Host: www.amazon.com

///   - name: tls-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 8443
///     uuid: 23ad6b10-8d1a-40f7-8ad0-e3e35cd38297
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     tls: true

///   - name: h2-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 8444
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     tls: true
///     network: h2
///     h2-opts:
///       path: /ray

///   - name: vmess-altid
///     type: vmess
///     server: tw-1.ac.laowanxiang.com
///     port: 153
///     uuid: 46dd0dd3-2cc0-3f55-907c-d94e54877687
///     alterId: 64
///     cipher: auto
///     udp: true
///     network: ws
///     ws-opts:
///       path: /api/v3/download.getFile
///       headers:
///         Host: 5607b9d187e655736f563fee87d7283994721.laowanxiang.com
///   - name: "ss-simple"
///     type: ss
///     server: 10.0.0.13
///     port: 8388
///     cipher: aes-256-gcm
///     password: "password"
///     udp: true
///   - name: "trojan"
///     type: trojan
///     server: 10.0.0.13
///     port: 9443
///     password: password1
///     udp: true
///     # sni: example.com # aka server name
///     alpn:
///       - h2
///       - http/1.1
///     skip-cert-verify: true

/// proxy-providers:
///   file-provider:
///     type: file
///     path: ./ss.yaml
///     interval: 300
///     health-check:
///       enable: true
///       url: http://www.gstatic.com/generate_204
///       interval: 300

/// rule-providers:
///   file-provider:
///     type: file
///     path: ./rule-set.yaml
///     interval: 300
///     behavior: domain

/// rules:
///   - DOMAIN,ipinfo.io,relay
///   - RULE-SET,file-provider,trojan
///   - GEOIP,CN,relay
///   - DOMAIN-SUFFIX,facebook.com,REJECT
///   - DOMAIN-KEYWORD,google,select
///   - DOMAIN,google.com,select
///   - SRC-IP-CIDR,192.168.1.1/24,DIRECT
///   - GEOIP,CN,DIRECT
///   - DST-PORT,53,trojan
///   - SRC-PORT,7777,DIRECT
///   - MATCH, DIRECT
/// ...
/// ```
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct Config {
    /// The HTTP proxy port
    pub port: Option<u16>,
    /// The SOCKS5 proxy port
    pub socks_port: Option<u16>,
    /// The redir port
    #[doc(hidden)]
    pub redir_port: Option<u16>,
    #[doc(hidden)]
    pub tproxy_port: Option<u16>,
    /// The HTTP/SOCKS5 mixed proxy port
    /// # Example
    /// ```yaml
    /// mixed-port: 7892
    /// ```
    pub mixed_port: Option<u16>,

    /// HTTP and SOCKS5 proxy authentication
    pub authentication: Vec<String>,
    /// Allow connections to the local-end server from other LAN IP addresses
    #[deprecated = "dont use. see `bind_address`"]
    pub allow_lan: bool,
    /// The address that the inbound listens on
    /// # Note
    /// - setting this to `*` will listen on all interfaces, which is essentially the same as setting it to `0.0.0.0`
    /// - setting this to non local IP will enable `allow_lan` automatically
    /// - and if you don't want `allow_lan` to be enabled, you should set this to `localhost` or `127.1`
    pub bind_address: String,
    /// Clash router working mode
    /// Either `rule`, `global` or `direct`
    pub mode: RunMode,
    /// Log level
    /// Either `debug`, `info`, `warning`, `error` or `off`
    pub log_level: LogLevel,
    /// DNS client/server settings
    pub dns: DNS,
    /// Profile settings
    pub profile: Profile,
    /// Proxy settings
    #[serde(rename = "proxies")]
    pub proxy: Vec<HashMap<String, Value>>,
    #[serde(rename = "proxy-groups")]
    /// Proxy group settings
    pub proxy_group: Vec<HashMap<String, Value>>,
    #[serde(rename = "rules")]
    /// Rule settings
    pub rule: Vec<String>,
    /// Hosts
    pub hosts: HashMap<String, String>,
    /// Country database path relative to the $CWD
    pub mmdb: String,
    /// Country database download url
    pub mmdb_download_url: Option<String>,

    /// these options has default vals,
    /// and needs extra processing
    #[deprecated = "this is essentially just dns.ipv6 in original clash"]
    pub ipv6: Option<bool>,
    /// external controller address
    pub external_controller: Option<String>,
    /// dashboard folder path relative to the $CWD
    pub external_ui: Option<String>,
    /// external controller secret
    pub secret: Option<String>,
    #[serde(rename = "interface-name")]
    /// outbound interface name
    /// # Note
    /// - not implemented yet
    pub interface: Option<String>,
    /// fwmark on Linux only
    /// # Note
    /// - not implemented yet
    pub routing_mask: Option<u32>,
    #[serde(rename = "proxy-providers")]
    /// proxy provider settings
    pub proxy_provider: Option<HashMap<String, HashMap<String, Value>>>,
    #[serde(rename = "rule-providers")]
    /// rule provider settings
    pub rule_provider: Option<HashMap<String, HashMap<String, Value>>>,
    /// experimental settings, if any
    pub experimental: Option<Experimental>,

    /// tun settings
    /// # Example
    /// ```yaml
    /// tun:
    ///   enable: true
    ///   device-id: "dev://utun1989"
    /// ```
    pub tun: Option<HashMap<String, Value>>,
    pub iptables: Iptables,
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(value)?;
        let config = content.parse::<Config>()?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s).map_err(|x| {
            Error::InvalidConfig(format!("cound not parse config content {}: {}", s, x))
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        #[allow(deprecated)]
        Self {
            port: Default::default(),
            socks_port: Default::default(),
            redir_port: Default::default(),
            tproxy_port: Default::default(),
            mixed_port: Default::default(),
            authentication: Default::default(),
            allow_lan: Default::default(),
            bind_address: String::from("*"),
            mode: Default::default(),
            log_level: Default::default(),
            ipv6: Default::default(),
            external_controller: Default::default(),
            external_ui: Default::default(),
            secret: Default::default(),
            interface: Default::default(),
            routing_mask: Default::default(),
            proxy_provider: Default::default(),
            rule_provider: Default::default(),
            hosts: Default::default(),
            dns: Default::default(),
            experimental: Default::default(),
            profile: Default::default(),
            proxy: Default::default(),
            proxy_group: Default::default(),
            rule: Default::default(),
            mmdb: "Country.mmdb".to_string(),
            mmdb_download_url: Some(
                "https://github.com/Loyalsoldier/geoip/releases/download/202307271745/Country.mmdb"
                    .to_owned(),
            ),
            tun: Default::default(),
            iptables: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    Multiple(HashMap<String, String>),
}

/// DNS client/server settings
/// This section is optional. When not present, the DNS server will be disabled and system DNS config will be used
/// # Example
/// ```yaml
/// dns:
///   enable: true
///   ipv6: false # when the false, response to AAAA questions will be empty
///   listen:
///     udp: 127.0.0.1:5353
///     tcp: 127.0.0.1:5353
///     doh: 127.0.0.1:5354
///     dot: 127.0.0.1:5355
/// ```

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct DNS {
    /// When disabled, system DNS config will be used
    /// All other DNS related options will only be used when this is enabled
    pub enable: bool,
    /// When false, response to AAAA questions will be empty
    pub ipv6: bool,
    /// Whether to `Config::hosts` as when resolving hostnames
    pub user_hosts: bool,
    /// DNS servers
    pub nameserver: Vec<String>,
    /// Fallback DNS servers
    pub fallback: Vec<String>,
    /// Fallback DNS filter
    pub fallback_filter: FallbackFilter,
    /// DNS server listening address. If not present, the DNS server will be disabled.
    pub listen: Option<DNSListen>,
    /// Whether to use fake IP addresses
    pub enhanced_mode: DNSMode,
    /// Fake IP addresses pool CIDR
    pub fake_ip_range: String,
    /// Fake IP addresses filter
    pub fake_ip_filter: Vec<String>,
    /// Default nameservers, used to resolve DoH hostnames
    pub default_nameserver: Vec<String>,
    /// Lookup domains via specific nameservers
    pub nameserver_policy: HashMap<String, String>,
}

impl Default for DNS {
    fn default() -> Self {
        Self {
            enable: Default::default(),
            ipv6: Default::default(),
            user_hosts: true,
            nameserver: Default::default(),
            fallback: Default::default(),
            fallback_filter: Default::default(),
            listen: Default::default(),
            enhanced_mode: Default::default(),
            fake_ip_range: String::from("198.18.0.1/16"),
            fake_ip_filter: Default::default(),
            default_nameserver: vec![String::from("114.114.114.114"), String::from("8.8.8.8")],
            nameserver_policy: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct FallbackFilter {
    #[serde(rename = "geoip")]
    pub geo_ip: bool,
    #[serde(rename = "geoip-code")]
    pub geo_ip_code: String,
    #[serde(rename = "ipcidr")]
    pub ip_cidr: Vec<String>,
    pub domain: Vec<String>,
}

impl Default for FallbackFilter {
    fn default() -> Self {
        Self {
            geo_ip: true,
            geo_ip_code: String::from("CN"),
            ip_cidr: Default::default(),
            domain: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Experimental {}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct Profile {
    /// Store the `select` results in $CWD/cache.db
    pub store_selected: bool,
    /// persistence fakeip
    pub store_fake_ip: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            store_selected: true,
            store_fake_ip: false,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct Iptables {
    enable: bool,
    inbound_interface: String,
    bypass: Vec<String>,
}

impl Default for Iptables {
    fn default() -> Self {
        Self {
            enable: false,
            inbound_interface: "lo".to_owned(),
            bypass: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use super::Config;

    #[test]
    fn parse_simple() {
        let cfg = r#"
        port: 9090
        "#;
        let c = cfg.parse::<Config>().expect("should parse");
        assert_eq!(c.port, Some(9090));
    }

    #[test]
    fn parse_example() {
        let example_cfg = r###"
# Port of HTTP(S) proxy server on the local end
port: 7890

# Port of SOCKS5 proxy server on the local end
socks-port: 7891

# Transparent proxy server port for Linux and macOS (Redirect TCP and TProxy UDP)
# redir-port: 7892

# Transparent proxy server port for Linux (TProxy TCP and TProxy UDP)
# tproxy-port: 7893

# HTTP(S) and SOCKS4(A)/SOCKS5 server on the same port
# mixed-port: 7890

# authentication of local SOCKS5/HTTP(S) server
# authentication:
#  - "user1:pass1"
#  - "user2:pass2"

# Set to true to allow connections to the local-end server from
# other LAN IP addresses
allow-lan: false

tun:
  enable: true
  stack: system
  device-url: dev://clash0
  dns-hijack:
    - 10.0.0.5

# This is only applicable when `allow-lan` is `true`
# '*': bind all IP addresses
# 192.168.122.11: bind a single IPv4 address
# "[aaaa::a8aa:ff:fe09:57d8]": bind a single IPv6 address
bind-address: '*'

# Clash router working mode
# rule: rule-based packet routing
# global: all packets will be forwarded to a single endpoint
# direct: directly forward the packets to the Internet
mode: rule

# Clash by default prints logs to STDOUT
# info / warning / error / debug / silent
log-level: info

# When set to false, resolver won't translate hostnames to IPv6 addresses
ipv6: false

# RESTful web API listening address
external-controller: 127.0.0.1:9090

# A relative path to the configuration directory or an absolute path to a
# directory in which you put some static web resource. Clash core will then
# serve it at `http://{{external-controller}}/ui`.
external-ui: folder

# Secret for the RESTful API (optional)
# Authenticate by spedifying HTTP header `Authorization: Bearer ${secret}`
# ALWAYS set a secret if RESTful API is listening on 0.0.0.0
# secret: ""

# Outbound interface name
interface-name: en0

# fwmark on Linux only
routing-mark: 6666

# Static hosts for DNS server and connection establishment (like /etc/hosts)
#
# Wildcard hostnames are supported (e.g. *.clash.dev, *.foo.*.example.com)
# Non-wildcard domain names have a higher priority than wildcard domain names
# e.g. foo.example.com > *.example.com > .example.com
# P.S. +.foo.com equals to .foo.com and foo.com
hosts:
  # '*.clash.dev': 127.0.0.1
  # '.dev': 127.0.0.1
  # 'alpha.clash.dev': '::1'

profile:
  # Store the `select` results in $HOME/.config/clash/.cache
  # set false If you don't want this behavior
  # when two different configurations have groups with the same name, the selected values are shared
  store-selected: false

  # persistence fakeip
  store-fake-ip: true

# DNS server settings
# This section is optional. When not present, the DNS server will be disabled.
dns:
  enable: false
  listen: 0.0.0.0:53
  # ipv6: false # when the false, response to AAAA questions will be empty

  # These nameservers are used to resolve the DNS nameserver hostnames below.
  # Specify IP addresses only
  default-nameserver:
    - 114.114.114.114
    - 8.8.8.8
  enhanced-mode: fake-ip # or redir-host (not recommended)
  fake-ip-range: 198.18.0.1/16 # Fake IP addresses pool CIDR
  # use-hosts: true # lookup hosts and return IP record
  
  # Hostnames in this list will not be resolved with fake IPs
  # i.e. questions to these domain names will always be answered with their
  # real IP addresses
  # fake-ip-filter:
  #   - '*.lan'
  #   - localhost.ptlogin2.qq.com
  
  # Supports UDP, TCP, DoT, DoH. You can specify the port to connect to.
  # All DNS questions are sent directly to the nameserver, without proxies
  # involved. Clash answers the DNS question with the first result gathered.
  nameserver:
    - 114.114.114.114 # default value
    - 8.8.8.8 # default value
    - tls://dns.rubyfish.cn:853 # DNS over TLS
    - https://1.1.1.1/dns-query # DNS over HTTPS
    - dhcp://en0 # dns from dhcp
    # - '8.8.8.8#en0'

  # When `fallback` is present, the DNS server will send concurrent requests
  # to the servers in this section along with servers in `nameservers`.
  # The answers from fallback servers are used when the GEOIP country
  # is not `CN`.
  # fallback:
  #   - tcp://1.1.1.1
  #   - 'tcp://1.1.1.1#en0'

  # If IP addresses resolved with servers in `nameservers` are in the specified
  # subnets below, they are considered invalid and results from `fallback`
  # servers are used instead.
  #
  # IP address resolved with servers in `nameserver` is used when
  # `fallback-filter.geoip` is true and when GEOIP of the IP address is `CN`.
  #
  # If `fallback-filter.geoip` is false, results from `nameserver` nameservers
  # are always used if not match `fallback-filter.ipcidr`.
  #
  # This is a countermeasure against DNS pollution attacks.
  # fallback-filter:
  #   geoip: true
  #   geoip-code: CN
  #   ipcidr:
  #     - 240.0.0.0/4
  #   domain:
  #     - '+.google.com'
  #     - '+.facebook.com'
  #     - '+.youtube.com'
  
  # Lookup domains via specific nameservers
  # nameserver-policy:
  #   'www.baidu.com': '114.114.114.114'
  #   '+.internal.crop.com': '10.0.0.1'

proxies:
  # Shadowsocks
  # The supported ciphers (encryption methods):
  #   aes-128-gcm aes-192-gcm aes-256-gcm
  #   aes-128-cfb aes-192-cfb aes-256-cfb
  #   aes-128-ctr aes-192-ctr aes-256-ctr
  #   rc4-md5 chacha20-ietf xchacha20
  #   chacha20-ietf-poly1305 xchacha20-ietf-poly1305
  - name: "ss1"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    # udp: true

  - name: "ss2"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: obfs
    plugin-opts:
      mode: tls # or http
      # host: bing.com

  - name: "ss3"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket # no QUIC now
      # tls: true # wss
      # skip-cert-verify: true
      # host: bing.com
      # path: "/"
      # mux: true
      # headers:
      #   custom: value

  # vmess
  # cipher support auto/aes-128-gcm/chacha20-poly1305/none
  - name: "vmess"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    # udp: true
    # tls: true
    # skip-cert-verify: true
    # servername: example.com # priority over wss host
    # network: ws
    # ws-opts:
    #   path: /path
    #   headers:
    #     Host: v2ray.com
    #   max-early-data: 2048
    #   early-data-header-name: Sec-WebSocket-Protocol

  - name: "vmess-h2"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    network: h2
    tls: true
    h2-opts:
      host:
        - http.example.com
        - http-alt.example.com
      path: /
  
  - name: "vmess-http"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    # udp: true
    # network: http
    # http-opts:
    #   # method: "GET"
    #   # path:
    #   #   - '/'
    #   #   - '/video'
    #   # headers:
    #   #   Connection:
    #   #     - keep-alive

  - name: vmess-grpc
    server: server
    port: 443
    type: vmess
    uuid: uuid
    alterId: 32
    cipher: auto
    network: grpc
    tls: true
    servername: example.com
    # skip-cert-verify: true
    grpc-opts:
      grpc-service-name: "example"

  # socks5
  - name: "socks"
    type: socks5
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true
    # skip-cert-verify: true
    # udp: true

  # http
  - name: "http"
    type: http
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true # https
    # skip-cert-verify: true
    # sni: custom.com

  # Snell
  # Beware that there's currently no UDP support yet
  - name: "snell"
    type: snell
    server: server
    port: 44046
    psk: yourpsk
    # version: 2
    # obfs-opts:
      # mode: http # or tls
      # host: bing.com

  # Trojan
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    # udp: true
    # sni: example.com # aka server name
    # alpn:
    #   - h2
    #   - http/1.1
    # skip-cert-verify: true

  - name: trojan-grpc
    server: server
    port: 443
    type: trojan
    password: "example"
    network: grpc
    sni: example.com
    # skip-cert-verify: true
    udp: true
    grpc-opts:
      grpc-service-name: "example"

  - name: trojan-ws
    server: server
    port: 443
    type: trojan
    password: "example"
    network: ws
    sni: example.com
    # skip-cert-verify: true
    udp: true
    # ws-opts:
      # path: /path
      # headers:
      #   Host: example.com

  # ShadowsocksR
  # The supported ciphers (encryption methods): all stream ciphers in ss
  # The supported obfses:
  #   plain http_simple http_post
  #   random_head tls1.2_ticket_auth tls1.2_ticket_fastauth
  # The supported supported protocols:
  #   origin auth_sha1_v4 auth_aes128_md5
  #   auth_aes128_sha1 auth_chain_a auth_chain_b  
  - name: "ssr"
    type: ssr
    server: server
    port: 443
    cipher: chacha20-ietf
    password: "password"
    obfs: tls1.2_ticket_auth
    protocol: auth_sha1_v4
    # obfs-param: domain.tld
    # protocol-param: "#"
    # udp: true

proxy-groups:
  # relay chains the proxies. proxies shall not contain a relay. No UDP support.
  # Traffic: clash <-> http <-> vmess <-> ss1 <-> ss2 <-> Internet
  - name: "relay"
    type: relay
    proxies:
      - http
      - vmess
      - ss1
      - ss2

  # url-test select which proxy will be used by benchmarking speed to a URL.
  - name: "auto"
    type: url-test
    proxies:
      - ss1
      - ss2
      - vmess1
    # tolerance: 150
    # lazy: true
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  # fallback selects an available policy by priority. The availability is tested by accessing an URL, just like an auto url-test group.
  - name: "fallback-auto"
    type: fallback
    proxies:
      - ss1
      - ss2
      - vmess1
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  # load-balance: The request of the same eTLD+1 will be dial to the same proxy.
  - name: "load-balance"
    type: load-balance
    proxies:
      - ss1
      - ss2
      - vmess1
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    # strategy: consistent-hashing # or round-robin

  # select is used for selecting proxy or proxy group
  # you can use RESTful API to switch proxy is recommended for use in GUI.
  - name: Proxy
    type: select
    # disable-udp: true
    proxies:
      - ss1
      - ss2
      - vmess1
      - auto
 
  # direct to another infacename or fwmark, also supported on proxy
  - name: en1
    type: select
    interface-name: en1
    routing-mark: 6667
    proxies:
      - DIRECT 

  - name: UseProvider
    type: select
    use:
      - provider1
    proxies:
      - Proxy
      - DIRECT

proxy-providers:
  provider1:
    type: http
    url: "url"
    interval: 3600
    path: ./provider1.yaml
    health-check:
      enable: true
      interval: 600
      # lazy: true
      url: http://www.gstatic.com/generate_204
  test:
    type: file
    path: /test.yaml
    health-check:
      enable: true
      interval: 36000
      url: http://www.gstatic.com/generate_204

rules:
  - DOMAIN-SUFFIX,google.com,auto
  - DOMAIN-KEYWORD,google,auto
  - DOMAIN,google.com,auto
  - DOMAIN-SUFFIX,ad.com,REJECT
  - SRC-IP-CIDR,192.168.1.201/32,DIRECT
  # optional param "no-resolve" for IP rules (GEOIP, IP-CIDR, IP-CIDR6)
  - IP-CIDR,127.0.0.0/8,DIRECT
  - GEOIP,CN,DIRECT
  - DST-PORT,80,DIRECT
  - SRC-PORT,7777,DIRECT
  - RULE-SET,apple,REJECT # Premium only
  - MATCH,auto
  "###;

        let des: Config = serde_yaml::from_str(example_cfg).expect("should parse yaml");
        assert_eq!(des.port.expect("invalid port"), 7890);
        assert_eq!(des.dns.fallback_filter.geo_ip_code, String::from("CN"));
        assert_eq!(des.proxy.len(), 14);
        assert_eq!(des.proxy[2].get("name").unwrap().as_str(), Some("ss3"));
        assert_eq!(
            des.proxy[2]
                .get("plugin-opts")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&Value::String("mode".into()))
                .unwrap()
                .as_str(),
            Some("websocket")
        );
    }
}
