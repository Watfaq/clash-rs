use crate::common::utils::default_bool_true;
use crate::config::utils;
use crate::proxy::CommonOption;
use crate::Error;
use serde::de::value::MapDeserializer;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub const PROXY_DIRECT: &str = "DIRECT";
pub const PROXY_REJECT: &str = "REJECT";
pub const PROXY_GLOBAL: &str = "GLOBAL";

#[allow(clippy::large_enum_variant)]
pub enum OutboundProxy {
    ProxyServer(OutboundProxyProtocol),
    ProxyGroup(OutboundGroupProtocol),
}

impl OutboundProxy {
    pub(crate) fn name(&self) -> String {
        match self {
            OutboundProxy::ProxyServer(s) => s.name().to_string(),
            OutboundProxy::ProxyGroup(g) => g.name().to_string(),
        }
    }
}

pub fn map_serde_error(name: String) -> impl FnOnce(serde_yaml::Error) -> crate::Error {
    move |x| {
        if let Some(loc) = x.location() {
            Error::InvalidConfig(format!(
                "invalid config for {} at line {}, column {} while parsing {}",
                name,
                loc.line(),
                loc.column(),
                name
            ))
        } else {
            Error::InvalidConfig(format!("error while parsine {}: {}", name, x))
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum OutboundProxyProtocol {
    #[serde(skip)]
    Direct,
    #[serde(skip)]
    Reject,
    #[serde(rename = "ss")]
    Ss(OutboundShadowsocks),
    #[serde(rename = "socks5")]
    Socks5(OutboundSocks5),
    #[serde(rename = "trojan")]
    Trojan(OutboundTrojan),
    #[serde(rename = "vmess")]
    Vmess(OutboundVmess),
    #[serde(rename = "wireguard")]
    Wireguard(OutboundWireguard),
    #[serde(rename = "tor")]
    Tor(OutboundTor),
}

impl OutboundProxyProtocol {
    fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct => PROXY_DIRECT,
            OutboundProxyProtocol::Reject => PROXY_REJECT,
            OutboundProxyProtocol::Ss(ss) => &ss.name,
            OutboundProxyProtocol::Socks5(socks5) => &socks5.name,
            OutboundProxyProtocol::Trojan(trojan) => &trojan.name,
            OutboundProxyProtocol::Vmess(vmess) => &vmess.name,
            OutboundProxyProtocol::Wireguard(wireguard) => &wireguard.name,
            OutboundProxyProtocol::Tor(tor) => &tor.name,
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProtocol {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy protocol".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

impl Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundProxyProtocol::Ss(_) => write!(f, "Shadowsocks"),
            OutboundProxyProtocol::Socks5(_) => write!(f, "Socks5"),
            OutboundProxyProtocol::Direct => write!(f, "{}", PROXY_DIRECT),
            OutboundProxyProtocol::Reject => write!(f, "{}", PROXY_REJECT),
            OutboundProxyProtocol::Trojan(_) => write!(f, "Trojan"),
            OutboundProxyProtocol::Vmess(_) => write!(f, "Vmess"),
            OutboundProxyProtocol::Wireguard(_) => write!(f, "Wireguard"),
            OutboundProxyProtocol::Tor(_) => write!(f, "Tor"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct OutboundShadowsocks {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
    pub plugin: Option<String>,
    #[serde(alias = "plugin-opts")]
    pub plugin_opts: Option<HashMap<String, serde_yaml::Value>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct OutboundSocks5 {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub skip_cert_verity: bool,
    pub udp: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct WsOpt {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub max_early_data: Option<i32>,
    pub early_data_header_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct H2Opt {
    pub host: Option<Vec<String>>,
    pub path: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOpt {
    pub grpc_service_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrojan {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub udp: Option<bool>,
    pub network: Option<String>,
    pub grpc_opts: Option<GrpcOpt>,
    pub ws_opts: Option<WsOpt>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVmess {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(alias = "alterId")]
    pub alter_id: u16,
    pub cipher: Option<String>,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub network: Option<String>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub grpc_opts: Option<GrpcOpt>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundWireguard {
    #[serde(flatten)]
    pub common_opts: CommonOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub mtu: Option<u16>,
    pub udp: Option<bool>,
    pub ip: String,
    pub ipv6: Option<String>,
    pub remote_dns_resolve: Option<bool>,
    pub dns: Option<Vec<String>>,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTor {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {
    #[serde(rename = "relay")]
    Relay(OutboundGroupRelay),
    #[serde(rename = "url-test")]
    UrlTest(OutboundGroupUrlTest),
    #[serde(rename = "fallback")]
    Fallback(OutboundGroupFallback),
    #[serde(rename = "load-balance")]
    LoadBalance(OutboundGroupLoadBalance),
    #[serde(rename = "select")]
    Select(OutboundGroupSelect),
}

impl OutboundGroupProtocol {
    pub fn name(&self) -> &str {
        match &self {
            OutboundGroupProtocol::Relay(g) => &g.name,
            OutboundGroupProtocol::UrlTest(g) => &g.name,
            OutboundGroupProtocol::Fallback(g) => &g.name,
            OutboundGroupProtocol::LoadBalance(g) => &g.name,
            OutboundGroupProtocol::Select(g) => &g.name,
        }
    }

    pub fn proxies(&self) -> Option<&Vec<String>> {
        match &self {
            OutboundGroupProtocol::Relay(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::UrlTest(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Fallback(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::LoadBalance(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Select(g) => g.proxies.as_ref(),
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundGroupProtocol {
    type Error = Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy grouop".to_owned(),
            ))?
            .to_owned();
        OutboundGroupProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

impl Display for OutboundGroupProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundGroupProtocol::Relay(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::UrlTest(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Fallback(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::LoadBalance(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Select(g) => write!(f, "{}", g.name),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupRelay {
    pub name: String,
    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupUrlTest {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub tolerance: Option<u16>,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupFallback {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupLoadBalance {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub strategy: Option<LoadBalanceStrategy>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default)]
pub enum LoadBalanceStrategy {
    #[default]
    #[serde(rename = "consistent-hashing")]
    ConsistentHashing,
    #[serde(rename = "round-robin")]
    RoundRobin,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSelect {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub udp: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum OutboundProxyProviderDef {
    Http(OutboundHttpProvider),
    File(OutboundFileProvider),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: u64,
    pub path: String,
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct HealthCheck {
    pub enable: bool,
    pub url: String,
    pub interval: u64,
    pub lazy: Option<bool>,
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy provider".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
