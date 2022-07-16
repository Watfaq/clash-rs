use crate::config::internal::config::BindInterface;
use crate::Error;
use serde::de::value::MapDeserializer;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub const PROXY_DIRECT: &str = "DIRECT";
pub const PROXY_REJECT: &str = "REJECT";
pub const PROXY_GLOBAL: &str = "GLOBAL";

pub enum OutboundProxy {
    ProxyServer(OutboundProxyProtocol),
    ProxyGroup(OutboundGroupProtocol),
}

impl OutboundProxy {
    pub(crate) fn name(&self) -> &str {
        match self {
            OutboundProxy::ProxyServer(s) => s.to_string().as_str(),
            OutboundProxy::ProxyGroup(g) => g.to_string().as_str(),
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
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProtocol {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into()))
    }
}

impl Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundProxyProtocol::Ss(ss) => write!(f, "{}", ss.name),
            OutboundProxyProtocol::Socks5(s5) => write!(f, "{}", s5.name),
            OutboundProxyProtocol::Direct => write!(f, "{}", PROXY_DIRECT),
            OutboundProxyProtocol::Reject => write!(f, "{}", PROXY_REJECT),
        }
    }
}

pub struct OutboundShadowsocks {
    pub name: String,
}
pub struct OutboundSocks5 {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub skip_cert_verity: bool,
    pub udp: bool,
}

impl Default for OutboundSocks5 {
    fn default() -> Self {
        Self {
            server: Default::default(),
            port: Default::default(),
            username: Default::default(),
            password: Default::default(),
            tls: Default::default(),
            skip_cert_verity: Default::default(),
            udp: Default::default(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
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

impl TryFrom<HashMap<String, Value>> for OutboundGroupProtocol {
    type Error = Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        OutboundGroupProtocol::deserialize(MapDeserializer::new(mapping.into()))
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

pub struct OutboundGroupRelay {
    pub name: String,
    pub proxies: Vec<String>,
}

pub struct OutboundGroupUrlTest {
    pub name: String,

    pub proxies: Vec<String>,
    pub url: String,
    pub interval: i32,
    pub tolerance: Option<i32>,
    pub lazy: bool,
}

pub struct OutboundGroupFallback {
    pub name: String,

    pub proxies: Vec<String>,
    pub url: String,
    pub interval: i32,
}

pub struct OutboundGroupLoadBalance {
    pub name: String,

    pub proxies: Vec<String>,
    pub url: String,
    pub interval: i32,
    pub strategy: LoadBalanceStrategy,
}

pub enum LoadBalanceStrategy {
    ConsistentHashing,
    RoundRobin,
}

pub struct OutboundGroupSelect {
    pub name: String,

    pub proxies: Vec<String>,
    pub iface: Option<String>,
    pub routing_mask: Option<i32>,
    pub proxy_provider: Option<Vec<String>>,
    pub disable_udp: bool,
}
