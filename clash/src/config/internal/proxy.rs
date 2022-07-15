use std::fmt::Display;

pub enum OutboundProtocol {
    Direct,
    Reject,
    Ss(String, OutboundShadowsocks),
    Socks5(String, OutboundSocks5),
}

impl Display for OutboundProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundProtocol::Ss(name, _) => write!(f, "{}", name),
            OutboundProtocol::Socks5(name, _) => write!(f, "{}", name),
            OutboundProtocol::Direct => write!(f, "Direct"),
            OutboundProtocol::Reject => write!(f, "Reject"),
        }
    }
}

pub struct OutboundShadowsocks {}
pub struct OutboundSocks5 {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub skip_cert_vefity: bool,
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
            skip_cert_vefity: Default::default(),
            udp: Default::default(),
        }
    }
}

pub enum OutboundGroupProtocol {
    Relay(String, OutboundGroupRelay),
    UrlTest(String, OutboundGroupUrlTest),
    Fallback(String, OutboundGroupFallback),
    LoadBalance(String, OutboundGroupLoadBalance),
    Select(String, OutboundGroupSelect),
}

pub struct OutboundGroupRelay {
    pub proxies: Vec<String>,
}

pub struct OutboundGroupUrlTest {
    pub proxies: Vec<String>,
    pub url: String,
    pub interval: i32,
    pub tolerance: Option<i32>,
    pub lazy: bool,
}

pub struct OutboundGroupFallback {
    pub proxies: Vec<String>,
    pub url: String,
    pub interval: i32,
}

pub struct OutboundGroupLoadBalance {
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
    pub proxies: Vec<String>,
    pub iface: Option<String>,
    pub routing_mask: Option<i32>,
    pub proxy_provider: Option<Vec<String>>,
    pub disable_udp: bool,
}
