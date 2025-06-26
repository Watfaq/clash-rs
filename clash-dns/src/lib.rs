use hickory_proto::op::Message;
use serde::Deserialize;
use std::{future::Future, net::SocketAddr};

mod dummy_keys;

mod handler;

#[cfg(test)]
mod tls;
mod utils;

pub use handler::{DNSError, get_dns_listener};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoHConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoH3Config {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DoTConfig {
    pub addr: SocketAddr,
    pub ca_cert: DnsServerCert,
    pub ca_key: DnsServerKey,
}

pub type DnsServerKey = Option<String>;
pub type DnsServerCert = Option<String>;

#[derive(Debug, Default, Clone)]
pub struct DNSListenAddr {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub doh: Option<DoHConfig>,
    pub dot: Option<DoTConfig>,
    pub doh3: Option<DoH3Config>,
}

#[cfg_attr(test, mockall::automock)]
pub trait DnsMessageExchanger {
    fn ipv6(&self) -> bool;
    fn exchange(
        &self,
        message: &Message,
    ) -> impl Future<Output = Result<Message, DNSError>> + Send;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

    pub(crate) fn setup_default_crypto_provider() {
        CRYPTO_PROVIDER_LOCK.get_or_init(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .unwrap()
        });
    }
}
