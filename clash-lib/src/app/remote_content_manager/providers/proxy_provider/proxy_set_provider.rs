use super::ProxyProvider;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "ssh")]
use crate::proxy::ssh;
#[cfg(feature = "onion")]
use crate::proxy::tor;
#[cfg(feature = "tuic")]
use crate::proxy::tuic;
#[cfg(feature = "wireguard")]
use crate::proxy::wg;
use crate::{
    Error,
    app::remote_content_manager::{
        healthcheck::HealthCheck,
        providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
    },
    common::errors::map_io_error,
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{
        AnyOutboundHandler, direct::DIRECT_OUTBOUND_HANDLER, hysteria2, reject,
        socks, trojan, vmess,
    },
};
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    #[serde(rename = "proxies")]
    proxies: Option<Vec<HashMap<String, Value>>>,
}

struct Inner {
    proxies: Vec<AnyOutboundHandler>,
    hc: Arc<HealthCheck>,
}

type ProxyUpdater = Box<
    dyn Fn(Vec<AnyOutboundHandler>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
>;
type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    inner: Arc<tokio::sync::RwLock<Inner>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if hc.auto() {
            let hc = hc.clone();
            debug!("kicking off healthcheck for: {}", &name);
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        let inner = Arc::new(tokio::sync::RwLock::new(Inner {
            proxies: vec![],
            hc: hc.clone(),
        }));

        let inner_clone = inner.clone();

        let n = name.clone();
        let updater: ProxyUpdater = Box::new(
            move |input: Vec<AnyOutboundHandler>| -> BoxFuture<'static, ()> {
                let hc = hc.clone();
                let n = n.clone();
                let inner: Arc<tokio::sync::RwLock<Inner>> = inner_clone.clone();
                Box::pin(async move {
                    let mut inner = inner.write().await;
                    debug!("updating {} proxies for: {}", n, input.len());
                    inner.proxies.clone_from(&input);
                    hc.update(input).await;
                    // check once after update
                    tokio::spawn(async move {
                        hc.check().await;
                    });
                })
            },
        );

        let n = name.clone();
        let parser: ProxyParser = Box::new(
            move |input: &[u8]| -> anyhow::Result<Vec<AnyOutboundHandler>> {
                let scheme: ProviderScheme =
                    serde_yaml::from_slice(input).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "proxy provider parse error {n}: {x}"
                        ))
                    })?;
                let proxies = scheme.proxies;
                match proxies {
                    Some(proxies) => {
                        let proxies = proxies
                            .into_iter()
                            .filter_map(|x| OutboundProxyProtocol::try_from(x).ok())
                            .map(|x| match x {
                                OutboundProxyProtocol::Direct => {
                                    Ok(Arc::new(DIRECT_OUTBOUND_HANDLER.clone())
                                        as _)
                                }
                                OutboundProxyProtocol::Reject => {
                                    Ok(Arc::new(reject::Handler::new()) as _)
                                }
                                #[cfg(feature = "shadowsocks")]
                                OutboundProxyProtocol::Ss(s) => {
                                    let h: shadowsocks::outbound::Handler =
                                        s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Socks5(s) => {
                                    let h: socks::outbound::Handler =
                                        s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Trojan(tr) => {
                                    let h: trojan::Handler = tr.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Vmess(vm) => {
                                    let h: vmess::Handler = vm.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Hysteria2(h) => {
                                    let h: hysteria2::Handler = h.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "ssh")]
                                OutboundProxyProtocol::Ssh(s) => {
                                    let h: ssh::Handler = s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "wireguard")]
                                OutboundProxyProtocol::Wireguard(wg) => {
                                    let h: wg::Handler = wg.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "onion")]
                                OutboundProxyProtocol::Tor(tor) => {
                                    let h: tor::Handler = tor.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "tuic")]
                                OutboundProxyProtocol::Tuic(tuic) => {
                                    let h: tuic::Handler = tuic.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "shadowquic")]
                                OutboundProxyProtocol::ShadowQuic(sq) => {
                                    let h: crate::proxy::shadowquic::Handler =
                                        sq.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                            })
                            .collect::<Result<Vec<_>, crate::Error>>();
                        Ok(proxies?)
                    }
                    _ => Err(Error::InvalidConfig(format!("{n}: proxies is empty"))
                        .into()),
                }
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));
        Ok(Self { fetcher, inner })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized with {} proxies", self.name(), ele.len());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} proxies, same? {}",
            self.name(),
            ele.len(),
            same
        );
        if !same && let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        m.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );

        m
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.inner.read().await.proxies.to_vec()
    }

    async fn touch(&self) {
        self.inner.read().await.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.inner.read().await.hc.check().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::time::sleep;

    use crate::app::{
        dns::MockClashResolver,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                MockProviderVehicle, Provider, ProviderVehicleType,
                proxy_provider::{
                    ProxyProvider, proxy_set_provider::ProxySetProvider,
                },
            },
        },
    };

    #[tokio::test]
    async fn test_proxy_set_provider() {
        let mut mock_vehicle = MockProviderVehicle::new();

        mock_vehicle.expect_read().returning(|| {
            Ok(r#"
proxies:
  - name: "ss"
    type: ss
    server: localhost
    port: 8388
    cipher: aes-256-gcm
    password: "password"
    udp: true
"#
            .as_bytes()
            .to_vec())
        });
        mock_vehicle
            .expect_path()
            .return_const("/tmp/test_proxy_set_provider".to_owned());
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let vehicle = Arc::new(mock_vehicle);

        let mock_resolver = MockClashResolver::new();

        let latency_manager = ProxyManager::new(Arc::new(mock_resolver));
        let hc = HealthCheck::new(
            vec![],
            "http://www.google.com".to_owned(),
            0,
            true,
            latency_manager.clone(),
        );

        let provider = ProxySetProvider::new(
            "test".to_owned(),
            Duration::from_secs(1),
            vehicle,
            hc,
        )
        .unwrap();

        assert_eq!(provider.proxies().await.len(), 0);

        provider.initialize().await.unwrap();

        sleep(Duration::from_secs_f64(1.5)).await;

        assert_eq!(provider.proxies().await.len(), 1);
    }
}
