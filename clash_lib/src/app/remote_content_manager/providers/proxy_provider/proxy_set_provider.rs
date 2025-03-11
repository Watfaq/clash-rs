use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use tracing::debug;
use watfaq_error::Result;

use super::ProxyProvider;
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
    proxy::{AnyOutboundHandler, direct, reject, socks, trojan, vmess},
};

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "ssh")]
use crate::proxy::ssh;
#[cfg(feature = "onion")]
use crate::proxy::tor;
#[cfg(feature = "wireguard")]
use crate::proxy::wg;

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
    dyn Fn(&[u8]) -> Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    inner: std::sync::Arc<tokio::sync::RwLock<Inner>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
    ) -> Result<Self> {
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
            move |input: &[u8]| -> Result<Vec<AnyOutboundHandler>> {
                let scheme: ProviderScheme =
                    serde_yaml::from_slice(input).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "proxy provider parse error {}: {}",
                            n, x
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
                                    Ok(Arc::new(direct::Handler::new()) as _)
                                }
                                OutboundProxyProtocol::Reject => {
                                    Ok(Arc::new(reject::Handler::new()) as _)
                                }
                                #[cfg(feature = "shadowsocks")]
                                OutboundProxyProtocol::Ss(s) => {
                                    let h: shadowsocks::Handler = s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Socks5(s) => {
                                    let h: socks::Handler = s.try_into()?;
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
                                OutboundProxyProtocol::Hysteria2(h) => h.try_into(),
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
                                    let h: watfaq_tuic::Handler = tuic.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                            })
                            .collect::<Result<Vec<_>>>();
                        Ok(proxies?)
                    }
                    _ => {
                        Err(Error::InvalidConfig(format!("{}: proxies is empty", n))
                            .into())
                    }
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

    async fn initialize(&self) -> Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized with {} proxies", self.name(), ele.len());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater.lock().await(ele).await;
        }
        Ok(())
    }

    async fn update(&self) -> Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} proxies, same? {}",
            self.name(),
            ele.len(),
            same
        );
        if !same {
            if let Some(updater) = self.fetcher.on_update.as_ref() {
                let f = updater.lock().await;
                f(ele).await;
            }
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
