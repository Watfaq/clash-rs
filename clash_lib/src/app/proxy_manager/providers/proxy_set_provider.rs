use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::{future, TryFutureExt};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use tokio::sync::Mutex;

use super::{
    fether::Fetcher, proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType,
    ThreadSafeProviderVehicle,
};
use crate::{
    app::proxy_manager::{healthcheck::HealthCheck, ProxyManager},
    common::errors::map_io_error,
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{direct, reject, AnyOutboundHandler},
    Error,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    #[serde(rename = "proxies")]
    proxies: Option<Vec<HashMap<String, Value>>>,
}

struct FileProviderInner {
    proxies: Vec<AnyOutboundHandler>,
}

struct ProxySetProvider {
    fetcher: Fetcher<
        Box<dyn Fn(Vec<AnyOutboundHandler>) + Send + Sync + 'static>,
        Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static>,
    >,
    healthcheck: HealthCheck,
    inner: std::sync::Arc<tokio::sync::Mutex<FileProviderInner>>,
    proxy_registry: Arc<Mutex<ProxyManager>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        mut hc: HealthCheck,
        proxy_registry: Arc<Mutex<ProxyManager>>,
    ) -> anyhow::Result<Self> {
        if hc.auto() {
            hc.kick_off();
        }

        let inner = Arc::new(tokio::sync::Mutex::new(FileProviderInner {
            proxies: vec![],
        }));

        let inner_clone = inner.clone();

        let updater: Box<dyn Fn(Vec<AnyOutboundHandler>) + Send + Sync + 'static> =
            Box::new(move |input: Vec<AnyOutboundHandler>| -> () {
                let inner = inner_clone.clone();
                tokio::spawn(future::lazy(|_| async move {
                    let mut inner = inner.lock().await;
                    inner.proxies = input;
                }));
            });

        let n = name.clone();
        let parser: Box<
            dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
        > = Box::new(
            move |input: &[u8]| -> anyhow::Result<Vec<AnyOutboundHandler>> {
                let scheme: ProviderScheme = serde_yaml::from_slice(input)?;
                let proxies = scheme.proxies;
                if let Some(proxies) = proxies {
                    let proxies = proxies
                        .into_iter()
                        .filter_map(|x| OutboundProxyProtocol::try_from(x).ok())
                        .map(|x| match x {
                            OutboundProxyProtocol::Direct => Ok(direct::Handler::new()),
                            OutboundProxyProtocol::Reject => Ok(reject::Handler::new()),
                            OutboundProxyProtocol::Ss(s) => s.try_into(),
                            OutboundProxyProtocol::Socks5(_) => todo!(),
                            OutboundProxyProtocol::Trojan(_) => todo!(),
                        })
                        .collect::<Result<Vec<_>, _>>();
                    Ok(proxies?)
                } else {
                    return Err(Error::InvalidConfig(format!("{}: proxies is empty", n)).into());
                }
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater.into()));
        Ok(Self {
            fetcher,
            healthcheck: hc,
            inner,
            proxy_registry,
        })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    async fn name(&self) -> &str {
        self.fetcher.name()
    }

    async fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type().await
    }

    async fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&mut self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().map_err(map_io_error).await?;
        if let Some(updater) = self.fetcher.on_update.clone().lock().await.as_ref() {
            updater(ele);
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().map_err(map_io_error).await?;
        if !same {
            if let Some(updater) = self.fetcher.on_update.clone().lock().await.as_ref() {
                updater(ele);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.inner
            .lock()
            .await
            .proxies
            .iter()
            .map(|x| x.clone())
            .collect()
    }

    async fn touch(&mut self) {
        self.healthcheck.touch().await;
    }

    async fn healthcheck(&self) {
        self.proxy_registry
            .lock()
            .await
            .check(&self.proxies().await)
            .await;
    }
}
