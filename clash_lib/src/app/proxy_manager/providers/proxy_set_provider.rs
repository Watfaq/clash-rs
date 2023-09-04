use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use tracing::debug;

use super::{
    fether::Fetcher, proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType,
    ThreadSafeProviderVehicle,
};
use crate::{
    app::proxy_manager::healthcheck::HealthCheck,
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

struct Inner {
    proxies: Vec<AnyOutboundHandler>,
    hc: Arc<HealthCheck>,
}

pub struct ProxySetProvider {
    fetcher: Fetcher<
        Box<dyn Fn(Vec<AnyOutboundHandler>) + Send + Sync + 'static>,
        Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static>,
    >,
    inner: std::sync::Arc<tokio::sync::Mutex<Inner>>,
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
            debug!("kicking off healthcheck for: {}", name);
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        let inner = Arc::new(tokio::sync::Mutex::new(Inner {
            proxies: vec![],
            hc: hc.clone(),
        }));

        let inner_clone = inner.clone();

        let updater: Box<dyn Fn(Vec<AnyOutboundHandler>) + Send + Sync + 'static> =
            Box::new(move |input: Vec<AnyOutboundHandler>| -> () {
                let hc = hc.clone();
                let inner = inner_clone.clone();
                tokio::spawn(async move {
                    let mut inner = inner.lock().await;
                    inner.proxies = input.clone();
                    hc.update(input).await;
                });
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
                            OutboundProxyProtocol::Socks5(_) => todo!("socks5 not supported yet"),
                            OutboundProxyProtocol::Trojan(_) => todo!("trojan not supported yet"),
                            OutboundProxyProtocol::Vmess(vm) => vm.try_into(),
                        })
                        .collect::<Result<Vec<_>, _>>();
                    Ok(proxies?)
                } else {
                    return Err(Error::InvalidConfig(format!("{}: proxies is empty", n)).into());
                }
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater.into()));
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
        self.inner
            .lock()
            .await
            .proxies
            .iter()
            .map(|x| x.clone())
            .collect()
    }

    async fn touch(&self) {
        self.inner.lock().await.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.inner.lock().await.hc.check().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::time::sleep;

    use crate::app::{
        dns::MockClashResolver,
        proxy_manager::{
            healthcheck::HealthCheck,
            providers::{
                proxy_provider::ProxyProvider, proxy_set_provider::ProxySetProvider,
                MockProviderVehicle, Provider, ProviderVehicleType,
            },
            ProxyManager,
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

        let latency_manager = Arc::new(ProxyManager::new(Arc::new(mock_resolver)));
        let hc = HealthCheck::new(
            vec![],
            "http://www.google.com".to_owned(),
            0,
            true,
            latency_manager.clone(),
        )
        .unwrap();

        let mut provider =
            ProxySetProvider::new("test".to_owned(), Duration::from_secs(1), vehicle, hc).unwrap();

        assert_eq!(provider.proxies().await.len(), 0);

        provider.initialize().await.unwrap();

        sleep(Duration::from_secs_f64(1.5)).await;

        assert_eq!(provider.proxies().await.len(), 1);
    }
}
