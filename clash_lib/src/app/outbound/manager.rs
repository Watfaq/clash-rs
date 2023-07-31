use anyhow::Result;
use http::Uri;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use crate::app::proxy_manager::healthcheck::HealthCheck;
use crate::app::proxy_manager::providers::file_vehicle;
use crate::app::proxy_manager::providers::http_vehicle;
use crate::app::proxy_manager::providers::plain_provider::PlainProvider;
use crate::app::proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider;
use crate::app::proxy_manager::providers::proxy_set_provider::ProxySetProvider;
use crate::app::proxy_manager::ProxyManager;
use crate::config::internal::proxy::{OutboundProxyProvider, PROXY_DIRECT, PROXY_REJECT};
use crate::proxy::{reject, relay};
use crate::{
    app::ThreadSafeDNSResolver,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, AnyOutboundHandler},
    Error,
};

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    proxy_manager: Arc<Mutex<ProxyManager>>,
}

static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

pub type ThreadSafeOutboundManager = Arc<RwLock<OutboundManager>>;

impl OutboundManager {
    pub async fn new(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProvider>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Result<Self, Error> {
        let mut handlers = HashMap::new();
        let mut provider_registry = HashMap::new();
        let proxy_manager = Arc::new(Mutex::new(ProxyManager::new()));

        Self::load_proxy_providers(
            proxy_providers,
            proxy_manager.clone(),
            dns_resolver.clone(),
            &mut provider_registry,
        )
        .await?;

        Self::load_handlers(
            outbounds,
            outbound_groups,
            proxy_manager.clone(),
            provider_registry,
            &mut handlers,
        )?;

        Ok(Self {
            handlers,
            proxy_manager,
        })
    }

    pub fn get(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).map(Clone::clone)
    }

    fn load_handlers(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_manager: Arc<Mutex<ProxyManager>>,
        provider_registry: HashMap<String, ThreadSafeProxyProvider>,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
    ) -> Result<(), Error> {
        for outbound in outbounds.iter() {
            match outbound {
                OutboundProxyProtocol::Direct => {
                    handlers.insert(PROXY_DIRECT.to_string(), direct::Handler::new());
                }

                OutboundProxyProtocol::Reject => {
                    handlers.insert(PROXY_REJECT.to_string(), reject::Handler::new());
                }

                OutboundProxyProtocol::Ss(s) => {
                    handlers.insert(s.name.clone(), s.try_into()?);
                }

                p => {
                    debug!("proto {} not supported yet", p);
                }
            }
        }

        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        let proxies = proxies
                            .into_iter()
                            .map(|x| {
                                handlers
                                    .get(x)
                                    .expect(format!("proxy {} not found", x).as_str())
                                    .clone()
                            })
                            .collect::<Vec<_>>();

                        let provider = PlainProvider::new(
                            proto.name.clone(),
                            proxies,
                            proxy_manager.clone(),
                            DEFAULT_LATENCY_TEST_URL.to_owned(),
                        )
                        .map_err(|x| {
                            Error::InvalidConfig(format!("invalid provider config: {}", x))
                        })?;

                        providers.push(Arc::new(provider));
                    }

                    if let Some(provider_names) = &proto.use_provider {
                        for provider_name in provider_names {
                            let provider = provider_registry
                                .get(provider_name)
                                .expect(format!("provider {} not found", provider_name).as_str())
                                .clone();
                            providers.push(provider);
                        }
                    }

                    let relay = relay::Handler::new(
                        relay::HandlerOptions {
                            name: proto.name.clone(),
                            ..Default::default()
                        },
                        providers,
                    );

                    handlers.insert(proto.name.clone(), relay);
                }
                OutboundGroupProtocol::UrlTest(_proto) => todo!(),
                OutboundGroupProtocol::Fallback(_proto) => todo!(),
                OutboundGroupProtocol::LoadBalance(_proto) => todo!(),
                OutboundGroupProtocol::Select(_proto) => todo!(),
            }
        }
        Ok(())
    }

    async fn load_proxy_providers(
        proxy_providers: HashMap<String, OutboundProxyProvider>,
        proxy_manager: Arc<Mutex<ProxyManager>>,
        resolver: ThreadSafeDNSResolver,
        provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
    ) -> Result<(), Error> {
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProvider::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url
                            .parse::<Uri>()
                            .expect(format!("invalid provider url: {}", http.url).as_str()),
                        http.path,
                        resolver.clone(),
                    );
                    let hc = HealthCheck::new(
                        vec![],
                        http.health_check.url,
                        http.health_check.interval,
                        true,
                        proxy_manager.clone(),
                    )
                    .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;
                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(http.interval),
                        Arc::new(Mutex::new(vehicle)),
                        hc,
                        proxy_manager.clone(),
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(provider));
                }
                OutboundProxyProvider::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(&file.path);
                    let hc = HealthCheck::new(
                        vec![],
                        file.health_check.url,
                        file.health_check.interval,
                        true,
                        proxy_manager.clone(),
                    )
                    .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;

                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(file.interval.unwrap_or_default()),
                        Arc::new(Mutex::new(vehicle)),
                        hc,
                        proxy_manager.clone(),
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(provider));
                }
            }
        }
        Ok(())
    }
}
