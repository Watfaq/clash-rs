use anyhow::Result;
use erased_serde::Serialize;
use http::Uri;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use crate::app::proxy_manager::healthcheck::HealthCheck;
use crate::app::proxy_manager::providers::file_vehicle;
use crate::app::proxy_manager::providers::http_vehicle;
use crate::app::proxy_manager::providers::plain_provider::PlainProvider;
use crate::app::proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider;
use crate::app::proxy_manager::providers::proxy_set_provider::ProxySetProvider;
use crate::app::proxy_manager::ProxyManager;
use crate::app::proxy_manager::ThreadSafeProxyManager;
use crate::config::internal::proxy::PROXY_GLOBAL;
use crate::config::internal::proxy::{OutboundProxyProvider, PROXY_DIRECT, PROXY_REJECT};
use crate::proxy::fallback;
use crate::proxy::loadbalance;
use crate::proxy::selector;

use crate::proxy::selector::ThreadSafeSelectorControl;
use crate::proxy::urltest;
use crate::proxy::{reject, relay};
use crate::{
    app::ThreadSafeDNSResolver,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, AnyOutboundHandler},
    Error,
};

use super::utils::proxy_groups_dag_sort;

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    proxy_manager: ThreadSafeProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
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
        let mut selector_control = HashMap::new();
        let proxy_manager = Arc::new(Mutex::new(ProxyManager::new(dns_resolver.clone())));

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
            &mut selector_control,
        )
        .await?;

        Ok(Self {
            handlers,
            proxy_manager,
            selector_control,
        })
    }

    pub fn get(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).map(Clone::clone)
    }

    // API handles start
    pub fn get_selector_control(&self, name: &str) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).map(Clone::clone)
    }

    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        let proxy_manager = self.proxy_manager.lock().await;

        for (k, v) in self.handlers.iter() {
            let mut m = v.as_map();

            let alive = proxy_manager.alive(k).await;
            let history = proxy_manager.delay_history(k).await;
            let support_udp = v.support_udp().await;

            m.insert("history".to_string(), Box::new(history));
            m.insert("alive".to_string(), Box::new(alive));
            m.insert("name".to_string(), Box::new(k.to_owned()));
            m.insert("udp".to_string(), Box::new(support_udp));

            r.insert(k.clone(), Box::new(m) as _);
        }

        r
    }

    // API handlers end

    async fn load_handlers(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_manager: Arc<Mutex<ProxyManager>>,
        provider_registry: HashMap<String, ThreadSafeProxyProvider>,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        selector_control: &mut HashMap<String, ThreadSafeSelectorControl>,
    ) -> Result<(), Error> {
        let mut proxy_providers = vec![];

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

                OutboundProxyProtocol::Vmess(v) => {
                    handlers.insert(v.name.clone(), v.try_into()?);
                }

                p => {
                    unimplemented!("proto {} not supported yet", p);
                }
            }
        }

        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        for outbound_group in outbound_groups.iter() {
            fn make_provider_from_proxies(
                name: &str,
                proxies: &Vec<String>,
                handlers: &HashMap<String, AnyOutboundHandler>,
                proxy_manager: Arc<Mutex<ProxyManager>>,
                proxy_providers: &mut Vec<ThreadSafeProxyProvider>,
            ) -> Result<ThreadSafeProxyProvider, Error> {
                let proxies = proxies
                    .into_iter()
                    .map(|x| {
                        handlers
                            .get(x)
                            .expect(format!("proxy {} not found", x).as_str())
                            .clone()
                    })
                    .collect::<Vec<_>>();

                let hc = HealthCheck::new(
                    proxies.clone(),
                    DEFAULT_LATENCY_TEST_URL.to_owned(),
                    0, // this is a manual HC
                    true,
                    proxy_manager.clone(),
                )
                .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;

                let pd = Arc::new(Mutex::new(
                    PlainProvider::new(
                        name.to_owned(),
                        proxies,
                        proxy_manager,
                        DEFAULT_LATENCY_TEST_URL.to_owned(),
                        hc,
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?,
                ));

                proxy_providers.push(pd.clone());

                Ok(pd)
            }
            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                        )?);
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
                OutboundGroupProtocol::UrlTest(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                        )?);
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

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            ..Default::default()
                        },
                        proto.tolerance.unwrap_or_default(),
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(url_test));
                }
                OutboundGroupProtocol::Fallback(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                        )?);
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

                    let fallback = fallback::Handler::new(
                        fallback::HandlerOptions {
                            name: proto.name.clone(),
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(fallback));
                }
                OutboundGroupProtocol::LoadBalance(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                        )?);
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

                    let load_balance = loadbalance::Handler::new(
                        loadbalance::HandlerOptions {
                            name: proto.name.clone(),
                            ..Default::default()
                        },
                        providers,
                    );

                    handlers.insert(proto.name.clone(), Arc::new(load_balance));
                }
                OutboundGroupProtocol::Select(proto) => {
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                        )?);
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

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or_default(),
                            ..Default::default()
                        },
                        providers,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(Mutex::new(selector)));
                }
            }
        }

        let mut g = vec![];
        for handler in handlers.values() {
            g.push(handler.clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            proxy_manager.clone(),
        )
        .unwrap();
        let pd = PlainProvider::new(
            PROXY_GLOBAL.to_owned(),
            g,
            proxy_manager.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            hc,
        )
        .unwrap();

        handlers.insert(
            PROXY_GLOBAL.to_owned(),
            Arc::new(
                selector::Handler::new(
                    selector::HandlerOptions {
                        name: PROXY_GLOBAL.to_owned(),
                        udp: true,
                        ..Default::default()
                    },
                    vec![Arc::new(Mutex::new(pd))],
                )
                .await,
            ),
        );

        for provider in proxy_providers {
            info!("initializing provider {}", provider.lock().await.name());
            provider.lock().await.initialize().await?;
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
                        Arc::new(vehicle),
                        hc,
                        proxy_manager.clone(),
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(Mutex::new(provider)));
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
                        Arc::new(vehicle),
                        hc,
                        proxy_manager.clone(),
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(Mutex::new(provider)));
                }
            }
        }
        Ok(())
    }
}
