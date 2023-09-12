use anyhow::Result;
use erased_serde::Serialize;
use http::Uri;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;
use tracing::info;

use crate::app::dns::ThreadSafeDNSResolver;
use crate::app::profile::ThreadSafeCacheFile;
use crate::app::proxy_manager::healthcheck::HealthCheck;
use crate::app::proxy_manager::providers::file_vehicle;
use crate::app::proxy_manager::providers::http_vehicle;
use crate::app::proxy_manager::providers::plain_provider::PlainProvider;
use crate::app::proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider;
use crate::app::proxy_manager::providers::proxy_set_provider::ProxySetProvider;
use crate::app::proxy_manager::ProxyManager;

use crate::config::internal::proxy::PROXY_GLOBAL;
use crate::config::internal::proxy::{OutboundProxyProvider, PROXY_DIRECT, PROXY_REJECT};
use crate::proxy::fallback;
use crate::proxy::loadbalance;
use crate::proxy::selector;

use crate::proxy::selector::ThreadSafeSelectorControl;
use crate::proxy::urltest;
use crate::proxy::{reject, relay};
use crate::{
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, AnyOutboundHandler},
    Error,
};

use super::utils::proxy_groups_dag_sort;

static RESERVED_PROVIDER_NAME: &str = "default";

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
}

static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

pub type ThreadSafeOutboundManager = Arc<RwLock<OutboundManager>>;

impl OutboundManager {
    pub async fn new(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProvider>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<Self, Error> {
        let mut handlers = HashMap::new();
        let mut provider_registry = HashMap::new();
        let mut selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone());

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
            proxy_names,
            proxy_manager.clone(),
            &mut provider_registry,
            &mut handlers,
            &mut selector_control,
            cache_store,
        )
        .await?;

        Ok(Self {
            handlers,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
        })
    }

    pub fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).map(Clone::clone)
    }

    /// this doesn't populate history/liveness information
    pub fn get_proxy_provider(&self, name: &str) -> Option<ThreadSafeProxyProvider> {
        self.proxy_providers.get(name).map(Clone::clone)
    }

    // API handles start
    pub fn get_selector_control(&self, name: &str) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).map(Clone::clone)
    }

    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        let proxy_manager = self.proxy_manager.clone();

        for (k, v) in self.handlers.iter() {
            let mut m = v.as_map().await;

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

    pub async fn get_proxy(
        &self,
        proxy: &AnyOutboundHandler,
    ) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = proxy.as_map().await;

        let proxy_manager = self.proxy_manager.clone();

        let alive = proxy_manager.alive(proxy.name()).await;
        let history = proxy_manager.delay_history(proxy.name()).await;
        let support_udp = proxy.support_udp().await;

        r.insert("history".to_string(), Box::new(history));
        r.insert("alive".to_string(), Box::new(alive));
        r.insert("name".to_string(), Box::new(proxy.name().to_owned()));
        r.insert("udp".to_string(), Box::new(support_udp));

        r
    }

    /// a wrapper of proxy_manager.url_test so that proxy_manager is not exposed
    pub async fn url_test(
        &self,
        proxy: AnyOutboundHandler,
        url: &str,
        timeout: Duration,
    ) -> std::io::Result<(u16, u16)> {
        let proxy_manager = self.proxy_manager.clone();

        proxy_manager.url_test(proxy, url, Some(timeout)).await
    }

    pub fn get_proxy_providers(&self) -> HashMap<String, ThreadSafeProxyProvider> {
        self.proxy_providers.clone()
    }

    // API handlers end

    async fn load_handlers(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        proxy_manager: ProxyManager,
        provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        selector_control: &mut HashMap<String, ThreadSafeSelectorControl>,
        cache_store: ThreadSafeCacheFile,
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
                interval: u64,
                lazy: bool,
                handlers: &HashMap<String, AnyOutboundHandler>,
                proxy_manager: ProxyManager,
                proxy_providers: &mut Vec<ThreadSafeProxyProvider>,
                provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
            ) -> Result<ThreadSafeProxyProvider, Error> {
                if name == PROXY_DIRECT || name == PROXY_REJECT {
                    return Err(Error::InvalidConfig(format!(
                        "proxy group {} is reserved",
                        name
                    )));
                }
                let proxies = proxies
                    .into_iter()
                    .map(|x| {
                        handlers
                            .get(x)
                            .ok_or_else(|| Error::InvalidConfig(format!("proxy {} not found", x)))
                            .map(Clone::clone)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let hc = HealthCheck::new(
                    proxies.clone(),
                    DEFAULT_LATENCY_TEST_URL.to_owned(),
                    interval,
                    lazy,
                    proxy_manager.clone(),
                )
                .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;

                let pd = Arc::new(RwLock::new(
                    PlainProvider::new(name.to_owned(), proxies, hc).map_err(|x| {
                        Error::InvalidConfig(format!("invalid provider config: {}", x))
                    })?,
                ));

                proxy_providers.push(pd.clone());
                provider_registry.insert(name.to_owned(), pd.clone());

                Ok(pd)
            }

            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    if proto.proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                        + proto
                            .use_provider
                            .as_ref()
                            .map(|x| x.len())
                            .unwrap_or_default()
                        == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            0,
                            true,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                            provider_registry,
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
                    if proto.proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                        + proto
                            .use_provider
                            .as_ref()
                            .map(|x| x.len())
                            .unwrap_or_default()
                        == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval,
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                            provider_registry,
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
                    if proto.proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                        + proto
                            .use_provider
                            .as_ref()
                            .map(|x| x.len())
                            .unwrap_or_default()
                        == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval,
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                            provider_registry,
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
                    if proto.proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                        + proto
                            .use_provider
                            .as_ref()
                            .map(|x| x.len())
                            .unwrap_or_default()
                        == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            proto.interval,
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                            provider_registry,
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
                    if proto.proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                        + proto
                            .use_provider
                            .as_ref()
                            .map(|x| x.len())
                            .unwrap_or_default()
                        == 0
                    {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }
                    let mut providers: Vec<ThreadSafeProxyProvider> = vec![];

                    if let Some(proxies) = &proto.proxies {
                        providers.push(make_provider_from_proxies(
                            &proto.name,
                            proxies,
                            0,
                            true,
                            handlers,
                            proxy_manager.clone(),
                            &mut proxy_providers,
                            provider_registry,
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

                    let stored_selection = cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            ..Default::default()
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(Mutex::new(selector)));
                }
            }
        }

        // insert GLOBAL
        let mut g = vec![];
        for name in proxy_names {
            g.push(handlers.get(&name).unwrap().clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            proxy_manager.clone(),
        )
        .unwrap();
        let pd = Arc::new(RwLock::new(
            PlainProvider::new(PROXY_GLOBAL.to_owned(), g, hc).unwrap(),
        ));

        let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
        let h = selector::Handler::new(
            selector::HandlerOptions {
                name: PROXY_GLOBAL.to_owned(),
                udp: true,
                ..Default::default()
            },
            vec![pd.clone()],
            stored_selection,
        )
        .await;

        provider_registry.insert(RESERVED_PROVIDER_NAME.to_owned(), pd);
        handlers.insert(PROXY_GLOBAL.to_owned(), Arc::new(h.clone()));
        selector_control.insert(PROXY_GLOBAL.to_owned(), Arc::new(Mutex::new(h)));

        Ok(())
    }

    async fn load_proxy_providers(
        proxy_providers: HashMap<String, OutboundProxyProvider>,
        proxy_manager: ProxyManager,
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
                        http.health_check.lazy.unwrap_or_default(),
                        proxy_manager.clone(),
                    )
                    .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;
                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(http.interval),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(RwLock::new(provider)));
                }
                OutboundProxyProvider::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(&file.path);
                    let hc = HealthCheck::new(
                        vec![],
                        file.health_check.url,
                        file.health_check.interval,
                        file.health_check.lazy.unwrap_or_default(),
                        proxy_manager.clone(),
                    )
                    .map_err(|e| Error::InvalidConfig(format!("invalid hc config {}", e)))?;

                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(file.interval.unwrap_or_default()),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| Error::InvalidConfig(format!("invalid provider config: {}", x)))?;

                    provider_registry.insert(name, Arc::new(RwLock::new(provider)));
                }
            }
        }

        for p in provider_registry.values() {
            info!("initializing provider {}", p.read().await.name());
            p.write().await.initialize().await?;
        }

        Ok(())
    }
}
