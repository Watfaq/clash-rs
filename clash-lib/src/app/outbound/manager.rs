use super::utils::proxy_groups_dag_sort;
#[cfg(feature = "shadowquic")]
use crate::proxy::shadowquic;
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
    app::{
        dns::ThreadSafeDNSResolver,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                ProviderVehicleType, file_vehicle, http_vehicle,
                proxy_provider::{
                    PlainProvider, ProxySetProvider, ThreadSafeProxyProvider,
                },
            },
        },
    },
    config::internal::proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    print_and_exit,
    proxy::{
        AnyOutboundHandler,
        direct::{self},
        fallback,
        group::smart,
        hysteria2, loadbalance, reject, relay,
        selector::{self, ThreadSafeSelectorControl},
        socks, trojan, urltest,
        utils::{DirectConnector, ProxyConnector},
        vless, vmess,
    },
};
use anyhow::Result;
use erased_serde::Serialize;
use hyper::Uri;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

static RESERVED_PROVIDER_NAME: &str = "default";

pub struct OutboundManager {
    /// name -> handler
    handlers: HashMap<String, AnyOutboundHandler>,
    /// name -> provider
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
}

static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;

/// Init process:
/// 1. Load all plaint outbounds from config using the unbounded function
///    `load_plain_outbounds`, so that any bootstrap proxy can be used to
///    download datasets
/// 2. Load all proxy providers from config, this should happen before loading
///    groups as groups my reference providers with `use_provider`
/// 3. Finally load all groups, and create `PlainProvider` for each explicit
///    referenced proxies in each group and register them in the
///    `proxy_providers` map.
/// 4. Create a `PlainProvider` for the global proxy set, which is the GLOBAL
///    selector, which should contain all plain outbound + provider proxies +
///    groups
///
/// Note that the `PlainProvider` is a special provider that contains plain
/// proxies for API compatibility with actual remote providers.
/// TODO: refactor this giant class
impl OutboundManager {
    pub async fn new(
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        cache_store: ThreadSafeCacheFile,
        cwd: String,
    ) -> Result<Self, Error> {
        let handlers = HashMap::new();
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone());

        let mut m = Self {
            handlers,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver)
            .await?;

        debug!("initializing handlers");
        m.load_handlers(outbounds, outbound_groups, proxy_names, cache_store)
            .await?;

        debug!("initializing connectors");
        m.init_handler_connectors().await?;

        Ok(m)
    }

    pub fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).cloned()
    }

    /// this doesn't populate history/liveness information
    pub fn get_proxy_provider(&self, name: &str) -> Option<ThreadSafeProxyProvider> {
        self.proxy_providers.get(name).cloned()
    }

    // API handles start
    pub fn get_selector_control(
        &self,
        name: &str,
    ) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).cloned()
    }

    /// Get all proxies in the manager, excluding those in providers.
    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        let proxy_manager = &self.proxy_manager;

        for (k, v) in self.handlers.iter() {
            let mut m = if let Some(g) = v.try_as_group_handler() {
                g.as_map().await
            } else {
                let mut m = HashMap::new();
                m.insert("type".to_string(), Box::new(v.proto()) as _);
                m
            };

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
        let mut r = if let Some(g) = proxy.try_as_group_handler() {
            g.as_map().await
        } else {
            let mut m = HashMap::new();
            m.insert("type".to_string(), Box::new(proxy.proto()) as _);
            m
        };

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
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Duration,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let proxy_manager = self.proxy_manager.clone();
        proxy_manager.check(outbounds, url, Some(timeout)).await
    }

    pub fn get_proxy_providers(&self) -> HashMap<String, ThreadSafeProxyProvider> {
        self.proxy_providers.clone()
    }

    // API handlers end

    /// Lazy initialization of connectors for each handler.
    async fn init_handler_connectors(&self) -> Result<(), Error> {
        let mut connectors = HashMap::new();
        for handler in self.handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = self.get_outbound(connector_name).ok_or(
                    Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )),
                )?;
                let connector =
                    connectors.entry(connector_name).or_insert_with(|| {
                        Arc::new(ProxyConnector::new(
                            outbound,
                            Box::new(DirectConnector::new()),
                        ))
                    });
                handler.register_connector(connector.clone()).await;
            }
        }

        Ok(())
    }

    pub fn load_plain_outbounds(
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Vec<AnyOutboundHandler> {
        outbounds
            .into_iter()
            .filter_map(|outbound| match outbound {
                OutboundProxyProtocol::Direct(d) => {
                    Some(Arc::new(direct::Handler::new(&d.name)) as _)
                }
                OutboundProxyProtocol::Reject(r) => {
                    Some(Arc::new(reject::Handler::new(&r.name)) as _)
                }
                #[cfg(feature = "shadowsocks")]
                OutboundProxyProtocol::Ss(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: shadowsocks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!(
                                "failed to load shadowsocks outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                OutboundProxyProtocol::Socks5(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: socks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!("failed to load socks5 outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Vmess(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vmess::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!("failed to load vmess outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Vless(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vless::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!("failed to load vless outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Trojan(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: trojan::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load trojan outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Hysteria2(h) => {
                    let name = h.name.clone();
                    h.try_into()
                        .map(|x: hysteria2::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!(
                                "failed to load hysteria2 outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                #[cfg(feature = "wireguard")]
                OutboundProxyProtocol::Wireguard(wg) => {
                    let name = wg.common_opts.name.clone();
                    wg.try_into()
                        .map(|x: wg::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!(
                                "failed to load wireguard outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                #[cfg(feature = "ssh")]
                OutboundProxyProtocol::Ssh(ssh) => {
                    let name = ssh.common_opts.name.clone();
                    ssh.try_into()
                        .map(|x: ssh::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load ssh outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "onion")]
                OutboundProxyProtocol::Tor(tor) => {
                    let name = tor.name.clone();
                    tor.try_into()
                        .map(|x: tor::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load tor outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "tuic")]
                OutboundProxyProtocol::Tuic(tuic) => {
                    let name = tuic.common_opts.name.clone();
                    tuic.try_into()
                        .map(|x: tuic::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load tuic outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "shadowquic")]
                OutboundProxyProtocol::ShadowQuic(sqcfg) => {
                    let name = sqcfg.common_opts.name.clone();
                    sqcfg
                        .try_into()
                        .map(|x: shadowquic::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!(
                                "failed to load shadowquic outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
            })
            .collect()
    }
}

impl OutboundManager {
    /// Load handlers from the provided outbound protocols and groups.
    /// handlers in proxy_providers are not loaded here as they are stored in
    /// the provider separately.
    async fn load_handlers(
        &mut self,
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        self.handlers.extend(outbounds.into_iter().map(|h| {
            let name = h.name().to_owned();
            (name, h)
        }));

        self.load_group_outbounds(outbound_groups, cache_store.clone())
            .await?;

        // insert GLOBAL
        let mut g = vec![];
        let mut keys = self.handlers.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| {
            proxy_names
                .iter()
                .position(|x| &x == a)
                .cmp(&proxy_names.iter().position(|x| &x == b))
        });
        for name in keys {
            g.push(self.handlers.get(name).unwrap().clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            self.proxy_manager.clone(),
        );

        let pd = Arc::new(RwLock::new(PlainProvider::new(
            PROXY_GLOBAL.to_owned(),
            g,
            hc,
        )?));

        let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
        let mut providers: Vec<ThreadSafeProxyProvider> = vec![pd.clone()];
        for p in self.proxy_providers.values() {
            let vehicle_type = p.read().await.vehicle_type();
            if matches!(
                vehicle_type,
                ProviderVehicleType::Http | ProviderVehicleType::File
            ) {
                providers.push(p.clone());
            }
        }

        let h = selector::Handler::new(
            selector::HandlerOptions {
                name: PROXY_GLOBAL.to_owned(),
                udp: true,
                common_opts: crate::proxy::HandlerCommonOptions {
                    icon: None,
                    ..Default::default()
                },
            },
            providers,
            stored_selection,
        )
        .await;

        self.proxy_providers
            .insert(RESERVED_PROVIDER_NAME.to_owned(), pd);
        self.handlers
            .insert(PROXY_GLOBAL.to_owned(), Arc::new(h.clone()));
        self.selector_control
            .insert(PROXY_GLOBAL.to_owned(), Arc::new(h));

        Ok(())
    }

    async fn load_group_outbounds(
        &mut self,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        // Sort outbound groups to ensure dependencies are resolved
        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        let handlers = &mut self.handlers;
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let selector_control = &mut self.selector_control;

        #[allow(clippy::too_many_arguments)]
        fn make_provider_from_proxies(
            name: &str,
            proxies: &[String],
            interval: u64,
            lazy: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: ProxyManager,
            provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
        ) -> Result<ThreadSafeProxyProvider, Error> {
            if name == PROXY_DIRECT || name == PROXY_REJECT {
                return Err(Error::InvalidConfig(format!(
                    "proxy group name `{name}` is reserved"
                )));
            }
            let proxies = proxies
                .iter()
                .map(|x| {
                    handlers
                        .get(x)
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!("proxy {x} not found"))
                        })
                        .cloned()
                })
                .collect::<Result<Vec<_>, _>>()?;

            let hc = HealthCheck::new(
                proxies.clone(),
                DEFAULT_LATENCY_TEST_URL.to_owned(),
                interval,
                lazy,
                proxy_manager.clone(),
            );

            let pd = Arc::new(RwLock::new(
                PlainProvider::new(name.to_owned(), proxies, hc).map_err(|x| {
                    Error::InvalidConfig(format!("invalid provider config: {x}"))
                })?,
            ));

            provider_registry.insert(name.to_owned(), pd.clone());

            Ok(pd)
        }

        fn maybe_append_use_providers(
            provider_names: &Option<Vec<String>>,
            provider_registry: &HashMap<String, ThreadSafeProxyProvider>,
            providers: &mut Vec<ThreadSafeProxyProvider>,
        ) {
            if let Some(provider_names) = provider_names {
                for provider_name in provider_names {
                    let provider = provider_registry
                        .get(provider_name)
                        .unwrap_or_else(|| {
                            print_and_exit!("provider {} not found", provider_name);
                        })
                        .clone();

                    providers.push(provider);
                }
            }
        }

        fn check_group_empty(
            proxies: &Option<Vec<String>>,
            use_provider: &Option<Vec<String>>,
        ) -> bool {
            proxies.as_ref().map(|x| x.len()).unwrap_or_default()
                + use_provider.as_ref().map(|x| x.len()).unwrap_or_default()
                == 0
        }

        // Initialize handlers for each outbound group protocol
        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let relay = relay::Handler::new(
                        relay::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                    );

                    handlers.insert(proto.name.clone(), relay);
                }
                OutboundGroupProtocol::UrlTest(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        proto.tolerance.unwrap_or_default(),
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(url_test));
                }
                OutboundGroupProtocol::Fallback(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let fallback = fallback::Handler::new(
                        fallback::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(fallback));
                }
                OutboundGroupProtocol::LoadBalance(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let load_balance = loadbalance::Handler::new(
                        loadbalance::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(load_balance));
                }
                OutboundGroupProtocol::Select(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let stored_selection =
                        cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(selector));
                }
                OutboundGroupProtocol::Smart(proto) => {
                    if check_group_empty(&proto.proxies, &proto.use_provider) {
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
                            proto.lazy.unwrap_or_default(),
                            handlers,
                            proxy_manager.clone(),
                            provider_registry,
                        )?);
                    }

                    maybe_append_use_providers(
                        &proto.use_provider,
                        provider_registry,
                        &mut providers,
                    );

                    let smart_handler = smart::Handler::new_with_cache(
                        smart::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                            udp: proto.udp.unwrap_or(true),
                            max_retries: proto.max_retries,
                            bandwidth_weight: proto.bandwidth_weight,
                        },
                        providers,
                        proxy_manager.clone(),
                        cache_store.clone(),
                    );

                    handlers.insert(proto.name.clone(), Arc::new(smart_handler));
                }
            }
        }

        Ok(())
    }

    async fn load_proxy_providers(
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url);
                        }),
                        http.path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );
                    let hc = HealthCheck::new(
                        vec![],
                        http.health_check.url,
                        http.health_check.interval,
                        http.health_check.lazy.unwrap_or_default(),
                        proxy_manager.clone(),
                    );

                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(http.interval),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| {
                        Error::InvalidConfig(format!("invalid provider config: {x}"))
                    })?;

                    provider_registry.insert(name, Arc::new(RwLock::new(provider)));
                }
                OutboundProxyProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );
                    let hc = HealthCheck::new(
                        vec![],
                        file.health_check.url,
                        file.health_check.interval,
                        file.health_check.lazy.unwrap_or_default(),
                        proxy_manager.clone(),
                    );

                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(file.interval.unwrap_or_default()),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| {
                        Error::InvalidConfig(format!("invalid provider config: {x}"))
                    })?;

                    provider_registry.insert(name, Arc::new(RwLock::new(provider)));
                }
            }
        }

        for p in provider_registry.values() {
            info!("initializing provider {}", p.read().await.name());
            let p = p.write().await;
            match p.initialize().await {
                Ok(_) => {}
                Err(err) => {
                    error!(
                        "failed to initialize proxy provider {}: {}",
                        p.name(),
                        err
                    );
                }
            }
            info!("initialized provider {}", p.name());
        }

        Ok(())
    }
}
