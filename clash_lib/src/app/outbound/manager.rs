use anyhow::Result;
use erased_serde::Serialize;
use hyper::Uri;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error};
use watfaq_config::OutboundCommonOptions;
use watfaq_resolver::Resolver;
use watfaq_state::Context;

use tracing::info;

use crate::app::{
    profile::ThreadSafeCacheFile,
    remote_content_manager::{
        ProxyManager,
        healthcheck::HealthCheck,
        providers::{file_vehicle, http_vehicle},
    },
};

use crate::{
    app::remote_content_manager::providers::proxy_provider::{
        PlainProvider, ProxySetProvider, ThreadSafeProxyProvider,
    },
    config::internal::proxy::{
        OutboundProxyProviderDef, PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    proxy::{
        OutboundType, fallback, loadbalance, selector, socks, trojan,
        utils::{DirectConnector, ProxyConnector},
        vmess,
    },
};

use crate::{
    Error,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{
        AnyOutboundHandler, direct, reject, selector::ThreadSafeSelectorControl,
        urltest,
    },
};

use super::utils::proxy_groups_dag_sort;

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "ssh")]
use crate::proxy::ssh;
#[cfg(feature = "onion")]
use crate::proxy::tor;

static RESERVED_PROVIDER_NAME: &str = "default";

pub struct OutboundManager {
    ctx: Arc<Context>,
    handlers: HashMap<String, AnyOutboundHandler>,
    proxy_providers: HashMap<String, ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
}

static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;

impl OutboundManager {
    pub async fn new(
        ctx: Arc<Context>,
        resolver: Arc<Resolver>,
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
        cwd: String,
    ) -> Result<Self, Error> {
        let handlers = HashMap::new();
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(ctx.clone(), resolver.clone());

        let mut m = Self {
            ctx,
            handlers,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, resolver)
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

    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        let proxy_manager = self.proxy_manager.clone();

        for (k, v) in self.handlers.iter() {
            let mut m = v.as_map().await;

            let alive = proxy_manager.alive(k).await;
            let history = proxy_manager.delay_history(k).await;
            let support_udp = v.support_udp().await;
            let icon = v.icon();

            m.insert("history".to_string(), Box::new(history));
            m.insert("alive".to_string(), Box::new(alive));
            m.insert("name".to_string(), Box::new(k.to_owned()));
            m.insert("udp".to_string(), Box::new(support_udp));

            if matches!(
                v.proto(),
                OutboundType::UrlTest
                    | OutboundType::Selector
                    | OutboundType::Fallback
                    | OutboundType::LoadBalance
            ) {
                m.insert("icon".to_string(), Box::new(icon));
            }

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

    async fn init_handler_connectors(&self) -> Result<(), Error> {
        let mut connectors = HashMap::new();
        for handler in self.handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = self.get_outbound(connector_name).ok_or(
                    Error::InvalidConfig(format!(
                        "connector {} not found",
                        connector_name
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

    async fn load_handlers(
        &mut self,
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let handlers = &mut self.handlers;
        let selector_control = &mut self.selector_control;

        let mut proxy_providers = vec![];

        for outbound in outbounds.iter() {
            match outbound {
                OutboundProxyProtocol::Direct => {
                    handlers.insert(PROXY_DIRECT.to_string(), {
                        let h = direct::Handler::new();
                        Arc::new(h)
                    });
                }

                OutboundProxyProtocol::Reject => {
                    handlers.insert(PROXY_REJECT.to_string(), {
                        let h = reject::Handler::new();
                        Arc::new(h)
                    });
                }
                #[cfg(feature = "shadowsocks")]
                OutboundProxyProtocol::Ss(s) => {
                    handlers.insert(s.common_opts.name.clone(), {
                        let h: shadowsocks::Handler = s.try_into()?;
                        Arc::new(h) as _
                    });
                }

                OutboundProxyProtocol::Socks5(s) => {
                    handlers.insert(s.common_opts.name.clone(), {
                        let h: socks::Handler = s.try_into()?;
                        Arc::new(h) as _
                    });
                }

                OutboundProxyProtocol::Vmess(v) => {
                    handlers.insert(v.common_opts.name.clone(), {
                        let h: vmess::Handler = v.try_into()?;
                        Arc::new(h) as _
                    });
                }

                OutboundProxyProtocol::Trojan(v) => {
                    handlers.insert(v.common_opts.name.clone(), {
                        let h: trojan::Handler = v.try_into()?;
                        Arc::new(h) as _
                    });
                }
                OutboundProxyProtocol::Hysteria2(h) => {
                    handlers.insert(h.name.clone(), h.clone().try_into()?);
                }
                #[cfg(feature = "wireguard")]
                OutboundProxyProtocol::Wireguard(wg) => {
                    warn!("wireguard is experimental");
                    handlers.insert(wg.common_opts.name.clone(), {
                        let h: wg::Handler = wg.try_into()?;
                        Arc::new(h) as _
                    });
                }

                #[cfg(feature = "ssh")]
                OutboundProxyProtocol::Ssh(ssh) => {
                    handlers.insert(ssh.common_opts.name.clone(), {
                        let h: ssh::Handler = ssh.try_into()?;
                        Arc::new(h) as _
                    });
                }

                #[cfg(feature = "onion")]
                OutboundProxyProtocol::Tor(tor) => {
                    handlers.insert(tor.name.clone(), {
                        let h: tor::Handler = tor.try_into()?;
                        Arc::new(h) as _
                    });
                }
                #[cfg(feature = "tuic")]
                OutboundProxyProtocol::Tuic(tuic) => {
                    handlers.insert(tuic.common_opts.name.clone(), {
                        let h: watfaq_tuic::Handler = tuic.try_into()?;
                        Arc::new(h) as _
                    });
                }
            }
        }

        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        #[allow(clippy::too_many_arguments)]
        fn make_provider_from_proxies(
            name: &str,
            proxies: &[String],
            interval: u64,
            lazy: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: ProxyManager,
            proxy_providers: &mut Vec<ThreadSafeProxyProvider>,
            provider_registry: &mut HashMap<String, ThreadSafeProxyProvider>,
        ) -> Result<ThreadSafeProxyProvider, Error> {
            if name == PROXY_DIRECT || name == PROXY_REJECT {
                return Err(Error::InvalidConfig(format!(
                    "proxy group name `{}` is reserved",
                    name
                )));
            }
            let proxies = proxies
                .iter()
                .map(|x| {
                    handlers
                        .get(x)
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!("proxy {} not found", x))
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

        for outbound_group in outbound_groups.iter() {
            match outbound_group {
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
                                .unwrap_or_else(|| {
                                    panic!("provider {} not found", provider_name)
                                })
                                .clone();
                            providers.push(provider);
                        }
                    }

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: OutboundCommonOptions {
                                icon: proto.icon.clone(),
                                ..Default::default()
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
                                .unwrap_or_else(|| {
                                    panic!("provider {} not found", provider_name)
                                })
                                .clone();
                            providers.push(provider);
                        }
                    }

                    let fallback = fallback::Handler::new(
                        fallback::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: OutboundCommonOptions {
                                icon: proto.icon.clone(),
                                ..Default::default()
                            },
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
                                .unwrap_or_else(|| {
                                    panic!("provider {} not found", provider_name)
                                })
                                .clone();
                            providers.push(provider);
                        }
                    }

                    let load_balance = loadbalance::Handler::new(
                        loadbalance::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: OutboundCommonOptions {
                                icon: proto.icon.clone(),
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        providers,
                        proxy_manager.clone(),
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
                                .unwrap_or_else(|| {
                                    panic!("provider {} not found", provider_name)
                                })
                                .clone();

                            providers.push(provider);
                        }
                    }

                    let stored_selection =
                        cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            common_opts: OutboundCommonOptions {
                                icon: proto.icon.clone(),
                                ..Default::default()
                            },
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control
                        .insert(proto.name.clone(), Arc::new(Mutex::new(selector)));
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
                common_opts: OutboundCommonOptions {
                    icon: None,
                    ..Default::default()
                },
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
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        resolver: Arc<Resolver>,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        for (name, provider) in proxy_providers.into_iter() {
            match provider {
                OutboundProxyProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        self.ctx.clone(),
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            panic!("invalid provider url: {}", http.url)
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
                    )
                    .map_err(|e| {
                        Error::InvalidConfig(format!("invalid hc config {}", e))
                    })?;
                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(http.interval),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| {
                        Error::InvalidConfig(format!(
                            "invalid provider config: {}",
                            x
                        ))
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
                    )
                    .map_err(|e| {
                        Error::InvalidConfig(format!("invalid hc config {}", e))
                    })?;

                    let provider = ProxySetProvider::new(
                        name.clone(),
                        Duration::from_secs(file.interval.unwrap_or_default()),
                        Arc::new(vehicle),
                        hc,
                    )
                    .map_err(|x| {
                        Error::InvalidConfig(format!(
                            "invalid provider config: {}",
                            x
                        ))
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
