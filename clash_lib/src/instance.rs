use std::{path::PathBuf, sync::Arc};

use tokio::sync::{Mutex, broadcast, mpsc::Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wait_counter::WaitCounter;
use watfaq_dns::get_dns_listener;
use watfaq_error::Result;
use watfaq_resolver::{Resolver, dns::resolver::SystemResolver};
use watfaq_state::Context;
use watfaq_utils::Mmdb;

use crate::{
    GlobalState,
    app::{logging::LogEvent, net::init_net_config},
    config::internal::InternalConfig,
    tasks::{build_controller_task, build_dns_task, build_tun_task},
};

use crate::{
    ClashRuntimeConfig,
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        inbound::manager::InboundManager,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
    },
    common::{geodata, http::new_http_client},
    config::proxy::OutboundProxy,
};

pub struct Instance {
    ctx: Arc<Context>,
    cache_store: profile::ThreadSafeCacheFile,
    resolver: Arc<Resolver>,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,
    inbound_manager: Arc<InboundManager>,
    token: CancellationToken,
    config: InternalConfig,
    work_dir: PathBuf,
    counter: WaitCounter,
}
impl Instance {
    pub async fn new(work_dir: PathBuf, config: InternalConfig) -> Result<Self> {
        let token = CancellationToken::new();
        if config.tun.enable {
            debug!("tun enabled, initializing default outbound interface");
            init_net_config(config.tun.so_mark).await;
        }
        let bootstrap_resolver: Arc<Resolver> =
            Arc::new(SystemResolver::new(config.dns.ipv6)?.into());
        let ctx = Context {
            system_ipv6_cap: todo!(),
            stack_prefer: todo!(),
            default_iface: todo!(),
            protector: todo!(),
        };
        let ctx = Arc::new(ctx);
        // FIXME On some system, system resolver already be catpured by TUN device.
        let client = new_http_client(ctx, bootstrap_resolver.clone())?;

        debug!("initializing mmdb");
        let country_mmdb =
            Arc::new(Mmdb::new(work_dir.join(&config.general.mmdb)).await?);

        let geodata = Arc::new(
            geodata::GeoData::new(
                work_dir.join(&config.general.geosite),
                config.general.geosite_download_url,
                client.clone(),
            )
            .await?,
        );

        debug!("initializing cache store");
        let cache_store = profile::ThreadSafeCacheFile::new(
            work_dir.join("cache.db").as_path().to_str().unwrap(),
            config.profile.store_selected,
        );

        let dns_listen = config.dns.listen.clone();
        debug!("initializing dns resolver");
        let resolver = watfaq_resolver::dns::resolver::new(
            ctx,
            config.dns,
            Some(country_mmdb.clone()),
        )
        .await?;
        let resolver = Arc::new(resolver);

        debug!("initializing outbound manager");
        let outbound_manager = Arc::new(
            OutboundManager::new(
                ctx.clone(),
                resolver.clone(),
                config
                    .proxies
                    .into_values()
                    .filter_map(|x| match x {
                        OutboundProxy::ProxyServer(s) => Some(s),
                        _ => None,
                    })
                    .collect(),
                config
                    .proxy_groups
                    .into_values()
                    .filter_map(|x| match x {
                        OutboundProxy::ProxyGroup(g) => Some(g),
                        _ => None,
                    })
                    .collect(),
                config.proxy_providers,
                config.proxy_names,
                cache_store.clone(),
                work_dir.to_string_lossy().to_string(),
            )
            .await?,
        );

        debug!("initializing country asn mmdb");
        let p = work_dir.join(&config.general.asn_mmdb);
        let asn_mmdb =
            if p.exists() || config.general.asn_mmdb_download_url.is_some() {
                Some(Arc::new(Mmdb::new(p).await?))
            } else {
                None
            };

        debug!("initializing router");
        let router = Arc::new(
            Router::new(
                ctx.clone(),
                config.rules,
                config.rule_providers,
                resolver.clone(),
                country_mmdb,
                asn_mmdb,
                geodata,
                work_dir.to_string_lossy().to_string(),
            )
            .await,
        );

        let statistics_manager = StatisticsManager::new();

        debug!("initializing dispatcher");
        let dispatcher = Arc::new(Dispatcher::new(
            ctx.clone(),
            outbound_manager.clone(),
            router.clone(),
            resolver.clone(),
            config.general.mode,
            statistics_manager.clone(),
            config.experimental.and_then(|e| e.tcp_buffer_size),
        ));

        debug!("initializing authenticator");
        let authenticator =
            Arc::new(crate::common::auth::PlainAuthenticator::new(config.users));

        debug!("initializing inbound manager");
        let inbound_manager = Arc::new(
            InboundManager::new(
                config.general.bind_address,
                config.general.authentication,
                dispatcher.clone(),
                authenticator,
                config.listeners,
            )
            .await?,
        );

        info!("all components initialized");
        Ok(Instance {
            cache_store,
            resolver,
            outbound_manager,
            router,
            dispatcher,
            statistics_manager,
            inbound_manager,
            ctx,
            token,
            config,
            work_dir,
            counter: WaitCounter::new(),
        })
    }

    pub async fn spawn(
        &mut self,
        log_tx: broadcast::Sender<LogEvent>,
        global_state: Arc<Mutex<GlobalState>>,
    ) {
        self.inbound_manager.start().await;

        if self.config.tun.enable {
            let tun_config = self.config.tun.clone();
            let dispatcher = self.dispatcher.clone();
            let resolver = self.resolver.clone();

            let token = self.token.child_token();
            let counter = self.counter.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => { }
                    _ = build_tun_task(tun_config, dispatcher, resolver, token.clone()) => { }
                }
                drop(counter);
            });
        }
        if self.config.dns.enable {
            let listen_addr = self.config.dns.listen.clone();
            let resolver = self.resolver.clone();
            let work_dir = self.work_dir.clone();

            let token = self.token.child_token();
            let counter = self.counter.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => { }
                    _ = build_dns_task(listen_addr, resolver, &work_dir) => { }
                }
                drop(counter);
            });
        }

        if self.config.general.controller.external_controller.is_some() {
            let cfg = self.config.general.controller.clone();
            let inbound_manager = self.inbound_manager.clone();
            let dispatcher = self.dispatcher.clone();
            let resolver = self.resolver.clone();
            let outbound_manager = self.outbound_manager.clone();
            let statistics_manager = self.statistics_manager.clone();
            let cache_store = self.cache_store.clone();
            let router = self.router.clone();
            let cwd = self.work_dir.clone();

            let token = self.token.child_token();
            let counter = self.counter.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => { }
                    _ = build_controller_task(cfg, log_tx, inbound_manager, dispatcher, global_state, resolver, outbound_manager, statistics_manager, cache_store, router, cwd) => { }
                }
                drop(counter);
            });
        }
    }

    pub async fn shutdown(self) {
        self.token.cancel();
        self.counter.wait().await;
    }
}
