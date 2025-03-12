use std::{path::PathBuf, sync::Arc};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use watfaq_dns::get_dns_listener;
use watfaq_error::Result;
use watfaq_resolver::dns::resolver::SystemResolver;
use watfaq_resolver::Resolver;
use watfaq_state::Context;
use watfaq_utils::Mmdb;

use crate::app::api::controller_task;
use crate::proxy::tun::tun_task;
use crate::{app::net::init_net_config, config::internal::InternalConfig};

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
    dns_resolver: Arc<Resolver>,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,
    inbound_manager: Arc<InboundManager>,
    token: CancellationToken,
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
                resolver.clone(),
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
        let authenticator = Arc::new(crate::common::auth::PlainAuthenticator::new(config.users));

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
            dns_resolver: resolver,
            outbound_manager,
            router,
            dispatcher,
            statistics_manager,
            inbound_manager,
            ctx,
            token,
        })
    }

    pub async fn spawn(&mut self) {
        self.inbound_manager.start().await;
        tun_task(cfg, dispatcher, resolver, token)
        get_dns_listener(listen, exchanger, cwd)
        controller_task(
            controller_cfg, 
            log_source, 
            inbound_manager, 
            dispatcher, 
            global_state, 
            dns_resolver, 
            outbound_manager, 
            statistics_manager, 
            cache_store, 
            router, 
            cwd, 
            token
        )

    }

    pub async fn shutdown(self) {
        self.token.cancel();
    }
}

