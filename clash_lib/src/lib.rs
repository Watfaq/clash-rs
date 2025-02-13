#![feature(ip)]
#![feature(sync_unsafe_cell)]
#![feature(unbounded_shifts)]

#[macro_use]
extern crate anyhow;

use crate::{
    app::{
        dispatcher::Dispatcher, dns, inbound::manager::InboundManager,
        outbound::manager::OutboundManager, router::Router,
    },
    config::{
        def,
        internal::{proxy::OutboundProxy, InternalConfig},
    },
};
use app::{
    dispatcher::StatisticsManager,
    dns::{SystemResolver, ThreadSafeDNSResolver},
    logging::LogEvent,
    profile,
};
use common::{auth, http::new_http_client, mmdb};
use config::def::LogLevel;
use once_cell::sync::OnceCell;
use proxy::tun::get_tun_runner;

use std::{io, path::PathBuf, sync::Arc};
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, oneshot, Mutex},
    task::JoinHandle,
};
use tracing::{debug, error, info};

mod app;
mod common;
mod config;
mod proxy;
mod session;

use crate::common::geodata;
pub use config::{
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error(transparent)]
    DNSServerError(#[from] watfaq_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
}

pub type Runner = futures::future::BoxFuture<'static, Result<(), Error>>;

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String),
    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<InternalConfig, Error> {
        match self {
            Config::Def(c) => c.try_into(),
            Config::Internal(c) => Ok(c),
            Config::File(file) => {
                TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into()
            }
            Config::Str(s) => s.parse::<def::Config>()?.try_into(),
        }
    }
}

pub struct GlobalState {
    log_level: LogLevel,
    // must be Some otherwise we'll refuse to start
    inbound_listener_handle: JoinHandle<Result<(), Error>>,

    tunnel_listener_handle: Option<JoinHandle<Result<(), Error>>>,
    api_listener_handle: Option<JoinHandle<Result<(), Error>>>,
    dns_listener_handle: Option<JoinHandle<Result<(), Error>>>,
    reload_tx: mpsc::Sender<(Config, oneshot::Sender<()>)>,
    cwd: String,
}

pub struct RuntimeController {
    shutdown_tx: mpsc::Sender<()>,
}

static RUNTIME_CONTROLLER: OnceCell<RuntimeController> = OnceCell::new();

pub fn start_scaffold(opts: Options) -> Result<(), Error> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    let _g = app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    )
    .map_err(|x| eprintln!("failed to setup logging: {}", x))
    .unwrap_or_default();

    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic(info);
        error!("panic hook: {:?}", info);
    }));

    rt.block_on(async {
        match start(config, cwd, log_tx).await {
            Err(e) => {
                eprintln!("start error: {}", e);
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

pub fn shutdown() -> bool {
    match RUNTIME_CONTROLLER.get() {
        Some(controller) => controller.shutdown_tx.blocking_send(()).is_ok(),
        _ => false,
    }
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<(), Error> {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    let _ = RUNTIME_CONTROLLER.get_or_init(|| RuntimeController { shutdown_tx });

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config).await?;

    let inbound_runner = components.inbound_manager.lock().await.get_runner()?;
    let inbound_listener_handle = tokio::spawn(inbound_runner);

    let tun_runner_handle = components.tun_runner.map(tokio::spawn);
    let dns_listener_handle = components.dns_listener.map(tokio::spawn);

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        inbound_listener_handle,
        tunnel_listener_handle: tun_runner_handle,
        dns_listener_handle,
        reload_tx,
        api_listener_handle: None,
        cwd: cwd.to_string_lossy().to_string(),
    }));

    let api_runner = app::api::get_api_runner(
        controller_cfg,
        log_tx.clone(),
        components.inbound_manager,
        components.dispatcher,
        global_state.clone(),
        components.dns_resolver,
        components.outbound_manager,
        components.statistics_manager,
        components.cache_store,
        components.router,
        cwd.to_string_lossy().to_string(),
    );
    if let Some(r) = api_runner {
        let api_listener_handle = tokio::spawn(r);
        global_state.lock().await.api_listener_handle = Some(api_listener_handle);
    }

    runners.push(Box::pin(async move {
        shutdown_rx.recv().await;
        info!("receiving shutdown signal");
        Ok(())
    }));

    tasks.push(Box::pin(async move {
        futures::future::select_all(runners).await.0
    }));

    tasks.push(Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
        Ok(())
    }));

    tasks.push(Box::pin(async move {
        while let Some((config, done)) = reload_rx.recv().await {
            info!("reloading config");
            let config = match config.try_parse() {
                Ok(c) => c,
                Err(e) => {
                    error!("failed to reload config: {}", e);
                    continue;
                }
            };

            let controller_cfg = config.general.controller.clone();

            let new_components = create_components(cwd.clone(), config).await?;

            done.send(()).unwrap();

            debug!("stopping listeners");
            let mut g = global_state.lock().await;
            g.inbound_listener_handle.abort();
            if let Some(h) = g.tunnel_listener_handle.take() {
                h.abort();
            }
            if let Some(h) = g.dns_listener_handle.take() {
                h.abort();
            }
            if let Some(h) = g.api_listener_handle.take() {
                h.abort();
            }

            debug!("reloading inbound listener");
            let inbound_listener_handle = new_components
                .inbound_manager
                .lock()
                .await
                .get_runner()
                .map(tokio::spawn)?;

            debug!("reloading tun runner");
            let tun_runner_handle = new_components.tun_runner.map(tokio::spawn);

            debug!("reloading dns listener");
            let dns_listener_handle = new_components.dns_listener.map(tokio::spawn);

            debug!("reloading api listener");
            let api_listener_handle = app::api::get_api_runner(
                controller_cfg,
                log_tx.clone(),
                new_components.inbound_manager,
                new_components.dispatcher,
                global_state.clone(),
                new_components.dns_resolver,
                new_components.outbound_manager,
                new_components.statistics_manager,
                new_components.cache_store,
                new_components.router,
                cwd.to_string_lossy().to_string(),
            )
            .map(tokio::spawn);

            g.inbound_listener_handle = inbound_listener_handle;
            g.tunnel_listener_handle = tun_runner_handle;
            g.dns_listener_handle = dns_listener_handle;
            g.api_listener_handle = api_listener_handle;
        }
        Ok(())
    }));

    futures::future::select_all(tasks).await.0.map_err(|x| {
        error!("runtime error: {}, shutting down", x);
        x
    })
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,
    inbound_manager: Arc<Mutex<InboundManager>>,

    tun_runner: Option<Runner>,
    dns_listener: Option<Runner>,
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
) -> Result<RuntimeComponents, Error> {
    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );
    let client = new_http_client(system_resolver.clone())
        .map_err(|x| Error::DNSError(x.to_string()))?;

    debug!("initializing mmdb");
    let country_mmdb = Arc::new(
        mmdb::Mmdb::new(
            cwd.join(&config.general.mmdb),
            config.general.mmdb_download_url,
            client.clone(),
        )
        .await?,
    );

    let geodata = Arc::new(
        geodata::GeoData::new(
            cwd.join(&config.general.geosite),
            config.general.geosite_download_url,
            client.clone(),
        )
        .await?,
    );

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let dns_listen = config.dns.listen.clone();
    debug!("initializing dns resolver");
    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        Some(country_mmdb.clone()),
    )
    .await;

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new(
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
            dns_resolver.clone(),
            cache_store.clone(),
            cwd.to_string_lossy().to_string(),
        )
        .await?,
    );

    debug!("initializing country asn mmdb");
    let p = cwd.join(&config.general.asn_mmdb);
    let asn_mmdb = if p.exists() || config.general.asn_mmdb_download_url.is_some() {
        Some(Arc::new(
            mmdb::Mmdb::new(p, config.general.asn_mmdb_download_url, client.clone())
                .await?,
        ))
    } else {
        None
    };

    debug!("initializing router");
    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
        )
        .await,
    );

    let statistics_manager = StatisticsManager::new();

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        config.experimental.and_then(|e| e.tcp_buffer_size),
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(Mutex::new(InboundManager::new(
        config.general.inbound,
        dispatcher.clone(),
        authenticator,
    )?));

    debug!("initializing tun runner");
    let tun_runner =
        get_tun_runner(config.tun, dispatcher.clone(), dns_resolver.clone())?;

    debug!("initializing dns listener");
    let dns_listener =
        dns::get_dns_listener(dns_listen, dns_resolver.clone(), &cwd).await;

    info!("all components initialized");
    Ok(RuntimeComponents {
        cache_store,
        dns_resolver,
        outbound_manager,
        router,
        dispatcher,
        statistics_manager,
        inbound_manager,
        tun_runner,
        dns_listener,
    })
}

#[cfg(test)]
mod tests {
    use crate::{shutdown, start_scaffold, Config, Options};
    use std::{sync::Once, thread, time::Duration};

    static INIT: Once = Once::new();

    #[allow(dead_code)]
    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[test]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        "#;

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
                rt: None,
                log_file: None,
            })
            .unwrap()
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            assert!(shutdown());
        });

        handle.join().unwrap();
    }
}
