#![feature(ip)]
#![feature(sync_unsafe_cell)]
#![feature(async_closure)]

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
use app::{dispatcher::StatisticsManager, dns::SystemResolver, profile};
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
    inbound_listener_handle: Option<JoinHandle<Result<(), Error>>>,
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

pub fn start(opts: Options) -> Result<(), Error> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    rt.block_on(async {
        match start_async(opts).await {
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

async fn start_async(opts: Options) -> Result<(), Error> {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    let _ = RUNTIME_CONTROLLER.get_or_init(|| RuntimeController { shutdown_tx });

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

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let cwd = PathBuf::from(cwd);

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    debug!("initializing dns resolver");
    let system_resolver = Arc::new(
        SystemResolver::new(config.general.ipv6 && config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );
    let client = new_http_client(system_resolver.clone())
        .map_err(|x| Error::DNSError(x.to_string()))?;

    debug!("initializing mmdb");
    let mmdb = Arc::new(
        mmdb::Mmdb::new(
            cwd.join(&config.general.mmdb),
            config.general.mmdb_download_url,
            client,
        )
        .await?,
    );

    let dns_resolver = dns::new_resolver(
        &config.dns,
        Some(cache_store.clone()),
        Some(mmdb.clone()),
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

    debug!("initializing router");
    let client = new_http_client(system_resolver)
        .map_err(|x| Error::DNSError(x.to_string()))?;
    let geodata = Arc::new(
        geodata::GeoData::new(
            cwd.join(&config.general.geosite),
            config.general.geosite_download_url,
            client,
        )
        .await?,
    );

    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
        )
        .await,
    );

    let statistics_manager = StatisticsManager::new();

    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
    ));

    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(Mutex::new(InboundManager::new(
        config.general.inbound,
        dispatcher.clone(),
        authenticator,
    )?));

    let inbound_runner = inbound_manager.lock().await.get_runner()?;
    let inbound_listener_handle = tokio::spawn(inbound_runner);

    let tun_runner =
        get_tun_runner(config.tun, dispatcher.clone(), dns_resolver.clone())?;
    let tun_runner_handle = tun_runner.map(tokio::spawn);

    debug!("initializing dns listener");
    let dns_listener_handle =
        dns::get_dns_listener(config.dns, dns_resolver.clone())
            .await
            .map(tokio::spawn);

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level: config.general.log_level,
        inbound_listener_handle: Some(inbound_listener_handle),
        tunnel_listener_handle: tun_runner_handle,
        dns_listener_handle,
        reload_tx,
        api_listener_handle: None,
        cwd: cwd.to_string_lossy().to_string(),
    }));

    let api_runner = app::api::get_api_runner(
        config.general.controller,
        log_tx.clone(),
        inbound_manager.clone(),
        dispatcher,
        global_state.clone(),
        dns_resolver,
        outbound_manager,
        statistics_manager,
        cache_store,
        router,
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

            debug!("reloading dns resolver");
            let system_resolver = Arc::new(
                SystemResolver::new(config.dns.ipv6)
                    .map_err(|x| Error::DNSError(x.to_string()))?,
            );
            let client = new_http_client(system_resolver.clone())
                .map_err(|x| Error::DNSError(x.to_string()))?;

            debug!("reloading mmdb");
            let mmdb = Arc::new(
                mmdb::Mmdb::new(
                    cwd.join(&config.general.mmdb),
                    config.general.mmdb_download_url,
                    client,
                )
                .await?,
            );

            let client = new_http_client(system_resolver)
                .map_err(|x| Error::DNSError(x.to_string()))?;
            let geodata = Arc::new(
                geodata::GeoData::new(
                    cwd.join(&config.general.geosite),
                    config.general.geosite_download_url,
                    client,
                )
                .await?,
            );

            debug!("reloading cache store");
            let cache_store = profile::ThreadSafeCacheFile::new(
                cwd.join("cache.db").as_path().to_str().unwrap(),
                config.profile.store_selected,
            );

            let dns_resolver = dns::new_resolver(
                &config.dns,
                Some(cache_store.clone()),
                Some(mmdb.clone()),
            )
            .await;

            debug!("reloading outbound manager");
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

            debug!("reloading router");
            let router = Arc::new(
                Router::new(
                    config.rules,
                    config.rule_providers,
                    dns_resolver.clone(),
                    mmdb,
                    geodata,
                    cwd.to_string_lossy().to_string(),
                )
                .await,
            );

            let statistics_manager = StatisticsManager::new();

            let dispatcher = Arc::new(Dispatcher::new(
                outbound_manager.clone(),
                router.clone(),
                dns_resolver.clone(),
                config.general.mode,
                statistics_manager.clone(),
            ));

            let authenticator =
                Arc::new(auth::PlainAuthenticator::new(config.users));

            debug!("reloading inbound manager");
            let inbound_manager = Arc::new(Mutex::new(InboundManager::new(
                config.general.inbound,
                dispatcher.clone(),
                authenticator,
            )?));

            done.send(()).unwrap();

            debug!("stopping listeners");
            let mut g = global_state.lock().await;
            if let Some(h) = g.inbound_listener_handle.take() {
                h.abort();
            }
            if let Some(h) = g.tunnel_listener_handle.take() {
                h.abort();
            }
            if let Some(h) = g.dns_listener_handle.take() {
                h.abort();
            }
            if let Some(h) = g.api_listener_handle.take() {
                h.abort();
            }

            let inbound_listener_handle = inbound_manager
                .lock()
                .await
                .get_runner()
                .map(tokio::spawn)?;

            let tun_runner_handle = get_tun_runner(
                config.tun,
                dispatcher.clone(),
                dns_resolver.clone(),
            )?
            .map(tokio::spawn);

            debug!("reloading dns listener");
            let dns_listener_handle =
                dns::get_dns_listener(config.dns, dns_resolver.clone())
                    .await
                    .map(tokio::spawn);

            debug!("reloading api listener");
            let api_listener_handle = app::api::get_api_runner(
                config.general.controller,
                log_tx.clone(),
                inbound_manager.clone(),
                dispatcher,
                global_state.clone(),
                dns_resolver,
                outbound_manager,
                statistics_manager,
                cache_store,
                router,
                cwd.to_string_lossy().to_string(),
            )
            .map(tokio::spawn);

            g.inbound_listener_handle = Some(inbound_listener_handle);
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

#[cfg(test)]
mod tests {
    use crate::{shutdown, start, Config, Options};
    use std::{thread, time::Duration};

    #[test]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        "#;

        let handle = thread::spawn(|| {
            start(Options {
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
