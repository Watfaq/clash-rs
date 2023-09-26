#[macro_use]
extern crate anyhow;
extern crate core;

use crate::app::dispatcher::Dispatcher;
use crate::app::dns;
use crate::app::inbound::manager::InboundManager;
use crate::app::outbound::manager::OutboundManager;
use crate::app::router::Router;
use crate::config::def;
use crate::config::internal::proxy::OutboundProxy;
use crate::config::internal::InternalConfig;
use app::dispatcher::StatisticsManager;
use app::dns::SystemResolver;
use app::profile;
use common::auth;
use common::http::new_http_client;
use common::mmdb;
use config::def::LogLevel;
use proxy::tun::get_tun_runner;
use state::Storage;
use std::io;
use tokio::task::JoinHandle;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

mod app;
mod common;
mod config;
mod proxy;
mod session;

pub use config::def::Config as ClashConfigDef;
pub use config::def::DNS as ClashDNSConfigDef;
pub use config::DNSListen as ClashDNSListen;
pub use config::RuntimeConfig as ClashRuntimeConfig;

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

pub type Runner = futures::future::BoxFuture<'static, ()>;

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
}

#[repr(C)]
pub enum Config {
    Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String, String),
    Str(String),
}

pub struct GlobalState {
    log_level: LogLevel,
    inbound_listener_handle: Option<JoinHandle<()>>,
    #[allow(dead_code)]
    dns_listener_handle: Option<JoinHandle<()>>,
}

pub struct RuntimeController {
    shutdown_tx: mpsc::Sender<()>,
}

static RUNTIME_CONTROLLER: Storage<std::sync::RwLock<RuntimeController>> = Storage::new();

pub fn start(opts: Options) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
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
    match RUNTIME_CONTROLLER.get().write() {
        Ok(rt) => rt.shutdown_tx.blocking_send(()).is_ok(),
        _ => false,
    }
}

async fn start_async(opts: Options) -> Result<(), Error> {
    #[cfg(feature = "tracing")]
    console_subscriber::init();

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    RUNTIME_CONTROLLER.set(std::sync::RwLock::new(RuntimeController { shutdown_tx }));

    let config: InternalConfig = match opts.config {
        Config::Def(c) => c.try_into()?,
        Config::Internal(c) => c,
        Config::File(_, file) => file.parse::<def::Config>()?.try_into()?,
        Config::Str(s) => s.as_str().parse::<def::Config>()?.try_into()?,
    };

    let (log_tx, _) = broadcast::channel(100);

    #[cfg(not(feature = "tracing"))]
    {
        let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

        app::logging::setup_logging(config.general.log_level, log_collector).map_err(|x| {
            Error::InvalidConfig(format!("failed to setup logging: {}", x.to_string()))
        })?;
    }

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let cwd = std::path::Path::new(&cwd);

    let system_resolver =
        Arc::new(SystemResolver::new().map_err(|x| Error::DNSError(x.to_string()))?);
    let client = new_http_client(system_resolver).map_err(|x| Error::DNSError(x.to_string()))?;
    let mmdb = Arc::new(
        mmdb::MMDB::new(
            cwd.join(&config.general.mmdb),
            config.general.mmdb_download_url,
            client,
        )
        .await?,
    );

    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let dns_resolver = dns::Resolver::new(&config.dns, cache_store.clone(), mmdb.clone()).await;

    let outbound_manager = Arc::new(RwLock::new(
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
    ));

    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            mmdb,
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

    let inbound_manager = Arc::new(Mutex::new(InboundManager::new(
        config.general.inbound,
        dispatcher.clone(),
        authenticator,
    )?));

    let inbound_runner = inbound_manager.lock().await.get_runner()?;
    let inbound_listener_handle = tokio::spawn(inbound_runner);

    let tun_runner = get_tun_runner(config.tun, dispatcher.clone(), dns_resolver.clone())?;
    if let Some(tun_runner) = tun_runner {
        runners.push(tun_runner);
    }

    let dns_listener_handle = dns::get_dns_listener(config.dns, dns_resolver.clone())
        .await
        .map(|l| tokio::spawn(l));

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level: config.general.log_level,
        inbound_listener_handle: Some(inbound_listener_handle),
        dns_listener_handle,
    }));

    let api_runner = app::api::get_api_runner(
        config.general.controller,
        log_tx,
        inbound_manager,
        dispatcher,
        global_state,
        dns_resolver,
        outbound_manager,
        statistics_manager,
        cache_store,
        router,
    );
    if let Some(r) = api_runner {
        runners.push(r);
    }

    runners.push(Box::pin(async move {
        shutdown_rx.recv().await;
    }));

    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    tasks.push(Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    }));

    futures::future::select_all(tasks).await;
    Ok(())
}

#[cfg(test)]
#[ctor::ctor]
fn setup_tests() {
    println!("setup tests");
}

#[cfg(test)]
mod tests {
    use crate::{shutdown, start, Config, Options};
    use std::thread;
    use std::time::Duration;

    #[test]
    #[ignore]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "clash_lib/tests/data/Country.mmdb"
        "#;

        let handle = thread::spawn(|| {
            start(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
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
