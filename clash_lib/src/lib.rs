#[macro_use]
extern crate anyhow;
extern crate core;

use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::manager::InboundManager;
use crate::app::outbound::manager::OutboundManager;
use crate::app::router::Router;
use crate::app::{dns, ThreadSafeDNSResolver};
use crate::config::def;
use crate::config::internal::proxy::OutboundProxy;
use crate::config::internal::InternalConfig;
use common::auth;
use config::def::LogLevel;
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
}

pub enum Config {
    Internal(InternalConfig),
    File(String, String),
    Str(String),
}

pub struct GlobalState {
    log_level: LogLevel,
    inbound_listener_handle: Option<JoinHandle<()>>,
    dns_listener_handle: Option<JoinHandle<()>>,
}

pub struct RuntimeController {
    shutdown_tx: mpsc::Sender<()>,
}

static RUNTIME_CONTROLLER: Storage<std::sync::RwLock<RuntimeController>> = Storage::new();

pub fn start(opts: Options) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            match start_async(opts).await {
                Err(e) => {
                    eprintln!("start error: {}", e);
                }
                Ok(_) => {}
            }
        });
    Ok(())
}

pub fn shutdown() -> bool {
    match RUNTIME_CONTROLLER.get().write() {
        Ok(rt) => rt.shutdown_tx.blocking_send(()).is_ok(),
        _ => false,
    }
}

async fn start_async(opts: Options) -> Result<(), Error> {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    RUNTIME_CONTROLLER.set(std::sync::RwLock::new(RuntimeController { shutdown_tx }));

    let config: InternalConfig = match opts.config {
        Config::Internal(c) => c,
        Config::File(home, file) => {
            if !home.is_empty() {
                std::env::set_current_dir(std::path::Path::new(&home))
                    .unwrap_or_else(|_| panic!("invalid home: {}", &home));
            }

            file.parse::<def::Config>()?.try_into()?
        }
        Config::Str(s) => s.as_str().parse::<def::Config>()?.try_into()?,
    };

    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(config.general.log_level, log_collector)
        .expect("failed to setup logging");

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let dns_resolver = dns::Resolver::new(&config.dns).await;

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
        )
        .await?,
    ));

    let router = Arc::new(
        Router::new(
            config.rules,
            dns_resolver.clone(),
            config.general.mmdb,
            config.general.mmdb_download_url,
        )
        .await,
    );

    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
    ));

    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    let inbound_manager = Arc::new(Mutex::new(InboundManager::new(
        config.general.inbound,
        dispatcher.clone(),
        authenticator,
    )?));

    let inbound_runner = inbound_manager.lock().await.get_runner()?;
    let inbound_listener_handle = tokio::spawn(inbound_runner);

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
        router,
    );
    if let Some(r) = api_runner {
        runners.push(r);
    }

    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    tasks.push(Box::pin(async move {
        shutdown_rx.recv().await;
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
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "clash_lib/tests/data/Country.mmdb"
        "#;

        let handle = thread::spawn(|| {
            start(Options {
                config: Config::Str(conf.to_string()),
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
