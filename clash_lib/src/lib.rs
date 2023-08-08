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
use state::Storage;
use std::io;

use std::sync::{Arc, Once};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

mod app;
mod common;
mod config;
mod proxy;
mod session;

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

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        app::logging::setup_logging(config.general.log_level).expect("failed to setup logging");
    });

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let default_dns_resolver = Arc::new(dns::Resolver::new(config.dns).await);

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
            default_dns_resolver.clone(),
        )
        .await?,
    ));

    let router = Arc::new(RwLock::new(
        Router::new(
            config.rules,
            default_dns_resolver.clone(),
            config.general.mmdb,
            config.general.mmdb_download_url,
        )
        .await,
    ));

    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager,
        router,
        default_dns_resolver,
    ));

    let inbound_manager = InboundManager::new(config.general.inbound, dispatcher)?;

    let mut inbound_runners = inbound_manager.get_runners()?;
    runners.append(&mut inbound_runners);

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
