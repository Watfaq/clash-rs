#![feature(cfg_version, ip, sync_unsafe_cell, let_chains)]
#![cfg_attr(not(version("1.86.0")), feature(unbounded_shifts))]

#[macro_use(anyhow, bail)]
extern crate watfaq_error;

use crate::{
    app::{dispatcher::Dispatcher},
    config::{
        def,
        internal::{InternalConfig},
    },
};
use app::{
    logging::LogEvent, net::init_net_config, profile,
};

use config::def::LogLevel;
use futures::TryFutureExt as _;
use instance::Instance;
use once_cell::sync::OnceCell;

use tokio_util::sync::CancellationToken;

use std::{io, path::PathBuf};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{error, info};

mod app;
mod common;
#[cfg(feature = "internal")]
pub mod config;
#[cfg(not(feature = "internal"))]
mod config;
mod instance;
mod proxy;
mod session;

pub use config::{
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
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
    #[error(transparent)]
    Other(#[from] watfaq_error::Error),
}
pub type Result<T> = watfaq_error::Result<T>;
pub type Runner = futures::future::BoxFuture<'static, Result<()>>;

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

pub struct GlobalState {
    log_level: LogLevel,

    reload_tx: mpsc::Sender<(Config, oneshot::Sender<()>)>,
    cwd: String,
}


impl Config {
    pub fn try_parse(self) -> watfaq_error::Result<InternalConfig> {
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


pub struct RuntimeController {
    shutdown_tx: mpsc::Sender<()>,
}

static RUNTIME_CONTROLLER: OnceCell<RuntimeController> = OnceCell::new();

pub fn start_scaffold(opts: Options) -> Result<()> {
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
        error!("panic hook: {:#}", info);
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
) -> Result<()> {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let (reload_tx, mut reload_rx) = mpsc::channel::<(Config, oneshot::Sender<()>)>(1);

    let _ = RUNTIME_CONTROLLER.get_or_init(|| RuntimeController { shutdown_tx });

    let token = CancellationToken::new();

    let work_dir = PathBuf::from(cwd);

    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let instance = Instance::new(work_dir.clone(), config).await?;
    let mut instance = Some(instance);

    // let reload_task = tokio::spawn(async {
    //     while let Some((config, done)) = .await {
    //         info!("reloading config");
    //         let config = match config.try_parse() {
    //             Ok(c) => c,
    //             Err(e) => {
    //                 error!("failed to reload config: {}", e);
    //                 continue;
    //             }
    //         };

    //         let controller_cfg = config.general.controller.clone();

    //         debug!("stopping listeners");
    //         inbound_manager.shutdown().await;

    //         let new_instace = Instance::new(work_dir.clone(), config).await?;

    //         done.send(()).unwrap();


    //         let mut g = global_state.lock().await;

    //         if let Some(h) = g.tunnel_listener_handle.take() {
    //             h.abort();
    //         }
    //         if let Some(h) = g.dns_listener_handle.take() {
    //             h.abort();
    //         }
    //         if let Some(h) = g.api_listener_handle.take() {
    //             h.abort();
    //         }

    //         let inbound_manager = new_instace.inbound_manager.clone();
    //         debug!("reloading inbound listener");
    //         inbound_manager.restart().await;

    //         debug!("reloading tun runner");
    //         let tun_runner_handle = new_instace.tun_runner.map(tokio::spawn);

    //         debug!("reloading dns listener");
    //         let dns_listener_handle = new_instace.dns_listener.map(tokio::spawn);

    //         debug!("reloading api listener");
    //         app::api::controller_task(
    //             controller_cfg,
    //             log_tx.clone(),
    //             new_instace.inbound_manager,
    //             new_instace.dispatcher,
    //             global_state.clone(),
    //             new_instace.dns_resolver,
    //             new_instace.outbound_manager,
    //             new_instace.statistics_manager,
    //             new_instace.cache_store,
    //             new_instace.router,
    //             work_dir.to_string_lossy().to_string(),
    //         );
    //     }
    // });

    let controller_token = token.child_token();
    let result: Result<()> = loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("received shutdown signal");
                token.cancel();
                break Ok(());
            }
            res = tokio::signal::ctrl_c() => {
                res?;
                info!("received ^C event");
                token.cancel();
                break Ok(());
            }
            Some((config, done)) = reload_rx.recv() => {
                reload_config(&mut instance, config, done).await;
                continue;
            }
        }
    };

    Ok(())
}

async fn reload_config(instance: &mut Option<Instance>, config: Config, done: oneshot::Sender<()>){
    info!("reloading config");
    match instance.take() {
        Some(v) => v.shutdown().await,
        None => {},
    }

    todo!()
}

#[cfg(test)]
mod tests {
    use crate::{Config, Options, shutdown, start_scaffold};
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
